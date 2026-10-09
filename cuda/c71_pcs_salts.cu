// Bounded private-coin work on the existing caller-owned explicit stream.
// No allocator, owner, host spill, fence, or numerical producer is added.
#include <cuda_runtime.h>
#include "c71_pcs_salts.cuh"
namespace {
using namespace c71_salts;

__device__ uint32_t inclusive_scan(uint32_t value, uint32_t shared[SCAN_THREADS]) {
    const unsigned lane=threadIdx.x;
    shared[lane]=value;
    __syncthreads();
    for(unsigned step=1;step<SCAN_THREADS;step<<=1) {
        const uint32_t left=lane>=step ? shared[lane-step] : 0;
        __syncthreads();
        shared[lane]+=left;
        __syncthreads();
    }
    return shared[lane];
}

__global__ void masks_and_prefix(const Descriptor* descriptor, Chunk c,
    uint8_t* masks, uint32_t* prefix, uint32_t* block_sums) {
    __shared__ uint32_t shared[SCAN_THREADS];
    const uint32_t block=blockIdx.x*SCAN_THREADS+threadIdx.x;
    const uint8_t mask=block<chunk_blocks(c) ? block_mask(*descriptor,c,block) : 0;
    const uint32_t value=popcount(mask);
    const uint32_t inclusive=inclusive_scan(value,shared);
    if(block<chunk_blocks(c)) { masks[block]=mask; prefix[block]=inclusive-value; }
    if(threadIdx.x==SCAN_THREADS-1) block_sums[blockIdx.x]=inclusive;
}

__global__ void prefix_block_sums(Chunk c, uint32_t* block_sums, uint32_t* group_sums) {
    __shared__ uint32_t shared[SCAN_THREADS];
    const uint32_t block=blockIdx.x*SCAN_THREADS+threadIdx.x;
    const uint32_t value=block<block_sum_slots(c) ? block_sums[block] : 0;
    const uint32_t inclusive=inclusive_scan(value,shared);
    if(block<block_sum_slots(c)) block_sums[block]=inclusive-value;
    if(threadIdx.x==SCAN_THREADS-1) group_sums[blockIdx.x]=inclusive;
}

__global__ void prefix_group_sums(Chunk c, Geometry g, uint32_t* group_sums,
    Progress* progress, uint32_t* failed) {
    __shared__ uint32_t shared[SCAN_THREADS];
    const unsigned lane=threadIdx.x;
    const uint32_t value=lane<group_sum_slots(c) ? group_sums[lane] : 0;
    const uint32_t inclusive=inclusive_scan(value,shared);
    if(lane<group_sum_slots(c)) group_sums[lane]=inclusive-value;
    if(lane==SCAN_THREADS-1) {
        const uint64_t accepted=c.accepted+inclusive;
        const bool complete=accepted>=c.target;
        // If complete, pass four selects the exact terminal cursor; the
        // speculative candidates in this chunk do not consume stream bytes.
        const uint64_t cursor=complete ? c.cursor : c.cursor+8*uint64_t(c.candidates);
        uint32_t rejected=*failed;
        if(!complete && CAP-cursor<8) { atomicExch(failed,1); rejected=1; }
        *progress={cursor,complete ? c.target : accepted,cursor-g.origin,
            physical_blocks(c),rejected,uint32_t(complete)};
    }
}

__global__ void select_boundaries(Chunk c, Geometry g, const uint8_t* masks,
    const uint32_t* prefix, const uint32_t* block_sums, const uint32_t* group_sums,
    uint64_t* starts, uint64_t* offsets, Progress* progress) {
    const uint32_t block=blockIdx.x*SCAN_THREADS+threadIdx.x;
    if(block>=chunk_blocks(c)) return;
    if(!block) { starts[0]=g.origin; offsets[0]=g.origin; }
    const uint8_t mask=masks[block];
    const uint32_t local_group=block/SCAN_THREADS;
    const uint64_t before=c.accepted+uint64_t(prefix[block])+block_sums[local_group]
        +group_sums[local_group/SCAN_THREADS];
    if(before>=c.target) return;
    const uint64_t row_boundary=4*uint64_t(g.cosets), cut_boundary=4*uint64_t(g.cut);
    const unsigned count=popcount(mask);
    // Most blocks contain neither a row/cut boundary nor the final sample.
    // These periods are powers of two; skip without per-candidate divisions.
    if((before&(row_boundary-1))+count<row_boundary &&
        (before&(cut_boundary-1))+count<cut_boundary && c.target-before>count) return;
    for(unsigned rank=1;rank<=count;++rank) {
        const uint64_t accepted=before+rank;
        if(accepted>c.target) break;
        const uint64_t cursor=after_accepted(c,block,mask,rank);
        if(!(accepted&(row_boundary-1)) && accepted/row_boundary<g.rows)
            starts[accepted/row_boundary]=cursor;
        if(!(accepted&(cut_boundary-1)) && accepted/cut_boundary<g.rows*g.cosets/g.cut)
            offsets[accepted/cut_boundary]=cursor;
        if(accepted==c.target) {
            progress->cursor=cursor; progress->logical_bytes=cursor-g.origin;
        }
    }
}

__global__ void empty_chunk(Chunk c, Geometry g, uint64_t* starts, uint64_t* offsets,
    Progress* progress, uint32_t* failed) {
    const bool complete=c.accepted==c.target;
    uint32_t rejected=*failed;
    if(!complete) { atomicExch(failed,1); rejected=1; }
    starts[0]=g.origin; offsets[0]=g.origin;
    *progress={c.cursor,c.accepted,c.cursor-g.origin,0,rejected,uint32_t(complete)};
}

__global__ void replay(const Descriptor* descriptor, uint64_t* current, uint64_t rows,
    uint64_t first, uint64_t count, uint64_t* salts, uint64_t* consumed, uint32_t* failed) {
    const uint64_t local=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    const uint64_t unique=count<rows ? count : rows;
    if(local>=unique) return;
    const uint64_t row=(first%rows+local)%rows;
    uint64_t bytes=0;
    if(!replay_row(*descriptor,current[row],rows,first,count,row,salts,bytes)) atomicExch(failed,1);
    atomicAdd(reinterpret_cast<unsigned long long*>(consumed),static_cast<unsigned long long>(bytes));
}
}

extern "C" cudaError_t c71_pcs_salts_prescan_launch(cudaStream_t stream,
    const c71_salts::Descriptor* descriptor,c71_salts::Chunk c,c71_salts::Geometry g,
    uint8_t* masks,uint32_t* prefix,uint32_t* block_sums,uint32_t* group_sums,
    uint64_t* starts,uint64_t* offsets,c71_salts::Progress* progress,uint32_t* failed,unsigned* attempted) {
    if(!stream || !descriptor || !starts || !offsets || !progress || !failed || !attempted ||
        !c71_salts::valid(c,g) || (starts==offsets) ||
        (c.candidates && (!masks || !prefix || !block_sums || !group_sums || prefix==block_sums ||
            prefix==group_sums || block_sums==group_sums))) return cudaErrorInvalidValue;
    if(!c.candidates) {
        ++*attempted;
        empty_chunk<<<1,1,0,stream>>>(c,g,starts,offsets,progress,failed);
        return cudaGetLastError();
    }
    ++*attempted;
    masks_and_prefix<<<c71_salts::block_sum_slots(c),c71_salts::SCAN_THREADS,0,stream>>>(
        descriptor,c,masks,prefix,block_sums);
    auto status=cudaGetLastError(); if(status!=cudaSuccess) return status;
    ++*attempted;
    prefix_block_sums<<<c71_salts::group_sum_slots(c),c71_salts::SCAN_THREADS,0,stream>>>(c,block_sums,group_sums);
    status=cudaGetLastError(); if(status!=cudaSuccess) return status;
    ++*attempted;
    prefix_group_sums<<<1,c71_salts::SCAN_THREADS,0,stream>>>(c,g,group_sums,progress,failed);
    status=cudaGetLastError(); if(status!=cudaSuccess) return status;
    ++*attempted;
    select_boundaries<<<c71_salts::block_sum_slots(c),c71_salts::SCAN_THREADS,0,stream>>>(
        c,g,masks,prefix,block_sums,group_sums,starts,offsets,progress);
    return cudaGetLastError();
}

extern "C" cudaError_t c71_pcs_salts_replay_launch(cudaStream_t stream,
    const c71_salts::Descriptor* descriptor,uint64_t* current,uint64_t rows,uint64_t first,uint64_t count,
    uint64_t* salts,uint64_t* consumed,uint32_t* failed) {
    if(!stream || !descriptor || !current || !salts || !consumed || !failed ||
        !c71_salts::valid_replay_span(rows,first,count) ||
        current==salts || current==consumed || salts==consumed)
        return cudaErrorInvalidValue;
    const uint64_t unique=count<rows ? count : rows;
    replay<<<unsigned((unique+127)/128),128,0,stream>>>(descriptor,current,rows,first,count,salts,consumed,failed);
    return cudaGetLastError();
}
