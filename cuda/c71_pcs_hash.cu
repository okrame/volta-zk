// Launchers only. Allocation, stream, sticky errors and accounting belong to
// the existing C71RangeContext; this translation unit creates no owner.
#include <cuda_runtime.h>
#include "c71_pcs_hash.cuh"
namespace {
__global__ void leaf(unsigned operation, const uint64_t* ring, const uint64_t* salts,
    c71_pcs::Hash32* states, uint64_t rows, uint64_t first, uint64_t count,
    unsigned first_column, uint32_t* failed) {
    const uint64_t local=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if (local>=count) return;
    const uint64_t row=first+local;
    const unsigned columns=operation==1 ? 8 : 4;
    for (unsigned j=0; j<columns; ++j) if (ring[j*rows+row]>=c71_pcs::MODULUS) {
        atomicExch(failed,1); return;
    }
    if (operation==0) states[row]=c71_pcs::leaf_start(ring,rows,row);
    else if (operation==1) states[row]=c71_pcs::leaf_step(states[row],ring+4*rows,ring,rows,row,first_column);
    else {
        for (unsigned j=0; j<4; ++j) if (salts[j*count+local]>=c71_pcs::MODULUS) {
            atomicExch(failed,1); return;
        }
        states[row]=c71_pcs::leaf_finish(states[row],ring,salts,rows,row,count,local);
    }
}
__global__ void nodes(const c71_pcs::Hash32* input, c71_pcs::Hash32* output, uint64_t count, uint64_t rows) {
    const uint64_t row=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if (row<count) {
        const uint64_t left=2*(row/rows)*rows+row%rows;
        output[row]=c71_pcs::node(input[left],input[left+rows]);
    }
}
__global__ void merge(c71_pcs::Hash32* frontier, c71_pcs::Hash32* roots,
    uint64_t rows, unsigned group, unsigned levels) {
    const uint64_t row=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if (row<rows) c71_pcs::merge_group(frontier,roots,rows,row,group,levels);
}
}
extern "C" cudaError_t c71_pcs_hash_launch(cudaStream_t stream, unsigned operation,
    const uint64_t* ring, const uint64_t* salts, c71_pcs::Hash32* states,
    uint64_t rows, uint64_t first, uint64_t count, unsigned first_column, uint32_t* failed) {
    if (!rows || rows>(uint64_t{1}<<25) || operation>2 || !ring || !states || !failed ||
        !count || first>rows || count>rows-first || (operation==2 && !salts)) return cudaErrorInvalidValue;
    leaf<<<unsigned((count+127)/128),128,0,stream>>>(operation,ring,salts,states,rows,first,count,first_column,failed);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_nodes_launch(cudaStream_t stream, const c71_pcs::Hash32* input,
    c71_pcs::Hash32* output, uint64_t count, uint64_t rows) {
    if (!count || count>(uint64_t{1}<<25) || !input || !output || input==output)
        return cudaErrorInvalidValue;
    if (!rows || count%rows) return cudaErrorInvalidValue;
    nodes<<<unsigned((count+127)/128),128,0,stream>>>(input,output,count,rows);
    return cudaGetLastError();
}
extern "C" cudaError_t c71_pcs_merge_launch(cudaStream_t stream, c71_pcs::Hash32* frontier,
    c71_pcs::Hash32* roots, uint64_t rows, unsigned group, unsigned levels) {
    if (!rows || rows>(uint64_t{1}<<25) || !frontier || !roots || frontier==roots ||
        !levels || levels>12 || group>=(1u<<levels)) return cudaErrorInvalidValue;
    merge<<<unsigned((rows+127)/128),128,0,stream>>>(frontier,roots,rows,group,levels);
    return cudaGetLastError();
}
