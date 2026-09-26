// EXP30 prefix component only. No FS, MAC, producer, or GPU admission here.
// PTX fragment mapping: NVIDIA PTX ISA, mma.m16n8k256 (A, B, C/D).
#ifdef __CUDACC__
#include <cuda_runtime.h>
#define HD __host__ __device__
#else
#define HD
#endif
#include <array>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "c71_fp3.cuh"

constexpr uint64_t FIELD_P = 0xffffffff00000001ULL;
constexpr unsigned BATCH_TILES = 64;
constexpr unsigned ROW_WORDS = 8;  // 256 public suffix positions per tile.
constexpr unsigned WIRE_WORDS = 16 * ROW_WORDS;

HD unsigned eq_index(unsigned tile, unsigned word, unsigned bit) { return (tile*8+word)*192+bit; }

HD unsigned a_row(unsigned lane, unsigned reg) { return lane / 4 + 8 * (reg & 1); }
HD unsigned a_word(unsigned lane, unsigned reg) { return lane % 4 + 4 * (reg / 2); }
HD unsigned b_word(unsigned lane, unsigned reg) { return lane % 4 + 4 * reg; }
HD unsigned c_row(unsigned lane, unsigned reg) { return lane / 4 + 8 * (reg / 2); }
HD unsigned c_col(unsigned lane, unsigned reg) { return 2 * (lane % 4) + (reg & 1); }

struct RatioLocation { unsigned cell, denominator, suffix; };
// Compact rank has 4 base layers x 32 heads x causal (query,key).
// The original suffix still includes query/key padding; never use rank as Eq's index.
HD RatioLocation ratio_location(unsigned rank, unsigned old, unsigned position) {
    const unsigned per_head=150*old+150*151/2, group=rank/per_head, offset=rank%per_head;
    unsigned lo=0, hi=150;
    while(lo+1<hi) {
        const unsigned mid=(lo+hi)/2;
        if(mid*old+mid*(mid+1)/2<=offset) lo=mid; else hi=mid;
    }
    const unsigned key=offset-lo*old-lo*(lo+1)/2;
    const unsigned layer_head=(position*4+group/32)*32+group%32;
    return {layer_head*per_head+offset, layer_head*150+lo,
            (group*256+lo)*(old?512:256)+key};
}

HD Fp3 equality_at(const Fp3* point, unsigned bits, unsigned index) {
    Fp3 value{1,0,0};
    for(unsigned d=0;d<bits;++d)
        value=mul6(value,(index>>(bits-1-d))&1?point[d]:sub(Fp3{1,0,0},point[d]));
    return value;
}

HD uint32_t stage_word(const uint64_t* packed, unsigned n, unsigned word, unsigned row) {
    const unsigned first=word*32;
    const unsigned valid=first>=n?0:(n-first<32?n-first:32);
    const uint32_t mask=valid==32?~uint32_t{0}:(valid?((uint32_t{1}<<valid)-1):0);
    if(row==15) return mask; // Auxiliary constant, not an original GKR wire.
    uint32_t out=0;
    for(unsigned q=0;q<8;++q) if(first+q*4<n) {
        const uint64_t x=(packed[word*8+q]>>row)&0x0001000100010001ULL;
        out|=uint32_t((x*0x0001000200040008ULL)>>48&15)<<(q*4);
    }
    return out&mask;
}

HD uint64_t reduce_count_bits(const uint32_t* counts, size_t stride) {
    uint64_t lo=0; uint32_t hi=0;
    for(unsigned bit=0;bit<64;++bit) {
        const uint64_t count=counts[bit*stride];
        const uint64_t term=count<<bit, next=lo+term;
        hi+=uint32_t(bit?count>>(64-bit):0)+uint32_t(next<lo);
        lo=next;
    }
    // 2^64 == 2^32-1 mod p; hi<=N<2^31, no 128-bit device arithmetic.
    constexpr uint64_t epsilon=0xffffffffULL;
    uint64_t reduced=lo+uint64_t(hi)*epsilon;
    if(reduced<lo) reduced+=epsilon;
    return reduced>=FIELD_P?reduced-FIELD_P:reduced;
}

// 225 quadratic coefficients followed by 15 linear coefficients; auxiliary
// row/column 15 contributes only XOR's linear margins, never the selector.
HD Fp3 weighted_moment(unsigned slot, const Fp3* binary, const Fp3* copies,
    const Fp3* binary_weights, const Fp3* copy_weights, const uint32_t* is_xor,
    unsigned gates, unsigned copy_count) {
    Fp3 out{};
    if(slot<225) {
        const unsigned cell=(slot/15)*16+slot%15;
        for(unsigned g=0;g<gates;++g) {
            const Fp3 term=mul6(binary[size_t(g)*256+cell],binary_weights[g]);
            out=is_xor[g]?sub(out,add(term,term)):add(out,term);
        }
    } else {
        const unsigned row=slot-225;
        for(unsigned g=0;g<gates;++g) if(is_xor[g])
            out=add(out,mul6(add(binary[size_t(g)*256+row*16+15],
                                binary[size_t(g)*256+15*16+row]),binary_weights[g]));
        for(unsigned g=0;g<copy_count;++g)
            out=add(out,mul6(copies[size_t(g)*15+row],copy_weights[g]));
    }
    return out;
}

#ifdef __CUDACC__
extern "C" __global__ void c71_exp30_weight_moments(
    const Fp3* binary, const Fp3* copies, const Fp3* binary_weights,
    const Fp3* copy_weights, const uint32_t* is_xor, unsigned gates,
    unsigned copy_count, Fp3* aggregate) {
    const unsigned slot=blockIdx.x*blockDim.x+threadIdx.x;
    if(slot<240) aggregate[slot]=weighted_moment(slot,binary,copies,binary_weights,
                                              copy_weights,is_xor,gates,copy_count);
}

// Public suffix Eq factor tables. bits=23/24, low 12 bits; no full Eq domain.
extern "C" __global__ void c71_exp30_eq_tables(const Fp3* point, unsigned bits, Fp3* tables) {
    const unsigned index=blockIdx.x*blockDim.x+threadIdx.x, high_count=1u<<(bits-12);
    if(index<high_count) tables[index]=equality_at(point,bits-12,index);
    else if(index<high_count+4096) tables[index]=equality_at(point+bits-12,12,index-high_count);
}

// Fuse original-coordinate Eq evaluation with bitplane packing. No canonical
// Eq input buffer, no host-to-device transfer per batch, no Eq(compact_rank).
extern "C" __global__ void c71_exp30_original_eq(
    const Fp3* tables, uint32_t* eq_bits, unsigned old, unsigned first, unsigned n) {
    const unsigned k=blockIdx.x*blockDim.x+threadIdx.x, lane=threadIdx.x&31;
    if(k/256>=(n+255)/256) return;
    Fp3 weight{};
    if(k<n) {
        const unsigned index=ratio_location(first+k,old,0).suffix;
        weight=mul6(tables[index>>12],tables[(old?4096:2048)+(index&4095)]);
    }
    const uint64_t limbs[3]={weight.c0,weight.c1,weight.c2};
#pragma unroll
    for(unsigned limb=0;limb<3;++limb) for(unsigned bit=0;bit<64;++bit) {
        const uint32_t value=__ballot_sync(0xffffffffu,(limbs[limb]>>bit)&1);
        if(lane==0) eq_bits[eq_index(k/256,(k%256)/32,limb*64+bit)]=value;
    }
}

// Public native DAG, level-parallel slot reuse. Exactly 128 threads per CTA,
// dynamic shared = 8*plan.slots. No per-quad global intermediate history.
// Directly consumes the ORIGINAL causal E/Pi and Z cache; one CTA = four
// compact suffix positions x 16 original prefix rows, row 15 zero.
extern "C" __global__ void c71_exp30_replay_shared(
    const uint8_t* cells, const uint8_t* denominators, unsigned old,
    unsigned first, unsigned n, const uint4* ops, const uint32_t* boundaries,
    unsigned stages, const uint32_t* outputs, unsigned wires, uint64_t* packed_stage) {
    if(blockIdx.x*4>=n) return;
    extern __shared__ uint64_t values[];
    if(threadIdx.x<64) {
        const unsigned local=blockIdx.x*4+threadIdx.x/16, position=threadIdx.x%16;
        const unsigned lane=threadIdx.x%32, warp=threadIdx.x/32;
        const bool live=local<n && position<15;
        uint32_t frame[3]={0,0,0};
        if(live) {
            const RatioLocation at=ratio_location(first+local,old,position);
            for(unsigned b=0;b<4;++b) frame[0]|=uint32_t(cells[size_t(at.cell)*6+b])<<(8*b);
            for(unsigned b=0;b<4;++b) frame[1]|=uint32_t(denominators[size_t(at.denominator)*6+b])<<(8*b);
            for(unsigned b=0;b<2;++b) {
                frame[2]|=uint32_t(denominators[size_t(at.denominator)*6+4+b])<<(8*b);
                frame[2]|=uint32_t(cells[size_t(at.cell)*6+4+b])<<(16+8*b);
            }
        }
        uint32_t* words=reinterpret_cast<uint32_t*>(values);
        const uint32_t live_bits=__ballot_sync(0xffffffffu,live);
        if(lane==0) { words[warp]=0; words[2+warp]=live_bits; }
        for(unsigned bit=0;bit<96;++bit) {
            const uint32_t bits=__ballot_sync(0xffffffffu,(frame[bit/32]>>(bit%32))&1);
            if(lane==0) words[2*(bit+2)+warp]=bits;
        }
    }
    __syncthreads();
    for(unsigned stage=0;stage<stages;++stage) {
        for(unsigned i=boundaries[stage]+threadIdx.x;i<boundaries[stage+1];i+=128) {
            const uint4 g=ops[i];
            const uint64_t x=values[g.z], y=values[g.w];
            values[g.y]=g.x?(x^y):(x&y);
        }
        __syncthreads(); // Slots retired here become reusable only in the NEXT stage.
    }
    for(unsigned wire=threadIdx.x;wire<wires;wire+=128)
        packed_stage[size_t(wire)*BATCH_TILES*64+blockIdx.x]=values[outputs[wire]];
}

// In-place transpose of a disjoint 512-byte tile. Launch exactly 128 threads.
// Producer quads use fixed [wire][64 tiles][64 u64] strides; compact rank
// must be mapped to original Eq before this component is called.
extern "C" __global__ void c71_exp30_pack_wires(
    uint64_t* packed_stage, unsigned wires, unsigned n) {
    const unsigned tiles=(n+255)/256, job=blockIdx.x;
    if(job>=wires*tiles) return;
    const unsigned wire=job/tiles, tile=job%tiles;
    const unsigned remaining=n-tile*256, count=remaining<256?remaining:256;
    uint64_t* input=packed_stage+(size_t(wire)*64+tile)*64;
    __shared__ uint64_t snapshot[64];
    if(threadIdx.x<64) snapshot[threadIdx.x]=threadIdx.x*4<count?input[threadIdx.x]:0;
    __syncthreads();
    const unsigned row=threadIdx.x%16, word=threadIdx.x/16;
    reinterpret_cast<uint32_t*>(input)[row*8+word]=stage_word(snapshot,count,word,row);
}

extern "C" __global__ void c71_exp30_pack_eq(
    const uint64_t* canonical_limbs, uint32_t* eq_bits, unsigned n) {
    const unsigned k=blockIdx.x*blockDim.x+threadIdx.x, lane=threadIdx.x&31;
    if(k/256>=(n+255)/256) return; // Uniform for every full warp.
    for(unsigned limb=0;limb<3;++limb) {
        const uint64_t value=k<n?canonical_limbs[size_t(k)*3+limb]:0;
        for(unsigned b=0;b<64;++b) {
            const uint32_t bits=__ballot_sync(0xffffffffu,(value>>b)&1);
            if(lane==0) eq_bits[eq_index(k/256,(k%256)/32,limb*64+b)]=bits;
        }
    }
}

// Separate binary and Copy layouts; output consists of three canonical limbs
// per original moment. Counts are consumed only after every batch fence.
extern "C" __global__ void c71_exp30_reduce_binary(
    const uint32_t* counts, uint64_t* moments, unsigned gates) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=size_t(gates)*256*3) return;
    const size_t gate=i/(256*3), cell=(i/3)%256, limb=i%3;
    moments[i]=reduce_count_bits(counts+(gate*192+limb*64)*256+cell,256);
}
extern "C" __global__ void c71_exp30_reduce_copy(
    const uint32_t* counts, uint64_t* moments, unsigned columns) {
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i>=size_t(columns)*3) return;
    moments[i]=reduce_count_bits(counts+(i/3)*192+(i%3)*64,1);
}

// One warp owns gate x (8 weight bits) x (8 output columns). Disjoint writes.
// tiles <=64; fixed public strides permit immediate-offset loads.
// Stage: [wire][64 K tiles][16 rows][8 u32]; row 15 is a public constant one.
// Eq: [64 K tiles][8 u32][192 weight bits], from ORIGINAL suffix indices, not compact rank.
// Counts: [gate][192 weight bits][16][16], carried between fenced batches.
// Caller must keep total contributed suffix positions <2^31 and zero padding.
extern "C" __global__ void c71_exp30_bmma8(
    const uint32_t* stage, const uint32_t* eq_bits, const uint2* gates,
    int32_t* counts, unsigned gate_count, unsigned tiles) {
    const unsigned lane = threadIdx.x & 31;
    const unsigned job = (blockIdx.x * blockDim.x + threadIdx.x) / 32;
    if (job >= gate_count * 48) return; // Uniform within every full warp.
    const unsigned gate = job / 48, first_bit = (job % 48 / 2) * 8;
    const unsigned half = job & 1;
    const uint2 operands = gates[gate];
    int acc[8][4];
#pragma unroll
    for (unsigned q=0;q<8;++q) {
#pragma unroll
        for (unsigned r=0;r<4;++r)
            acc[q][r] = counts[(size_t(gate)*192+first_bit+q)*256
                +c_row(lane,r)*16+half*8+c_col(lane,r)];
    }
    for (unsigned tile=0;tile<tiles;++tile) {
        uint32_t a[4], y[2];
#pragma unroll
        for (unsigned r=0;r<4;++r)
            a[r]=stage[(size_t(operands.x)*BATCH_TILES+tile)*WIRE_WORDS
                +a_row(lane,r)*8+a_word(lane,r)];
#pragma unroll
        for (unsigned r=0;r<2;++r)
            y[r]=stage[(size_t(operands.y)*BATCH_TILES+tile)*WIRE_WORDS
                +(lane/4+half*8)*8+b_word(lane,r)];
        const uint4* p0=reinterpret_cast<const uint4*>(eq_bits+eq_index(tile,b_word(lane,0),first_bit));
        const uint4* p1=reinterpret_cast<const uint4*>(eq_bits+eq_index(tile,b_word(lane,1),first_bit));
        const uint4 e00=p0[0], e01=p0[1], e10=p1[0], e11=p1[1];
        const uint32_t w0[8]={e00.x,e00.y,e00.z,e00.w,e01.x,e01.y,e01.z,e01.w};
        const uint32_t w1[8]={e10.x,e10.y,e10.z,e10.w,e11.x,e11.y,e11.z,e11.w};
#pragma unroll
        for (unsigned q=0;q<8;++q) {
            const uint32_t b0=y[0]&w0[q], b1=y[1]&w1[q];
            asm volatile("mma.sync.aligned.m16n8k256.row.col.s32.b1.b1.s32.and.popc "
                "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
                : "+r"(acc[q][0]), "+r"(acc[q][1]), "+r"(acc[q][2]), "+r"(acc[q][3])
                : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b0),"r"(b1));
        }
    }
#pragma unroll
    for (unsigned q=0;q<8;++q) {
#pragma unroll
        for (unsigned r=0;r<4;++r)
            counts[(size_t(gate)*192+first_bit+q)*256
                +c_row(lane,r)*16+half*8+c_col(lane,r)] = acc[q][r];
    }
}
// Copy moments: 16 different Eq bits x 8 original wire/position columns.
// No Boolean weighting or scatter is needed. counts has ceil(copies*15/8)*8
// columns, each with 192 counters; padded columns must start at zero.
extern "C" __global__ void c71_exp30_copy_bmma(
    const uint32_t* stage, const uint32_t* eq_bits, const uint32_t* copy_wires,
    int32_t* counts, unsigned copy_count, unsigned tiles) {
    const unsigned lane=threadIdx.x&31;
    const unsigned job=(blockIdx.x*blockDim.x+threadIdx.x)/32;
    const unsigned groups=(copy_count*15+7)/8;
    if(job>=groups*12) return;
    const unsigned group=job/12, first_bit=(job%12)*16;
    const unsigned col=group*8+lane/4;
    const bool live=col<copy_count*15;
    const unsigned wire=live?copy_wires[col/15]:0, row=col%15;
    int d[4];
#pragma unroll
    for(unsigned r=0;r<4;++r)
        d[r]=counts[size_t(group*8+c_col(lane,r))*192+first_bit+c_row(lane,r)];
    for(unsigned tile=0;tile<tiles;++tile) {
        uint32_t a[4],b[2];
#pragma unroll
        for(unsigned r=0;r<4;++r)
            a[r]=eq_bits[eq_index(tile,a_word(lane,r),first_bit+a_row(lane,r))];
#pragma unroll
        for(unsigned r=0;r<2;++r)
            b[r]=live?stage[(size_t(wire)*BATCH_TILES+tile)*WIRE_WORDS+row*8+b_word(lane,r)]:0;
        asm volatile("mma.sync.aligned.m16n8k256.row.col.s32.b1.b1.s32.and.popc "
            "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};"
            : "+r"(d[0]),"+r"(d[1]),"+r"(d[2]),"+r"(d[3])
            : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(b[0]),"r"(b[1]));
    }
#pragma unroll
    for(unsigned r=0;r<4;++r)
        counts[size_t(group*8+c_col(lane,r))*192+first_bit+c_row(lane,r)]=d[r];
}

#endif

// CPU semantic/packing check. This does NOT execute or time the GPU kernel.
bool host_check(unsigned n) {
    const unsigned tiles=(n+255)/256;
    std::vector<uint32_t> stage(2*BATCH_TILES*WIRE_WORDS), bits(192*BATCH_TILES*8);
    std::vector<std::array<uint64_t,3>> eq(n);
    std::vector<std::array<uint16_t,2>> values(n);
    uint64_t seed=0x7130031;
    auto random=[&] {seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;};
    for(unsigned k=0;k<n;++k) {
        values[k]={uint16_t(random()|0x8000),uint16_t(random()|0x8000)};
        for(unsigned limb=0;limb<3;++limb) {
            eq[k][limb] = k%3==0 ? FIELD_P-1 : random()%FIELD_P;
            for(unsigned b=0;b<64;++b)
                bits[eq_index(k/256,(k%256)/32,limb*64+b)]
                    |=uint32_t(eq[k][limb]>>b&1)<<(k%32);
        }
        for(unsigned wire=0;wire<2;++wire)
            for(unsigned j=0;j<16;++j)
                stage[(wire*BATCH_TILES+k/256)*WIRE_WORDS+j*8+(k%256)/32]
                    |=uint32_t(values[k][wire]>>j&1)<<(k%32);
    }
    std::vector<uint64_t> packed(2*((n+3)/4));
    for(unsigned k=0;k<n;++k) for(unsigned wire=0;wire<2;++wire)
        packed[wire*((n+3)/4)+k/4]|=uint64_t(values[k][wire]&0x7fff)<<(16*(k%4));
    for(unsigned wire=0;wire<2;++wire) for(unsigned word=0;word<tiles*8;++word)
        for(unsigned row=0;row<16;++row)
            if(stage_word(packed.data()+wire*((n+3)/4),n,word,row)
               !=stage[(wire*64+word/8)*128+row*8+word%8]) return false;
    std::vector<uint32_t> inplace(2*64*128);
    for(unsigned wire=0;wire<2;++wire) for(unsigned q=0;q<(n+3)/4;++q) {
        const uint64_t v=packed[wire*((n+3)/4)+q];
        inplace[wire*64*128+2*q]=uint32_t(v);
        inplace[wire*64*128+2*q+1]=uint32_t(v>>32);
    }
    for(unsigned wire=0;wire<2;++wire) for(unsigned tile=0;tile<tiles;++tile) {
        const unsigned base=(wire*64+tile)*128, count=n-tile*256<256?n-tile*256:256;
        std::array<uint64_t,64> snapshot{};
        for(unsigned q=0;q<64;++q)
            snapshot[q]=uint64_t(inplace[base+2*q])|(uint64_t(inplace[base+2*q+1])<<32);
        for(unsigned row=0;row<16;++row) for(unsigned word=0;word<8;++word)
            inplace[base+row*8+word]=stage_word(snapshot.data(),count,word,row);
        for(unsigned i=0;i<128;++i) if(inplace[base+i]!=stage[base+i]) return false;
    }
    std::vector<uint32_t> counts(192*256);
    for(unsigned q=0;q<192;++q) for(unsigned tile=0;tile<tiles;++tile) {
        uint32_t a[32][4], b[2][32][2];
        for(unsigned lane=0;lane<32;++lane) {
            for(unsigned r=0;r<4;++r)
                a[lane][r]=stage[tile*WIRE_WORDS+a_row(lane,r)*8+a_word(lane,r)];
            for(unsigned h=0;h<2;++h) for(unsigned r=0;r<2;++r)
                b[h][lane][r]=stage[(BATCH_TILES+tile)*WIRE_WORDS+(lane/4+h*8)*8+b_word(lane,r)]
                    &bits[eq_index(tile,b_word(lane,r),q)];
        }
        // Emulate the documented collective MMA using exactly these fragments.
        for(unsigned h=0;h<2;++h) for(unsigned lane=0;lane<32;++lane)
            for(unsigned r=0;r<4;++r) {
                unsigned row=c_row(lane,r), col=c_col(lane,r), sum=0;
                for(unsigned w=0;w<8;++w) {
                    const unsigned al=(row%8)*4+w%4, ar=(row/8)+2*(w/4);
                    const unsigned bl=col*4+w%4, br=w/4;
                    sum+=__builtin_popcount(a[al][ar]&b[h][bl][br]);
                }
                counts[q*256+row*16+h*8+col]+=sum;
            }
    }
    std::vector<uint32_t> copy_counts(32*192);
    for(unsigned first=0;first<192;first+=16) for(unsigned tile=0;tile<tiles;++tile)
        for(unsigned group=0;group<4;++group) {
            uint32_t a[32][4],b[32][2];
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<4;++r)
                    a[lane][r]=bits[eq_index(tile,a_word(lane,r),first+a_row(lane,r))];
                for(unsigned r=0;r<2;++r) {
                    const unsigned col=group*8+lane/4;
                    b[lane][r]=col<30?stage[((col/15)*BATCH_TILES+tile)*WIRE_WORDS+(col%15)*8+b_word(lane,r)]:0;
                }
            }
            for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
                const unsigned row=c_row(lane,r), col=c_col(lane,r);
                unsigned sum=0;
                for(unsigned w=0;w<8;++w)
                    sum+=__builtin_popcount(a[(row%8)*4+w%4][row/8+2*(w/4)]&b[col*4+w%4][w/4]);
                copy_counts[(group*8+col)*192+first+row]+=sum;
            }
        }
    for(unsigned j=0;j<32;++j) for(unsigned q=0;q<192;++q) {
        unsigned direct=0;
        for(unsigned k=0;k<n;++k)
            direct+=j<30 && (values[k][j/15]>>(j%15)&1) && (eq[k][q/64]>>(q%64)&1);
        if(copy_counts[j*192+q]!=direct) return false;
    }
    for(unsigned i=0;i<16;++i) for(unsigned j=0;j<16;++j)
        for(unsigned limb=0;limb<3;++limb) {
            __uint128_t recovered=0,direct=0;
            for(unsigned b=0;b<64;++b)
                recovered+=__uint128_t(counts[(limb*64+b)*256+i*16+j])<<b;
            for(unsigned k=0;k<n;++k)
                if((values[k][0]>>i&1)&&(values[k][1]>>j&1)) direct+=eq[k][limb];
            if(recovered!=direct || recovered%FIELD_P!=direct%FIELD_P) return false;
            if(reduce_count_bits(counts.data()+limb*64*256+i*16+j,256)!=uint64_t(direct%FIELD_P)) return false;
        }
    std::vector<Fp3> binary(512), copies(30);
    for(unsigned cell=0;cell<256;++cell) {
        const Fp3 m{reduce_count_bits(counts.data()+cell,256),
                    reduce_count_bits(counts.data()+64*256+cell,256),
                    reduce_count_bits(counts.data()+128*256+cell,256)};
        binary[cell]=binary[256+cell]=m; // And and Xor on the same original operands.
    }
    for(unsigned i=0;i<30;++i) copies[i]={reduce_count_bits(copy_counts.data()+i*192,1),
        reduce_count_bits(copy_counts.data()+i*192+64,1),reduce_count_bits(copy_counts.data()+i*192+128,1)};
    const Fp3 weights[4]={{P-3,7,11},{19,P-5,23},{29,31,P-7},{37,41,43}};
    const uint32_t is_xor[2]={0,1};
    for(unsigned slot=0;slot<240;++slot) {
        const Fp3 got=weighted_moment(slot,binary.data(),copies.data(),weights,weights+2,is_xor,2,2);
        Fp3 direct{};
        for(unsigned k=0;k<n;++k) {
            const Fp3 w{eq[k][0],eq[k][1],eq[k][2]};
            const unsigned i=slot<225?slot/15:slot-225, j=slot%15;
            const bool x=(values[k][0]>>i)&1, y=(values[k][1]>>i)&1;
            if(slot<225) {
                if(x&&((values[k][1]>>j)&1)) direct=add(direct,mul(w,sub(weights[0],add(weights[1],weights[1]))));
            } else {
                if(x) direct=add(direct,mul(w,add(weights[1],weights[2])));
                if(y) direct=add(direct,mul(w,add(weights[1],weights[3])));
            }
        }
        if(got.c0!=direct.c0||got.c1!=direct.c1||got.c2!=direct.c2) return false;
    }
    return true;
}

bool location_check() {
    for(unsigned old:{0u,150u,300u}) {
        const unsigned per_head=150*old+150*151/2, key_domain=old?512:256;
        unsigned rank=0;
        for(unsigned group=0;group<128;++group) for(unsigned q=0;q<150;++q) {
            for(unsigned key:{0u,old+q}) for(unsigned position:{0u,7u,14u}) {
                const RatioLocation at=ratio_location(rank+key,old,position);
                const unsigned layer=position*4+group/32, head=group%32;
                if(at.cell!=(layer*32+head)*per_head+q*old+q*(q+1)/2+key ||
                   at.denominator!=(layer*32+head)*150+q ||
                   at.suffix!=((group*256+q)*key_domain+key)) return false;
            }
            rank+=old+q+1;
        }
        if(rank!=128*per_head) return false;
    }
    return true;
}

bool original_eq_check() {
    for(unsigned old:{0u,150u,300u}) for(unsigned boundary:{0u,1u,2u}) {
        const unsigned bits=old?24:23, high=bits-12, count=1u<<high;
        std::vector<Fp3> point(bits), tables(count+4096);
        for(unsigned i=0;i<bits;++i) point[i]=boundary<2?Fp3{boundary,0,0}:Fp3{P-7-i,13+i,29+i};
        for(unsigned i=0;i<count;++i) tables[i]=equality_at(point.data(),high,i);
        for(unsigned i=0;i<4096;++i) tables[count+i]=equality_at(point.data()+high,12,i);
        const unsigned n=128*(150*old+150*151/2);
        for(unsigned rank:{0u,1u,255u,256u,16383u,16384u,n-1}) {
            const unsigned index=ratio_location(rank,old,0).suffix;
            const Fp3 got=mul6(tables[index>>12],tables[count+(index&4095)]);
            Fp3 expected{1,0,0};
            // Independent original-coordinate evaluation with the direct product.
            for(unsigned i=0;i<bits;++i)
                expected=mul(expected,(index>>(bits-1-i))&1?point[i]:sub(Fp3{1,0,0},point[i]));
            if(got.c0!=expected.c0||got.c1!=expected.c1||got.c2!=expected.c2) return false;
        }
    }
    return true;
}

// Native-generated public schedules and original packed inputs/outputs only.
// Bounded file reader; this exercises the GPU's slot layout on CPU, not CUDA.
unsigned replay_fixture(const char* path) {
    std::ifstream in(path,std::ios::binary);
    in.exceptions(std::ios::failbit|std::ios::badbit);
    char magic[8]; in.read(magic,8);
    if(std::string(magic,8)!="C71DAG01") throw std::runtime_error("bad DAG fixture");
    auto read32=[&]() {
        uint8_t b[4]; in.read(reinterpret_cast<char*>(b),4);
        return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);
    };
    auto read64=[&]() { const uint64_t lo=read32(); return lo|(uint64_t(read32())<<32); };
    const unsigned cases=read32();
    if(!cases||cases>95) throw std::runtime_error("DAG cases exceed bound");
    for(unsigned c=0;c<cases;++c) {
        const unsigned depth=read32(), ports=read32(), slots=read32(), stages=read32();
        const unsigned nodes=read32(), wires=read32();
        if(depth!=c||ports!=98||slots<ports||slots>16384||stages>94||nodes>100000||wires>4096)
            throw std::runtime_error("DAG shape exceeds bound");
        std::vector<uint32_t> boundaries(stages+1), outputs(wires);
        std::vector<std::array<uint32_t,4>> ops(nodes);
        for(auto& n:boundaries) n=read32();
        for(auto& g:ops) for(auto& n:g) n=read32();
        for(auto& n:outputs) { n=read32(); if(n>=slots) throw std::runtime_error("DAG output"); }
        if(boundaries[0]!=0||boundaries.back()!=nodes) throw std::runtime_error("DAG bounds");
        for(unsigned d=0;d<stages;++d) {
            if(boundaries[d]>boundaries[d+1]||boundaries[d+1]>nodes) throw std::runtime_error("DAG order");
            std::vector<bool> writes(slots);
            for(unsigned i=boundaries[d];i<boundaries[d+1];++i) {
                const auto g=ops[i];
                if(g[0]>1||g[1]>=slots||g[2]>=slots||g[3]>=slots||writes[g[1]])
                    throw std::runtime_error("DAG gate");
                writes[g[1]]=true;
            }
            for(unsigned i=boundaries[d];i<boundaries[d+1];++i)
                if(writes[ops[i][2]]||writes[ops[i][3]]) throw std::runtime_error("DAG stage race");
        }
        for(unsigned trial=0;trial<3;++trial) {
            std::vector<uint64_t> values(slots);
            for(unsigned i=0;i<ports;++i) values[i]=read64();
            for(const auto g:ops) values[g[1]]=g[0]?(values[g[2]]^values[g[3]]):(values[g[2]]&values[g[3]]);
            for(const auto n:outputs) if(values[n]!=read64()) throw std::runtime_error("original wire differs");
        }
    }
    return cases;
}

int main(int argc, char** argv) {
    std::array<uint32_t,64> edge;
    edge.fill(0x7ffffffeu);
    const __uint128_t expected=__uint128_t(0x7ffffffeu)*UINT64_MAX;
    const bool boundary=reduce_count_bits(edge.data(),1)==uint64_t(expected%FIELD_P);
    const unsigned native_cases=argc==2?replay_fixture(argv[1]):0;
    const bool ok=boundary&&location_check()&&original_eq_check()&&host_check(17)&&host_check(256)&&host_check(513);
    std::cout << "{\"host_exact_gram_and_fragments\":" << (ok?"true":"false")
        << ",\"native_shared_replay_cases\":" << native_cases
        << ",\"original_suffix_mapping\":true,\"gpu_execution\":false,\"credit\":false}\n";
    return ok?0:1;
}
