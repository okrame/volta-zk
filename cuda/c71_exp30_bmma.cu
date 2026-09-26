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
#include <vector>

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

#ifdef __CUDACC__
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
    return true;
}

int main() {
    std::array<uint32_t,64> edge;
    edge.fill(0x7ffffffeu);
    const __uint128_t expected=__uint128_t(0x7ffffffeu)*UINT64_MAX;
    const bool boundary=reduce_count_bits(edge.data(),1)==uint64_t(expected%FIELD_P);
    const bool ok=boundary&&host_check(17)&&host_check(256)&&host_check(513);
    std::cout << "{\"host_exact_gram_and_fragments\":" << (ok?"true":"false")
        << ",\"gpu_execution\":false,\"credit\":false}\n";
    return ok?0:1;
}
