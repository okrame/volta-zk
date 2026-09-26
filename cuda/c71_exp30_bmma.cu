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

#ifdef __CUDACC__
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
        }
    return true;
}

int main() {
    const bool ok=host_check(17)&&host_check(256)&&host_check(513);
    std::cout << "{\"host_exact_gram_and_fragments\":" << (ok?"true":"false")
        << ",\"gpu_execution\":false,\"credit\":false}\n";
    return ok?0:1;
}
