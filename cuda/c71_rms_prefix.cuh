// Prover-private four-round RMS moments. Original Boolean frames and Eq only.
// No transcript, MAC, correlations, auxiliary prefix row or canonical selection.
#pragma once
#include "c71_range_native.cuh"

namespace c71_rms_prefix {
constexpr unsigned block=16, moments=block*block+block, gate_chunk=512;
struct Program {
    uint32_t ports, slots, stages, nodes_first, boundaries_first, outputs_first, outputs_count;
};
struct Node { uint32_t op, z, x, y; }; // And=0, Xor=1; Copy is an output alias.
struct Gate { uint32_t op, x, y, reserved; Fp3 weight; }; // And=0, Xor=1, Copy=2.
static_assert(sizeof(Program)==28 && sizeof(Node)==16 && sizeof(Gate)==40);
struct GateRange { uint32_t first,count; };
struct Section { uint32_t first,end; };
struct Shape {
    uint32_t programs,width,capacity,suffix_bits,nodes,boundaries,outputs,gates,masks,sections;
};
static_assert(sizeof(GateRange)==8 && sizeof(Section)==8 && sizeof(Shape)==40);
// Immutable original compact P/S/Y bytes, with the public dyadic tile lookup.
struct SourceShape { uint64_t bytes; uint32_t live,padded,norms,tiles,programs,reserved; };
struct SourceNorm {
    uint64_t product,statistic,output,cells;
    uint32_t pbytes,columns,rows,program;
};
struct SourceTile { uint32_t first,end,norm,row,col,cols,program,reserved; };
static_assert(sizeof(SourceShape)==32 && sizeof(SourceNorm)==48 && sizeof(SourceTile)==32);

// producer -> transpose -> original suffix Eq -> fused counts -> late weight.
// All buffers are caller owned; launches do not allocate or download.
// capacity is a multiple of256, <=4096; stage has width*capacity/4 u64.
// Frames/assignments use [original prefix row][capacity][12 bytes/u16].
// None is0xffff. Program masks select the decoder, never producer wire rows.
#ifdef __CUDACC__
cudaError_t source_frames(cudaStream_t,const uint8_t*,const SourceNorm*,const SourceTile*,
    unsigned tiles,unsigned suffix,unsigned first,unsigned capacity,unsigned n,
    uint8_t* frames,uint16_t* assignments,unsigned* launches=nullptr);
cudaError_t source_frames_fold(cudaStream_t,const uint8_t*,const SourceNorm*,const SourceTile*,
    unsigned tiles,unsigned active,unsigned first,unsigned capacity,unsigned n,unsigned side,
    unsigned group_first,unsigned groups,uint8_t* frames,uint16_t* assignments,unsigned* launches=nullptr);
cudaError_t replay_raw(cudaStream_t,const uint8_t*,const uint16_t*,const Program*,const Node*,
    const uint32_t*,const uint32_t*,unsigned,unsigned,unsigned,unsigned,unsigned,uint64_t*,unsigned*,uint64_t*);
cudaError_t replay(cudaStream_t, const uint8_t*, const uint16_t*, const Program*,
    const Node*, const uint32_t*, const uint32_t*, unsigned programs, unsigned width,
    unsigned capacity, unsigned n, unsigned shared_slots, uint64_t* stage,
    unsigned* launches=nullptr, uint64_t* zeroed=nullptr);
cudaError_t suffix_eq(cudaStream_t, const Fp3* point, unsigned bits, unsigned first,
    unsigned capacity, unsigned n, uint32_t* planes, unsigned* launches=nullptr);
cudaError_t consume(cudaStream_t, const uint32_t* stage, const uint32_t* eq,
    const Gate*, unsigned gates, unsigned capacity, Fp3* chunk, Fp3* aggregate, unsigned* launches=nullptr);
#endif
}
