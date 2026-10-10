// Tests the real owner with a deferred fake driver, NOT GPU math/execution.
#include "c71_range_runtime.h"
#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
#include <algorithm>
#include <cmath>
#include "c71_fft.cuh"
#include "c71_pcs_weight_tensor.cuh"
#include "c71_pcs_residual_query.cuh"
using namespace c71_range;
struct FakeStream { std::vector<std::function<void()>> pending; };
static bool fail_launch=false, fail_fence=false, fail_free=false, corrupt=false;
static bool fail_dense=false;
static unsigned stack_fault=0;
static bool corrupt_query_data=false;
static int copy_fail_after=-1;
static int download_fail_after=-1;
static int upload_fail_after=-1;
static size_t fake_free=80000000000ULL;
static unsigned allocations=0, frees=0, launches=0;
static void* last_allocation=nullptr;
static std::vector<uint8_t> expected_bytes;
static std::vector<int64_t> expected_raw;
static std::vector<uint64_t> expected_pcs;
static std::vector<uint64_t> recorded_pcs;
static bool record_pcs=false;
static std::vector<uint64_t> expected_short_ring;
cudaError_t cudaSetDevice(int n) { return n==0?0:1; }
cudaError_t cudaDeviceSetLimit(cudaLimit limit,size_t bytes) {
    assert(limit==cudaLimitStackSize && bytes==256); return stack_fault==1?1:0;
}
cudaError_t cudaDeviceGetLimit(size_t* bytes,cudaLimit limit) {
    assert(limit==cudaLimitStackSize); *bytes=stack_fault==3?512:256;
    return stack_fault==2?1:0;
}
cudaError_t cudaStreamCreateWithFlags(cudaStream_t* s,unsigned flags) {
    assert(flags==cudaStreamNonBlocking); *s=new FakeStream; return 0;
}
cudaError_t cudaStreamSynchronize(cudaStream_t s) {
    for(auto& f:s->pending) f();
    s->pending.clear();
    return fail_fence?1:0;
}
cudaError_t cudaStreamDestroy(cudaStream_t s) { assert(s->pending.empty()); delete s; return 0; }
cudaError_t cudaMalloc(void** p,size_t n) { ++allocations; *p=new unsigned char[n]; last_allocation=*p; return 0; }
cudaError_t cudaMemGetInfo(size_t* free,size_t* total) { *free=fake_free; *total=80000000000ULL; return 0; }
cudaError_t cudaFree(void* p) {
    ++frees; delete[] static_cast<unsigned char*>(p); return fail_free?1:0;
}
cudaError_t cudaMemcpyAsync(void* d,const void* s,size_t n,cudaMemcpyKind kind,cudaStream_t stream) {
    if(kind==cudaMemcpyHostToDevice) {
        if(upload_fail_after==0) return 1;
        if(upload_fail_after>0) --upload_fail_after;
    }
    if(kind==cudaMemcpyDeviceToHost) {
        if(download_fail_after==0) return 1;
        if(download_fail_after>0) --download_fail_after;
    }
    if(kind==cudaMemcpyDeviceToDevice) {
        if(copy_fail_after==0) return 1;
        if(copy_fail_after>0) --copy_fail_after;
    }
    stream->pending.push_back([=] { std::memcpy(d,s,n); if(kind==cudaMemcpyDeviceToHost && (corrupt || (corrupt_query_data && n>=8))) {
        if(n>=8) *static_cast<uint64_t*>(d)=P; else *static_cast<uint32_t*>(d)=1;
    } });
    return 0;
}
cudaError_t cudaMemsetAsync(void* p,int x,size_t n,cudaStream_t s) {
    s->pending.push_back([=] { std::memset(p,x,n); }); return 0;
}
const char* cudaGetErrorString(cudaError_t) { return "injected CUDA failure"; }
static int launch(cudaStream_t s,std::function<void()> operation) {
    ++launches; if(fail_launch) return 1;
    s->pending.push_back(std::move(operation)); return 0;
}
extern "C" int c71_linear_weights_launch(cudaStream_t stream,const int16_t* input,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t first,uint64_t count,
    c71_linear::Shape shape,const c71_linear::Chunk* chunks,const Fp3* tables,
    const c71_linear::Group* groups,const c71_linear::Interval* intervals,const Fp3* points,
    c71_linear::Result* output,uint32_t* flag) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) {
            const auto original=input[c71_pcs::packed_address(tiles,tile_count,first+i,shape.live)];
            if(original==INT16_MIN) { *flag=1; continue; }
            const uint64_t scalar=original<0 ? P-uint64_t(-int32_t(original)) : uint64_t(original);
            *output=c71_linear::sum(*output,c71_linear::contribution(first+i,scalar,shape,chunks,tables,groups,intervals,points));
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_linear_source_launch(cudaStream_t stream,const void* input,unsigned kind,c71_pcs::SourceTile tile,
    c71_linear::Shape shape,const c71_linear::Chunk* chunks,const Fp3* tables,
    const c71_linear::Group* groups,const c71_linear::Interval* intervals,const Fp3* points,
    c71_linear::Result* output,uint32_t* flag) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<tile.rows*tile.columns;++i) {
            const auto address=tile.input_first+(i/tile.columns)*tile.input_stride+i%tile.columns;
            const int64_t original=kind==C71_I16 ? static_cast<const int16_t*>(input)[address] : static_cast<const int64_t*>(input)[address];
            for(unsigned lane=0;lane<tile.width;++lane) {
                uint8_t byte=0;
                if(!c71_byte::encode(original,tile.signed_width,tile.byte_first+lane,byte)) { *flag=1; continue; }
                *output=c71_linear::sum(*output,c71_linear::contribution(tile.original_first+i*tile.width+lane,
                    byte,shape,chunks,tables,groups,intervals,points));
            }
        }
        if(fail_dense) *flag=1;
    });
}

// Independent polynomial convolution and ordinary integer modulo oracle for
// deferred owner tests. This does not model CUDA scheduling or reductions.
namespace residual_oracle {
using E=c71_pcs_residual::E;
using Wide=unsigned __int128;
uint64_t add(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+b)%P); }
uint64_t sub(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+P-b)%P); }
uint64_t mul(uint64_t a,uint64_t b) { return uint64_t(Wide(a)*b%P); }
E add(E a,E b) { return {residual_oracle::add(a.c0,b.c0),residual_oracle::add(a.c1,b.c1),residual_oracle::add(a.c2,b.c2)}; }
E sub(E a,E b) { return {residual_oracle::sub(a.c0,b.c0),residual_oracle::sub(a.c1,b.c1),residual_oracle::sub(a.c2,b.c2)}; }
E mul(E a,E b) {
    uint64_t polynomial[5]{};
    const uint64_t left[]={a.c0,a.c1,a.c2},right[]={b.c0,b.c1,b.c2};
    for(unsigned i=0;i<3;++i) for(unsigned j=0;j<3;++j) polynomial[i+j]=residual_oracle::add(polynomial[i+j],residual_oracle::mul(left[i],right[j]));
    for(unsigned i=4;i>=3;--i) { polynomial[i-2]=residual_oracle::add(polynomial[i-2],polynomial[i]); polynomial[i-3]=residual_oracle::add(polynomial[i-3],polynomial[i]); }
    return {polynomial[0],polynomial[1],polynomial[2]};
}
E power(E a,uint64_t n) { E value{1,0,0}; while(n) { if(n&1) value=residual_oracle::mul(value,a); a=residual_oracle::mul(a,a); n>>=1; } return value; }
E fold(E a,E b,E r) { return residual_oracle::add(a,residual_oracle::mul(r,residual_oracle::sub(b,a))); }
E lookup(uint64_t index,const c71_pcs_residual::Chunk* chunks,unsigned count,const E* tables) {
    E value{1,0,0};
    for(unsigned i=0;i<count;++i) { const auto c=chunks[i]; value=residual_oracle::mul(value,tables[c.first+((index>>c.shift)&((uint64_t{1}<<c.bits)-1))]); }
    return value;
}
void contribution(uint64_t index,E original,c71_pcs_residual::Shape shape,
    const c71_pcs_residual::Chunk* chunks,const E* tables,c71_pcs_residual::Phase phase,
    c71_pcs_residual::Output output,c71_pcs_residual::CosetShape cosets,const uint64_t* high,
    c71_pcs_residual::PowerShape powers,const E* power_low,const E* power_high,uint32_t* flag) {
    namespace pcs=c71_pcs_residual;
    if(!pcs::canonical(original)) { *flag=1; return; }
    const uint64_t folded=index&((uint64_t{1}<<shape.remaining)-1);
    const auto value=residual_oracle::mul(residual_oracle::lookup(phase==pcs::Phase::singleton?folded:index>>shape.remaining,chunks,shape.equality.chunks,tables),original);
    if(phase==pcs::Phase::singleton) output.reduced[index>>shape.remaining]=residual_oracle::add(output.reduced[index>>shape.remaining],value);
    else if(phase==pcs::Phase::retention) {
        output.retained.c0[folded]=residual_oracle::add(output.retained.c0[folded],value.c0);
        output.retained.c1[folded]=residual_oracle::add(output.retained.c1[folded],value.c1);
        output.retained.c2[folded]=residual_oracle::add(output.retained.c2[folded],value.c2);
    } else if(phase==pcs::Phase::ood) {
        const E lo=power_low[folded&((uint64_t{1}<<powers.low_bits)-1)],hi=power_high[folded>>powers.low_bits];
        if(!pcs::canonical(lo) || !pcs::canonical(hi)) { *flag=1; return; }
        *output.reduced=residual_oracle::add(*output.reduced,residual_oracle::mul(value,residual_oracle::mul(lo,hi)));
    } else {
        const uint64_t n=uint64_t{1}<<(shape.remaining-2),within=folded%n,row=within%cosets.rows;
        const unsigned column=unsigned(folded/n);
        const uint64_t limbs[]={value.c0,value.c1,value.c2};
        for(unsigned lane=0;lane<2;++lane) for(unsigned component=0;component<3;++component) {
            const uint64_t factor=high[within/cosets.rows*2+lane];
            if(factor>=P) { *flag=1; continue; }
            const uint64_t address=(uint64_t(column*3+component)*2+lane)*cosets.rows+row;
            output.ring[address]=residual_oracle::add(output.ring[address],residual_oracle::mul(limbs[component],factor));
        }
    }
}
}
extern "C" int c71_pcs_residual_weights_launch(cudaStream_t stream,const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t first,uint64_t count,
    c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,const c71_pcs_residual::E* tables,
    c71_pcs_residual::Phase phase,c71_pcs_residual::Output output,c71_pcs_residual::CosetShape cosets,
    const uint64_t* high,c71_pcs_residual::PowerShape powers,const c71_pcs_residual::E* power_low,
    const c71_pcs_residual::E* power_high,uint32_t* flag) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) {
            const uint64_t address=c71_pcs::packed_address(tiles,tile_count,first+i,shape.live);
            if(address>=input_words || input[address]==INT16_MIN) { *flag=1; continue; }
            const int16_t value=input[address];
            residual_oracle::contribution(first+i,{value<0?P-uint64_t(-int32_t(value)):uint64_t(value),0,0},
                shape,chunks,tables,phase,output,cosets,high,powers,power_low,power_high,flag);
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_source_launch(cudaStream_t stream,const void* input,uint64_t input_words,unsigned kind,
    c71_pcs::SourceTile tile,c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,
    const c71_pcs_residual::E* tables,c71_pcs_residual::Phase phase,c71_pcs_residual::Output output,
    c71_pcs_residual::CosetShape cosets,const uint64_t* high,c71_pcs_residual::PowerShape powers,
    const c71_pcs_residual::E* power_low,const c71_pcs_residual::E* power_high,uint32_t* flag) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<tile.rows*tile.columns;++i) {
            const uint64_t address=tile.input_first+i/tile.columns*tile.input_stride+i%tile.columns;
            if(address>=input_words) { *flag=1; continue; }
            const int64_t original=kind==C71_I16?static_cast<const int16_t*>(input)[address]:static_cast<const int64_t*>(input)[address];
            for(unsigned lane=0;lane<tile.width;++lane) {
                const int64_t bound=int64_t{1}<<(8*tile.signed_width-1);
                if(original<-bound || original>=bound) { *flag=1; continue; }
                const uint64_t byte=(uint64_t(original+bound)>>(8*(tile.byte_first+lane)))&255;
                residual_oracle::contribution(tile.original_first+i*tile.width+lane,{byte,0,0},shape,chunks,tables,
                    phase,output,cosets,high,powers,power_low,power_high,flag);
            }
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_resident_launch(cudaStream_t stream,c71_pcs_residual::ConstPlanes input,uint64_t count,
    c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,const c71_pcs_residual::E* tables,
    c71_pcs_residual::Phase phase,c71_pcs_residual::Output output,c71_pcs_residual::CosetShape cosets,
    const uint64_t* high,c71_pcs_residual::PowerShape powers,const c71_pcs_residual::E* power_low,
    const c71_pcs_residual::E* power_high,uint32_t* flag) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) residual_oracle::contribution(i,{input.c0[i],input.c1[i],input.c2[i]},shape,chunks,tables,
            phase,output,cosets,high,powers,power_low,power_high,flag);
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_coset_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,
    c71_pcs_residual::Shape shape,c71_pcs_residual::CosetShape cosets) {
    return launch(stream,[=] {
        const auto omega=residual_oracle::power({7,0,0},(P-1)/(cosets.rows*cosets.cosets)).c0;
        for(uint64_t i=0;i<2*cosets.rows;++i) low[i]=residual_oracle::power({omega,0,0},uint64_t(cosets.first_coset+i/cosets.rows)*(i%cosets.rows)).c0;
        const uint64_t n=uint64_t{1}<<(shape.remaining-2),high_rows=(n+cosets.pad_rows+cosets.rows-1)/cosets.rows;
        for(uint64_t i=0;i<2*high_rows;++i) high[i]=residual_oracle::power({omega,0,0},uint64_t(cosets.first_coset+i%2)*(i/2)*cosets.rows).c0;
    });
}
extern "C" int c71_pcs_residual_ood_powers_launch(cudaStream_t stream,c71_pcs_residual::E* low,c71_pcs_residual::E* high,
    c71_pcs_residual::PowerShape powers,c71_pcs_residual::E point) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<(uint64_t{1}<<powers.low_bits);++i) low[i]=residual_oracle::power(point,i);
        for(uint64_t i=0;i<(uint64_t{1}<<(powers.bits-powers.low_bits));++i) high[i]=residual_oracle::power(point,i<<powers.low_bits);
    });
}
extern "C" int c71_pcs_residual_pad_launch(cudaStream_t stream,uint64_t* ring,const c71_pcs_residual::E* pads,
    const uint64_t* low,const uint64_t* high,c71_pcs_residual::Shape shape,c71_pcs_residual::CosetShape cosets,uint32_t* flag) {
    return launch(stream,[=] {
        const uint64_t n=uint64_t{1}<<(shape.remaining-2);
        for(unsigned column=0;column<4;++column) for(unsigned component=0;component<3;++component)
            for(unsigned lane=0;lane<2;++lane) for(uint64_t row=0;row<cosets.rows;++row) {
                const auto address=(uint64_t(column*3+component)*2+lane)*cosets.rows+row;
                uint64_t value=ring[address];
                for(uint64_t j=0;j<cosets.pad_rows;++j) if((n+j)%cosets.rows==row) {
                    const auto pad=pads[uint64_t(column)*cosets.pad_rows+j];
                    const uint64_t coefficient=component==0?pad.c0:component==1?pad.c1:pad.c2;
                    if(!c71_pcs_residual::canonical(pad)) *flag=1;
                    value=residual_oracle::add(value,residual_oracle::mul(coefficient,high[(n+j)/cosets.rows*2+lane]));
                }
                if(value>=P || low[uint64_t(lane)*cosets.rows+row]>=P) *flag=1;
                ring[address]=residual_oracle::mul(value,low[uint64_t(lane)*cosets.rows+row]);
            }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_ood_pad_launch(cudaStream_t stream,c71_pcs_residual::E* reduced,
    const c71_pcs_residual::E* pads,uint32_t count,uint64_t length,c71_pcs_residual::E point,uint32_t* flag) {
    return launch(stream,[=] {
        for(unsigned i=0;i<count;++i) {
            if(!c71_pcs_residual::canonical(pads[i])) *flag=1;
            *reduced=residual_oracle::add(*reduced,residual_oracle::mul(pads[i],residual_oracle::power(point,length+i)));
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_fold_launch(cudaStream_t stream,c71_pcs_residual::ConstPlanes input,
    c71_pcs_residual::Planes output,uint64_t count,unsigned rounds,c71_pcs_residual::E r0,c71_pcs_residual::E r1,uint32_t* flag) {
    return launch(stream,[=] {
        const uint64_t size=count>>rounds;
        for(uint64_t i=0;i<size;++i) {
            c71_pcs_residual::E values[4]{};
            for(unsigned j=0;j<(1u<<rounds);++j) {
                const uint64_t k=i+j*size; values[j]={input.c0[k],input.c1[k],input.c2[k]};
                if(!c71_pcs_residual::canonical(values[j])) *flag=1;
            }
            const auto value=rounds==1?residual_oracle::fold(values[0],values[1],r0):
                residual_oracle::fold(residual_oracle::fold(values[0],values[2],r0),residual_oracle::fold(values[1],values[3],r0),r1);
            output.c0[i]=value.c0; output.c1[i]=value.c1; output.c2[i]=value.c2;
        }
        if(fail_dense) *flag=1;
    });
}



static uint64_t query_original_reads=0,query_resident_reads=0;
static int query_weight_fail_after=-1;
static void query_store(uint64_t* low,uint64_t capacity,uint64_t i,residual_oracle::E value) {
    low[i]=value.c0; low[capacity+i]=value.c1; low[2*capacity+i]=value.c2;
}
extern "C" int c71_pcs_residual_query_weights_launch(cudaStream_t stream,const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,c71_pcs_residual::Shape shape,
    const c71_pcs_residual::Chunk* chunks,const c71_pcs_residual::E* tables,const c71_pcs_residual::E* pads,
    uint64_t pad_count,uint64_t* low,uint64_t capacity,c71_pcs::QueryBlock block,uint32_t* flag,unsigned* attempted) {
    if(!attempted) return 1;
    ++*attempted;
    if(query_weight_fail_after==0) { ++launches;return 1; }
    if(query_weight_fail_after>0)--query_weight_fail_after;
    if(const auto error=launch(stream,[=] {
        for(uint64_t i=0;i<capacity;++i) {
            const uint64_t j=block.first+i;residual_oracle::E value{};
            if(j<block.source_rows && j>=block.message_rows) {
                const uint64_t address=block.pad_first+j-block.message_rows;
                if(address>=pad_count || !c71_pcs_residual::canonical(pads[address]))*flag=1;
                else value=pads[address];
            }
            query_store(low,capacity,i,value);
        }
        if(fail_dense)*flag=1;
    });error) return error;
    if(!c71_pcs_residual_query::weight_work(shape,capacity,block).tasks)return 0;
    ++*attempted;
    if(query_weight_fail_after==0) { ++launches;return 1; }
    if(query_weight_fail_after>0)--query_weight_fail_after;
    return launch(stream,[=] {
        const uint64_t virtual_size=uint64_t{1}<<shape.remaining,prefixes=uint64_t{1}<<(shape.dimension-shape.remaining);
        for(uint64_t i=0;i<capacity;++i) {
            const uint64_t j=block.first+i; residual_oracle::E value{};
            if(j>=block.message_rows)continue;
            if(j<block.source_rows) {
                for(uint64_t prefix=0;prefix<prefixes;++prefix) {
                    const uint64_t index=prefix*virtual_size+block.byte_first+j;
                    if(index>=shape.live) continue;
                    const uint64_t address=c71_pcs::packed_address(tiles,tile_count,index,shape.live);
                    if(address>=input_words || input[address]==INT16_MIN) { *flag=1; continue; }
                    ++query_original_reads;
                    const int32_t original=input[address];
                    const uint64_t scalar=original<0?P-uint64_t(-original):uint64_t(original);
                    const auto equality=residual_oracle::lookup(prefix,chunks,shape.equality.chunks,tables);
                    value=residual_oracle::add(value,residual_oracle::mul(equality,{scalar,0,0}));
                }
            }
            query_store(low,capacity,i,value);
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_query_resident_launch(cudaStream_t stream,c71_pcs_residual::ConstPlanes input,
    uint64_t input_count,c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,
    const c71_pcs_residual::E* tables,const c71_pcs_residual::E* pads,uint64_t pad_count,
    uint64_t* low,uint64_t capacity,c71_pcs::QueryBlock block,uint32_t* flag) {
    return launch(stream,[=] {
        const uint64_t virtual_size=uint64_t{1}<<shape.remaining,prefixes=uint64_t{1}<<(shape.dimension-shape.remaining);
        for(uint64_t i=0;i<capacity;++i) {
            const uint64_t j=block.first+i; residual_oracle::E value{};
            if(j<block.source_rows) {
                if(j>=block.message_rows) {
                    const uint64_t address=block.pad_first+j-block.message_rows;
                    if(address>=pad_count || !c71_pcs_residual::canonical(pads[address])) *flag=1;
                    else value=pads[address];
                } else for(uint64_t prefix=0;prefix<prefixes;++prefix) {
                    const uint64_t index=prefix*virtual_size+block.byte_first+j;
                    if(index>=input_count) { *flag=1; continue; }
                    ++query_resident_reads;
                    const residual_oracle::E original{input.c0[index],input.c1[index],input.c2[index]};
                    if(!c71_pcs_residual::canonical(original)) { *flag=1; continue; }
                    value=residual_oracle::add(value,residual_oracle::mul(original,
                        residual_oracle::lookup(prefix,chunks,shape.equality.chunks,tables)));
                }
            }
            query_store(low,capacity,i,value);
        }
        if(fail_dense) *flag=1;
    });
}

static uint64_t contract_original_reads=0,contract_resident_reads=0;
static void contract_fake_value(uint64_t index,residual_oracle::E original,c71_pcs_residual::Shape shape,
    const c71_pcs_residual::Chunk* chunks,const c71_pcs_residual::E* tables,unsigned kind,uint64_t start,
    const c71_pcs_residual::E* left,const c71_pcs_residual::E* right,c71_pcs_residual::E* output,uint32_t* flag) {
    if(!c71_pcs_residual::canonical(original)) { *flag=1; return; }
    const auto value=residual_oracle::mul(original,residual_oracle::lookup(index>>shape.remaining,chunks,shape.equality.chunks,tables));
    const uint64_t size=uint64_t{1}<<(shape.remaining-kind),local=(index&(size-1))-start;
    if(!c71_pcs_residual::canonical(left[local]) || (right && !c71_pcs_residual::canonical(right[local]))) { *flag=1; return; }
    if(!kind) output[0]=residual_oracle::add(output[0],residual_oracle::mul(value,left[local]));
    else if(index&size) output[1]=residual_oracle::add(output[1],residual_oracle::mul(value,residual_oracle::sub(right[local],left[local])));
    else { output[0]=residual_oracle::add(output[0],residual_oracle::mul(value,left[local])); output[1]=residual_oracle::sub(output[1],residual_oracle::mul(value,residual_oracle::sub(right[local],left[local]))); }
}
extern "C" int c71_pcs_residual_contract_weights_launch(cudaStream_t stream,const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,
    const c71_pcs_residual::E* tables,unsigned kind,uint64_t start,uint32_t count,const c71_pcs_residual::E* left,
    const c71_pcs_residual::E* right,c71_pcs_residual::E* output,uint32_t* flag) {
    return launch(stream,[=] {
        const auto tasks=c71_pcs_residual::contract_tasks(shape,kind,count);
        for(uint64_t task=0;task<tasks;++task) {
            const uint64_t index=c71_pcs_residual::contract_index(task,shape,kind,start,count);
            if(index>=shape.live) continue;
            const uint64_t address=c71_pcs::packed_address(tiles,tile_count,index,shape.live);
            if(address>=input_words) { *flag=1; continue; }
            ++contract_original_reads;
            const auto original=input[address];
            if(original==INT16_MIN) { *flag=1; continue; }
            contract_fake_value(index,{original<0?P-uint64_t(-int32_t(original)):uint64_t(original),0,0},
                shape,chunks,tables,kind,start,left,right,output,flag);
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_residual_contract_resident_launch(cudaStream_t stream,c71_pcs_residual::ConstPlanes input,
    uint64_t input_count,c71_pcs_residual::Shape shape,const c71_pcs_residual::Chunk* chunks,const c71_pcs_residual::E* tables,
    unsigned kind,uint64_t start,uint32_t count,const c71_pcs_residual::E* left,const c71_pcs_residual::E* right,
    c71_pcs_residual::E* output,uint32_t* flag) {
    return launch(stream,[=] {
        const auto tasks=c71_pcs_residual::contract_tasks(shape,kind,count);
        for(uint64_t task=0;task<tasks;++task) {
            const uint64_t index=c71_pcs_residual::contract_index(task,shape,kind,start,count);
            if(index>=shape.live || index>=input_count) continue;
            ++contract_resident_reads;
            contract_fake_value(index,{input.c0[index],input.c1[index],input.c2[index]},shape,chunks,tables,
                kind,start,left,right,output,flag);
        }
        if(fail_dense) *flag=1;
    });
}
extern "C" int c71_pcs_short_pairs_launch(cudaStream_t stream,const uint64_t* ring,const uint64_t* salts,
    c71_pcs::Hash32* output,uint64_t rows,uint64_t first,uint64_t count,uint32_t* flag) {
    return launch(stream,[=] {
        if(!expected_short_ring.empty()) {
            assert(expected_short_ring.size()==24*rows);
            for(uint64_t i=0;i<24*rows;++i) assert(expected_short_ring[i]==ring[i]);
            expected_short_ring.clear();
        }
        for(uint64_t local=0;local<count;++local) {
            const uint64_t leaf=first+local,lane=leaf/rows,row=leaf%rows;
            for(unsigned column=0;column<12;++column) if(ring[uint64_t(column*2+lane)*rows+row]>=P) *flag=1;
            for(unsigned i=0;i<4;++i) if(salts[uint64_t(i)*count+local]>=P) *flag=1;
            // Hash serialization is separately pinned against live Rust in
            // the short-leaf component; this fixture tests deferred lifetime.
            const auto hash=c71_pcs::short_leaf(ring+lane*rows,2*rows,row,salts,count,local);
            output[row]=lane==0?hash:c71_pcs::short_pair_finish(output[row],hash);
        }
        if(fail_dense) *flag=1;
    });
}

// Sequential oracle for deferred owner/lifetime tests. It does not emulate
// the CUDA hierarchy; that scheduling still requires real kernel execution.
extern "C" int c71_pcs_salts_prescan_launch(cudaStream_t stream,const c71_salts::Descriptor* d,
    c71_salts::Chunk c,c71_salts::Geometry g,uint8_t*,uint32_t*,uint32_t*,uint32_t*,
    uint64_t* starts,uint64_t* offsets,c71_salts::Progress* progress,uint32_t* failed,unsigned* attempted) {
    *attempted=fail_launch?1:c.candidates?4:1;
    return launch(stream,[=] {
        uint64_t cursor=c.cursor,accepted=c.accepted;
        starts[0]=offsets[0]=g.origin;
        c71_salts::BlockCache cache;
        for(uint32_t i=0;i<c.candidates && accepted<c.target;++i) {
            uint64_t value=0;
            if(!c71_salts::candidate(*d,cursor,cache,value)) { *failed=1; break; }
            cursor+=8;
            if(value>=c71_salts::MODULUS) continue;
            ++accepted;
            if(!(accepted%(4*g.cosets)) && accepted/(4*g.cosets)<g.rows)
                starts[accepted/(4*g.cosets)]=cursor;
            if(!(accepted%(4*g.cut)) && accepted/(4*g.cut)<g.rows*g.cosets/g.cut)
                offsets[accepted/(4*g.cut)]=cursor;
        }
        if((accepted<c.target && c71_salts::CAP-cursor<8) || fail_dense) *failed=1;
        *progress={cursor,accepted,cursor-g.origin,c71_salts::physical_blocks(c),*failed,uint32_t(accepted==c.target)};
    });
}
extern "C" int c71_pcs_salts_replay_launch(cudaStream_t stream,const c71_salts::Descriptor* d,
    uint64_t* current,uint64_t rows,uint64_t first,uint64_t count,uint64_t* salts,uint64_t* consumed,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t local=0;local<std::min(count,rows);++local) {
            const uint64_t row=(first%rows+local)%rows;
            uint64_t bytes=0;
            if(!c71_salts::replay_row(*d,current[row],rows,first,count,row,salts,bytes)) *failed=1;
            *consumed+=bytes;
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_hash_launch(cudaStream_t stream,unsigned operation,const uint64_t* ring,
    const uint64_t* salts,c71_pcs::Hash32* states,uint64_t rows,uint64_t first,uint64_t count,
    unsigned column,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t local=0;local<count;++local) {
            const uint64_t row=first+local;
            for(unsigned j=0;j<(operation==1?8u:4u);++j) if(ring[j*rows+row]>=P) *failed=1;
            if(operation==0) states[row]=c71_pcs::leaf_start(ring,rows,row);
            else if(operation==1) states[row]=c71_pcs::leaf_step(states[row],ring+4*rows,ring,rows,row,column);
            else {
                for(unsigned j=0;j<4;++j) if(salts[j*count+local]>=P) *failed=1;
                states[row]=c71_pcs::leaf_finish(states[row],ring,salts,rows,row,count,local);
            }
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_nodes_launch(cudaStream_t stream,const c71_pcs::Hash32* input,
    c71_pcs::Hash32* output,uint64_t count,uint64_t rows) {
    return launch(stream,[=] { for(uint64_t i=0;i<count;++i) {
        const uint64_t left=2*(i/rows)*rows+i%rows;
        output[i]=c71_pcs::node(input[left],input[left+rows]);
    } });
}
extern "C" int c71_pcs_merge_launch(cudaStream_t stream,c71_pcs::Hash32* frontier,
    c71_pcs::Hash32* roots,uint64_t rows,unsigned group,unsigned levels) {
    return launch(stream,[=] { for(uint64_t row=0;row<rows;++row)
        c71_pcs::merge_group(frontier,roots,rows,row,group,levels); });
}
extern "C" int c71_pcs_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,c71_pcs::WeightShape s) {
    return launch(stream,[=] {
        const uint64_t omega=c71_pcs::power(7,(P-1)/(s.rows*s.cosets));
        for(unsigned lane=0;lane<32;++lane) {
            for(uint64_t row=0;row<s.rows;++row) low[lane*s.rows+row]=c71_pcs::power(omega,(s.first_coset+lane)*row);
            for(uint64_t q=0;q<c71_pcs::high_rows(s);++q) high[q*32+lane]=c71_pcs::power(omega,(s.first_coset+lane)*q*s.rows);
        }
    });
}
extern "C" int c71_pcs_twiddles_launch(cudaStream_t stream,uint64_t* output,unsigned log_rows) {
    return launch(stream,[=] {
        const uint64_t rows=uint64_t{1}<<log_rows,root=c71_pcs::power(7,(P-1)/rows);
        for(uint64_t row=0;row<rows;++row) output[row]=c71_pcs::power(root,row);
    });
}
extern "C" int c71_pcs_transform_twiddles_launch(cudaStream_t stream,uint64_t* output,unsigned log_rows,unsigned inverse) {
    return launch(stream,[=] {
        const uint64_t rows=uint64_t{1}<<log_rows;
        uint64_t root=c71_pcs::power(7,(P-1)/rows);
        if(inverse) root=c71_pcs::power(root,P-2);
        for(uint64_t row=0;row<rows;++row) output[row]=c71_pcs::power(root,row);
    });
}
extern "C" int c71_pcs_transform_launch(cudaStream_t stream,uint64_t* values,uint64_t* scratch,
    const uint64_t* twiddles,unsigned log_rows,unsigned batch,unsigned inverse,unsigned* attempted) {
    const size_t rows=size_t{1}<<log_rows;
    if(fail_launch) { ++*attempted; return launch(stream,[]{}); }
    *attempted+=(log_rows==1 ? 1 : 5+(log_rows%2))*((uint64_t(batch)+32766)/32767);
    if(log_rows%2 && log_rows>1) ++*attempted;
    return launch(stream,[=] {
        if(log_rows%2 && log_rows>1) {
            for(size_t i=0;i<rows*batch;++i) {
                scratch[c71_fft::parity_index(i,rows)]=values[i];
            }
        }
        // Shared five-pass/odd adapter model; actual CUDA is not executed.
        for(unsigned b=0;b<batch;++b) {
            std::vector<uint64_t> current(values+b*rows,values+(b+1)*rows);
            c71_fft::natural_fft_host(current,log_rows,twiddles[1],inverse!=0);
            std::copy(current.begin(),current.end(),values+b*rows);
        }
    });
}
static void query_fft(std::vector<uint64_t>& values,const uint64_t* twiddles,bool inverse) {
    c71_fft::fft_radix2(values,twiddles[1]);
    if(inverse) {
        const auto scale=c71_pcs::power(values.size(),P-2);
        for(auto& value:values) value=fp_mul(value,scale);
    }
}
static unsigned query_transform_launches(uint64_t degree,unsigned batch) {
    unsigned log=0; while((uint64_t{1}<<log)<2*degree) ++log;
    return (log==1?1:5+(log%2))*((batch+32766)/32767)+unsigned(log%2 && log>1);
}
extern "C" int c71_pcs_query_low_launch(cudaStream_t stream,const uint8_t* bytes,const uint64_t* pads,
    uint64_t* output,uint64_t count,c71_pcs::QueryBlock s) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) {
            const auto j=s.first+i; uint64_t value=0;
            if(j<s.source_rows) {
                if(s.pad_only) value=pads[s.pad_first+j];
                else if(j<s.active) value=bytes[s.byte_first+j-s.window_first];
                else if(j>=s.message_rows) value=pads[s.pad_first+j-s.message_rows];
            }
            output[i]=value;
        }
    });
}
static uint64_t initial_query_weight_reads=0;
extern "C" int c71_pcs_query_weight_low_launch(cudaStream_t stream,const int16_t* weights,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,uint64_t live,const uint64_t* pads,
    uint64_t pad_count,uint64_t* output,uint64_t capacity,c71_pcs::QueryBlock shape) {
    (void)pad_count;
    // Deferred driver only: independent linear tile search and signed mapping.
    // The pure fixture separately checks the shared binary-search helper.
    return launch(stream,[=] {
        for(uint64_t i=0;i<capacity;++i) {
            const uint64_t j=shape.first+i;uint64_t value=0;
            if(j<shape.source_rows) {
                if(shape.pad_only)value=pads[shape.pad_first+j];
                else if(j<shape.active) {
                    const uint64_t index=shape.byte_first+j;
                    if(index<live) {
                        uint64_t address=UINT64_MAX;
                        for(uint64_t t=0;t<tile_count;++t) if(index>=tiles[t].first && index-tiles[t].first<tiles[t].count) {
                            const auto& tile=tiles[t];const uint64_t local=index-tile.first;
                            address=tile.packed_first+(local/tile.columns)*tile.packed_stride+local%tile.columns;break;
                        }
                        assert(address<live && weights[address]!=INT16_MIN);
                        const int32_t original=weights[address];
                        value=original<0?P-uint64_t(-original):uint64_t(original);++initial_query_weight_reads;
                    }
                } else if(j>=shape.message_rows)value=pads[shape.pad_first+j-shape.message_rows];
            }
            output[i]=value;
        }
    });
}
extern "C" int c71_pcs_query_remainder_launch(cudaStream_t stream,const uint64_t* high,const uint64_t* low,
    const uint64_t* inverse,const uint64_t* modulus,const uint64_t* forward,const uint64_t* backward,
    uint64_t* work,uint64_t* scratch,uint64_t* output,uint64_t degree,uint64_t count,unsigned children,
    unsigned* attempted,uint64_t* copied) {
    (void)work; (void)scratch;
    if(fail_launch) { ++*attempted; return launch(stream,[]{}); }
    *attempted+=degree<=8 ? 1 : 5+4*query_transform_launches(degree,unsigned(count/degree));
    unsigned log=0; while((uint64_t{1}<<log)<2*degree) ++log;
    if(degree>8 && log%2) *copied+=4*2*count*8;
    return launch(stream,[=] {
        for(uint64_t task=0;task<count/degree;++task) {
            const auto high_first=children ? (task/2)*2*degree+degree : 0;
            const auto low_first=children ? (task/2)*2*degree : 0;
            const auto* mod=modulus+task*2*degree;
            if(degree<=8) {
                std::vector<uint64_t> polynomial(mod,mod+2*degree);
                query_fft(polynomial,backward,true);
                std::vector<uint64_t> current(low+low_first,low+low_first+degree);
                current.insert(current.end(),high+high_first,high+high_first+degree);
                for(uint64_t j=2*degree;j-->degree;) {
                    const auto quotient=current[j];
                    for(uint64_t k=0;k<degree;++k) current[j-degree+k]=fp_sub(current[j-degree+k],fp_mul(quotient,polynomial[k]));
                }
                std::copy(current.begin(),current.begin()+degree,output+task*degree);
            } else {
                std::vector<uint64_t> quotient(2*degree);
                for(uint64_t j=0;j<degree;++j) quotient[j]=high[high_first+degree-1-j];
                query_fft(quotient,forward,false);
                for(uint64_t j=0;j<2*degree;++j) quotient[j]=fp_mul(quotient[j],inverse[task*2*degree+j]);
                query_fft(quotient,backward,true);
                std::reverse(quotient.begin(),quotient.begin()+degree);
                std::fill(quotient.begin()+degree,quotient.end(),0);
                query_fft(quotient,forward,false);
                for(uint64_t j=0;j<2*degree;++j) quotient[j]=fp_mul(quotient[j],mod[j]);
                query_fft(quotient,backward,true);
                for(uint64_t j=0;j<degree;++j) output[task*degree+j]=fp_sub(low[low_first+j],quotient[j]);
            }
        }
    });
}
extern "C" int c71_pcs_query_shift_launch(cudaStream_t stream,const uint64_t* values,const uint64_t* shift,
    const uint64_t* forward,const uint64_t* backward,uint64_t* work,uint64_t* scratch,uint64_t* low,uint64_t* high,
    uint64_t degree,unsigned* attempted,uint64_t* copied) {
    (void)work; (void)scratch;
    if(fail_launch) { ++*attempted; return launch(stream,[]{}); }
    *attempted+=3+2*query_transform_launches(degree,1);
    unsigned log=0; while((uint64_t{1}<<log)<2*degree) ++log;
    if(log%2 && log>1) *copied+=2*2*degree*8;
    return launch(stream,[=] {
        std::vector<uint64_t> product(values,values+degree); product.resize(2*degree);
        query_fft(product,forward,false);
        for(uint64_t j=0;j<2*degree;++j) product[j]=fp_mul(product[j],shift[j]);
        query_fft(product,backward,true);
        std::copy(product.begin(),product.begin()+degree,low);
        std::copy(product.begin()+degree,product.end(),high);
    });
}
extern "C" int c71_pcs_query_add_launch(cudaStream_t stream,uint64_t* values,const uint64_t* correction,uint64_t count) {
    return launch(stream,[=] { for(uint64_t i=0;i<count;++i) values[i]=fp_add(values[i],correction[i]); });
}
extern "C" int c71_pcs_weight_launch(cudaStream_t stream,const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,const uint64_t* high,
    uint64_t* ring,c71_pcs::WeightShape s,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<32;++lane) for(uint64_t row=0;row<s.rows;++row)
            ring[(s.slots+column)*32*s.rows+lane*s.rows+row]=c71_pcs::accumulate(
                weights,tiles,tile_count,live,pads,low,high,s,s.first_column+column,row,lane);
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_weight_tensor_launch(cudaStream_t stream,const int16_t* weights,const c71_pcs::WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,const uint64_t* high,
    uint64_t* ring,c71_pcs::WeightShape s,uint32_t* failed) {
    // Deferred HOST digit arithmetic, not MMA/PTX, GPU timing or W traffic.
    // Independent fragment/layout parity lives in pcs_weight_tensor_host.cpp.
    return launch(stream,[=] {
        for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<32;++lane) for(uint64_t row=0;row<s.rows;++row) {
            int32_t original_sum=0; int64_t dots[4]{};
            for(uint64_t q=0;q<s.message_rows/s.rows;++q) {
                const uint64_t index=uint64_t(s.first_column+column)*s.message_rows+q*s.rows+row;
                if(index>=live) break;
                const int16_t value=weights[c71_pcs::packed_address(tiles,tile_count,index,live)];
                if(value==INT16_MIN) { *failed=1; continue; }
                original_sum+=value;
                for(unsigned limb=0;limb<4;++limb) dots[limb]+=int64_t(value)*c71_pcs_tensor::digit(high[q*32+lane],limb);
            }
            c71_pcs::SignedWide sum;
            for(unsigned limb=0;limb<4;++limb) if(!c71_pcs_tensor::add_dot(sum,dots[limb],original_sum,limb)) *failed=1;
            uint64_t value=sum.residue();
            for(uint64_t j=row;j<s.pad_rows;j+=s.rows) value=fp_add(value,
                fp_mul(pads[uint64_t(s.first_column+column)*s.pad_rows+j],high[((s.message_rows+j)/s.rows)*32+lane]));
            ring[(s.slots+column)*32*s.rows+lane*s.rows+row]=fp_mul(value,low[lane*s.rows+row]);
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_compare_words_launch(cudaStream_t stream,const uint64_t* left,const uint64_t* right,
    uint64_t count,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) if(left[i]>=P || right[i]>=P || left[i]!=right[i]) *failed=1;
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_fft_launch(cudaStream_t stream,uint64_t* values,const uint64_t* twiddles,
    unsigned log_rows,unsigned batch,unsigned* attempted) {
    *attempted+=5;
    return launch(stream,[=] {
        const size_t rows=size_t{1}<<log_rows, side=size_t{1}<<(log_rows/2);
        for(unsigned b=0;b<batch;++b) {
            std::vector<uint64_t> current(values+b*rows,values+(b+1)*rows);
            c71_fft::five_pass_fft(current,side,twiddles[1]);
            std::copy(current.begin(),current.end(),values+b*rows);
        }
        if(record_pcs) recorded_pcs.insert(recorded_pcs.end(),values,values+batch*rows);
        if(!expected_pcs.empty()) {
            assert(expected_pcs.size()>=batch*rows && expected_pcs.size()%(batch*rows)==0);
            assert(std::memcmp(values,expected_pcs.data(),batch*rows*8)==0);
            expected_pcs.erase(expected_pcs.begin(),expected_pcs.begin()+batch*rows);
        }
    });
}
extern "C" int c71_pcs_source_powers_launch(cudaStream_t stream,uint64_t* low,uint64_t* high,c71_pcs::SourceShape s) {
    return launch(stream,[=] {
        const auto omega=c71_pcs::power(7,(P-1)/(s.rows*s.cosets));
        for(unsigned lane=0;lane<4;++lane) {
            for(uint64_t row=0;row<s.rows;++row) low[lane*s.rows+row]=c71_pcs::power(omega,(s.first_coset+lane)*row);
            for(uint64_t q=0;q<c71_pcs::high_rows(s);++q) high[q*4+lane]=c71_pcs::power(omega,(s.first_coset+lane)*q*s.rows);
        }
    });
}
extern "C" int c71_pcs_source_tile_launch(cudaStream_t stream,const void* input,unsigned kind,c71_pcs::SourceTile t,
    const uint64_t* high,uint64_t* first,uint64_t* second,uint64_t* counts,c71_pcs::SourceShape s,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<t.rows*t.columns;++i) {
            const auto address=t.input_first+(i/t.columns)*t.input_stride+i%t.columns;
            const int64_t word=kind==1?static_cast<const int16_t*>(input)[address]:static_cast<const int64_t*>(input)[address];
            for(unsigned j=0;j<t.width;++j) {
                uint8_t byte=0;
                if(!c71_byte::encode(word,t.signed_width,t.byte_first+j,byte)) { *failed=1; continue; }
                const auto index=t.original_first+i*t.width+j, within=index%s.message_rows;
                const unsigned column=unsigned(index/s.message_rows);
                auto* out=(column<64?first:second)+uint64_t(column%64)*4*s.rows;
                for(unsigned lane=0;lane<4;++lane) {
                    auto& value=out[uint64_t(lane)*s.rows+within%s.rows];
                    value=fp_add(value,fp_mul(byte,high[(within/s.rows)*4+lane]));
                }
                if(counts) ++counts[byte];
            }
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_source_pad_launch(cudaStream_t stream,uint64_t* values,const uint64_t* pads,
    const uint64_t* low,const uint64_t* high,c71_pcs::SourceShape s,unsigned first_column,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned column=0;column<64;++column) for(unsigned lane=0;lane<4;++lane) for(uint64_t row=0;row<s.rows;++row) {
            const auto index=uint64_t(column)*4*s.rows+uint64_t(lane)*s.rows+row;
            values[index]=c71_pcs::padded(values[index],pads,low,high,s,first_column+column,row,lane);
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_pcs_full_leaves_launch(cudaStream_t stream,const uint64_t* first,const uint64_t* second,
    const uint64_t* salts,c71_pcs::Hash32* out,uint64_t rows,uint64_t begin,uint64_t count,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t i=0;i<count;++i) {
            const uint64_t row=begin+i;
            auto cv=c71_pcs::leaf_start(first,rows,row);
            for(unsigned column=4;column<=116;column+=8) {
                const auto* pending=(column<64?first:second)+uint64_t(column%64)*rows;
                const auto* next=(column+4<64?first:second)+uint64_t((column+4)%64)*rows;
                cv=c71_pcs::leaf_step(cv,pending,next,rows,row,column);
            }
            out[row]=c71_pcs::leaf_finish(cv,second+60*rows,salts,rows,row,count,i);
        }
        if(fail_dense) *failed=1;
    });
}
// Host arithmetic for cross-language protocol parity. This executes neither
// CUDA kernels nor their thread scheduling; it is never a production fallback.
static Pair fraction(const void* input,unsigned kind,size_t first,size_t n,Fp3 alpha) {
    if(n==1) {
        const int64_t x=kind?static_cast<const int16_t*>(input)[first]:static_cast<const uint8_t*>(input)[first];
        return {{1,0,0},sub(alpha,integer(x))};
    }
    return merge(fraction(input,kind,first,n/2,alpha),fraction(input,kind,first+n/2,n/2,alpha));
}
extern "C" int c71_range_launch_roots(cudaStream_t s,unsigned kind,const void* input,size_t,unsigned bottom,Fp3 alpha,Pair* p,size_t n) {
    return launch(s,[=] {
        if(!expected_bytes.empty()) {
            assert(kind==0 && expected_bytes.size()==(n<<bottom));
            assert(std::memcmp(input,expected_bytes.data(),expected_bytes.size())==0);
            expected_bytes.clear();
        }
        for(size_t i=0;i<n;++i) p[i]=fraction(input,kind,i<<bottom,size_t{1}<<bottom,alpha);
    });
}
extern "C" int c71_range_launch_groups(cudaStream_t s,unsigned kind,const void* input,size_t words,Group g,Children* p,size_t,Fp3* h,size_t) {
    return launch(s,[=] {
        const size_t length=size_t{1}<<g.width, subtree=size_t{1}<<g.bottom, old_count=size_t{1}<<g.prefix_bits;
        for(size_t t=0;t<words/(length*subtree*old_count);++t) {
            Children bucket[32]{};
            for(size_t u=0;u<length;++u) for(size_t old=0;old<old_count;++old) {
                const size_t first=((t*old_count+old)*length+u)*subtree;
                const auto a=fraction(input,kind,first,subtree/2,g.alpha), b=fraction(input,kind,first+subtree/2,subtree/2,g.alpha);
                const Fp3 child[]={a.p,a.q,b.p,b.q},weight=equality(g.prefix,g.prefix_bits,old);
                for(unsigned j=0;j<4;++j) bucket[u].v[j]=add(bucket[u].v[j],mul6(weight,child[j]));
            }
            const size_t tail=g.first_tail+t;
            if(!g.width) p[tail]=bucket[0];
            else for(size_t u=0;u<length;++u) for(size_t v=0;v<length;++v) {
                auto& cell=h[(tail%g.buckets)*length*length+u*length+v];
                cell=add(cell,gram(bucket[u],bucket[v],g.lambda,equality(g.tail_point,g.tail_bits,tail)));
            }
        }
    });
}
extern "C" int c71_range_launch_canopy(cudaStream_t s,const Pair* a,Pair* p,size_t n) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) p[i]=merge(a[2*i],a[2*i+1]); });
}
extern "C" int c71_range_launch_h_sum(cudaStream_t s,const Fp3* a,Fp3* p,unsigned n,unsigned buckets) {
    return launch(s,[=] { for(unsigned i=0;i<n;++i) { p[i]={}; for(unsigned b=0;b<buckets;++b) p[i]=add(p[i],a[b*n+i]); } });
}
extern "C" int c71_range_launch_h_fold(cudaStream_t s,const Fp3* a,Fp3* p,unsigned half,Fp3 r) {
    return launch(s,[=] { const unsigned n=2*half; for(unsigned i=0;i<half;++i) for(unsigned j=0;j<half;++j)
        p[i*half+j]=fold(fold(a[i*n+j],a[i*n+j+half],r),fold(a[(i+half)*n+j],a[(i+half)*n+j+half],r),r); });
}
extern "C" int c71_range_launch_child_fold(cudaStream_t s,Children* p,size_t n,Fp3 r) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) p[i]=fold(p[i],p[i+n],r); });
}
extern "C" int c71_range_launch_coefficients(cudaStream_t s,const Children* a,size_t half,Round r,Cubic* p) {
    return launch(s,[=] { for(size_t i=0;i<half;++i) {
        if(i%256==0) p[i/256]={};
        p[i/256]=sum(p[i/256],coefficients(a[i],a[i+half],r.lambda,
            mul6(r.prefix_equality,equality(r.point,r.bits,i)),mul6(r.prefix_equality,equality(r.point,r.bits,i+half))));
    } });
}
extern "C" int c71_range_launch_reduce(cudaStream_t s,const Cubic* a,size_t n,Cubic* p) {
    return launch(s,[=] { for(size_t i=0;i<n;++i) { if(i%256==0) p[i/256]={}; p[i/256]=sum(p[i/256],a[i]); } });
}
extern "C" int c71_range_launch_h_coefficients(cudaStream_t s,const Fp3* a,unsigned half,Round r,Cubic* p) {
    return launch(s,[=] { *p=h_coefficients(a,half,r); });
}
extern "C" int c71_dense_i16_launch(cudaStream_t s,const int16_t* x,uint64_t nx,const int16_t* w,uint64_t nw,
    int64_t* out,uint64_t no,uint32_t* failed,c71_dense::Shape shape) {
    assert(c71_dense::valid_buffers(x,nx,w,nw,out,no,failed,shape));
    return launch(s,[=] {
        for(unsigned i=0;i<shape.m;++i) for(unsigned j=0;j<shape.n;++j) {
            int64_t sum=0;
            for(unsigned k=0;k<shape.k;++k) {
                const auto a=x[size_t(i)*shape.k+k], b=w[size_t(j)*shape.k+k];
                if(a==INT16_MIN || b==INT16_MIN) *failed=1;
                sum+=int64_t(a)*b;
            }
            out[size_t(i)*shape.n+j]=sum;
        }
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_dense_rne_launch(cudaStream_t s,const int64_t* raw,int16_t* out,uint64_t count,
    int32_t shift,uint32_t* failed) {
    return launch(s,[=] {
        if(!expected_raw.empty()) {
            assert(expected_raw.size()==count && std::memcmp(raw,expected_raw.data(),count*8)==0);
            expected_raw.clear();
        }
        for(uint64_t i=0;i<count;++i) if(!c71_dense::quantize(raw[i],shift,out[i])) *failed=1;
        if(fail_dense) *failed=1;
    });
}
extern "C" int c71_byte_scatter_launch(cudaStream_t s,const void* input,unsigned kind,uint64_t input_count,
    uint8_t* output,uint64_t output_count,uint32_t* failed,c71_byte::Tile t) {
    assert(c71_byte::valid(t,kind,input_count,output_count));
    return launch(s,[=] {
        if(!expected_raw.empty()) {
            assert(expected_raw.size()==input_count);
            for(uint64_t index=0;index<input_count;++index) {
                const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
                assert(value==expected_raw[index]);
            }
            expected_raw.clear();
        }
        for(uint64_t i=0;i<t.rows*t.columns*t.width;++i) {
            const uint64_t address=c71_byte::ordered(t.original_first+i,t);
            if(address<t.window_first || address-t.window_first>=t.window_length) continue;
            const uint64_t word=i/t.width, index=t.input_first+(word/t.columns)*t.input_stride+word%t.columns;
            const int64_t value=kind==1?static_cast<const int16_t*>(input)[index]:static_cast<const int64_t*>(input)[index];
            uint8_t byte=0;
            if(!c71_byte::encode(value,t.signed_width,t.byte_first+i%t.width,byte)) *failed=1;
            else output[address-t.window_first]=byte;
        }
    });
}
extern "C" int c71_dense_pointwise_launch(cudaStream_t s,const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,c71_dense::Pointwise op,uint32_t* failed) {
    assert(c71_dense::valid_pointwise(op));
    return launch(s,[=] {
        for(uint64_t i=0;i<count;++i) {
            const int16_t a=(op.multiply || op.a)?x[i]:0, b=(op.multiply || op.b)?y[i]:0;
            if(!c71_dense::pointwise(a,b,op,output[i])) *failed=1;
        }
    });
}

extern "C" int c71_lookup_launch(cudaStream_t stream,const int16_t* input,const int16_t* table,
    int16_t* output,int64_t* histogram,uint64_t count,uint32_t* failed) {
    return launch(stream,[=] {
        for(uint64_t index=0;index<count;++index) {
            int16_t value; uint32_t entry;
            if(!c71_nonlinear::lookup(input[index],table,value,entry)) *failed=1;
            else { output[index]=value; ++histogram[entry]; }
        }
    });
}
extern "C" int c71_histogram_seal_launch(cudaStream_t stream,int64_t* histogram,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned entry=0;entry<65535;++entry) {
            if(histogram[entry]<0 || histogram[entry]>INT32_MAX) *failed=1;
        }
    });
}
extern "C" int c71_rope_launch(cudaStream_t stream,const int16_t* input,const int32_t* coefficients,
    int64_t* output,c71_nonlinear::Rope shape,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<shape.rows;++row) for(unsigned head=0;head<shape.heads;++head)
            for(unsigned pair=0;pair<shape.width/2;++pair) {
                const auto first=(uint64_t(row)*shape.heads+head)*shape.width+pair,second=first+shape.width/2;
                const int32_t cosine=pair<shape.pairs?coefficients[(row*shape.pairs+pair)*2]:1<<30;
                const int32_t sine=pair<shape.pairs?coefficients[(row*shape.pairs+pair)*2+1]:0;
                if(!c71_nonlinear::rotate(input[first],input[second],cosine,sine,output[first],output[second])) *failed=1;
            }
    });
}
extern "C" int c71_argmax_select_launch(cudaStream_t stream,const int16_t* input,uint32_t* tokens,
    unsigned rows,unsigned columns,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<rows;++row) {
            unsigned best=0;
            for(unsigned column=0;column<columns;++column) {
                if(input[uint64_t(row)*columns+column]==INT16_MIN) *failed=1;
                if(input[uint64_t(row)*columns+column]>input[uint64_t(row)*columns+best]) best=column;
            }
            tokens[row]=best;
        }
    });
}
extern "C" int c71_argmax_slack_launch(cudaStream_t stream,const int16_t* input,const uint32_t* tokens,
    int16_t* output,unsigned rows,unsigned columns,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<rows;++row) for(unsigned column=0;column<columns;++column) {
            const auto index=uint64_t(row)*columns+column;
            if(tokens[row]>=columns || !c71_nonlinear::slack(input[uint64_t(row)*columns+tokens[row]],
                input[index],column,tokens[row],output[index])) *failed=1;
        }
    });
}

extern "C" int c71_rms_launch(cudaStream_t stream,const int16_t* input,const int16_t* weights,
    int64_t* products,int64_t* statistics,int16_t* output,c71_nonlinear::Rms shape,uint32_t* failed) {
    return launch(stream,[=] {
        for(unsigned row=0;row<shape.rows*shape.heads;++row) {
            int64_t sum=0;
            for(unsigned column=0;column<shape.columns;++column) {
                const int64_t value=input[uint64_t(row)*shape.columns+column];
                if(value==INT16_MIN) *failed=1;
                sum+=value*value;
            }
            statistics[row]=sum;
            for(unsigned column=0;column<shape.columns;++column) {
                const auto index=uint64_t(row)*shape.columns+column;
                const int16_t weight=shape.weighted?weights[column]:1;
                const int64_t product=int64_t(input[index])*weight;
                if(weight==INT16_MIN || !c71_nonlinear::rms_round(shape,product,sum,output[index])) *failed=1;
                if(shape.weighted) products[index]=product;
            }
        }
    });
}
extern "C" int c71_qk_launch(cudaStream_t stream,const int16_t* query,const int16_t* keys,int64_t* output,
    c71_nonlinear::Attention shape,uint32_t* failed) {
    return launch(stream,[=] {
        const unsigned columns=shape.old+150,group=shape.head/(32/shape.groups);
        for(unsigned row=0;row<shape.rows;++row) for(unsigned key=0;key<columns;++key) {
            int64_t sum=0;
            if(key<=shape.old+shape.first+row) for(unsigned lane=0;lane<shape.lanes;++lane) {
                const int16_t left=query[(uint64_t(row)*32+shape.head)*shape.lanes+lane];
                const int16_t right=keys[(uint64_t(key)*shape.groups+group)*shape.lanes+lane];
                if(left==INT16_MIN || right==INT16_MIN) *failed=1;
                sum+=int64_t(left)*right;
            }
            output[uint64_t(row)*columns+key]=sum;
        }
    });
}
extern "C" int c71_pv_launch(cudaStream_t stream,const int16_t* const* probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention shape,uint32_t* failed) {
    std::vector<const int16_t*> pointers(probabilities,probabilities+32);
    return launch(stream,[=] {
        const unsigned columns=shape.old+150;
        for(unsigned row=0;row<shape.rows;++row) for(unsigned head=0;head<32;++head) for(unsigned lane=0;lane<shape.lanes;++lane) {
            int64_t sum=0;
            for(unsigned key=0;key<=shape.old+shape.first+row;++key) {
                const int16_t probability=pointers[head][uint64_t(row)*columns+key];
                const int16_t value=values[(uint64_t(key)*shape.groups+head/(32/shape.groups))*shape.lanes+lane];
                if(probability<0 || probability>16384 || value==INT16_MIN) *failed=1;
                sum+=int64_t(probability)*value;
            }
            output[(uint64_t(row)*32+head)*shape.lanes+lane]=sum;
        }
    });
}
extern "C" int c71_softmax_launch(cudaStream_t stream,const int16_t* scores,const int32_t* table,
    int16_t* maximum,int16_t* difference,int64_t* exponential,int64_t* denominator,int16_t* probabilities,
    int64_t* histogram,c71_nonlinear::Attention shape,uint32_t* failed) {
    return launch(stream,[=] {
        const unsigned columns=shape.old+150;
        for(unsigned row=0;row<shape.rows;++row) {
            const uint64_t first=uint64_t(row)*columns;
            const unsigned live=shape.old+shape.first+row+1;
            int16_t largest=INT16_MIN;
            for(unsigned column=0;column<columns;++column) {
                const int16_t value=scores[first+column];
                if(value==INT16_MIN || (column>=live && value!=0)) *failed=1;
                if(column<live && value>largest) largest=value;
            }
            maximum[row]=largest; int64_t sum=0;
            for(unsigned column=0;column<columns;++column) {
                const int delta=column<live?int(largest)-scores[first+column]:0;
                exponential[first+column]=0;
                if(delta<0 || delta>65534) { *failed=1; continue; }
                const int32_t value=table[delta];
                if(value<0 || value>(1<<30) || (delta==0 && value!=(1<<30))) { *failed=1; continue; }
                difference[first+column]=int16_t(delta-32767); exponential[first+column]=value; ++histogram[delta];
                if(column<live) sum+=value;
            }
            denominator[row]=sum;
            if(sum<(int64_t{1}<<30) || sum>int64_t(live)*(1<<30)) { *failed=1; continue; }
            for(unsigned column=0;column<columns;++column)
                probabilities[first+column]=column<live?c71_nonlinear::probability(int32_t(exponential[first+column]),sum):0;
        }
    });
}

#ifdef C71_RANGE_FFI_TEST
// Test library only; production exports neither error injection nor host math.
extern "C" void c71_range_test_expect_bytes(const uint8_t* p,uint64_t n) {
    assert(n && expected_bytes.empty()); expected_bytes.assign(p,p+n);
}
extern "C" void c71_range_test_expect_raw(const int64_t* p,uint64_t n) {
    assert(n && expected_raw.empty()); expected_raw.assign(p,p+n);
}
extern "C" void c71_range_test_expect_pcs(const uint64_t* p,uint64_t n) {
    assert(n && expected_pcs.empty()); expected_pcs.assign(p,p+n);
}
extern "C" void c71_range_test_pcs_record(unsigned mode) {
    if(mode==0) { assert(!record_pcs && recorded_pcs.empty() && expected_pcs.empty()); record_pcs=true; }
    else if(mode==1) {
        assert(record_pcs && !recorded_pcs.empty() && expected_pcs.empty());
        record_pcs=false; expected_pcs.swap(recorded_pcs);
    } else {
        assert(mode==2 && !record_pcs && recorded_pcs.empty() && expected_pcs.empty());
        // Release private fixture capacity before the next geometry; it is
        // never a production PCS cache or part of the device arena.
        std::vector<uint64_t>().swap(recorded_pcs); std::vector<uint64_t>().swap(expected_pcs);
    }
}
extern "C" void c71_range_test_failure(unsigned kind) {
    fail_launch=kind==1; fail_fence=kind==2; fail_free=kind==3; corrupt=kind==4;
    copy_fail_after=kind==5?0:kind==6?1:-1;
    download_fail_after=kind==7?0:kind==8?1:-1;
    upload_fail_after=kind==10?0:kind==11?1:-1;
    fail_dense=kind==9;
    corrupt_query_data=kind==12;
}
#else

static C71RangeContext* create(uint64_t bytes=262144) {
    C71RangeContext* c=nullptr; assert(!c71_range_create(0,bytes,256,nullptr,&c)); return c;
}
static uint64_t alloc(C71RangeContext* c,unsigned kind,uint64_t n) {
    uint64_t id=0; assert(!c71_range_alloc(c,kind,n,&id)); return id;
}
static C71RangeStats stats(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_stats(c,&s)); return s; }
static void close(C71RangeContext* c) { C71RangeStats s{}; assert(!c71_range_close(c,&s)); assert(!s.arena_bytes && !s.weights_bytes && !s.cleanup_failed); }
static uint64_t roots(C71RangeContext* c,unsigned kind=0,unsigned n=2048) {
    const auto in=alloc(c,kind,2*n), out=alloc(c,C71_PAIR,n);
    std::vector<int16_t> data(2*n,3);
    assert(!c71_range_upload(c,in,data.data(),2*n*(kind+1)));
    assert(!c71_range_roots(c,in,1,{5,2,3},out,0));
    assert(!c71_range_release(c,in)); return out;
}
static void install(C71RangeContext* c) {
    const int16_t w[]={123,321, 1,2,3,4, 4,3,2,1};
    assert(!c71_dense_weights_begin(c,10));
    assert(!c71_dense_weights_upload(c,0,w,3));
    assert(!c71_dense_weights_upload(c,3,w+3,7));
    assert(!c71_dense_weights_seal(c));
}
static uint64_t dense_input(C71RangeContext* c) {
    const auto x=alloc(c,C71_I16,8);
    const int16_t values[]={1,2,3,4,-1,-2,-3,-4};
    assert(!c71_range_upload(c,x,values,sizeof(values))); return x;
}
static void dense_checks() {
    auto* c=create(); install(c); const auto x=dense_input(c);
    const auto before=stats(c);
    assert(before.weights_bytes==20 && before.weights_loaded_bytes==20 && before.weights_sealed);
    assert(before.peak_reserved_bytes==before.arena_bytes+20);
    // Two batches, original W offset after a sentinel prefix. W is never
    // copied again; output stays device-resident into RNE and signed range.
    for(unsigned batch=0;batch<2;++batch) {
        const auto raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4), root=alloc(c,C71_PAIR,1);
        assert(!c71_dense_product(c,x,2,{2,2,4},raw));
        assert(!c71_dense_quantize(c,raw,2,y));
        assert(!c71_range_roots(c,y,2,{19,2,3},root,0));
        uint64_t limbs[6]{}; assert(!c71_range_read(c,root,limbs,6));
        const int16_t expected[]={8,5,-8,-5}; // 30/4 ties to even, 20/4 exact.
        const auto reference=fraction(expected,1,0,4,{19,2,3});
        assert(std::memcmp(limbs,&reference,sizeof(reference))==0);
        assert(!c71_range_release(c,root) && !c71_range_release(c,y) && !c71_range_release(c,raw));
        assert(stats(c).h2d_bytes==before.h2d_bytes);
        assert(stats(c).live_capacity_bytes==before.live_capacity_bytes+256);
        assert(stats(c).peak_capacity_bytes>=before.live_capacity_bytes+4*256);
    }
    assert(stats(c).d2h_bytes-before.d2h_bytes==2*(8+48));
    const auto selected_raw=alloc(c,C71_I64,2), selected_y=alloc(c,C71_I16,2), selected_root=alloc(c,C71_PAIR,1);
    assert(!c71_dense_product_rows(c,x,1,2,{1,2,4},selected_raw));
    assert(!c71_dense_quantize(c,selected_raw,2,selected_y));
    assert(!c71_range_roots(c,selected_y,1,{19,2,3},selected_root,0));
    uint64_t selected_limbs[6]{}; assert(!c71_range_read(c,selected_root,selected_limbs,6));
    const int16_t selected_expected[]={-8,-5};
    const auto selected_reference=fraction(selected_expected,1,0,2,{19,2,3});
    assert(std::memcmp(selected_limbs,&selected_reference,sizeof(selected_reference))==0);
    assert(stats(c).h2d_bytes==before.h2d_bytes);
    close(c);
    for(unsigned test=0;test<23;++test) {
        c=create(); int status=0;
        if(test<6) {
            const int16_t w[]={1,2,3,4};
            switch(test) {
            case 0: status=c71_dense_weights_begin(c,61394690560ULL/2+1); break;
            case 1: fake_free=uint64_t{1}<<30; status=c71_dense_weights_begin(c,4); fake_free=80000000000ULL; break;
            case 2: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_seal(c); break;
            case 3: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_upload(c,1,w,3); break;
            case 4: { const int16_t bad=INT16_MIN; assert(!c71_dense_weights_begin(c,1)); status=c71_dense_weights_upload(c,0,&bad,1); break; }
            case 5: assert(!c71_dense_weights_begin(c,4)); status=c71_dense_weights_begin(c,4); break;
            }
        } else {
            install(c); const auto x=dense_input(c), raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4);
            switch(test) {
            case 6: status=c71_dense_weights_upload(c,0,nullptr,1); break;
            case 7: status=c71_dense_product(c,x,UINT64_MAX,{2,2,4},raw); break;
            case 8: status=c71_dense_product(c,x,2,{3,2,4},raw); break;
            case 9: status=c71_dense_product(c,x,2,{2,2,4},x); break;
            case 10: status=c71_dense_quantize(c,raw,2,y); break;
            case 11: fail_launch=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_launch=false; break;
            case 12: fail_fence=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_fence=false; break;
            case 13: fail_dense=true; status=c71_dense_product(c,x,2,{2,2,4},raw); fail_dense=false; break;
            case 14: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); status=c71_dense_quantize(c,raw,-15,y); break;
            case 15: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); status=c71_dense_product(c,x,2,{2,2,4},raw); break;
            case 16: assert(!c71_dense_product(c,x,2,{2,2,4},raw)); fail_fence=true;
                status=c71_dense_quantize(c,raw,2,y); fail_fence=false; break;
            case 17: status=c71_dense_weights_seal(c); break;
            case 18: status=c71_dense_product(c,y,2,{2,2,4},raw); break;
            case 19: status=c71_dense_product_rows(c,x,UINT64_MAX,2,{2,2,4},raw); break;
            case 20: status=c71_dense_product_rows(c,x,1,2,{2,2,4},raw); break;
            case 21: status=c71_dense_product_rows(c,x,1,2,{1,2,4},raw); break; // output shape
            case 22: status=c71_range_abort(c); break;
            }
        }
        const auto attempts=launches;
        assert(status && stats(c).stopped && *c71_range_error(c));
        uint64_t ignored=0; assert(c71_range_alloc(c,C71_I16,1,&ignored));
        assert(c71_dense_weights_seal(c) && launches==attempts);
        close(c);
    }
    c=create(); install(c); fail_free=true; C71RangeStats final{};
    assert(c71_range_close(c,&final) && final.cleanup_failed && final.weights_bytes==20 && final.arena_bytes==0);
    fail_free=false;
}
static void embedding_checks() {
    auto* c=create(); install(c);
    for(unsigned rows: {1u,4u,150u}) {
        std::vector<uint32_t> ids(rows);
        for(unsigned i=0;i<rows;++i) ids[i]=(i%3==0)?1:0;
        const auto out=alloc(c,C71_I16,rows*4);
        const auto before=stats(c);
        assert(!c71_dense_embedding(c,2,2,4,ids.data(),rows,out));
        auto after=stats(c);
        assert(after.d2d_bytes-before.d2d_bytes==rows*8);
        assert(after.h2d_bytes==before.h2d_bytes && after.d2h_bytes==before.d2h_bytes);
        assert(after.launches==before.launches && after.allocations==before.allocations);
        assert(after.fences==before.fences+1);
        for(auto token:ids) for(int j=0;j<4;++j) expected_raw.push_back(token?4-j:j+1);
        const auto raw=alloc(c,C71_I64,rows*4), rounded=alloc(c,C71_I16,rows*4);
        assert(!c71_dense_pointwise(c,out,0,0,0,{1,0,0},raw));
        assert(!c71_dense_quantize(c,raw,0,rounded)); // exact ordered observation
        assert(expected_raw.empty());
        assert(!c71_range_release(c,raw) && !c71_range_release(c,rounded) && !c71_range_release(c,out));
        assert(stats(c).live_capacity_bytes==256);
    }
    close(c);
    for(unsigned test=0;test<17;++test) {
        c=create(); if(test!=0) install(c);
        const auto out=alloc(c,C71_I16,8);
        uint32_t tokens[]={0,1}; int status=0;
        switch(test) {
        case 0: status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 1: tokens[1]=2; status=c71_dense_embedding(c,2,2,4,tokens,2,out); assert(!stats(c).d2d_bytes); break;
        case 2: tokens[0]=UINT32_MAX; status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 3: status=c71_dense_embedding(c,UINT64_MAX,2,4,tokens,2,out); break;
        case 4: status=c71_dense_embedding(c,3,2,4,tokens,2,out); break;
        case 5: status=c71_dense_embedding(c,2,0,4,tokens,2,out); break;
        case 6: status=c71_dense_embedding(c,2,2,0,tokens,2,out); break;
        case 7: status=c71_dense_embedding(c,2,2,4,tokens,0,out); break;
        case 8: status=c71_dense_embedding(c,2,2,4,tokens,151,out); break;
        case 9: status=c71_dense_embedding(c,2,2,4,tokens,1,out); break;
        case 10: status=c71_dense_embedding(c,2,2,4,nullptr,2,out); break;
        case 11: assert(!c71_dense_embedding(c,2,2,4,tokens,2,out)); status=c71_dense_embedding(c,2,2,4,tokens,2,out); break;
        case 12: { auto raw=alloc(c,C71_I64,8); status=c71_dense_embedding(c,2,2,4,tokens,2,raw); break; }
        case 13: copy_fail_after=0; status=c71_dense_embedding(c,2,2,4,tokens,2,out); copy_fail_after=-1; assert(!stats(c).d2d_bytes); break;
        case 14: copy_fail_after=1; status=c71_dense_embedding(c,2,2,4,tokens,2,out); copy_fail_after=-1; assert(stats(c).d2d_bytes==8); break;
        case 15: fail_fence=true; status=c71_dense_embedding(c,2,2,4,tokens,2,out); fail_fence=false; assert(stats(c).d2d_bytes==16); break;
        case 16: { auto* other=create(); auto foreign=alloc(other,C71_I16,8); status=c71_dense_embedding(c,2,2,4,tokens,2,foreign); close(other); break; }
        }
        assert(status && stats(c).stopped);
        const auto before=stats(c);
        assert(c71_dense_embedding(c,2,2,4,tokens,2,out));
        assert(stats(c).d2d_bytes==before.d2d_bytes && stats(c).launches==before.launches);
        close(c);
    }
}
static void pointwise_checks() {
    auto* c=create(); const auto x=dense_input(c);
    const c71_dense::Pointwise ops[]={{3,-2,0},{1,1,1},{0,2,0},{3,0,0},{0,0,0}};
    for(const auto op:ops) {
        const auto raw=alloc(c,C71_I64,4), y=alloc(c,C71_I16,4), root=alloc(c,C71_PAIR,1);
        const auto before=stats(c);
        assert(!c71_dense_pointwise(c,op.a?x:0,op.a?4:0,op.b?x:0,0,op,raw));
        assert(!c71_dense_quantize(c,raw,0,y));
        int16_t expected[4];
        for(int i=0;i<4;++i) expected[i]=op.multiply?-(i+1)*(i+1):int16_t(-op.a*(i+1)+op.b*(i+1));
        const auto reference=fraction(expected,1,0,4,{19,2,3});
        assert(!c71_range_roots(c,y,2,{19,2,3},root,0));
        uint64_t limbs[6]; assert(!c71_range_read(c,root,limbs,6));
        assert(std::memcmp(limbs,&reference,sizeof(reference))==0);
        assert(stats(c).h2d_bytes==before.h2d_bytes && stats(c).d2h_bytes-before.d2h_bytes==56);
        assert(!c71_range_release(c,root) && !c71_range_release(c,y) && !c71_range_release(c,raw));
    }
    close(c);
    for(unsigned test=0;test<14;++test) {
        c=create(); const auto x=dense_input(c),raw=alloc(c,C71_I64,4); int status=0;
        switch(test) {
        case 0: status=c71_dense_pointwise(c,x,UINT64_MAX,x,0,{1,1,0},raw); break;
        case 1: status=c71_dense_pointwise(c,x,6,x,0,{1,1,0},raw); break;
        case 2: status=c71_dense_pointwise(c,x,0,x,0,{INT64_MIN,1,0},raw); break;
        case 3: status=c71_dense_pointwise(c,x,0,x,0,{1,1,2},raw); break;
        case 4: status=c71_dense_pointwise(c,x,0,x,0,{0,1,1},raw); break;
        case 5: status=c71_dense_pointwise(c,x,0,x,0,{0,1,0},raw); break;
        case 6: status=c71_dense_pointwise(c,0,0,x,0,{1,1,0},raw); break;
        case 7: status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},x); break;
        case 8: { auto empty=alloc(c,C71_I16,4); status=c71_dense_pointwise(c,empty,0,x,0,{1,1,0},raw); break; }
        case 9: assert(!c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw)); status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); break;
        case 10: fail_launch=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); fail_launch=false; break;
        case 11: fail_fence=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); fail_fence=false; break;
        case 12: corrupt=true; status=c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw); corrupt=false; break;
        case 13: { auto* other=create(); auto foreign=dense_input(other); status=c71_dense_pointwise(c,foreign,0,x,0,{1,1,0},raw); close(other); break; }
        }
        assert(status && stats(c).stopped);
        const auto attempts=launches;
        assert(c71_dense_pointwise(c,x,0,x,0,{1,1,0},raw) && launches==attempts);
        close(c);
    }
}
static void byte_checks() {
    // Independent biased addition, including both signed-48 and signed-32 ends.
    for(unsigned width: {2u,4u,6u}) {
        const int64_t bound=int64_t{1}<<(8*width-1);
        for(int64_t value: {-bound,-bound+1,int64_t{-257},int64_t{-1},int64_t{0},int64_t{255},bound-1,bound}) {
            for(unsigned lane=0;lane<width;++lane) {
                uint8_t byte=99;
                const bool valid=value>=-bound && value<bound;
                assert(c71_byte::encode(value,width,lane,byte)==valid);
                if(valid) assert(byte==uint8_t(uint64_t(value+bound)>>(8*lane)));
            }
        }
    }
    const c71_byte::Tile base{0,4,2,4,32,0,128,0,2,2,7,2,1};
    auto* c=create(); const auto input=dense_input(c), out=alloc(c,C71_BYTE_PENDING,128);
    const auto before=stats(c);
    assert(!c71_byte_begin(c,out));
    assert(!c71_byte_scatter(c,input,&base,out));
    assert(stats(c).fences==before.fences && stats(c).d2h_bytes==before.d2h_bytes);
    // Producer lifetime ends before seal. Its reused allocation is ordered
    // AFTER the queued scatter, not an input copy hidden in the gather.
    assert(!c71_range_release(c,input));
    const auto replacement=alloc(c,C71_I16,8);
    const int16_t replacement_values[8]={99,99,99,99,99,99,99,99};
    assert(!c71_range_upload(c,replacement,replacement_values,sizeof(replacement_values)));
    assert(!c71_byte_seal(c,out));
    assert(stats(c).d2h_bytes-before.d2h_bytes==4 && stats(c).h2d_bytes==before.h2d_bytes+16);
    expected_bytes.assign(128,0);
    const int16_t values[]={1,2,3,4,-1,-2,-3,-4};
    for(unsigned i=0;i<16;++i) {
        const unsigned original=32+i;
        // Independent bit mapping: low subtree bit stays, next two move up.
        unsigned address=original&1;
        for(unsigned bit=1;bit<7;++bit) address|=((original>>bit)&1)<<(bit<3?bit+4:bit-2);
        expected_bytes[address]=uint8_t((int(values[i/2])+32768)>>(8*(i%2)));
    }
    const auto root=alloc(c,C71_PAIR,1);
    assert(!c71_range_roots(c,out,7,{19,2,3},root,0));
    uint64_t limbs[6]; assert(!c71_range_read(c,root,limbs,6));
    assert(expected_bytes.empty());
    close(c);
    for(unsigned test=0;test<19;++test) {
        c=create(); const auto x=dense_input(c), pending=alloc(c,C71_BYTE_PENDING,128);
        if(test!=1) assert(!c71_byte_begin(c,pending));
        auto t=base; int status=0;
        switch(test) {
        case 0: { auto r=alloc(c,C71_PAIR,1); status=c71_range_roots(c,pending,7,{19,2,3},r,0); break; }
        case 1: status=c71_byte_scatter(c,x,&t,pending); break;
        case 2: status=c71_byte_begin(c,pending); break;
        case 3: { auto empty=alloc(c,C71_I16,8); status=c71_byte_scatter(c,empty,&t,pending); break; }
        case 4: t.signed_width=6; status=c71_byte_scatter(c,x,&t,pending); break;
        case 5: t.original_first=UINT64_MAX; status=c71_byte_scatter(c,x,&t,pending); break;
        case 6: t.input_stride=0; status=c71_byte_scatter(c,x,&t,pending); break;
        case 7: t.input_first=UINT64_MAX; status=c71_byte_scatter(c,x,&t,pending); break;
        case 8: t.dimension=36; status=c71_byte_scatter(c,x,&t,pending); break;
        case 9: t.suffix=7; status=c71_byte_scatter(c,x,&t,pending); break;
        case 10: t.bottom=8; status=c71_byte_scatter(c,x,&t,pending); break;
        case 11: t.window_first=1; status=c71_byte_scatter(c,x,&t,pending); break;
        case 12: t.window_length=64; status=c71_byte_scatter(c,x,&t,pending); break;
        case 13: status=c71_byte_scatter(c,pending,&t,pending); break;
        case 14: assert(!c71_byte_seal(c,pending)); status=c71_byte_scatter(c,x,&t,pending); break;
        case 15: assert(!c71_byte_scatter(c,x,&t,pending)); fail_fence=true; status=c71_byte_seal(c,pending); fail_fence=false; break;
        case 16: assert(!c71_byte_scatter(c,x,&t,pending)); corrupt=true; status=c71_byte_seal(c,pending); corrupt=false; break;
        case 17: fail_launch=true; status=c71_byte_scatter(c,x,&t,pending); fail_launch=false; break;
        case 18: {
            const int16_t large[]={32767,32767,32767,32767};
            assert(!c71_dense_weights_begin(c,4));
            assert(!c71_dense_weights_upload(c,0,large,4)); assert(!c71_dense_weights_seal(c));
            const auto in=alloc(c,C71_I16,4), raw=alloc(c,C71_I64,1);
            assert(!c71_range_upload(c,in,large,sizeof(large)));
            assert(!c71_dense_product(c,in,0,{1,1,4},raw));
            const c71_byte::Tile narrow{0,1,1,1,0,0,128,0,4,4,7,0,0};
            assert(!c71_byte_scatter(c,raw,&narrow,pending));
            status=c71_byte_seal(c,pending); break; // actual device-codec flag
        }
        }
        assert(status && stats(c).stopped);
        const auto attempted=launches;
        assert(c71_byte_seal(c,pending) && launches==attempted);
        close(c);
    }
    // Releasing an unfinished window frees its flag and capacity after a fence.
    c=create(); const auto pending=alloc(c,C71_BYTE_PENDING,128);
    assert(!c71_byte_begin(c,pending)); assert(stats(c).live_capacity_bytes==512);
    assert(!c71_range_release(c,pending)); assert(!stats(c).live_capacity_bytes);
    close(c);
}
static uint64_t joint_live=0, joint_limit=uint64_t{1}<<20;
static int joint_account(int64_t delta) {
    if(delta>0 && uint64_t(delta)>joint_limit-joint_live) return -1;
    if(delta>=0) joint_live+=uint64_t(delta); else joint_live-=uint64_t(-delta);
    return 0;
}
static void joint_budget_checks() {
    C71RangeContext* c=nullptr;
    assert(!c71_range_create(0,262144,256,joint_account,&c));
    const auto owner=stats(c).host_owner_bytes;
    assert(joint_live==owner && !stats(c).arena_bytes);
    joint_limit=owner+256;
    const auto a=alloc(c,C71_U8,17);
    assert(joint_live==owner+256 && stats(c).arena_bytes==256);
    assert(!c71_range_release(c,a));
    assert(joint_live==owner && !stats(c).arena_bytes);
    alloc(c,C71_U8,17);
    const auto before=allocations;
    uint64_t denied=0;
    assert(c71_range_alloc(c,C71_U8,1,&denied));
    assert(!denied && allocations==before && stats(c).stopped);
    close(c);
    assert(joint_live==0);
}
static void dense_completion_fence_checks() {
    // Deferred writes execute only at the unchanged completion fence.
    joint_limit=uint64_t{1}<<20;
    for(unsigned fault=0;fault<4;++fault) {
        assert(!joint_live);
        C71RangeContext* c=nullptr;
        assert(!c71_range_create(0,262144,256,joint_account,&c));
        const auto x=dense_input(c), raw=alloc(c,C71_I64,8);
        const auto before=stats(c);
        const auto free_before=frees;
        fail_fence=fault==1; corrupt=fault==2; fail_launch=fault==3;
        const int status=c71_dense_pointwise(c,x,0,0,0,{2,0,0},raw);
        fail_fence=false; corrupt=false; fail_launch=false;
        const auto after=stats(c);
        assert(after.fences==before.fences+unsigned(fault!=3));
        assert(after.d2h_bytes==before.d2h_bytes+4*unsigned(fault!=3));
        assert(after.allocations==before.allocations+1);
        assert(after.releases==before.releases && frees==free_before);
        assert(after.arena_bytes==before.arena_bytes+256);
        assert(joint_live==after.host_owner_bytes+after.arena_bytes);
        if(!fault) {
            assert(!status && !after.stopped);
            int64_t actual[8]{};
            const int64_t expected[]={2,4,6,8,-2,-4,-6,-8};
            assert(!c71_original_read(c,raw,C71_I64,0,8,actual));
            assert(std::memcmp(actual,expected,sizeof(expected))==0);
            const auto release_before=stats(c);
            assert(!c71_range_release(c,raw));
            assert(stats(c).fences==release_before.fences+1);
            close(c);
            assert(!joint_live);
        } else {
            assert(status && after.stopped);
            int64_t untouched=1234;
            assert(c71_original_read(c,raw,C71_I64,0,1,&untouched) && untouched==1234);
            assert(c71_dense_pointwise(c,x,0,0,0,{2,0,0},raw));
            assert(c71_range_release(c,raw));
            const auto stopped=stats(c);
            assert(stopped.launches==after.launches && stopped.allocations==after.allocations);
            assert(stopped.fences==after.fences && frees==free_before);
            C71RangeStats final{};
            assert(!c71_range_close(c,&final));
            assert(frees==free_before+3);
            assert(!final.cleanup_failed && !final.arena_bytes && !joint_live);
        }
    }

    C71RangeContext* c=nullptr;
    assert(!c71_range_create(0,262144,256,joint_account,&c));
    const auto input=dense_input(c);
    const auto before=stats(c);
    void* flag_pointer=nullptr;
    for(unsigned operation=0;operation<32;++operation) {
        const auto raw=alloc(c,C71_I64,8);
        const auto submitted=stats(c);
        assert(!c71_dense_pointwise(c,input,0,0,0,{2,0,0},raw));
        if(!operation) flag_pointer=last_allocation;
        assert(stats(c).fences==submitted.fences+1 && stats(c).d2h_bytes==submitted.d2h_bytes+4);
        int64_t actual[8]{};
        const int64_t expected[]={2,4,6,8,-2,-4,-6,-8};
        assert(!c71_original_read(c,raw,C71_I64,0,8,actual));
        assert(!std::memcmp(actual,expected,sizeof(expected)));
        assert(!c71_range_release(c,raw));
        // Poison the retained device word after completion: the next call
        // must reset it before launch even when no allocation occurs.
        *static_cast<uint32_t*>(flag_pointer)=UINT32_MAX;
    }
    const auto after=stats(c);
    assert(after.allocations-before.allocations==33 && after.releases-before.releases==32);
    assert(after.launches-before.launches==32 && after.fences-before.fences==96);
    assert(after.d2h_bytes-before.d2h_bytes==32*(4+64) && after.zeroed_bytes-before.zeroed_bytes==32*4);
    assert(!c71_range_release(c,input));
    assert(stats(c).arena_bytes==256 && joint_live==stats(c).host_owner_bytes+256);
    const auto retained=stats(c);
    close(c); assert(!joint_live);
    std::printf("C71_SYNC_ERROR_FLAG_REUSE {\"host_owner_bytes\":%llu,\"retained_device_capacity_bytes\":256,\"flag_count\":1,\"sync_flag_reuse\":true,\"numeric_operations\":32,\"numeric_flag_allocations\":1,\"numeric_flag_allocations_before\":32,\"numeric_completion_fences\":32,\"numeric_flag_download_bytes\":128,\"gpu_execution\":false,\"credit\":false}\n",
        (unsigned long long)retained.host_owner_bytes);

    // Lazy pool allocation must respect the same simultaneous joint budget.
    assert(!c71_range_create(0,262144,256,joint_account,&c));
    const auto x=dense_input(c), raw=alloc(c,C71_I64,8);
    joint_limit=joint_live;
    const auto bounded=stats(c);
    assert(c71_dense_pointwise(c,x,0,0,0,{2,0,0},raw));
    assert(stats(c).stopped && stats(c).allocations==bounded.allocations && stats(c).launches==bounded.launches);
    joint_limit=uint64_t{1}<<20;
    close(c); assert(!joint_live);

    // A sticky byte flag survives a successful producer between begin/seal.
    c=create();
    const auto large=alloc(c,C71_I16,4), bad_raw=alloc(c,C71_I64,4), good_raw=alloc(c,C71_I64,4);
    const int16_t values[]={32767,32767,32767,32767};
    assert(!c71_range_upload(c,large,values,sizeof(values)));
    assert(!c71_dense_pointwise(c,large,0,0,0,{1<<30,0,0},bad_raw));
    const auto bytes=alloc(c,C71_BYTE_PENDING,128);
    assert(!c71_byte_begin(c,bytes));
    const c71_byte::Tile tile{0,4,1,1,0,0,128,0,4,4,7,0,0};
    assert(!c71_byte_scatter(c,bad_raw,&tile,bytes));
    assert(!c71_dense_pointwise(c,large,0,0,0,{1,0,0},good_raw));
    assert(c71_byte_seal(c,bytes) && stats(c).stopped);
    close(c);

    // Dedicated transaction flags retain the previous free-failure behavior.
    assert(!c71_range_create(0,262144,256,joint_account,&c));
    const auto pending=alloc(c,C71_BYTE_PENDING,8);
    assert(!c71_byte_begin(c,pending));
    fail_free=true;
    assert(c71_byte_seal(c,pending) && stats(c).stopped);
    fail_free=false;
    const auto free_before=frees;
    C71RangeStats final{};
    assert(c71_range_close(c,&final) && final.cleanup_failed);
    assert(frees==free_before+1 && final.arena_bytes==256 && joint_live==256);
    joint_live=0; // Isolated receipt retains the failed-free debt above.

    // A pooled flag is private even if an internal handle is guessed.
    for(unsigned fault=0;fault<3;++fault) {
        c=create(); const auto original=dense_input(c), output=alloc(c,C71_I64,8);
        assert(!c71_dense_pointwise(c,original,0,0,0,{2,0,0},output));
        const uint64_t private_flag=output+1;
        const auto guarded=stats(c); uint32_t word=123;
        int status=0;
        if(fault==0) status=c71_range_release(c,private_flag);
        if(fault==1) status=c71_range_upload(c,private_flag,&word,4);
        if(fault==2) status=c71_original_read(c,private_flag,C71_U8,0,4,&word);
        assert(status && stats(c).stopped && word==123);
        assert(stats(c).d2h_bytes==guarded.d2h_bytes && stats(c).h2d_bytes==guarded.h2d_bytes);
        close(c);
    }
}

namespace residual_test {
namespace pcs=c71_pcs_residual;
using E=pcs::E;
bool same(E a,E b) { return a.c0==b.c0 && a.c1==b.c1 && a.c2==b.c2; }
struct Lookup { pcs::EqShape shape{}; std::vector<pcs::Chunk> chunks; std::vector<E> tables; };
E eq(const std::vector<E>& point,uint64_t index) {
    E out{1,0,0};
    for(size_t i=0;i<point.size();++i) out=residual_oracle::mul(out,(index>>(point.size()-1-i))&1?point[i]:residual_oracle::sub({1,0,0},point[i]));
    return out;
}
Lookup lookup(const std::vector<E>& point) {
    Lookup out;
    for(size_t first=0;first<point.size();first+=8) {
        const auto bits=std::min<size_t>(8,point.size()-first);
        out.chunks.push_back({unsigned(point.size()-first-bits),unsigned(bits),unsigned(out.tables.size()),0});
        std::vector<E> chunk(point.begin()+first,point.begin()+first+bits);
        for(uint64_t i=0;i<(uint64_t{1}<<bits);++i) out.tables.push_back(eq(chunk,i));
    }
    out.shape={unsigned(point.size()),unsigned(out.chunks.size()),unsigned(out.tables.size()),0}; return out;
}
uint64_t begin(C71RangeContext* c,pcs::Shape shape,pcs::Phase phase,const Lookup& packet,
    pcs::CosetShape cosets={},const std::vector<E>& pads={},E point={}) {
    shape.equality=packet.shape; uint64_t token=0;
    assert(!c71_pcs_residual_begin(c,shape,phase,packet.chunks.data(),packet.tables.data(),cosets,pads.data(),unsigned(pads.size()),point,&token));
    assert(token); return token;
}
C71PcsResidualResult finish(C71RangeContext* c,uint64_t token) {
    C71PcsResidualResult out{}; assert(!c71_pcs_residual_finish(c,token,&out)); return out;
}
std::vector<E> dense_fold(std::vector<E> values,const std::vector<E>& prefix) {
    for(const auto r:prefix) {
        const size_t half=values.size()/2;
        for(size_t i=0;i<half;++i) values[i]=residual_oracle::fold(values[i],values[i+half],r);
        values.resize(half);
    }
    return values;
}
std::vector<E> originals() {
    const int16_t words[]={-32767,-257,-1,0,1,255,256,32767,-13,7,11,-29,31,2,-3,5};
    std::vector<E> out(128);
    for(unsigned i=0;i<16;++i) for(unsigned lane=0;lane<2;++lane)
        out[2*i+lane]={uint64_t(uint16_t(int32_t(words[i])+32768)>>(8*lane))&255,0,0};
    return out;
}
uint64_t input(C71RangeContext* c) {
    const int16_t words[]={-32767,-257,-1,0,1,255,256,32767,-13,7,11,-29,31,2,-3,5};
    const auto id=alloc(c,C71_I16,16); assert(!c71_range_upload(c,id,words,sizeof(words))); return id;
}
void source(C71RangeContext* c,uint64_t token,uint64_t original) {
    // Reversed trusted tile order, exactly one live prefix partition.
    assert(!c71_pcs_residual_source_tile(c,token,original,{8,8,1,8,16,0,2,2}));
    assert(!c71_pcs_residual_source_tile(c,token,original,{0,8,1,8,0,0,2,2}));
}
void read_copy(C71RangeContext* c,C71PcsResidualPlanes planes,const std::vector<E>& expected) {
    const auto empty=lookup({});
    unsigned dimension=0; while((uint64_t{1}<<dimension)<planes.count) ++dimension;
    assert(dimension); // Final copies here have at least two coefficients.
    const auto token=begin(c,{planes.count,dimension,dimension,{}},pcs::Phase::retention,empty);
    assert(!c71_pcs_residual_resident(c,token,planes)); const auto copy=finish(c,token).planes;
    std::vector<E> values(copy.count); const auto before=stats(c);
    assert(!c71_pcs_residual_final_read(c,copy,values.data(),unsigned(values.size())));
    assert(stats(c).d2h_bytes-before.d2h_bytes==copy.count*24);
    assert(values.size()==expected.size()); for(size_t i=0;i<values.size();++i) assert(same(values[i],expected[i]));
}
void component_checks() {
    auto* c=create(); const auto original=input(c); const auto values=originals();
    const std::vector<E> prefix{{0,0,0},{0,0,0},{7,11,13}};
    const auto suffix=lookup({{0,0,0},{1,0,0},{0,1,0},{3,5,7}});
    auto before=stats(c);
    auto token=begin(c,{32,7,4,{}},pcs::Phase::singleton,suffix); source(c,token,original); const auto singleton=finish(c,token);
    assert(singleton.reduced_count==8 && !singleton.ring && !singleton.planes.c0);
    for(unsigned i=0;i<8;++i) {
        E expected{}; for(unsigned j=0;j<16;++j) expected=residual_oracle::add(expected,residual_oracle::mul(values[16*i+j],suffix.tables[j]));
        assert(same(singleton.reduced[i],expected));
    }
    assert(stats(c).d2h_bytes-before.d2h_bytes==8*24+4 && stats(c).arena_bytes==before.arena_bytes);
    const auto packet=lookup(prefix); const auto folded=dense_fold(values,prefix);
    before=stats(c); token=begin(c,{32,7,4,{}},pcs::Phase::retention,packet); source(c,token,original);
    const auto retained=finish(c,token).planes;
    assert(retained.count==16 && retained.c0 && retained.c1 && retained.c2);
    assert(stats(c).d2h_bytes-before.d2h_bytes==4);
    assert(stats(c).arena_bytes==before.arena_bytes+3*256);
    read_copy(c,retained,folded);
    const E point{17,19,23}; const std::vector<E> pads{{29,31,37},{0,1,0},{0,0,1}};
    token=begin(c,{32,7,4,{}},pcs::Phase::ood,packet,{},pads,point); source(c,token,original); const auto ood=finish(c,token);
    E expected{}; for(size_t i=0;i<folded.size();++i) expected=residual_oracle::add(expected,residual_oracle::mul(folded[i],residual_oracle::power(point,i)));
    for(size_t i=0;i<pads.size();++i) expected=residual_oracle::add(expected,residual_oracle::mul(pads[i],residual_oracle::power(point,folded.size()+i)));
    assert(ood.reduced_count==1 && same(ood.reduced[0],expected));
    for(const std::vector<E>& virtual_prefix:{std::vector<E>{},std::vector<E>{{1,0,0}},std::vector<E>{{0,0,0},{0,1,0}}}) {
        const auto virtual_packet=lookup(virtual_prefix); const auto current=dense_fold(folded,virtual_prefix);
        token=begin(c,{16,4,unsigned(4-virtual_prefix.size()),{}},pcs::Phase::ood,virtual_packet,{},pads,point);
        assert(!c71_pcs_residual_resident(c,token,retained)); const auto actual=finish(c,token);
        expected={}; for(size_t i=0;i<current.size();++i) expected=residual_oracle::add(expected,residual_oracle::mul(current[i],residual_oracle::power(point,i)));
        for(size_t i=0;i<pads.size();++i) expected=residual_oracle::add(expected,residual_oracle::mul(pads[i],residual_oracle::power(point,current.size()+i)));
        assert(same(actual.reduced[0],expected));
    }
    for(unsigned rounds:{1u,2u}) {
        const E r0{0,1,0},r1{0,0,1}; C71PcsResidualPlanes next{}; before=stats(c);
        assert(!c71_pcs_residual_fold(c,retained,rounds,r0,r1,&next));
        const auto expected_fold=dense_fold(folded,rounds==1?std::vector<E>{r0}:std::vector<E>{r0,r1});
        read_copy(c,next,expected_fold); assert(!c71_pcs_residual_retire_planes(c,next));
        assert(stats(c).arena_bytes==before.arena_bytes);
    }
    assert(!c71_pcs_residual_retire_planes(c,retained)); assert(!c71_range_release(c,original)); close(c);
    std::puts("C71_PCS_RESIDUAL_OWNER_COMPONENT {\"singleton\":1,\"original_retention\":1,\"ood_original\":1,\"ood_resident\":3,\"paired_folds\":2,\"bounded_consuming_reads\":3,\"gpu_execution\":false,\"credit\":false}");
}
void contract_checks() {
    const int16_t weights[]={0,1,-1,32767,-32767,2,-2,3,4,-4,7,-7,11,-11,13,-13,
        17,-17,19,-19,23,-23,29,-29,31,-31,37,-37,41,-41,43,-43};
    auto* c=create(); assert(!c71_dense_weights_begin(c,32)); assert(!c71_dense_weights_upload(c,0,weights,32)); assert(!c71_dense_weights_seal(c));
    const auto tiles=alloc(c,C71_PCS_WEIGHT_TILES,2); const c71_pcs::WeightTile layout[]={{0,16,0,4,2},{16,16,2,4,2}};
    assert(!c71_pcs_tiles_upload(c,tiles,layout,2));
    std::vector<E> values(128);
    for(unsigned i=0;i<32;++i) { const unsigned address=i<16?i/2*4+i%2:((i-16)/2*4+2+(i-16)%2); const auto w=weights[address]; values[i]={w<0?P-uint64_t(-int32_t(w)):uint64_t(w),0,0}; }
    const std::vector<E> prefix{{0,0,0},{0,0,0},{7,11,13}}; const auto packet=lookup(prefix); const auto folded=dense_fold(values,prefix);
    unsigned cases=0;
    for(unsigned kind:{0u,1u}) {
        const unsigned length=16>>kind; std::vector<E> left(length),right(length); E expected[2]{};
        for(unsigned i=0;i<length;++i) {
            left[i]=i%3==0?E{}:i%3==1?E{1,0,0}:E{7+i,11+i,13+i}; right[i]={17+i,19+i,23+i};
            expected[0]=residual_oracle::add(expected[0],residual_oracle::mul(folded[i],left[i]));
            if(kind) expected[1]=residual_oracle::add(expected[1],residual_oracle::mul(residual_oracle::sub(folded[i+length],folded[i]),residual_oracle::sub(right[i],left[i])));
        }
        uint64_t token=0; const auto before=stats(c); const auto reads=contract_original_reads;
        assert(!c71_pcs_residual_contract_begin(c,{32,7,4,packet.shape},packet.chunks.data(),packet.tables.data(),kind,3,&token));
        unsigned bands=0;
        for(unsigned start=0;start<length;start+=3) {
            const auto count=std::min(3u,length-start);
            assert(!c71_pcs_residual_contract_weights_band(c,token,tiles,start,count,left.data()+start,kind?right.data()+start:nullptr)); ++bands;
        }
        E actual[2]{}; assert(!c71_pcs_residual_contract_finish(c,token,actual));
        assert(same(actual[0],expected[0]) && same(actual[1],expected[1]));
        assert(contract_original_reads-reads==32 && stats(c).d2h_bytes-before.d2h_bytes==52);
        assert(stats(c).fences-before.fences==bands+2 && stats(c).arena_bytes==before.arena_bytes); ++cases;
    }
    const auto token=begin(c,{32,7,4,{}},pcs::Phase::retention,packet); assert(!c71_pcs_residual_weights(c,token,tiles)); const auto retained=finish(c,token).planes;
    for(const std::vector<E>& virtual_prefix:{std::vector<E>{},std::vector<E>{{1,0,0}},std::vector<E>{{0,1,0},{0,0,1}}}) for(unsigned kind:{0u,1u}) {
        const auto current=dense_fold(folded,virtual_prefix); const auto virtual_packet=lookup(virtual_prefix);
        const unsigned remaining=4-unsigned(virtual_prefix.size()),length=unsigned(current.size())>>kind;
        std::vector<E> left(length),right(length); E expected[2]{};
        for(unsigned i=0;i<length;++i) {
            left[i]={3+i,5+i,7+i}; right[i]={11+i,13+i,17+i};
            expected[0]=residual_oracle::add(expected[0],residual_oracle::mul(current[i],left[i]));
            if(kind) expected[1]=residual_oracle::add(expected[1],residual_oracle::mul(residual_oracle::sub(current[i+length],current[i]),residual_oracle::sub(right[i],left[i])));
        }
        uint64_t job=0; const auto reads=contract_resident_reads; const auto before=stats(c);
        const unsigned capacity=std::min(3u,length);
        assert(!c71_pcs_residual_contract_begin(c,{16,4,remaining,virtual_packet.shape},virtual_packet.chunks.data(),virtual_packet.tables.data(),kind,capacity,&job));
        for(unsigned start=0;start<length;start+=capacity) assert(!c71_pcs_residual_contract_resident_band(c,job,retained,start,std::min(capacity,length-start),left.data()+start,kind?right.data()+start:nullptr));
        E actual[2]{}; assert(!c71_pcs_residual_contract_finish(c,job,actual));
        assert(same(actual[0],expected[0]) && same(actual[1],expected[1])); assert(contract_resident_reads-reads==16);
        assert(stats(c).d2h_bytes-before.d2h_bytes==52 && stats(c).arena_bytes==before.arena_bytes); ++cases;
    }
    assert(!c71_pcs_residual_retire_planes(c,retained)); assert(!c71_range_release(c,tiles)); close(c);
    std::printf("C71_PCS_RESIDUAL_CONTRACT_OWNER {\"cases\":%u,\"W_bands_one_scan\":true,\"resident_virtual_bits\":2,\"consumer_d2h_bytes\":52,\"public_tail_reads\":0,\"gpu_execution\":false,\"credit\":false}\n",cases);
}
}


namespace residual_test {
void failure_checks() {
    const auto packet=lookup({{0,0,0},{1,0,0},{7,11,13}});
    for(unsigned fault=0;fault<31;++fault) {
        auto* c=create(); const auto original=input(c);
        auto shape=pcs::Shape{32,7,4,packet.shape}; auto chunks=packet.chunks; auto tables=packet.tables;
        uint64_t token=0xababababababababULL; int status=0;
        C71PcsResidualResult out{}; std::memset(&out,0xa5,sizeof(out)); const auto unchanged=out;
        if(fault<=10) {
            switch(fault) {
            case 0: shape.equality.bits=2; break;
            case 1: chunks[0].shift=1; break;
            case 2: tables[0].c2=P; break;
            case 3: shape.remaining=29; shape.dimension=35; shape.equality={6,1,64,0}; break;
            case 4: shape.live=129; break;
            case 5: shape.equality.reserved=1; break;
            case 6: status=c71_range_alloc(c,C71_PCS_RESIDUAL_PRIVATE,1,&token); break;
            case 7: fail_fence=true; break;
            case 8: upload_fail_after=0; break;
            case 9: upload_fail_after=1; break;
            case 10: fail_launch=true; break;
            }
            if(fault!=6) status=c71_pcs_residual_begin(c,shape,fault==10?pcs::Phase::ood:pcs::Phase::retention,
                chunks.data(),tables.data(),{},nullptr,0,fault==10?E{7,11,13}:E{},&token);
            // Only OOD accepts a point. The other fault cases use zero;
            // retrying a poisoned owner is deliberately impossible.
        } else {
            token=begin(c,shape,pcs::Phase::retention,packet);
            switch(fault) {
            case 11: status=c71_pcs_residual_finish(c,token,&out); break;
            case 12: status=c71_pcs_residual_source_tile(c,0,original,{0,8,1,8,0,0,2,2}); break;
            case 13: status=c71_pcs_residual_source_tile(c,token,original,{0,8,1,8,32,0,2,2}); break;
            case 14: status=c71_pcs_residual_source_tile(c,token,original,{0,7,1,8,0,0,2,2}); break;
            case 15: { const auto pending=alloc(c,C71_I16,16); status=c71_pcs_residual_source_tile(c,token,pending,{0,8,1,8,0,0,2,2}); break; }
            case 16: { const auto wrong=alloc(c,C71_U8,16); status=c71_pcs_residual_source_tile(c,token,wrong,{0,8,1,8,0,0,2,2}); break; }
            case 17: assert(!c71_pcs_residual_source_tile(c,token,original,{0,8,1,8,0,0,2,2})); status=c71_pcs_residual_finish(c,token,&out); break;
            case 18: source(c,token,original); status=c71_pcs_residual_source_tile(c,token,original,{0,8,1,8,0,0,2,2}); break;
            case 19: fail_launch=true; status=c71_pcs_residual_source_tile(c,token,original,{0,8,1,8,0,0,2,2}); break;
            case 20: fail_dense=true; source(c,token,original); status=c71_pcs_residual_finish(c,token,&out); break;
            case 21: source(c,token,original); download_fail_after=0; status=c71_pcs_residual_finish(c,token,&out); break;
            case 22: source(c,token,original); fail_fence=true; status=c71_pcs_residual_finish(c,token,&out); break;
            case 23: source(c,token,original); fail_free=true; status=c71_pcs_residual_finish(c,token,&out); break;
            case 24: source(c,token,original); corrupt=true; status=c71_pcs_residual_finish(c,token,&out); break;
            case 25: { uint64_t words=123; const auto before=stats(c).d2h_bytes; status=c71_pcs_read_words(c,token,0,1,&words); assert(words==123 && stats(c).d2h_bytes==before); break; }
            case 26: status=c71_range_release(c,token); break;
            case 27: status=c71_pcs_residual_begin(c,shape,pcs::Phase::retention,chunks.data(),tables.data(),{},nullptr,0,{},&token); break;
            case 28: { auto* other=create(); const auto foreign=input(other); status=c71_pcs_residual_source_tile(c,token,foreign,{0,8,1,8,0,0,2,2}); close(other); break; }
            case 29: source(c,token,original); status=c71_pcs_residual_finish(c,token,nullptr); break;
            case 30: { C71PcsResidualPlanes forged{original,original+1,original+2,16}; status=c71_pcs_residual_resident(c,token,forged); break; }
            }
        }
        fail_launch=false; fail_fence=false; fail_free=false; corrupt=false; fail_dense=false;
        upload_fail_after=download_fail_after=-1;
        assert(status && stats(c).stopped && !std::memcmp(&out,&unchanged,sizeof(out)));
        assert(c71_pcs_residual_finish(c,token,&out));
        C71RangeStats final{}; const auto closed=c71_range_close(c,&final);
        assert((closed!=0)==(fault==23));
    }
    // Plane capabilities cannot be spliced, exposed as base words, released
    // through the generic allocator, or published before an auxiliary free.
    for(unsigned fault=0;fault<14;++fault) {
        auto* c=create(); const auto original=input(c); const auto shape=pcs::Shape{32,7,4,packet.shape};
        auto token=begin(c,shape,pcs::Phase::retention,packet); source(c,token,original); auto planes=finish(c,token).planes;
        int status=0; C71PcsResidualPlanes out{123,127,131,137}; const auto unchanged=out;
        E values[16]; for(auto& value:values) value={23,29,31};
        switch(fault) {
        case 0: status=c71_range_release(c,planes.c0); break;
        case 1: { uint64_t word=17; const auto before=stats(c).d2h_bytes; status=c71_pcs_read_words(c,planes.c0,0,1,&word); assert(word==17 && stats(c).d2h_bytes==before); break; }
        case 2: planes.c1=planes.c0; status=c71_pcs_residual_retire_planes(c,planes); break;
        case 3: planes.count=8; status=c71_pcs_residual_retire_planes(c,planes); break;
        case 4: status=c71_pcs_residual_retire_ring(c,planes.c0); break;
        case 5: status=c71_pcs_residual_fold(c,planes,0,{}, {},&out); break;
        case 6: status=c71_pcs_residual_fold(c,planes,2,{P,0,0},{},&out); break;
        case 7: fail_launch=true; status=c71_pcs_residual_fold(c,planes,1,{0,1,0},{},&out); break;
        case 8: fail_fence=true; status=c71_pcs_residual_fold(c,planes,1,{0,1,0},{},&out); break;
        case 9: fail_dense=true; status=c71_pcs_residual_fold(c,planes,1,{0,1,0},{},&out); break;
        case 10: fail_free=true; status=c71_pcs_residual_fold(c,planes,1,{0,1,0},{},&out); break;
        case 11: download_fail_after=1; status=c71_pcs_residual_final_read(c,planes,values,16); break;
        case 12: corrupt=true; status=c71_pcs_residual_final_read(c,planes,values,16); break;
        case 13: fail_free=true; status=c71_pcs_residual_final_read(c,planes,values,16); break;
        }
        fail_launch=false; fail_fence=false; fail_free=false; corrupt=false; fail_dense=false; download_fail_after=-1;
        assert(status && stats(c).stopped && !std::memcmp(&out,&unchanged,sizeof(out)));
        for(auto value:values) assert(same(value,{23,29,31}));
        C71RangeStats final{}; const auto closed=c71_range_close(c,&final); assert((closed!=0)==(fault==10 || fault==13));
    }
    std::puts("C71_PCS_RESIDUAL_OWNER_FAILURE {\"terminal_rejections\":45,\"private_read_d2h_bytes\":0,\"publication_after_free\":true,\"gpu_execution\":false,\"credit\":false}");
}
void contract_failures() {
    const auto packet=lookup({{0,0,0},{1,0,0},{7,11,13}});
    for(unsigned fault=0;fault<19;++fault) {
        auto* c=create(); const auto original=input(c); auto token=begin(c,{32,7,4,{}},pcs::Phase::retention,packet);
        source(c,token,original); const auto planes=finish(c,token).planes;
        const auto empty=lookup({}); E left[8],right[8]; for(auto& x:left) x={3,5,7}; for(auto& x:right) x={11,13,17};
        E out[2]={{19,23,29},{31,37,41}}; int status=0;
        if(fault<5) {
            auto shape=pcs::Shape{16,4,4,empty.shape};
            if(fault==0) shape.remaining=5;
            if(fault==1) shape.equality.bits=1;
            if(fault==2) upload_fail_after=0;
            if(fault==3) fail_fence=true;
            status=c71_pcs_residual_contract_begin(c,shape,nullptr,nullptr,1,fault==4?1u<<22:3,&token);
        } else {
            assert(!c71_pcs_residual_contract_begin(c,{16,4,4,empty.shape},nullptr,nullptr,1,3,&token));
            if(fault>=11) for(unsigned start=0;start<8;start+=3)
                assert(!c71_pcs_residual_contract_resident_band(c,token,planes,start,std::min(3u,8-start),left+start,right+start));
            switch(fault) {
            case 5: status=c71_pcs_residual_contract_resident_band(c,token,planes,1,3,left,right); break;
            case 6: status=c71_pcs_residual_contract_resident_band(c,token,planes,0,4,left,right); break;
            case 7: left[0].c1=P; status=c71_pcs_residual_contract_resident_band(c,token,planes,0,3,left,right); break;
            case 8: status=c71_pcs_residual_contract_resident_band(c,token,planes,0,3,left,nullptr); break;
            case 9: fail_launch=true; status=c71_pcs_residual_contract_resident_band(c,token,planes,0,3,left,right); break;
            case 10: status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 11: download_fail_after=0; status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 12: download_fail_after=1; status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 13: fail_free=true; status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 14: corrupt=true; status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 15: fail_fence=true; status=c71_pcs_residual_contract_finish(c,token,out); break;
            case 16: status=c71_pcs_residual_contract_resident_band(c,token,planes,8,1,left,right); break;
            case 17: status=c71_pcs_residual_retire_planes(c,planes); break;
            case 18: status=c71_pcs_residual_contract_finish(c,token,nullptr); break;
            }
        }
        upload_fail_after=download_fail_after=-1; fail_launch=false; fail_fence=false; fail_free=false; corrupt=false;
        assert(status && stats(c).stopped && same(out[0],{19,23,29}) && same(out[1],{31,37,41}));
        C71RangeStats final{}; const auto closed=c71_range_close(c,&final); assert((closed!=0)==(fault==13));
    }
    std::puts("C71_PCS_RESIDUAL_CONTRACT_FAILURE {\"terminal_rejections\":19,\"gpu_execution\":false,\"credit\":false}");
}
}


namespace residual_test {
uint64_t private_salts(C71RangeContext* c,uint64_t& end) {
    uint8_t seed[32]; for(unsigned i=0;i<32;++i) seed[i]=uint8_t(i*7+3);
    uint64_t token=0; assert(!c71_pcs_salts_begin(c,seed,{8,0,32,32},2,64,&token));
    c71_salts::Progress progress{};
    do { assert(!c71_pcs_salts_prescan(c,token,&progress)); } while(!progress.complete);
    assert(!progress.failed && progress.accepted==4*8*32); end=progress.cursor;
    uint64_t starts[8]{},offsets[8]{}; assert(!c71_pcs_salts_indices(c,token,starts,8,offsets,8));
    assert(starts[0]==0 && offsets[0]==0); return token;
}
std::vector<uint64_t> expected_ring(const std::vector<E>& folded,const std::vector<E>& pads,unsigned first_coset) {
    std::vector<uint64_t> out(24*8);
    const auto omega=residual_oracle::power({7,0,0},(P-1)/256),row_root=residual_oracle::power({7,0,0},(P-1)/8);
    for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<2;++lane) for(unsigned row=0;row<8;++row) {
        const auto point=residual_oracle::mul(residual_oracle::power(omega,first_coset+lane),residual_oracle::power(row_root,row));
        E value{};
        for(unsigned j=0;j<4;++j) value=residual_oracle::add(value,residual_oracle::mul(folded[column*4+j],residual_oracle::power(point,j)));
        for(unsigned j=0;j<3;++j) value=residual_oracle::add(value,residual_oracle::mul(pads[column*3+j],residual_oracle::power(point,4+j)));
        const uint64_t limbs[]={value.c0,value.c1,value.c2};
        for(unsigned component=0;component<3;++component) out[(uint64_t(column*3+component)*2+lane)*8+row]=limbs[component];
    }
    return out;
}
void short_hash_checks() {
    auto* c=create(); const auto original=input(c); const std::vector<E> prefix{{0,0,0},{0,0,0},{7,11,13}};
    const auto packet=lookup(prefix); const auto folded=dense_fold(originals(),prefix);
    std::vector<E> pads(12); for(unsigned i=0;i<12;++i) pads[i]={3+i,5+i,7+i};
    uint64_t end=0; const auto salts=private_salts(c,end);
    const auto frontier=alloc(c,C71_PCS_FRONTIER_PENDING,8*4); assert(!c71_pcs_frontier_begin(c,frontier,8,16));
    uint64_t completed=0,last_roots=0;
    for(unsigned group=0;group<16;++group) {
        const auto before=stats(c);
        const auto token=begin(c,{32,7,4,{}},pcs::Phase::cosets,packet,{8,3,32,2*group,0},pads);
        source(c,token,original); const auto ring=finish(c,token).ring;
        assert(ring && stats(c).d2h_bytes-before.d2h_bytes==4);
        const auto expected=expected_ring(folded,pads,2*group);
        assert(expected_short_ring.empty()); expected_short_ring=expected;
        const auto roots=alloc(c,C71_PCS_HASH_PENDING,8);
        assert(!c71_pcs_short_leaves_private(c,salts,ring,roots,group,0,8,&completed));
        assert(!c71_pcs_short_leaves_private(c,salts,ring,roots,group,8,8,&completed));
        assert(expected_short_ring.empty());
        assert(!c71_pcs_merge_group(c,frontier,roots,group));
        assert(!c71_pcs_residual_retire_ring(c,ring));
        if(group!=15) assert(!c71_range_release(c,roots)); else last_roots=roots;
    }
    uint64_t cursors[8]{},consumed=0; assert(!c71_pcs_salts_complete(c,salts,cursors,8,&consumed));
    assert(completed==end && consumed==end && cursors[7]==end);
    c71_pcs::Hash32 roots[8]; assert(!c71_pcs_read_digests(c,last_roots,0,8,roots));
    assert(!c71_range_release(c,last_roots)); assert(!c71_range_release(c,frontier)); assert(!c71_range_release(c,original)); close(c);
    std::puts("C71_PCS_SHORT_OWNER {\"two_coset_groups\":16,\"private_salts\":1024,\"ring_words_checked\":3072,\"odd_fft_log_rows\":3,\"input_d2h_bytes\":0,\"gpu_execution\":false,\"credit\":false}");
    // Large metadata is rejected by the small arena before cudaMalloc; the
    // new frontier shape reaches arena admission rather than the old cap.
    c=create(); const auto allocations_before=allocations; uint64_t denied=0;
    assert(c71_range_alloc(c,C71_PCS_FRONTIER_PENDING,6*(uint64_t{1}<<23),&denied));
    assert(!denied && allocations==allocations_before && std::strcmp(c71_range_error(c),"range arena exhausted")==0); close(c);
    for(unsigned group:{4u,32u}) {
        c=create(); uint8_t seed[32]{}; uint64_t session=0;
        assert(c71_pcs_salts_begin(c,seed,{uint64_t{1}<<23,0,128,4096},group,8,&session));
        assert(!session && !stats(c).allocations); close(c);
    }
}
void short_hash_failures() {
    const auto packet=lookup({{0,0,0},{1,0,0},{7,11,13}});
    std::vector<E> pads(12); for(unsigned i=0;i<12;++i) pads[i]={3+i,5+i,7+i};
    for(unsigned fault=0;fault<13;++fault) {
        auto* c=create(); const auto original=input(c);
        // Deliberately wrong ring group can be prepared before the stream;
        // once the private stream is live, begin requires exact group binding.
        const auto token=begin(c,{32,7,4,{}},pcs::Phase::cosets,packet,{8,3,32,fault==1?2u:0u,0},pads);
        source(c,token,original); const auto ring=finish(c,token).ring;
        uint64_t end=0; const auto session=private_salts(c,end);
        const auto leaves=alloc(c,fault==2?C71_PCS_BASE:C71_PCS_HASH_PENDING,8);
        uint64_t completed=0xababababababababULL; int status=0;
        switch(fault) {
        case 0: status=c71_pcs_short_leaves_private(c,session,ring,leaves,1,0,8,&completed); break;
        case 1: status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed); break;
        case 2: status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed); break;
        case 3: status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,1,8,&completed); break;
        case 4: status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,16,&completed); break;
        case 5: fail_launch=true; status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed); break;
        case 6: assert(!c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed)); completed=0xababababababababULL; fail_dense=true; status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,8,8,&completed); break;
        case 7: assert(!c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed)); completed=0xababababababababULL; corrupt=true; status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,8,8,&completed); break;
        case 8: assert(!c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed)); completed=0xababababababababULL; fail_free=true; status=c71_pcs_short_leaves_private(c,session,ring,leaves,0,8,8,&completed); break;
        case 9: status=c71_range_release(c,ring); break;
        case 12: {
            assert(!c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed)); completed=0xababababababababULL;
            status=c71_pcs_residual_retire_ring(c,ring); break;
        }
        case 11: {
            assert(!c71_pcs_short_leaves_private(c,session,ring,leaves,0,0,8,&completed)); completed=0xababababababababULL;
            const auto swapped=alloc(c,C71_PCS_HASH_PENDING,8);
            status=c71_pcs_short_leaves_private(c,session,ring,swapped,0,8,8,&completed); break;
        }
        case 10: { uint64_t words=123; const auto before=stats(c).d2h_bytes; status=c71_pcs_read_words(c,ring,0,1,&words); assert(words==123 && stats(c).d2h_bytes==before); break; }
        }
        fail_launch=false; fail_dense=false; corrupt=false; fail_free=false;
        assert(status && stats(c).stopped && completed==0xababababababababULL);
        C71RangeStats final{}; const auto closed=c71_range_close(c,&final); assert((closed!=0)==(fault==8));
    }
    std::puts("C71_PCS_SHORT_OWNER_FAILURE {\"terminal_rejections\":13,\"old_groups_large_rows_rejected\":2,\"gpu_execution\":false,\"credit\":false}");
}
}

namespace residual_query_test {
namespace pcs=c71_pcs_residual;
using E=pcs::E;
struct Level { unsigned degree; uint64_t inverse,modulus,forward,backward; };
std::vector<uint64_t> spectrum(const std::vector<uint64_t>& coefficients,unsigned size) {
    std::vector<uint64_t> values(size);
    const auto root=residual_oracle::power({7,0,0},(P-1)/size).c0;
    for(unsigned i=0;i<size;++i) {
        const auto point=residual_oracle::power({root,0,0},i).c0;
        for(auto it=coefficients.rbegin();it!=coefficients.rend();++it)
            values[i]=residual_oracle::add(residual_oracle::mul(values[i],point),*it);
    }
    return values;
}
uint64_t words(C71RangeContext* c,const std::vector<uint64_t>& values) {
    const auto id=alloc(c,C71_PCS_BASE,values.size());
    assert(!c71_pcs_words_upload(c,id,0,values.data(),values.size())); return id;
}
std::vector<Level> factors(C71RangeContext* c,const std::vector<uint64_t>& points) {
    const unsigned capacity=unsigned(points.size()); std::vector<Level> levels;
    for(unsigned degree=capacity;;degree/=2) {
        std::vector<uint64_t> inverse(2*capacity),modulus(2*capacity);
        for(unsigned task=0;task<capacity/degree;++task) {
            std::vector<uint64_t> polynomial{1};
            for(unsigned j=0;j<degree;++j) {
                std::vector<uint64_t> next(polynomial.size()+1);
                const auto p=points[task*degree+j];
                for(unsigned k=0;k<polynomial.size();++k) {
                    next[k]=residual_oracle::sub(next[k],residual_oracle::mul(polynomial[k],p));
                    next[k+1]=residual_oracle::add(next[k+1],polynomial[k]);
                }
                polynomial.swap(next);
            }
            std::vector<uint64_t> reciprocal(degree); reciprocal[0]=1;
            for(unsigned k=1;k<degree;++k) for(unsigned j=1;j<=k;++j)
                reciprocal[k]=residual_oracle::sub(reciprocal[k],residual_oracle::mul(polynomial[degree-j],reciprocal[k-j]));
            const auto m=spectrum(polynomial,2*degree),i=spectrum(reciprocal,2*degree);
            std::copy(m.begin(),m.end(),modulus.begin()+task*2*degree);
            std::copy(i.begin(),i.end(),inverse.begin()+task*2*degree);
        }
        const auto forward=alloc(c,C71_PCS_POWERS,2*degree),backward=alloc(c,C71_PCS_POWERS,2*degree);
        unsigned log=0;while((1u<<log)<2*degree)++log;
        assert(!c71_pcs_transform_twiddles(c,forward,log,0));assert(!c71_pcs_transform_twiddles(c,backward,log,1));
        levels.push_back({degree,words(c,inverse),words(c,modulus),forward,backward});
        if(degree==1)break;
    }
    return levels;
}
void release_factors(C71RangeContext* c,const std::vector<Level>& levels) {
    for(const auto& level:levels) for(auto id:{level.inverse,level.modulus,level.forward,level.backward}) assert(!c71_range_release(c,id));
}
struct Work { uint64_t current[3]{},spare=0,work=0,scratch=0; };
Work workspace(C71RangeContext* c,unsigned capacity) {
    Work w{};for(auto& id:w.current)id=alloc(c,C71_PCS_BASE,capacity);
    w.spare=alloc(c,C71_PCS_BASE,capacity);w.work=alloc(c,C71_PCS_BASE,2*capacity);w.scratch=alloc(c,C71_PCS_BASE,2*capacity);return w;
}
void release_work(C71RangeContext* c,Work w) {
    for(auto id:{w.current[0],w.current[1],w.current[2],w.spare,w.work,w.scratch})assert(!c71_range_release(c,id));
}
uint64_t query_begin(C71RangeContext* c,pcs::Shape shape,const residual_test::Lookup& packet,
    const std::vector<E>& pads,unsigned capacity,unsigned column) {
    uint64_t token=0;shape.equality=packet.shape;
    assert(!c71_pcs_residual_query_begin(c,shape,packet.chunks.data(),packet.tables.data(),pads.data(),unsigned(pads.size()),capacity,column,&token));
    assert(token);return token;
}
c71_pcs::QueryBlock block(unsigned remaining,unsigned pad_rows,unsigned column,uint64_t first) {
    const uint64_t n=uint64_t{1}<<(remaining-2);
    return {first,n+pad_rows,n,n,uint64_t(column)*n,0,uint64_t(column)*pad_rows,pad_rows,0};
}
void roots(C71RangeContext* c,uint64_t token,const std::vector<Level>& levels,Work& work,bool first) {
    // Deliberately permute the three limbs. Each block still consumes all three.
    const auto& root=levels.front();
    for(unsigned limb:{2u,0u,1u}) {
        assert(!c71_pcs_residual_query_root(c,token,limb,first?0:work.current[limb],root.inverse,root.modulus,
            root.forward,root.backward,work.work,work.scratch,work.spare));
        std::swap(work.current[limb],work.spare);
    }
}
void children(C71RangeContext* c,const std::vector<Level>& levels,Work& work) {
    for(size_t level=1;level<levels.size();++level)for(unsigned limb:{1u,2u,0u}) {
        const auto& factor=levels[level];
        assert(!c71_pcs_query_remainder(c,work.current[limb],work.current[limb],factor.inverse,factor.modulus,
            factor.forward,factor.backward,work.work,work.scratch,work.spare,factor.degree,1));
        std::swap(work.current[limb],work.spare);
    }
}
E horner(const std::vector<E>& values,const std::vector<E>& pads,unsigned column,uint64_t point) {
    const size_t n=values.size()/4,pad_rows=pads.size()/4;E result{};
    for(size_t j=pad_rows;j-->0;)result=residual_oracle::add(residual_oracle::mul(result,{point,0,0}),pads[column*pad_rows+j]);
    for(size_t j=n;j-->0;)result=residual_oracle::add(residual_oracle::mul(result,{point,0,0}),values[column*n+j]);
    return result;
}
void positive() {
    auto* c=create();const int16_t original_weights[]={0,1,-1,32767,-32767,2,-2,3,4,-4,7,-7,11,-11,13,-13,
        17,-17,19,-19,23,-23,29,-29,31,-31,37,-37,41,-41,43,-43};
    assert(!c71_dense_weights_begin(c,32));assert(!c71_dense_weights_upload(c,0,original_weights,32));assert(!c71_dense_weights_seal(c));
    const auto tiles=alloc(c,C71_PCS_WEIGHT_TILES,2);const c71_pcs::WeightTile mapping[]={{0,16,0,4,2},{16,16,2,4,2}};
    assert(!c71_pcs_tiles_upload(c,tiles,mapping,2));
    std::vector<E> original(128);
    for(unsigned i=0;i<32;++i) { const unsigned address=i<16?i/2*4+i%2:(i-16)/2*4+2+(i-16)%2;
        const int32_t value=original_weights[address];original[i]={value<0?P-uint64_t(-value):uint64_t(value),0,0}; }
    const std::vector<E> prefix{{0,0,0},{0,0,0},{7,11,13}};const auto packet=residual_test::lookup(prefix);
    const auto weight_values=residual_test::dense_fold(original,prefix);
    const auto input=residual_test::input(c);auto token=residual_test::begin(c,{32,7,4,{}},pcs::Phase::retention,packet);
    residual_test::source(c,token,input);const auto retained=residual_test::finish(c,token).planes;
    const auto retained_values=residual_test::dense_fold(residual_test::originals(),prefix);
    std::vector<E> pads(12);for(unsigned i=0;i<pads.size();++i)pads[i]=i%3==0?E{}:i%3==1?E{1,0,0}:E{5+i,7+i,11+i};
    unsigned cases=0;uint64_t visits=0,rows=0,blocks=0;
    for(unsigned capacity:{1u,2u,4u,8u,16u}) {
        const unsigned count=capacity>2?capacity-1:capacity;
        const auto domain_root=residual_oracle::power({7,0,0},(P-1)/256).c0;std::vector<uint64_t> points(capacity);
        for(unsigned i=0;i<count;++i)points[i]=residual_oracle::power({domain_root,0,0},i==2?3:3*i).c0;
        const auto levels=factors(c,points);auto work=workspace(c,capacity);
        for(unsigned view=0;view<4;++view) {
            const std::vector<E> suffix=view==2?std::vector<E>{{1,0,0}}:view==3?std::vector<E>{{0,1,0},{0,0,1}}:std::vector<E>{};
            const auto p=view==0?packet:residual_test::lookup(suffix);
            const pcs::Shape shape=view==0?pcs::Shape{32,7,4,p.shape}:pcs::Shape{16,4,unsigned(4-suffix.size()),p.shape};
            const auto values=view==0?weight_values:residual_test::dense_fold(retained_values,suffix);
            const uint64_t read_before=view==0?query_original_reads:query_resident_reads;
            for(unsigned column=0;column<4;++column) {
                const auto before=stats(c);token=query_begin(c,shape,p,pads,capacity,column);
                const uint64_t source_rows=values.size()/4+3;bool first=true;
                for(uint64_t b=(source_rows+capacity-1)/capacity;b-->0;) {
                    const auto geometry=block(shape.remaining,3,column,b*capacity);
                    assert(!(view==0?c71_pcs_residual_query_weights(c,token,tiles,geometry):c71_pcs_residual_query_resident(c,token,retained,geometry)));
                    roots(c,token,levels,work,first);first=false;++blocks;
                }
                children(c,levels,work);
                assert(stats(c).d2h_bytes==before.d2h_bytes && stats(c).fences==before.fences+1);
                std::vector<uint64_t> actual(3*count,0x12345678);
                assert(!c71_pcs_residual_query_finish(c,token,work.current,count,actual.data()));
                for(unsigned row=0;row<count;++row) {
                    const auto expected=horner(values,pads,column,points[row]);
                    assert(actual[row]==expected.c0 && actual[count+row]==expected.c1 && actual[2*count+row]==expected.c2);
                }
                assert(stats(c).d2h_bytes-before.d2h_bytes==24*count+4 && stats(c).fences-before.fences==2);
                assert(stats(c).arena_bytes==before.arena_bytes && stats(c).host_owner_bytes==before.host_owner_bytes);
                ++cases;rows+=count;
            }
            const uint64_t read_after=view==0?query_original_reads:query_resident_reads;
            assert(read_after-read_before==(view==0?32:16));visits+=read_after-read_before;
        }
        release_work(c,work);release_factors(c,levels);
    }
    assert(!c71_pcs_residual_retire_planes(c,retained));assert(!c71_range_release(c,input));assert(!c71_range_release(c,tiles));close(c);
    std::printf("C71_PCS_QUERY_E_OWNER {\"column_cases\":%u,\"query_rows\":%llu,\"original_or_plane_visits\":%llu,\"root_blocks\":%llu,\"private_limb_loads\":3,\"fences_per_column\":2,\"input_d2h_bytes\":0,\"W_scans_per_batch\":1,\"gpu_execution\":false,\"credit\":false}\n",
        cases,(unsigned long long)rows,(unsigned long long)visits,(unsigned long long)blocks);
}
}

namespace residual_query_test {
void drive(C71RangeContext* c,uint64_t token,C71PcsResidualPlanes retained,const std::vector<Level>& levels,Work& w,bool descend=true) {
    const unsigned capacity=levels.front().degree;bool first=true;
    for(uint64_t b=(7+capacity-1)/capacity;b-->0;) {
        assert(!c71_pcs_residual_query_resident(c,token,retained,block(4,3,0,b*capacity)));
        roots(c,token,levels,w,first);first=false;
    }
    if(descend)children(c,levels,w);
}
void negative() {
    constexpr unsigned capacity=2;
    const auto empty=residual_test::lookup({});
    const auto prefix=residual_test::lookup({{0,0,0},{0,0,0},{7,11,13}});
    const std::vector<E> pads{{0,0,0},{1,0,0},{3,5,7},{11,13,17},{19,23,29},{31,37,41},
        {43,47,53},{59,61,67},{71,73,79},{83,89,97},{101,103,107},{109,113,127}};
    for(unsigned fault=0;fault<56;++fault) {
        auto* c=create();const auto original=residual_test::input(c);
        const auto initial=residual_test::begin(c,{32,7,4,{}},pcs::Phase::retention,prefix);
        residual_test::source(c,initial,original);const auto retained=residual_test::finish(c,initial).planes;
        const std::vector<uint64_t> points{1,7};const auto levels=factors(c,points);auto w=workspace(c,capacity);
        uint64_t token=0;std::vector<uint64_t> output(6,0x12345678);int status=0;
        const pcs::Shape shape{16,4,4,empty.shape};
        const bool begin_fault=fault<=7 || fault==44 || (fault>=47 && fault<=50);
        if(begin_fault) {
            auto badshape=shape;auto badpads=pads;auto badpacket=empty;uint32_t cap=capacity,column=0;
            uint64_t* token_pointer=&token;
            if(fault==0)badshape.remaining=1;
            if(fault==1)badshape.dimension=36;
            if(fault==2)badpads[3].c2=P;
            if(fault==3) { badpacket=residual_test::lookup({{0,1,0}});badshape.remaining=3;
                badshape.equality=badpacket.shape;badpacket.chunks[0].reserved=1; }
            if(fault==4)cap=3;
            if(fault==5)column=4;
            if(fault==6)token_pointer=nullptr;
            if(fault==7)badshape.equality.reserved=1;
            if(fault==44)cap=1u<<21;
            if(fault==47)token_pointer=reinterpret_cast<uint64_t*>(badpads.data());
            if(fault==48)upload_fail_after=1;
            if(fault==49)fail_fence=true;
            if(fault==50)cap=1u<<20; // reject the complete 24 MiB phase before allocation
            const auto allocations_before=allocations;
            status=c71_pcs_residual_query_begin(c,badshape,badpacket.chunks.data(),badpacket.tables.data(),badpads.data(),
                unsigned(badpads.size()),cap,column,token_pointer);
            if(fault==50)assert(allocations==allocations_before);
            if(token_pointer==&token)assert(!token);
            upload_fail_after=-1;fail_fence=false;
        } else {
            token=query_begin(c,shape,empty,pads,capacity,0);
            auto geometry=block(4,3,0,6);const auto& root=levels.front();
            const auto root_call=[&](unsigned limb,uint64_t high,uint64_t out,uint64_t forward,uint64_t backward,uint64_t work) {
                return c71_pcs_residual_query_root(c,token,limb,high,root.inverse,root.modulus,forward,backward,work,w.scratch,out);
            };
            switch(fault) {
            case 8: status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());break;
            case 9: status=c71_pcs_residual_query_resident(c,token+1,retained,geometry);break;
            case 10: geometry.first=4;status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 11: geometry.byte_first=4;status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 12: geometry.window_first=1;status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 13: geometry.pad_only=1;status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 14: geometry.source_rows=6;status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 15: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));status=c71_pcs_residual_query_resident(c,token,retained,geometry);break;
            case 16: status=c71_pcs_residual_query_weights(c,token,original,geometry);break;
            case 17: { auto bad=retained;bad.c1=bad.c0;status=c71_pcs_residual_query_resident(c,token,bad,geometry);break; }
            case 18: status=c71_pcs_residual_retire_planes(c,retained);break;
            case 19: { const auto before=stats(c);status=c71_pcs_read_words(c,levels[0].modulus,0,1,output.data());assert(stats(c).d2h_bytes==before.d2h_bytes);break; }
            case 20: { const auto before=stats(c);status=c71_original_read(c,original,C71_I16,0,1,output.data());assert(stats(c).d2h_bytes==before.d2h_bytes);break; }
            case 21: status=c71_range_release(c,w.work);break;
            case 22: { const uint64_t word=1;status=c71_pcs_words_upload(c,levels[0].modulus,0,&word,1);break; }
            case 23: { uint64_t other=0;status=c71_linear_begin(c,{},nullptr,nullptr,0,nullptr,nullptr,nullptr,&other);break; }
            case 24: { uint64_t other=0;status=c71_pcs_residual_begin(c,shape,pcs::Phase::retention,nullptr,nullptr,{},nullptr,0,{},&other);break; }
            case 25: { uint8_t seed[32]{};uint64_t other=0;status=c71_pcs_salts_begin(c,seed,{8,0,32,32},2,64,&other);break; }
            case 26: status=root_call(0,0,w.spare,root.forward,root.backward,w.work);break;
            case 27: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));status=root_call(3,0,w.spare,root.forward,root.backward,w.work);break;
            case 28: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));status=root_call(0,w.current[0],w.spare,root.forward,root.backward,w.work);break;
            case 29: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));assert(!root_call(0,0,w.spare,root.forward,root.backward,w.work));
                std::swap(w.current[0],w.spare);status=root_call(0,0,w.spare,root.forward,root.backward,w.work);break;
            case 30: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));assert(!root_call(0,0,w.spare,root.forward,root.backward,w.work));
                std::swap(w.current[0],w.spare);status=root_call(1,0,w.current[0],root.forward,root.backward,w.work);break;
            case 31: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));status=root_call(0,0,w.spare,root.backward,root.forward,w.work);break;
            case 32: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));status=root_call(0,0,w.spare,root.forward,root.backward,w.current[2]);break;
            case 33: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));copy_fail_after=0;status=root_call(0,0,w.spare,root.forward,root.backward,w.work);copy_fail_after=-1;break;
            case 34: fail_launch=true;status=c71_pcs_residual_query_resident(c,token,retained,geometry);fail_launch=false;break;
            case 35: assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));roots(c,token,levels,w,true);
                geometry.first=4;assert(!c71_pcs_residual_query_resident(c,token,retained,geometry));fail_launch=true;
                status=root_call(0,w.current[0],w.spare,root.forward,root.backward,w.work);fail_launch=false;break;
            case 36: drive(c,token,retained,levels,w);fail_dense=true;status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());fail_dense=false;break;
            case 37: case 38: case 39: drive(c,token,retained,levels,w);download_fail_after=fault==37?0:fault==38?1:3;
                status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());download_fail_after=-1;break;
            case 40: drive(c,token,retained,levels,w);fail_fence=true;status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());fail_fence=false;break;
            case 41: drive(c,token,retained,levels,w);corrupt=true;status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());corrupt=false;break;
            case 42: drive(c,token,retained,levels,w);fail_free=true;status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());fail_free=false;break;
            case 43: { drive(c,token,retained,levels,w);uint64_t ids[]={w.spare,w.current[1],w.current[2]};status=c71_pcs_residual_query_finish(c,token,ids,2,output.data());break; }
            case 45: drive(c,token,retained,levels,w);status=c71_pcs_residual_query_finish(c,token,w.current,3,output.data());break;
            case 46: { drive(c,token,retained,levels,w);const auto ids=std::vector<uint64_t>(w.current,w.current+3);
                status=c71_pcs_residual_query_finish(c,token,w.current,2,w.current);assert(std::equal(ids.begin(),ids.end(),w.current));break; }
            case 51: { auto* other=create();const auto other_original=residual_test::input(other);
                const auto other_token=residual_test::begin(other,{32,7,4,{}},pcs::Phase::retention,prefix);residual_test::source(other,other_token,other_original);
                const auto foreign=residual_test::finish(other,other_token).planes;status=c71_pcs_residual_query_resident(c,token,foreign,geometry);close(other);break; }
            case 52: drive(c,token,retained,levels,w,false);status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());break;
            case 53: { auto swapped=retained;std::swap(swapped.c1,swapped.c2);
                status=c71_pcs_residual_query_resident(c,token,swapped,geometry);break; }
            case 54: drive(c,token,retained,levels,w);status=c71_pcs_transform(c,w.current[0],w.spare,levels.back().forward,1,1,0);break;
            case 55: drive(c,token,retained,levels,w);corrupt_query_data=true;
                status=c71_pcs_residual_query_finish(c,token,w.current,2,output.data());corrupt_query_data=false;break;
            default: assert(false);
            }
        }
        assert(status && stats(c).stopped && *c71_range_error(c));
        for(auto word:output)assert(word==0x12345678);
        C71RangeStats final{};const auto closed=c71_range_close(c,&final);
        if(fault==42)assert(closed && final.cleanup_failed && final.arena_bytes==256);
        else assert(!closed && !final.cleanup_failed && !final.arena_bytes && !final.weights_bytes);
    }
    std::puts("C71_PCS_QUERY_E_FAILURE {\"terminal_rejections\":56,\"forbidden_read_d2h_bytes\":0,\"publication_after_free\":true,\"root_columns_are_not_queries\":true,\"gpu_execution\":false,\"credit\":false}");
}
}

namespace residual_query_test {
void weight_launch_failures() {
    for(unsigned failed_launch=0;failed_launch<2;++failed_launch) {
        auto* c=create();const int16_t weights[]={1,-1,2,-2,3,-3,4,-4,5,-5,6,-6,7,-7,8,-8};
        assert(!c71_dense_weights_begin(c,16));assert(!c71_dense_weights_upload(c,0,weights,16));assert(!c71_dense_weights_seal(c));
        const auto tiles=alloc(c,C71_PCS_WEIGHT_TILES,1);const c71_pcs::WeightTile mapping{0,16,0,4,4};
        assert(!c71_pcs_tiles_upload(c,tiles,&mapping,1));
        const auto packet=residual_test::lookup({{0,0,0},{0,0,0},{7,11,13}});
        std::vector<E> pads(12,E{3,5,7});const auto levels=factors(c,{1,7});auto w=workspace(c,2);
        const auto token=query_begin(c,{16,7,4,packet.shape},packet,pads,2,0);
        for(unsigned first:{6u,4u}) {
            const auto before=stats(c);assert(!c71_pcs_residual_query_weights(c,token,tiles,block(4,3,0,first)));
            assert(stats(c).launches-before.launches==1); // private pad block only
            roots(c,token,levels,w,first==6);
        }
        const auto before=stats(c);const auto global_launches=launches;
        query_weight_fail_after=int(failed_launch);
        const int status=c71_pcs_residual_query_weights(c,token,tiles,block(4,3,0,2));
        query_weight_fail_after=-1;
        assert(status && stats(c).stopped && stats(c).launches-before.launches==failed_launch+1);
        assert(launches-global_launches==failed_launch+1 && stats(c).d2h_bytes==before.d2h_bytes);
        uint64_t untouched[6];std::fill(untouched,untouched+6,uint64_t{0x12345678});
        assert(c71_pcs_residual_query_finish(c,token,w.current,2,untouched));
        for(auto word:untouched)assert(word==0x12345678);
        close(c); // drains an accepted init before releasing its private low
    }
    std::puts("C71_PCS_QUERY_E_WEIGHT_FAILURE {\"terminal_rejections\":2,\"pad_only_launches\":1,\"real_work_launches\":2,\"accepted_init_drained\":true,\"gpu_execution\":false,\"credit\":false}");
}
void trusted_source_partition_checks() {
    namespace pcs=c71_pcs_residual;
    const auto packet=residual_test::lookup({{0,0,0},{0,0,0},{7,11,13}});
    auto* c=create();const auto original=residual_test::input(c);
    auto token=residual_test::begin(c,{32,7,4,{}},pcs::Phase::retention,packet);
    bool covered[32]{}; // Reduced independent partition oracle, never a runtime A bitmap.
    for(unsigned first:{8u,24u,0u,16u}) {
        for(unsigned i=first;i<first+8;++i) { assert(!covered[i]);covered[i]=true; }
        assert(!c71_pcs_residual_source_tile(c,token,original,{first/2,1,4,1,first,0,2,2}));
    }
    for(bool visited:covered)assert(visited);
    const auto retained=residual_test::finish(c,token).planes;
    residual_test::read_copy(c,retained,residual_test::dense_fold(residual_test::originals(),{{0,0,0},{0,0,0},{7,11,13}}));
    assert(!c71_pcs_residual_retire_planes(c,retained));close(c);
    // NativeSource's canonical producer checks duplicate/omitted original rows;
    // Bytes::resident_original_tiles preserves its disjoint dyadic byte partition.
    // The standalone C byte-count boundary does not attest uniqueness.
    std::puts("C71_PCS_TRUSTED_SOURCE_PARTITION {\"reversed_ragged_cases\":1,\"trusted_row_coverage\":true,\"standalone_byte_count_proves_uniqueness\":false,\"gpu_execution\":false,\"credit\":false}");
}

}


namespace initial_weight_query_test {
using residual_query_test::words;
using residual_query_test::factors;
using residual_query_test::workspace;
using residual_query_test::release_work;
using residual_query_test::release_factors;
uint64_t field(int16_t value) {
    const int32_t signed_value=value;
    return signed_value<0 ? P-uint64_t(-signed_value) : uint64_t(signed_value);
}
uint64_t horner(const std::vector<uint64_t>& original,const std::vector<uint64_t>& pads,
    unsigned n,unsigned column,unsigned pad_rows,uint64_t point) {
    uint64_t value=0;
    for(unsigned row=pad_rows;row-->0;)
        value=residual_oracle::add(residual_oracle::mul(value,point),pads[column*pad_rows+row]);
    for(unsigned row=n;row-->0;) {
        const uint64_t index=uint64_t(column)*n+row;
        value=residual_oracle::add(residual_oracle::mul(value,point),index<original.size()?original[index]:0);
    }
    return value;
}
void positive() {
    auto* c=create();
    const int16_t weights[]={0,1,-1,32767,-32767,2,-2,3,4,-4,7,-7,11,-11,13,-13,
        17,-17,19,-19,23,-23,29,-29,31,-31,37,-37,41,-41,43,-43};
    assert(!c71_dense_weights_begin(c,32));assert(!c71_dense_weights_upload(c,0,weights,32));assert(!c71_dense_weights_seal(c));
    const auto tiles=alloc(c,C71_PCS_WEIGHT_TILES,2);
    const c71_pcs::WeightTile mapping[]={{0,16,0,4,2},{16,16,2,4,2}};
    assert(!c71_pcs_tiles_upload(c,tiles,mapping,2));
    std::vector<uint64_t> original(32),pads(8*3);
    // Independent public tile decoding, rather than the production binary search.
    for(unsigned i=0;i<32;++i)original[i]=field(weights[i<16?i/2*4+i%2:(i-16)/2*4+2+(i-16)%2]);
    for(unsigned i=0;i<pads.size();++i)pads[i]=i%4==0?0:i%4==1?1:i%4==2?P-1:17+i;
    const auto pad_id=words(c,pads);
    unsigned cases=0;uint64_t rows=0,blocks=0,visits=0;
    for(unsigned capacity:{1u,2u,4u,8u,16u}) {
        const unsigned count=capacity>2?capacity-1:capacity;
        std::vector<uint64_t> points(capacity);
        for(unsigned i=0;i<count;++i)points[i]=i%4==0?0:i%4==1?1:i%4==2?P-1:7;
        const auto levels=factors(c,points);auto w=workspace(c,capacity);
        const auto zero=words(c,std::vector<uint64_t>(capacity));
        for(unsigned n:{4u,8u,16u,64u}) {
            const auto first_visit=initial_query_weight_reads;
            for(unsigned column=0;column<8;++column) {
                const auto before=stats(c);bool first=true;
                const uint64_t left=32>uint64_t(column)*n?32-uint64_t(column)*n:0;
                const uint64_t active=std::min(left,uint64_t(n));
                for(uint64_t b=(n+3+capacity-1)/capacity;b-->0;) {
                    const c71_pcs::QueryBlock geometry{b*capacity,n+3,n,active,uint64_t(column)*n,0,uint64_t(column)*3,3,0};
                    assert(!c71_pcs_query_weight_low(c,tiles,pad_id,w.current[1],geometry));
                    const auto& root=levels.front();
                    assert(!c71_pcs_query_remainder(c,first?zero:w.current[0],w.current[1],root.inverse,root.modulus,
                        root.forward,root.backward,w.work,w.scratch,w.spare,capacity,0));
                    std::swap(w.current[0],w.spare);first=false;++blocks;
                }
                for(size_t level=1;level<levels.size();++level) {
                    const auto& f=levels[level];
                    assert(!c71_pcs_query_remainder(c,w.current[0],w.current[0],f.inverse,f.modulus,
                        f.forward,f.backward,w.work,w.scratch,w.spare,f.degree,1));
                    std::swap(w.current[0],w.spare);
                }
                const auto queued=stats(c);
                assert(queued.fences==before.fences && queued.d2h_bytes==before.d2h_bytes && queued.h2d_bytes==before.h2d_bytes);
                assert(queued.arena_bytes==before.arena_bytes && queued.host_owner_bytes==before.host_owner_bytes);
                std::vector<uint64_t> actual(count,0x12345678);
                assert(!c71_pcs_read_words(c,w.current[0],0,count,actual.data()));
                for(unsigned i=0;i<count;++i)assert(actual[i]==horner(original,pads,n,column,3,points[i]));
                assert(stats(c).fences-before.fences==1 && stats(c).d2h_bytes-before.d2h_bytes==8*count);
                ++cases;rows+=count;
            }
            assert(initial_query_weight_reads-first_visit==32);visits+=32;
        }
        assert(!c71_range_release(c,zero));release_work(c,w);release_factors(c,levels);
    }
    // Full D35 public domain geometry is checked without allocating or looping
    // over that domain: only its last pad block and a public zero column.
    const auto low=alloc(c,C71_PCS_BASE,8);const auto before=stats(c);const auto reads=initial_query_weight_reads;
    const uint64_t n=uint64_t{1}<<28;
    assert(!c71_pcs_query_weight_low(c,tiles,pad_id,low,{n,n+3,n,32,0,0,0,3,0}));
    uint64_t output[8]{};assert(!c71_pcs_read_words(c,low,0,8,output));
    for(unsigned i=0;i<8;++i)assert(output[i]==(i<3?pads[i]:0));
    assert(!c71_pcs_query_weight_low(c,tiles,pad_id,low,{0,n+3,n,0,7*n,0,21,3,0}));
    assert(!c71_pcs_read_words(c,low,0,8,output));for(auto value:output)assert(!value);
    assert(!c71_pcs_query_weight_low(c,tiles,pad_id,low,{0,3,n,0,0,0,0,3,1}));
    assert(!c71_pcs_read_words(c,low,0,8,output));
    for(unsigned i=0;i<8;++i)assert(output[i]==(i<3?pads[i]:0));
    assert(initial_query_weight_reads==reads && stats(c).h2d_bytes==before.h2d_bytes);
    // Existing byte/None-zero loader remains a distinct legal initializer.
    assert(!c71_pcs_query_low(c,0,pad_id,low,{0,0,4,0,0,0,0,3,0}));
    assert(!c71_pcs_read_words(c,low,0,8,output));for(auto value:output)assert(!value);
    assert(!c71_range_release(c,low));assert(!c71_range_release(c,pad_id));assert(!c71_range_release(c,tiles));close(c);
    std::printf("C71_PCS_QUERY_W_INITIAL_OWNER {\"column_cases\":%u,\"query_rows\":%llu,\"root_blocks\":%llu,\"original_visits\":%llu,\"W_scans_per_batch\":1,\"loader_launches_per_block\":1,\"loader_extra_temp_bytes\":0,\"block_input_transfer_bytes\":0,\"fences_per_column\":1,\"D35_sparse_geometry\":true,\"None_zero_unchanged\":true,\"gpu_execution\":false,\"credit\":false}\n",
        cases,(unsigned long long)rows,(unsigned long long)blocks,(unsigned long long)visits);
}
void negative() {
    constexpr unsigned faults=33;
    for(unsigned fault=0;fault<faults;++fault) {
        auto* c=create();uint64_t tiles=alloc(c,C71_PCS_WEIGHT_TILES,1);
        const int16_t weights[]={0,1,-1,32767,-32767,2,-2,3};
        if(fault!=0 && fault!=32) {
            assert(!c71_dense_weights_begin(c,8));assert(!c71_dense_weights_upload(c,0,weights,8));
            if(fault!=1) {
                assert(!c71_dense_weights_seal(c));const c71_pcs::WeightTile mapping{0,8,0,2,2};
                assert(!c71_pcs_tiles_upload(c,tiles,&mapping,1));
            }
        }
        uint64_t pads=words(c,{0,1,P-1,3,5,7,11,13,17,19,23,29});
        uint64_t low=alloc(c,C71_PCS_BASE,2);
        c71_pcs::QueryBlock geometry{0,7,4,4,0,0,0,3,0};
        switch(fault) {
        case 2: tiles=words(c,{0,1});break;
        case 3: tiles=alloc(c,C71_PCS_WEIGHT_TILES,1);break;
        case 4: assert(!c71_range_release(c,tiles));break;
        case 5: { auto* other=create();tiles=alloc(other,C71_PCS_WEIGHT_TILES,1);close(other);break; }
        case 6: pads=alloc(c,C71_U8,12);break;
        case 7: pads=alloc(c,C71_PCS_BASE,12);break;
        case 8: pads=words(c,{0,1});low=pads;break;
        case 9: low=alloc(c,C71_U8,2);break;
        case 10: low=alloc(c,C71_PCS_BASE,3);break;
        case 11: geometry.message_rows=0;break;
        case 12: geometry.message_rows=3;break;
        case 13: geometry.message_rows=uint64_t{1}<<29;break;
        case 14: geometry.active=5;break;
        case 15: geometry.active=0;break;
        case 16: geometry.window_first=1;break;
        case 17: geometry.byte_first=1;break;
        case 18: geometry.byte_first=128*4;geometry.active=0;geometry.pad_first=128*3;break;
        case 19: geometry.pad_first=1;break;
        case 20: geometry.pad_rows=0;break;
        case 21: geometry.pad_rows=1537;break;
        case 22: pads=words(c,{0,1});break;
        case 23: geometry.source_rows=5;break;
        case 24: geometry.pad_only=2;break;
        case 25: geometry.pad_only=1;geometry.source_rows=3;break;
        case 26: geometry.pad_only=1;geometry.active=0;geometry.source_rows=4;break;
        case 27: geometry.first=1;break;
        case 28: geometry.first=8;break;
        case 29: {
            const auto packet=residual_test::lookup({{0,0,0},{0,0,0},{7,11,13}});
            const std::vector<c71_pcs_residual::E> extension_pads(12,{3,5,7});
            (void)residual_query_test::query_begin(c,{8,7,4,packet.shape},packet,extension_pads,2,0);break;
        }
        default:break;
        }
        if(fault==32)assert(!c71_dense_weights_begin(c,8));
        const auto before=stats(c);const auto calls=launches;int status=0;
        if(fault==30)fail_launch=true;
        if(fault==31) { const auto bad=alloc(c,C71_PCS_BASE,1);const uint64_t noncanonical=P;status=c71_pcs_words_upload(c,bad,0,&noncanonical,1); }
        else if(fault==32) { const int16_t marker=INT16_MIN;status=c71_dense_weights_upload(c,0,&marker,1); }
        else status=c71_pcs_query_weight_low(c,tiles,pads,low,geometry);
        fail_launch=false;
        assert(status && stats(c).stopped && *c71_range_error(c));
        const unsigned attempted=fault==30?1:0;
        assert(stats(c).launches-before.launches==attempted && launches-calls==attempted);
        assert(stats(c).d2h_bytes==before.d2h_bytes && stats(c).h2d_bytes==before.h2d_bytes);
        assert(c71_pcs_query_weight_low(c,tiles,pads,low,geometry));
        assert(launches-calls==attempted);close(c);
    }
    // GPU unavailability is terminal; no fake host computation is selected.
    C71RangeContext* unavailable=nullptr;assert(c71_range_create(1,262144,256,nullptr,&unavailable) && unavailable);
    assert(c71_pcs_query_weight_low(unavailable,0,0,0,{}));
    C71RangeStats final{};assert(c71_range_close(unavailable,&final) && final.cleanup_failed && !final.arena_bytes);
    std::printf("C71_PCS_QUERY_W_INITIAL_FAILURE {\"terminal_rejections\":%u,\"input_d2h_bytes\":0,\"unavailable_GPU_fail_closed\":true,\"gpu_execution\":false,\"credit\":false}\n",faults+1);
}
}

int main() {
    // Original P3 66e2906 Goldilocks generator, including canonical 2^32.
    uint64_t two_adic_root=0x185629dcda58878cULL;
    for(int bits=32;bits>=0;--bits) {
        assert(c71_pcs::power(7,(P-1)/(uint64_t{1}<<bits))==two_adic_root);
        two_adic_root=fp_mul(two_adic_root,two_adic_root);
    }
    // Independent signed i128 modulo reference, including every prefix and
    // the 256-product bound used by the resident W kernel.
    uint64_t random=0x53c71a28b79d024fULL;
    for(unsigned test=0;test<2056;++test) {
        c71_pcs::SignedWide dot{};
        __int128 exact=0;
        for(unsigned k=0;k<256;++k) {
            random^=random<<13; random^=random>>7; random^=random<<17;
            int16_t weight=int16_t(int(random%65535)-32767);
            uint64_t factor=random>=P ? random-P : random;
            if(test<8) {
                const int16_t edges[]={-32767,32767,0,1,-1,32767,-32767,1};
                weight=edges[test];
                factor=(test==0 || test==1) ? P-1 : (k%3 ? P-1 : 0);
                if(test>=5 && k%2) weight=int16_t(-weight);
            }
            dot.add(weight,factor);
            exact+=__int128(weight)*factor;
            __int128 residue=exact%__int128(P);
            if(residue<0) residue+=P;
            assert(dot.residue()==uint64_t(residue));
        }
    }
    C71RangeContext* c=nullptr;
    assert(c71_range_runtime_abi()==4);
    assert(c71_range_create(0,6442451200ULL,256,nullptr,&c) && !c && !allocations);
    assert(c71_range_create(0,512,512,nullptr,&c) && !c && !allocations);
    assert(c71_range_create(1,512,256,nullptr,&c) && c);
    C71RangeStats final{}; assert(c71_range_close(c,&final) && final.cleanup_failed);
    for(stack_fault=1;stack_fault<=3;++stack_fault) {
        c=nullptr; const auto launched_before=launches, allocated_before=allocations;
        assert(c71_range_create(0,262144,256,nullptr,&c) && c && stats(c).stopped);
        uint64_t id=0;
        assert(c71_range_alloc(c,C71_U8,1,&id) && !id);
        assert(launches==launched_before && allocations==allocated_before);
        assert(!c71_range_close(c,&final) && !final.arena_bytes && !final.cleanup_failed);
    }
    stack_fault=0;
    std::puts("C71_RUNTIME_STACK_LIMIT {\"requested_bytes\":256,\"terminal_rejections\":3,\"gpu_execution\":false,\"credit\":false}");
    c=create(); const auto a=roots(c); const auto root=alloc(c,C71_PAIR,1024);
    assert(!c71_range_runtime_canopy(c,a,root));
    assert(!c71_range_as_children(c,a));
    const auto before=stats(c);
    Round r{}; r.bits=10;
    Cubic result{}; assert(!c71_range_runtime_coefficients(c,a,&r,&result));
    auto after=stats(c);
    assert(after.live_capacity_bytes==before.live_capacity_bytes && after.allocations==before.allocations+2);
    assert(after.peak_capacity_bytes>=before.live_capacity_bytes+512 && after.d2h_bytes==96);
    for(unsigned i=0;i<10;++i) assert(!c71_range_runtime_child_fold(c,a,{0,1,0}));
    after=stats(c); assert(after.live_capacity_bytes==before.live_capacity_bytes && after.logical_bytes<before.logical_bytes);
    uint64_t limbs[12]; assert(!c71_range_read(c,a,limbs,12));
    assert(!c71_range_release(c,a) && !c71_range_release(c,root));
    after=stats(c); assert(!after.live_capacity_bytes && !after.arena_bytes && frees);
    close(c); assert(allocations==frees);

    // Both source types, append coverage, H and retention, scalar root fencing.
    for(unsigned kind=0;kind<2;++kind) {
        c=create(); const auto input=alloc(c,kind,8); int16_t values[8]{};
        assert(!c71_range_upload(c,input,values,8*(kind+1)));
        const auto pairs=alloc(c,C71_PAIR,2), scalar=alloc(c,C71_PAIR,1);
        assert(!c71_range_roots(c,input,3,{1,0,0},pairs,0));
        assert(!c71_range_roots(c,input,3,{1,0,0},pairs,1));
        assert(!c71_range_runtime_canopy(c,pairs,scalar)); assert(!c71_range_read(c,scalar,limbs,6));
        Group g{}; g.bottom=1; g.width=1; g.tail_bits=1; g.buckets=2;
        const auto buckets=alloc(c,C71_GRAM,8), h=alloc(c,C71_GRAM,4), small=alloc(c,C71_GRAM,1);
        assert(!c71_range_zero(c,buckets)); assert(!c71_range_groups(c,input,&g,buckets));
        assert(!c71_range_runtime_h_sum(c,buckets,h,2)); r.bits=1;
        assert(!c71_range_runtime_h_coefficients(c,h,&r,&result));
        assert(!c71_range_runtime_h_fold(c,h,small,{0,1,0}));
        g.width=0; g.tail_bits=2; const auto children=alloc(c,C71_CHILDREN,4);
        assert(!c71_range_groups(c,input,&g,children));
        assert(!c71_range_runtime_child_fold(c,children,{1,0,0}));
        close(c);
    }
    // Every rejection poisons this owner; no subsequent launch or fallback.
    for(unsigned test=0;test<13;++test) {
        c=create(); auto id=roots(c,0,2); int status=0;
        auto initial_launches=launches;
        switch(test) {
        case 0: status=c71_range_read(c,id,limbs,6); break; // not scalar
        case 1: status=c71_range_runtime_canopy(c,id,id); break;
        case 2: assert(!c71_range_release(c,id)); status=c71_range_release(c,id); break;
        case 3: { auto* other=create(); auto foreign=alloc(other,C71_PAIR,1); status=c71_range_release(c,foreign); close(other); break; }
        case 4: { uint64_t ignored; status=c71_range_alloc(c,C71_PAIR,1ULL<<25,&ignored); break; }
        case 5: { uint64_t ignored; status=c71_range_alloc(c,C71_U8,262144,&ignored); break; }
        case 6: { auto x=alloc(c,C71_I16,1); int16_t bad=INT16_MIN; status=c71_range_upload(c,x,&bad,2); break; }
        case 7: { auto x=alloc(c,C71_PAIR,1); status=c71_range_runtime_canopy(c,x,id); break; }
        case 8: assert(!c71_range_as_children(c,id)); status=c71_range_runtime_child_fold(c,id,{P,0,0}); break;
        case 9: { auto x=alloc(c,C71_PAIR,1); fail_launch=true; status=c71_range_runtime_canopy(c,id,x); fail_launch=false; ++initial_launches; break; }
        case 10: assert(!c71_range_as_children(c,id)); fail_fence=true; limbs[0]=123;
            status=c71_range_read(c,id,limbs,12); fail_fence=false; assert(limbs[0]==123); break;
        case 11: assert(!c71_range_as_children(c,id)); corrupt=true; limbs[0]=123;
            status=c71_range_read(c,id,limbs,12); corrupt=false; assert(limbs[0]==123); break;
        case 12: { auto x=alloc(c,C71_U8,8); status=c71_range_roots(c,x,1,{},id,0); break; }
        }
        assert(status && stats(c).stopped && *c71_range_error(c));
        assert(c71_range_runtime_canopy(c,id,id) && launches==initial_launches);
        close(c);
    }
    c=create(); alloc(c,C71_U8,1); fail_free=true;
    assert(c71_range_close(c,&final) && final.cleanup_failed && final.arena_bytes==256);
    fail_free=false;
    joint_budget_checks();
    dense_completion_fence_checks();
    dense_checks();
    embedding_checks();
    pointwise_checks();
    byte_checks();
    residual_test::component_checks();
    residual_test::contract_checks();
    residual_test::failure_checks();
    residual_test::contract_failures();
    residual_test::short_hash_checks();
    residual_test::short_hash_failures();
    residual_query_test::positive();
    residual_query_test::negative();
    residual_query_test::weight_launch_failures();
    residual_query_test::trusted_source_partition_checks();
    initial_weight_query_test::positive();
    initial_weight_query_test::negative();
    assert(allocations==frees);
    std::puts("C71_RANGE_OWNER_HOST {\"rejections\":13,\"dense_rejections\":23,\"byte_rejections\":19,\"pointwise_rejections\":14,\"embedding_rejections\":17,\"dense_batches\":2,\"dense_row_views\":1,\"max_arena_bytes\":262144,\"gpu_execution\":false,\"credit\":false}");
}
#endif
