// Independent dense MSB-fold/polynomial oracle. Host component only.
#include "c71_pcs_residual_query.cuh"
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <utility>
#include <vector>

namespace pcs=c71_pcs_residual;
namespace query=c71_pcs_residual_query;
namespace oracle {
using Wide=unsigned __int128;
struct E { std::array<uint64_t,3> c; };
uint64_t add(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+b)%P); }
uint64_t sub(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+P-b)%P); }
uint64_t mul(uint64_t a,uint64_t b) { return uint64_t(Wide(a)*b%P); }
E add(E a,E b) { for(unsigned i=0;i<3;++i) a.c[i]=add(a.c[i],b.c[i]); return a; }
E sub(E a,E b) { for(unsigned i=0;i<3;++i) a.c[i]=sub(a.c[i],b.c[i]); return a; }
E scale(E a,uint64_t b) { for(auto& x:a.c) x=mul(x,b); return a; }
E mul(E a,E b) {
    uint64_t poly[5]{};
    for(unsigned i=0;i<3;++i) for(unsigned j=0;j<3;++j)
        poly[i+j]=add(poly[i+j],mul(a.c[i],b.c[j]));
    for(unsigned d=4;d>=3;--d) { poly[d-2]=add(poly[d-2],poly[d]); poly[d-3]=add(poly[d-3],poly[d]); }
    return {{poly[0],poly[1],poly[2]}};
}
void fold(std::vector<E>& data,E point) {
    const size_t half=data.size()/2;
    for(size_t i=0;i<half;++i) data[i]=add(data[i],mul(point,sub(data[half+i],data[i])));
    data.resize(half);
}
E eq(const std::vector<E>& point,uint64_t index) {
    E result{{1,0,0}};
    for(size_t i=0;i<point.size();++i)
        result=mul(result,(index>>(point.size()-1-i))&1 ? point[i] : sub(E{{1,0,0}},point[i]));
    return result;
}
E horner(const std::vector<E>& values,uint64_t point) {
    E result{};
    for(auto i=values.rbegin();i!=values.rend();++i) result=add(scale(result,point),*i);
    return result;
}
}
pcs::E native(oracle::E value) { return {value.c[0],value.c[1],value.c[2]}; }
oracle::E reference(pcs::E value) { return {{value.c0,value.c1,value.c2}}; }
bool same(pcs::E a,oracle::E b) { return a.c0==b.c[0] && a.c1==b.c[1] && a.c2==b.c[2]; }
uint64_t rng=0x5b7a193e43c86021ULL;
uint64_t random_word() { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }
oracle::E random_e() { return {{random_word()%P,random_word()%P,random_word()%P}}; }

struct Packet {
    pcs::EqShape shape{};
    std::vector<pcs::Chunk> chunks;
    std::vector<pcs::E> table;
    const pcs::Chunk* chunk_pointer() const { return chunks.empty() ? nullptr : chunks.data(); }
    const pcs::E* table_pointer() const { return table.empty() ? nullptr : table.data(); }
};
Packet packet(const std::vector<oracle::E>& point) {
    Packet result;
    for(size_t first=0;first<point.size();first+=8) {
        const size_t bits=std::min<size_t>(8,point.size()-first);
        result.chunks.push_back({unsigned(point.size()-first-bits),unsigned(bits),unsigned(result.table.size()),0});
        const std::vector<oracle::E> part(point.begin()+first,point.begin()+first+bits);
        for(uint64_t index=0;index<(uint64_t{1}<<bits);++index) result.table.push_back(native(oracle::eq(part,index)));
    }
    result.shape={unsigned(point.size()),unsigned(result.chunks.size()),unsigned(result.table.size()),0};
    assert(pcs::valid_packet(result.shape,result.chunk_pointer(),result.table_pointer()));
    return result;
}

struct Inputs {
    std::vector<int16_t> packed;
    std::vector<c71_pcs::WeightTile> tiles;
    std::array<std::vector<uint64_t>,3> planes;
    std::vector<oracle::E> dense;
    uint64_t live=0;
    pcs::ConstPlanes plane_pointer() const { return {planes[0].data(),planes[1].data(),planes[2].data()}; }
    uint64_t bytes() const {
        uint64_t result=packed.capacity()*2+tiles.capacity()*sizeof(c71_pcs::WeightTile)+dense.capacity()*sizeof(oracle::E);
        for(const auto& p:planes) result+=p.capacity()*8;
        return result;
    }
};
Inputs inputs(unsigned dimension,bool retained) {
    Inputs result;
    const uint64_t domain=uint64_t{1}<<dimension;
    result.live=retained ? domain : domain-3;
    result.dense.resize(domain);
    if(retained) {
        for(auto& p:result.planes) p.resize(domain);
        for(uint64_t i=0;i<domain;++i) {
            const auto value=i==0 ? oracle::E{} : i==1 ? oracle::E{{1,0,0}} : i==2 ? oracle::E{{0,1,0}} :
                i==3 ? oracle::E{{0,0,1}} : i==4 ? oracle::E{{P-1,P-1,P-1}} : random_e();
            result.dense[i]=value;
            for(unsigned limb=0;limb<3;++limb) result.planes[limb][i]=value.c[limb];
        }
    } else {
        const std::array<int16_t,9> edges{-32767,-257,-1,0,1,255,256,32767,-12345};
        uint64_t first=0;
        while(first<result.live) {
            const uint64_t count=std::min<uint64_t>(result.live-first,first==0 ? result.live/3 : result.live/4+1);
            const uint64_t columns=std::min<uint64_t>(5,count),stride=columns+2;
            const uint64_t packed_first=result.packed.size()+1,rows=(count+columns-1)/columns;
            result.packed.resize(packed_first+rows*stride,INT16_MIN);
            result.tiles.push_back({first,count,packed_first,stride,columns});
            for(uint64_t i=0;i<count;++i) {
                const int16_t value=i<edges.size() ? edges[i] : int16_t(int64_t(random_word()%65535)-32767);
                result.packed[packed_first+i/columns*stride+i%columns]=value;
                result.dense[first+i]={{value<0 ? P-uint64_t(-int32_t(value)) : uint64_t(value),0,0}};
            }
            first+=count;
        }
    }
    return result;
}
struct Counts {
    uint64_t cases=0,coefficient_outputs=0,pad_outputs=0,zero_outputs=0,horner_checks=0,rejections=0;
    uint64_t w_expected_reads=0,a_expected_e_reads=0,logical_passes=0,max_named_heap=0;
    uint64_t emulated_w_reads=0,emulated_cta_tasks=0,emulated_eq_cache_entries=0,emulated_field_updates=0;
};

// Emulate the NEW CUDA scheduling, independently of weights_at: cache one
// EQ per prefix, eight worker partials per coefficient, shared reduction,
// then modular accumulation. Dense MSB fold + polynomial convolution above
// remain the independent mathematical oracle. These are HOST visit counts,
// never observations of CUDA/CAS contention or H100 speed.
bool emulate_weights(const Inputs& input,uint64_t input_words,pcs::Shape shape,const Packet& eq,
    const std::vector<pcs::E>& pads,uint64_t capacity,c71_pcs::QueryBlock block,std::vector<uint64_t>& output,
    Counts* counts=nullptr,std::vector<bool>* coverage=nullptr,uint64_t* visits=nullptr) {
    assert(output.size()==3*capacity);
    bool ok=true;
    for(uint64_t i=0;i<capacity;++i) {
        const uint64_t j=block.first+i;
        pcs::E value{};
        if(j<block.source_rows && (block.pad_only || j>=block.message_rows) &&
           !query::pad_at(pads.data(),block,j,value)) {ok=false;value={};}
        output[i]=value.c0;output[capacity+i]=value.c1;output[2*capacity+i]=value.c2;
    }
    const auto work=query::weight_work(shape,capacity,block);
    if(!work.tasks) return ok;
    const uint64_t grid=std::min<uint64_t>(work.tasks,query::max_blocks),length=uint64_t{1}<<shape.remaining;
    std::array<pcs::E,query::prefix_tile> cache{};
    std::array<pcs::E,query::threads> partial{};
    for(uint64_t cta=0;cta<grid;++cta) for(uint64_t task=cta;task<work.tasks;task+=grid) {
        if(counts) ++counts->emulated_cta_tasks;
        const uint64_t coefficient_first=(task/work.prefix_tiles)*query::coefficient_tile;
        const uint64_t prefix_first=(task%work.prefix_tiles)*query::prefix_tile;
        for(unsigned thread=0;thread<query::threads;++thread) {
            const uint64_t prefix=prefix_first+thread;
            pcs::E value{};
            if(prefix<work.prefixes) {
                if(counts) ++counts->emulated_eq_cache_entries;
                if(!query::checked_equality(prefix,shape.equality,eq.chunk_pointer(),eq.table_pointer(),value)) {ok=false;value={};}
            }
            cache[thread]=value;
        }
        for(unsigned thread=0;thread<query::threads;++thread) {
            const unsigned lane=thread%query::coefficient_tile,worker=thread/query::coefficient_tile;
            const uint64_t coefficient=coefficient_first+lane;
            pcs::E sum{};
            if(coefficient<work.message_count) {
                const uint64_t local=block.byte_first+block.first+coefficient;
                for(unsigned digit=worker;digit<query::prefix_tile;digit+=query::workers) {
                    const uint64_t prefix=prefix_first+digit;
                    if(prefix>=work.prefixes) break;
                    const uint64_t index=prefix*length+local;
                    if(index>=shape.live) break;
                    const uint64_t address=c71_pcs::packed_address(input.tiles.data(),input.tiles.size(),index,shape.live);
                    uint64_t original=0;
                    if(address>=input_words) {ok=false;continue;}
                    if(counts) ++counts->emulated_w_reads;
                    if(coverage) {assert(!(*coverage)[index]);(*coverage)[index]=true;}
                    if(visits) ++*visits;
                    if(!pcs::weight_scalar(input.packed[address],original)) {ok=false;continue;}
                    sum=pcs::add(sum,pcs::base_mul(cache[digit],original));
                }
            }
            partial[thread]=sum;
        }
        for(unsigned lane=0;lane<query::coefficient_tile;++lane) {
            const uint64_t coefficient=coefficient_first+lane;
            if(coefficient>=work.message_count) continue;
            pcs::E combined=partial[lane];
            for(unsigned worker=1;worker<query::workers;++worker) combined=pcs::add(combined,partial[worker*query::coefficient_tile+lane]);
            for(unsigned limb=0;limb<3;++limb) {
                const auto value=pcs::limb(combined,limb);
                if(value && counts) ++counts->emulated_field_updates;
                output[limb*capacity+coefficient]=fp_add(output[limb*capacity+coefficient],value);
            }
        }
    }
    return ok;
}

void check_case(unsigned dimension,unsigned prefix,unsigned variant,bool retained,uint64_t cap,unsigned pad_rows,Counts& counts) {
    Inputs input=inputs(dimension,retained);
    std::vector<oracle::E> points(prefix);
    for(auto& value:points) value=variant==0 ? oracle::E{} : variant==1 ? oracle::E{{1,0,0}} : random_e();
    const auto eq=packet(points);
    const pcs::Shape shape{input.live,dimension,dimension-prefix,eq.shape};
    const uint64_t n=query::message_rows(shape);
    assert(query::valid_shape(shape,retained));
    auto expected=input.dense;
    for(const auto point:points) oracle::fold(expected,point); // independent dense MSB folds
    assert(expected.size()==4*n);
    std::vector<pcs::E> pads(4*pad_rows);
    for(auto& value:pads) value=native(random_e());
    std::vector<uint64_t> output(3*cap,P);
    std::vector<bool> original_coverage(input.live,false);
    uint64_t visits=0;
    for(unsigned column=0;column<4;++column) {
        c71_pcs::QueryBlock block{0,n+pad_rows,n,n,uint64_t(column)*n,0,uint64_t(column)*pad_rows,pad_rows,0};
        assert(query::valid_arguments(shape,cap,block,eq.chunk_pointer(),eq.table_pointer(),pads.data(),pads.size(),output.data()));
        std::vector<oracle::E> polynomial(expected.begin()+column*n,expected.begin()+(column+1)*n);
        for(unsigned j=0;j<pad_rows;++j) polynomial.push_back(reference(pads[column*pad_rows+j]));
        std::vector<oracle::E> loaded(polynomial.size());
        for(uint64_t reverse=(block.source_rows+cap-1)/cap;reverse;--reverse) {
            block.first=(reverse-1)*cap;
            assert(query::valid_block(shape,cap,block));
            if(!retained) assert(emulate_weights(input,input.packed.size(),shape,eq,pads,cap,block,output,&counts,&original_coverage,&visits));
            for(uint64_t i=0;i<cap;++i) {
                const uint64_t j=block.first+i;
                pcs::E value{output[i],output[cap+i],output[2*cap+i]};
                const bool ok=!retained || query::resident_at(input.plane_pointer(),input.live,shape,eq.chunk_pointer(),eq.table_pointer(),pads.data(),block,j,value);
                assert(ok && pcs::canonical(value));
                // Emulate the kernel's limb-major publication, then read it back.
                output[i]=value.c0; output[cap+i]=value.c1; output[2*cap+i]=value.c2;
                if(j<polynomial.size()) {
                    assert(same({output[i],output[cap+i],output[2*cap+i]},polynomial[j]));
                    loaded[j]={{output[i],output[cap+i],output[2*cap+i]}};
                    if(j<n) {
                        ++counts.coefficient_outputs;
                        const uint64_t virtual_length=4*n;
                        for(uint64_t p=0;retained && p<(uint64_t{1}<<prefix);++p) {
                            const uint64_t original=p*virtual_length+column*n+j;
                            if(original>=input.live) break;
                            assert(!original_coverage[original]); original_coverage[original]=true; ++visits;
                        }
                    } else ++counts.pad_outputs;
                } else { assert(pcs::zero(value)); ++counts.zero_outputs; }
            }
        }
        for(uint64_t point:{uint64_t{0},uint64_t{1},P-1,uint64_t{65537}}) {
            const auto a=oracle::horner(loaded,point),b=oracle::horner(polynomial,point);
            assert(a.c==b.c); ++counts.horner_checks;
        }
        block.first=0; block.source_rows=0;
        assert(query::valid_block(shape,cap,block));
        if(!retained) assert(emulate_weights(input,input.packed.size(),shape,eq,pads,cap,block,output));
        for(uint64_t i=0;i<cap;++i) {
            pcs::E value{output[i],output[cap+i],output[2*cap+i]};
            assert((!retained || query::resident_at(input.plane_pointer(),input.live,shape,eq.chunk_pointer(),eq.table_pointer(),pads.data(),block,i,value)) && pcs::zero(value));
            ++counts.zero_outputs;
        }
        block.source_rows=pad_rows; block.active=0; block.pad_only=1;
        assert(query::valid_block(shape,cap,block));
        for(uint64_t reverse=(pad_rows+cap-1)/cap;reverse;--reverse) {
            block.first=(reverse-1)*cap;
            if(!retained) assert(emulate_weights(input,input.packed.size(),shape,eq,pads,cap,block,output));
            for(uint64_t i=0;i<cap;++i) {
                const uint64_t j=block.first+i;
                pcs::E value{output[i],output[cap+i],output[2*cap+i]};
                assert(!retained || query::resident_at(input.plane_pointer(),input.live,shape,eq.chunk_pointer(),eq.table_pointer(),pads.data(),block,j,value));
                assert(j<pad_rows ? same(value,reference(pads[column*pad_rows+j])) : pcs::zero(value));
            }
        }
        const uint64_t named=input.bytes()+points.capacity()*sizeof(oracle::E)+eq.chunks.capacity()*sizeof(pcs::Chunk)+
            eq.table.capacity()*sizeof(pcs::E)+expected.capacity()*sizeof(oracle::E)+pads.capacity()*sizeof(pcs::E)+
            output.capacity()*8+((original_coverage.capacity()+7)/8)+
            polynomial.capacity()*sizeof(oracle::E)+loaded.capacity()*sizeof(oracle::E);
        counts.max_named_heap=std::max(counts.max_named_heap,named);
    }
    assert(visits==input.live && std::all_of(original_coverage.begin(),original_coverage.end(),[](bool x){return x;}));
    if(retained) counts.a_expected_e_reads+=visits; else counts.w_expected_reads+=visits;
    ++counts.logical_passes; ++counts.cases;
}

void check_guards(Counts& counts) {
    const auto eq=packet({oracle::E{}});
    pcs::Shape s{32,5,4,eq.shape};
    c71_pcs::QueryBlock b{0,8,4,4,0,0,0,4,0};
    assert(query::valid_block(s,8,b));
    auto reject=[&](c71_pcs::QueryBlock bad,uint64_t cap=8){assert(!query::valid_block(s,cap,bad));++counts.rejections;};
    reject(b,0); reject(b,3); reject(b,query::max_capacity*2);
    auto bad=b; bad.first=1; reject(bad);
    bad=b; bad.first=16; reject(bad);
    bad=b; bad.window_first=1; reject(bad);
    bad=b; bad.message_rows=2; reject(bad);
    bad=b; bad.active=7; reject(bad);
    bad=b; bad.byte_first=1; reject(bad);
    bad=b; bad.byte_first=32; reject(bad);
    bad=b; bad.pad_first=4; reject(bad);
    bad=b; bad.pad_rows=0; reject(bad);
    bad=b; bad.pad_rows=1537; reject(bad);
    bad=b; bad.source_rows=4; reject(bad);
    bad=b; bad.pad_only=2; reject(bad);
    bad=b; bad.pad_only=1; reject(bad);
    bad=b; bad.source_rows=0; bad.first=8; reject(bad);
    auto malformed=s; malformed.remaining=1; assert(!query::valid_shape(malformed,false)); ++counts.rejections;
    malformed=s; malformed.live=31; assert(!query::valid_shape(malformed,true)); ++counts.rejections;
    const auto eq3=packet({oracle::E{},oracle::E{},oracle::E{}});
    malformed={32,5,2,eq3.shape}; assert(!query::valid_shape(malformed,true)); ++counts.rejections;
    const auto empty=packet({});
    malformed={uint64_t{1}<<30,30,30,empty.shape}; assert(!query::valid_shape(malformed,false)); ++counts.rejections;
    const auto eq6=packet(std::vector<oracle::E>(6,oracle::E{{1,0,0}}));
    const pcs::Shape maximum{uint64_t{1}<<35,35,29,eq6.shape};
    const uint64_t maximum_n=query::max_message_rows;
    const c71_pcs::QueryBlock maximum_block{maximum_n,maximum_n+1536,maximum_n,maximum_n,
        3*maximum_n,0,3*1536,1536,0};
    assert(query::valid_block(maximum,query::max_capacity,maximum_block)); // metadata only, no large allocation
    std::vector<pcs::E> pads(16,{0,0,0}); std::vector<uint64_t> low(24);
    assert(!query::valid_arguments(s,8,b,nullptr,eq.table_pointer(),pads.data(),pads.size(),low.data())); ++counts.rejections;
    assert(!query::valid_arguments(s,8,b,eq.chunk_pointer(),nullptr,pads.data(),pads.size(),low.data())); ++counts.rejections;
    assert(!query::valid_arguments(s,8,b,eq.chunk_pointer(),eq.table_pointer(),pads.data(),15,low.data())); ++counts.rejections;
    pcs::E value{};
    auto a=inputs(5,true);
    // p=1 has zero EQ weight for point=0. Its noncanonical c1 must still fail.
    a.planes[1][16]=P;
    assert(!query::resident_at(a.plane_pointer(),32,s,eq.chunk_pointer(),eq.table_pointer(),pads.data(),b,0,value)); ++counts.rejections;
    a.planes[1][16]=0;
    assert(!query::resident_at(a.plane_pointer(),16,s,eq.chunk_pointer(),eq.table_pointer(),pads.data(),b,0,value)); ++counts.rejections;
    auto w=inputs(5,false); s.live=w.live;
    const uint64_t address=c71_pcs::packed_address(w.tiles.data(),w.tiles.size(),16,w.live);
    w.packed[address]=INT16_MIN;
    assert(!emulate_weights(w,w.packed.size(),s,eq,pads,8,b,low)); ++counts.rejections;
    w.packed[address]=0;
    assert(!emulate_weights(w,0,s,eq,pads,8,b,low)); ++counts.rejections;
    pads[0].c2=P;
    assert(!emulate_weights(w,w.packed.size(),s,eq,pads,8,b,low)); ++counts.rejections;
    pads[0].c2=0;
    auto bad_eq=eq; bad_eq.table[1].c0=P;
    assert(!emulate_weights(w,w.packed.size(),s,bad_eq,pads,8,b,low)); ++counts.rejections;
    auto chunks=eq.chunks; chunks[0].shift=35;
    assert(!query::checked_equality(0,eq.shape,chunks.data(),eq.table_pointer(),value)); ++counts.rejections;
    chunks=eq.chunks; chunks[0].bits=0;
    assert(!query::checked_equality(0,eq.shape,chunks.data(),eq.table_pointer(),value)); ++counts.rejections;
    chunks=eq.chunks; chunks[0].first=eq.shape.entries;
    assert(!query::checked_equality(0,eq.shape,chunks.data(),eq.table_pointer(),value)); ++counts.rejections;
}

void check_large_sparse_weight(Counts& counts) {
    // Full D35 geometry with only six live coefficients; no D35 allocation.
    std::vector<oracle::E> point(33,oracle::E{{1,0,0}});
    const auto eq=packet(point);
    const pcs::Shape shape{6,35,2,eq.shape};
    assert(query::valid_shape(shape,false));
    Inputs input;input.live=6;input.packed={-32767,-1,0,1,256,32767,INT16_MIN};
    input.tiles={{0,6,0,6,6}};
    const std::vector<pcs::E> pads(4);
    std::vector<uint64_t> low(3);
    for(unsigned col=0;col<4;++col) {
        c71_pcs::QueryBlock b{0,2,1,1,col,0,col,1,0};
        assert(emulate_weights(input,input.packed.size(),shape,eq,pads,1,b,low));
        const pcs::E out{low[0],low[1],low[2]};
        assert(pcs::zero(out)); // selected all-ones prefix is in public suffix
        ++counts.coefficient_outputs;
    }
    ++counts.cases;
}
int main() {
    Counts counts;
    check_guards(counts);
    check_large_sparse_weight(counts);
    const auto begin=std::chrono::steady_clock::now();
    for(bool retained:{false,true}) for(unsigned dimension:{5u,8u,10u})
        for(unsigned prefix:{0u,1u,2u,7u}) {
            if(prefix>dimension-2 || (retained && prefix>2)) continue;
            for(unsigned variant=0;variant<3;++variant)
                for(const auto& config:{std::pair<uint64_t,unsigned>{1,1},{8,33},{64,1536}})
                    check_case(dimension,prefix,variant,retained,config.first,config.second,counts);
        }
    // Prefix tiles cross 256/512 boundaries and end in the live suffix;
    // the coefficient tile is ragged and pads are longer than its message.
    for(unsigned prefix:{9u,10u}) for(unsigned variant=0;variant<3;++variant)
        for(const auto& config:{std::pair<uint64_t,unsigned>{1,1},{8,33},{64,1536}})
            check_case(13,prefix,variant,false,config.first,config.second,counts);
    const double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();
    assert(counts.emulated_w_reads==counts.w_expected_reads);
    std::printf("C71_PCS_RESIDUAL_QUERY_HOST {\"cases\":%llu,\"coefficient_outputs\":%llu,\"pad_outputs\":%llu,\"zero_outputs\":%llu,\"horner_checks\":%llu,\"rejections\":%llu,\"logical_passes\":%llu,\"expected_W_original_reads\":%llu,\"expected_A_retained_E_reads\":%llu,\"expected_A_retained_word_reads\":%llu,\"named_fixture_heap_upper_bytes\":%llu,\"emulated_W_reads\":%llu,\"emulated_CTA_tasks\":%llu,\"emulated_EQ_cache_entries\":%llu,\"emulated_field_updates\":%llu,\"max_low_payload_bytes\":25165824,\"W_shared_bytes\":12288,\"resident_shared_bytes\":0,\"host_component_s\":%.9g,\"PCS_basis_v3_v1\":true,\"gpu_execution\":false,\"integrated\":false,\"credit\":false}\n",
        (unsigned long long)counts.cases,(unsigned long long)counts.coefficient_outputs,
        (unsigned long long)counts.pad_outputs,(unsigned long long)counts.zero_outputs,
        (unsigned long long)counts.horner_checks,(unsigned long long)counts.rejections,
        (unsigned long long)counts.logical_passes,(unsigned long long)counts.w_expected_reads,
        (unsigned long long)counts.a_expected_e_reads,(unsigned long long)(3*counts.a_expected_e_reads),
        (unsigned long long)counts.max_named_heap,(unsigned long long)counts.emulated_w_reads,
        (unsigned long long)counts.emulated_cta_tasks,(unsigned long long)counts.emulated_eq_cache_entries,
        (unsigned long long)counts.emulated_field_updates,elapsed);
}
