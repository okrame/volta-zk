// Independent integer/polynomial oracle; this does NOT execute CUDA kernels.
#include "c71_pcs_residual.cuh"
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <vector>

namespace pcs=c71_pcs_residual;
namespace oracle {
using Wide=unsigned __int128;
struct E { std::array<uint64_t,3> c; };
uint64_t add(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+b)%P); }
uint64_t sub(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+P-b)%P); }
uint64_t mul(uint64_t a,uint64_t b) { return uint64_t(Wide(a)*b%P); }
uint64_t power(uint64_t a,uint64_t n) {
    uint64_t result=1;
    while(n) { if(n&1) result=mul(result,a); a=mul(a,a); n>>=1; }
    return result;
}
E add(E a,E b) { for(unsigned i=0;i<3;++i) a.c[i]=add(a.c[i],b.c[i]); return a; }
E sub(E a,E b) { for(unsigned i=0;i<3;++i) a.c[i]=sub(a.c[i],b.c[i]); return a; }
E mul(E a,E b) {
    // Ordinary degree-4 convolution then long reduction by v^3-v-1.
    // Independent of the six-product formula and Goldilocks folding helper.
    uint64_t polynomial[5]{};
    for(unsigned i=0;i<3;++i) for(unsigned j=0;j<3;++j)
        polynomial[i+j]=add(polynomial[i+j],mul(a.c[i],b.c[j]));
    for(unsigned degree=4;degree>=3;--degree) {
        polynomial[degree-2]=add(polynomial[degree-2],polynomial[degree]);
        polynomial[degree-3]=add(polynomial[degree-3],polynomial[degree]);
    }
    return {{polynomial[0],polynomial[1],polynomial[2]}};
}
E scale(E a,uint64_t b) { for(auto& limb:a.c) limb=mul(limb,b); return a; }
E power(E a,uint64_t n) {
    E result{{1,0,0}};
    while(n) { if(n&1) result=mul(result,a); a=mul(a,a); n>>=1; }
    return result;
}
E eq(const std::vector<E>& point,uint64_t index) {
    E value{{1,0,0}};
    for(size_t i=0;i<point.size();++i)
        value=mul(value,(index>>(point.size()-1-i))&1 ? point[i] : sub(E{{1,0,0}},point[i]));
    return value;
}
void fold(std::vector<E>& values,E r) {
    const size_t half=values.size()/2;
    for(size_t i=0;i<half;++i) values[i]=add(values[i],mul(r,sub(values[i+half],values[i])));
    values.resize(half);
}
}
oracle::E oracle_value(pcs::E x) { return {{x.c0,x.c1,x.c2}}; }
pcs::E native(oracle::E x) { return {x.c[0],x.c[1],x.c[2]}; }
bool same(pcs::E a,oracle::E b) { return a.c0==b.c[0] && a.c1==b.c[1] && a.c2==b.c[2]; }
uint64_t state=0x2876ea2f18dd103bULL;
uint64_t random_word() { state^=state<<13; state^=state>>7; state^=state<<17; return state; }
oracle::E random_e() { return {{random_word()%P,random_word()%P,random_word()%P}}; }
std::vector<oracle::E> point(unsigned bits,unsigned variant) {
    std::vector<oracle::E> out(bits);
    for(auto& value:out) value=variant==0 ? oracle::E{} : variant==1 ? oracle::E{{1,0,0}} : random_e();
    return out;
}
struct Lookup {
    pcs::EqShape shape{};
    std::vector<pcs::Chunk> chunks;
    std::vector<pcs::E> values;
};
Lookup prepare(const std::vector<oracle::E>& coordinates) {
    Lookup out;
    for(size_t first=0;first<coordinates.size();first+=8) {
        const size_t bits=std::min<size_t>(8,coordinates.size()-first);
        std::vector<oracle::E> chunk(coordinates.begin()+first,coordinates.begin()+first+bits);
        out.chunks.push_back({unsigned(coordinates.size()-first-bits),unsigned(bits),unsigned(out.values.size()),0});
        for(uint64_t i=0;i<(uint64_t{1}<<bits);++i) out.values.push_back(native(oracle::eq(chunk,i)));
    }
    out.shape={unsigned(coordinates.size()),unsigned(out.chunks.size()),unsigned(out.values.size()),0};
    assert(pcs::valid_packet(out.shape,out.chunks.data(),out.values.data()));
    return out;
}
uint64_t lookup_bytes(const Lookup& l) {
    return l.chunks.capacity()*sizeof(pcs::Chunk)+l.values.capacity()*sizeof(pcs::E);
}
struct Counters {
    uint64_t arithmetic=0,equality=0,cases=0,scans=0,loads=0,original_visits=0;
    uint64_t retained=0,singleton=0,ood=0,ring=0,fold=0,codec=0,rejected=0,max_named_heap=0;
};
void check_arithmetic(Counters& counts) {
    std::vector<pcs::E> edge{{0,0,0},{1,0,0},{0,1,0},{0,0,1},{P-1,0,0},{0,P-1,0},{0,0,P-1},
        {P-1,P-1,P-1},{P-2,P-3,P-4},{0,1,P-1},{1,P-1,0},{P-1,0,1},
        {0x100000000ULL,0xffffffffULL,P-1},{P-1,0xffffffffULL,0x100000000ULL},{2,3,5},{7,11,13}};
    for(unsigned i=0;i<32;++i) edge.push_back(native(random_e()));
    for(const auto a:edge) for(const auto b:edge) {
        assert(same(pcs::add(a,b),oracle::add(oracle_value(a),oracle_value(b))));
        assert(same(pcs::sub(a,b),oracle::sub(oracle_value(a),oracle_value(b))));
        assert(same(pcs::mul(a,b),oracle::mul(oracle_value(a),oracle_value(b))));
        assert(same(pcs::base_mul(a,b.c0),oracle::scale(oracle_value(a),b.c0)));
        assert(pcs::canonical(pcs::mul(a,b)));
        ++counts.arithmetic;
    }
    // v^3=v+1, v^4=v^2+v explicitly distinguish this basis from MAC u^3=2.
    assert(same(pcs::power({0,1,0},3),oracle::E{{1,1,0}}));
    assert(same(pcs::power({0,1,0},4),oracle::E{{0,1,1}}));
    for(unsigned bits:{0u,1u,7u,8u,9u,16u,17u,25u,35u}) for(unsigned variant=0;variant<3;++variant) {
        const auto coordinates=point(bits,variant);
        const auto packet=prepare(coordinates);
        for(unsigned i=0;i<16;++i) {
            const uint64_t index=(i<2 ? i ? (uint64_t{1}<<bits)-1 : 0 : random_word())&((uint64_t{1}<<bits)-1);
            assert(same(pcs::lookup(index,packet.chunks.data(),packet.shape.chunks,packet.values.data()),oracle::eq(coordinates,index)));
            ++counts.equality;
        }
    }
}

struct Original {
    bool weight;
    unsigned kind,signed_width,byte_first,width;
    uint64_t live;
    std::vector<int16_t> small;
    std::vector<int64_t> wide;
    std::vector<c71_pcs::WeightTile> weight_tiles;
    std::vector<c71_pcs::SourceTile> source_tiles;
    std::vector<uint64_t> scalar; // Independent expected original values only.
    uint64_t named_bytes() const {
        return small.capacity()*sizeof(int16_t)+wide.capacity()*sizeof(int64_t)+
            weight_tiles.capacity()*sizeof(c71_pcs::WeightTile)+source_tiles.capacity()*sizeof(c71_pcs::SourceTile)+
            scalar.capacity()*sizeof(uint64_t);
    }
    template<class Emit> void scan(Emit emit,Counters& counts) const {
        ++counts.scans;
        if(weight) {
            for(uint64_t reverse=live;reverse;--reverse) {
                const uint64_t index=reverse-1,address=c71_pcs::packed_address(weight_tiles.data(),weight_tiles.size(),index,live);
                uint64_t value=0;
                assert(address<small.size() && pcs::weight_scalar(small[address],value));
                assert(value==scalar[index]); emit(index,value); ++counts.loads; ++counts.original_visits;
            }
        } else {
            const uint64_t words=kind==1 ? small.size() : wide.size();
            for(auto tile=source_tiles.rbegin();tile!=source_tiles.rend();++tile) {
                assert(c71_pcs::valid(*tile,kind,words,live));
                for(uint64_t reverse=tile->rows*tile->columns;reverse;--reverse) {
                    const uint64_t i=reverse-1,address=tile->input_first+i/tile->columns*tile->input_stride+i%tile->columns;
                    const int64_t word=kind==1 ? small[address] : wide[address];
                    ++counts.loads;
                    for(unsigned j=0;j<tile->width;++j) {
                        uint8_t byte=0;
                        assert(c71_byte::encode(word,tile->signed_width,tile->byte_first+j,byte));
                        const uint64_t index=tile->original_first+i*tile->width+j;
                        assert(byte==scalar[index]); emit(index,byte); ++counts.original_visits; ++counts.codec;
                    }
                }
            }
        }
    }
};
Original originals(unsigned dimension,unsigned codec) {
    Original out{};
    out.weight=codec==0; out.kind=codec==1 ? 1 : 6;
    out.signed_width=codec<=1 ? 2 : codec==2 ? 4 : 6;
    out.byte_first=codec==4 ? 1 : 0; out.width=codec==4 ? 3 : out.signed_width;
    const uint64_t domain=uint64_t{1}<<dimension;
    if(out.weight) {
        out.live=domain-3; out.scalar.resize(out.live);
        uint64_t covered=0;
        while(covered<out.live) {
            uint64_t count=1; while(count<=(out.live-covered)/2) count*=2;
            const uint64_t columns=std::min<uint64_t>(4,count),stride=columns+2,rows=count/columns;
            const uint64_t first=out.small.size()+1;
            out.small.resize(first+rows*stride,INT16_MIN); // physical padding never read
            out.weight_tiles.push_back({covered,count,first,stride,columns});
            for(uint64_t i=0;i<count;++i) {
                const int16_t value=i<8 ? std::array<int16_t,8>{-32767,-257,-1,0,1,255,256,32767}[i] : int16_t(int64_t(random_word()%65535)-32767);
                out.small[first+i/columns*stride+i%columns]=value;
                out.scalar[covered+i]=value<0 ? P-uint64_t(-int32_t(value)) : uint64_t(value);
            }
            covered+=count;
        }
    } else {
        const uint64_t words=(domain-5)/out.width;
        out.live=words*out.width; out.scalar.resize(out.live);
        uint64_t covered=0;
        while(covered<words) {
            const uint64_t count=std::min<uint64_t>(9,words-covered),columns=count>=3 ? 3 : count;
            // A partial final block may have a second shorter tile.
            const uint64_t rows=count/columns,actual=rows*columns,stride=columns+2;
            const uint64_t first=(out.kind==1 ? out.small.size() : out.wide.size())+2;
            if(out.kind==1) out.small.resize(first+rows*stride,INT16_MIN);
            else out.wide.resize(first+rows*stride,INT64_MIN);
            out.source_tiles.push_back({first,stride,rows,columns,covered*out.width,out.byte_first,out.width,out.signed_width});
            const int64_t bound=int64_t{1}<<(8*out.signed_width-1);
            for(uint64_t i=0;i<actual;++i) {
                const std::array<int64_t,8> edges{-bound,-bound+1,-257,-1,0,1,255,bound-1};
                const int64_t value=(covered+i)<edges.size() ? edges[covered+i] : int64_t(random_word()%uint64_t(2*bound))-bound;
                const uint64_t address=first+i/columns*stride+i%columns;
                if(out.kind==1) out.small[address]=int16_t(value); else out.wide[address]=value;
                // Addition of the bias (rather than helper XOR) is an
                // independent codec oracle, with explicit LE lane order.
                const uint64_t biased=uint64_t(value+bound);
                for(unsigned j=0;j<out.width;++j)
                    out.scalar[(covered+i)*out.width+j]=(biased>>(8*(out.byte_first+j)))&255;
            }
            covered+=actual;
        }
    }
    return out;
}
template<class T> uint64_t bytes(const std::vector<T>& values) { return values.capacity()*sizeof(T); }
struct NativePlanes {
    std::array<std::vector<uint64_t>,3> values;
    explicit NativePlanes(size_t count) { for(auto& plane:values) plane.resize(count); }
    pcs::Planes output() { return {values[0].data(),values[1].data(),values[2].data()}; }
    pcs::ConstPlanes input() const { return {values[0].data(),values[1].data(),values[2].data()}; }
    uint64_t named_bytes() const { return bytes(values[0])+bytes(values[1])+bytes(values[2]); }
};
void check_case(unsigned dimension,unsigned first_fold,unsigned variant,unsigned codec,bool benchmark,Counters& counts) {
    const auto original=originals(dimension,codec);
    const unsigned remaining=dimension-first_fold;
    const uint64_t size=uint64_t{1}<<remaining;
    const auto prefix=point(first_fold,variant),suffix=point(remaining,variant);
    const auto started=std::chrono::steady_clock::now();
    std::vector<oracle::E> dense(uint64_t{1}<<dimension);
    for(uint64_t i=0;i<original.live;++i) dense[i]={{original.scalar[i],0,0}};
    for(const auto coordinate:prefix) oracle::fold(dense,coordinate);
    const auto oracle_done=std::chrono::steady_clock::now();
    const auto eq=prepare(prefix),singleton_eq=prepare(suffix);
    const pcs::Shape shape{original.live,dimension,remaining,eq.shape};
    const pcs::Shape singleton_shape{original.live,dimension,remaining,singleton_eq.shape};
    assert(pcs::valid(shape,pcs::Phase::retention) && pcs::valid(singleton_shape,pcs::Phase::singleton));
    double helper_seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-oracle_done).count();
    auto measure=[&](auto operation) {
        const auto before=std::chrono::steady_clock::now();
        operation();
        helper_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-before).count();
    };
    std::array<pcs::E,128> singleton{};
    std::array<oracle::E,128> expected_singleton{};
    measure([&]() { original.scan([&](uint64_t index,uint64_t value) {
        const uint64_t bucket=index>>remaining;
        const auto weight=pcs::lookup(index&(size-1),singleton_eq.chunks.data(),singleton_eq.shape.chunks,singleton_eq.values.data());
        singleton[bucket]=pcs::add(singleton[bucket],pcs::base_mul(weight,value));
    },counts); });
    for(uint64_t i=0;i<original.live;++i)
        expected_singleton[i>>remaining]=oracle::add(expected_singleton[i>>remaining],oracle::scale(oracle::eq(suffix,i&(size-1)),original.scalar[i]));
    for(unsigned i=0;i<128;++i) { assert(same(singleton[i],expected_singleton[i])); ++counts.singleton; }
    // Target reconstructed from the 128 scalar buckets and direct dense MLE.
    oracle::E target{},original_target{};
    std::vector<oracle::E> full_point=prefix;
    full_point.insert(full_point.end(),suffix.begin(),suffix.end());
    for(unsigned i=0;i<(1u<<first_fold);++i) target=oracle::add(target,oracle::mul(expected_singleton[i],oracle::eq(prefix,i)));
    for(uint64_t i=0;i<original.live;++i) original_target=oracle::add(original_target,oracle::scale(oracle::eq(full_point,i),original.scalar[i]));
    assert(same(native(target),original_target));

    NativePlanes retained(size);
    measure([&]() { original.scan([&](uint64_t index,uint64_t value) {
        const uint64_t at=pcs::folded_index(index,shape);
        const auto contribution=pcs::original_contribution(index,value,shape,eq.chunks.data(),eq.values.data());
        pcs::store(retained.output(),at,pcs::add(pcs::load(retained.input(),at),contribution));
    },counts); });
    for(uint64_t i=0;i<size;++i) { assert(same(pcs::load(retained.input(),i),dense[i])); ++counts.retained; }

    const oracle::E ood_point=variant==0 ? oracle::E{} : variant==1 ? oracle::E{{1,0,0}} : random_e();
    const pcs::PowerShape power_shape{remaining,(remaining+1)/2,0,0};
    assert(pcs::valid(power_shape));
    std::vector<pcs::E> low_powers(pcs::low_count(power_shape)),high_powers(pcs::high_count(power_shape));
    measure([&]() {
        for(uint64_t i=0;i<low_powers.size();++i) low_powers[i]=pcs::power(native(ood_point),i);
        for(uint64_t i=0;i<high_powers.size();++i) high_powers[i]=pcs::power(native(ood_point),i<<power_shape.low_bits);
    });
    for(uint64_t i=0;i<size;++i) assert(same(pcs::power_lookup(i,power_shape,low_powers.data(),high_powers.data()),oracle::power(ood_point,i)));
    std::array<pcs::E,256> ood_reduction{};
    measure([&]() { original.scan([&](uint64_t index,uint64_t value) {
        const auto contribution=pcs::original_contribution(index,value,shape,eq.chunks.data(),eq.values.data());
        const auto weight=pcs::power_lookup(pcs::folded_index(index,shape),power_shape,low_powers.data(),high_powers.data());
        ood_reduction[index%256]=pcs::add(ood_reduction[index%256],pcs::mul(contribution,weight));
    },counts);
        for(unsigned stride=128;stride;stride/=2) for(unsigned i=0;i<stride;++i)
            ood_reduction[i]=pcs::add(ood_reduction[i],ood_reduction[i+stride]);
    });
    oracle::E expected_ood{};
    for(uint64_t i=size;i;--i) expected_ood=oracle::add(oracle::mul(expected_ood,ood_point),dense[i-1]);
    assert(same(ood_reduction[0],expected_ood)); ++counts.ood;
    // The original mask suffix remains a separate CPU/public contribution;
    // combining it with the returned E agrees with full polynomial Horner.
    std::vector<oracle::E> mask(13); for(auto& value:mask) value=random_e();
    oracle::E mask_horner{};
    for(auto value=mask.rbegin();value!=mask.rend();++value) mask_horner=oracle::add(oracle::mul(mask_horner,ood_point),*value);
    const auto padded_ood=pcs::add(ood_reduction[0],pcs::mul(native(mask_horner),pcs::power(native(ood_point),size)));
    oracle::E full_horner=mask_horner;
    for(uint64_t i=size;i;--i) full_horner=oracle::add(oracle::mul(full_horner,ood_point),dense[i-1]);
    assert(same(padded_ood,full_horner));

    std::vector<uint64_t> ring,low,high;
    std::vector<pcs::E> pads;
    if(remaining>=2) {
        const uint64_t n=size/4;
        // Also test n<rows: pad j then occupies row (n+j)%rows.
        const uint64_t rows=variant==1 ? 2*std::min<uint64_t>(16,n) : std::max<uint64_t>(2,std::min<uint64_t>(64,n));
        const unsigned pad_rows=variant==0 ? 1 : variant==1 ? 13 : codec==4 ? 1536 : 512;
        unsigned cosets=2;
        while(uint64_t(cosets)*rows<16*n || uint64_t(cosets)*rows<n+pad_rows) cosets*=2;
        const unsigned first_coset=variant==0 ? 0 : variant==1 ? cosets-2 : cosets>=8 ? 6 : 0;
        const pcs::CosetShape geometry{rows,pad_rows,cosets,first_coset,0};
        assert(pcs::valid(geometry,shape));
        const uint64_t omega=oracle::power(7,(P-1)/(rows*cosets));
        low.resize(2*rows); high.resize(2*pcs::high_rows(shape,geometry));
        measure([&]() {
            for(uint64_t i=0;i<low.size();++i) low[i]=c71_pcs::power(omega,uint64_t(first_coset+i/rows)*(i%rows));
            for(uint64_t i=0;i<high.size();++i) high[i]=c71_pcs::power(omega,uint64_t(first_coset+i%2)*(i/2)*rows);
        });
        ring.resize(24*rows); pads.resize(4*pad_rows);
        for(auto& value:pads) value=native(random_e());
        pads.front()={}; pads.back()={1,0,0};
        measure([&]() { original.scan([&](uint64_t index,uint64_t scalar) {
            const uint64_t folded=pcs::folded_index(index,shape),within=folded%n;
            const unsigned column=unsigned(folded/n);
            const auto value=pcs::original_contribution(index,scalar,shape,eq.chunks.data(),eq.values.data());
            for(unsigned lane=0;lane<2;++lane) {
                const auto contribution=pcs::base_mul(value,high[(within/rows)*2+lane]);
                for(unsigned component=0;component<3;++component) {
                    const uint64_t at=pcs::ring_index(column,component,lane,within%rows,geometry);
                    ring[at]=fp_add(ring[at],pcs::limb(contribution,component));
                }
            }
        },counts); });
        measure([&]() {
            for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<2;++lane) for(uint64_t row=0;row<rows;++row)
                for(unsigned component=0;component<3;++component) {
                    const uint64_t at=pcs::ring_index(column,component,lane,row,geometry);
                    ring[at]=pcs::padded(ring[at],pads.data(),low.data(),high.data(),shape,geometry,column,component,row,lane);
                }
        });
        for(unsigned column=0;column<4;++column) for(unsigned lane=0;lane<2;++lane) for(uint64_t row=0;row<rows;++row) {
            oracle::E expected{};
            const uint64_t offset=oracle::power(omega,first_coset+lane);
            for(uint64_t j=row;j<n+pad_rows;j+=rows) {
                const oracle::E coefficient=j<n ? dense[uint64_t(column)*n+j] : oracle_value(pads[uint64_t(column)*pad_rows+j-n]);
                expected=oracle::add(expected,oracle::scale(coefficient,oracle::power(offset,j)));
            }
            for(unsigned component=0;component<3;++component) {
                const uint64_t at=pcs::ring_index(column,component,lane,row,geometry);
                assert(ring[at]==expected.c[component]); ++counts.ring;
            }
        }
    }
    // Capacity upper bound for named fixture allocations, not process RSS.
    // Include temporary EQ chunks and old vectors during their reallocation;
    // arithmetic/original construction peaks are smaller than this bound.
    // Allocator/runtime overhead and other stack objects are measured by the
    // serial process wrapper, never credited as zero by this named subtotal.
    const uint64_t preparation_extra=2*uint64_t(eq.shape.entries+singleton_eq.shape.entries)*sizeof(pcs::E)+
        2*8*sizeof(oracle::E)+2*5*sizeof(pcs::Chunk);
    uint64_t named=original.named_bytes()+bytes(dense)+bytes(prefix)+bytes(suffix)+bytes(full_point)+
        lookup_bytes(eq)+lookup_bytes(singleton_eq)+retained.named_bytes()+bytes(low_powers)+bytes(high_powers)+
        bytes(mask)+bytes(ring)+bytes(low)+bytes(high)+bytes(pads)+preparation_extra;
    if(remaining) for(unsigned rounds=1;rounds<=std::min<unsigned>(2,remaining);++rounds) for(unsigned choice=0;choice<3;++choice) {
        const auto r0=choice==0 ? oracle::E{} : choice==1 ? oracle::E{{1,0,0}} : random_e();
        const auto r1=choice==0 ? oracle::E{{1,0,0}} : choice==1 ? oracle::E{} : random_e();
        assert(pcs::valid_fold(size,rounds,native(r0),native(r1)));
        auto expected=dense;
        oracle::fold(expected,r0); if(rounds==2) oracle::fold(expected,r1);
        NativePlanes output(size>>rounds);
        measure([&]() {
            for(uint64_t i=0;i<expected.size();++i)
                pcs::store(output.output(),i,pcs::folded_at(retained.input(),size,i,rounds,native(r0),native(r1)));
        });
        for(uint64_t i=0;i<expected.size();++i) {
            assert(same(pcs::load(output.input(),i),expected[i])); ++counts.fold;
        }
        counts.max_named_heap=std::max(counts.max_named_heap,named+bytes(expected)+output.named_bytes());
    }
    counts.max_named_heap=std::max(counts.max_named_heap,named);
    ++counts.cases;
    if(benchmark) {
        // Checked host simulation: public EQ preparation, four fused scans,
        // pad/fold helpers, scalar codec assertions and counters are timed.
        // This is not an isolated kernel benchmark or a CUDA speed estimate.
        const double oracle_seconds=std::chrono::duration<double>(oracle_done-started).count();
        const double total_seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
        std::printf("C71_PCS_RESIDUAL_BENCH {\"dimension\":%u,\"remaining\":%u,\"live\":%llu,\"codec\":%u,\"dense_fold_oracle_host_s\":%.9f,\"checked_fixture_helper_phases_host_s\":%.9f,\"other_oracle_checks_and_fixture_overhead_host_s\":%.9f,\"named_heap_upper_bytes\":%llu,\"stack_array_bytes\":%zu,\"original_scans\":4,\"gpu_execution\":false,\"integrated\":false,\"credit\":false}\n",
            dimension,remaining,static_cast<unsigned long long>(original.live),codec,
            oracle_seconds,helper_seconds,total_seconds-oracle_seconds-helper_seconds,
            static_cast<unsigned long long>(named),sizeof(singleton)+sizeof(expected_singleton)+sizeof(ood_reduction));
    }
}

void rejections(Counters& counts) {
    auto reject=[&](bool value) { assert(!value); ++counts.rejected; };
    auto eq=prepare(point(9,2));
    assert(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data()));
    eq.chunks[0].reserved=1; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); eq.chunks[0].reserved=0;
    ++eq.chunks[0].shift; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); --eq.chunks[0].shift;
    ++eq.chunks[1].first; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); --eq.chunks[1].first;
    eq.values[0].c2=P; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); eq.values[0].c2=0;
    ++eq.shape.entries; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); --eq.shape.entries;
    eq.shape.reserved=1; reject(pcs::valid_packet(eq.shape,eq.chunks.data(),eq.values.data())); eq.shape.reserved=0;
    auto shape=pcs::Shape{123,16,7,eq.shape};
    assert(pcs::valid(shape,pcs::Phase::retention));
    reject(pcs::valid(shape,static_cast<pcs::Phase>(4)));
    auto invalid=shape; invalid.dimension=36; reject(pcs::valid(invalid,pcs::Phase::retention));
    invalid=shape; invalid.remaining=17; reject(pcs::valid(invalid,pcs::Phase::retention));
    invalid=shape; invalid.live=(uint64_t{1}<<16)+1; reject(pcs::valid(invalid,pcs::Phase::retention));
    invalid=shape; invalid.equality.bits=8; reject(pcs::valid(invalid,pcs::Phase::retention));
    reject(pcs::valid(pcs::Shape{1,16,8,{8,1,256,0}},pcs::Phase::singleton)); // first-fold 8 unsupported
    reject(pcs::valid(pcs::Shape{1,16,16,{16,2,512,0}},pcs::Phase::singleton)); // first-fold 0
    reject(pcs::valid(pcs::Shape{1,2,1,{1,1,2,0}},pcs::Phase::cosets));
    reject(pcs::valid(pcs::PowerShape{35,17,0,0}));
    reject(pcs::valid(pcs::PowerShape{36,18,0,0}));
    reject(pcs::valid(pcs::PowerShape{7,4,1,0}));
    reject(pcs::valid_fold(8,0,{1,0,0},{}));
    reject(pcs::valid_fold(8,3,{1,0,0},{}));
    reject(pcs::valid_fold(6,1,{1,0,0},{}));
    reject(pcs::valid_fold(2,2,{1,0,0},{1,0,0}));
    reject(pcs::valid_fold(8,1,{P,0,0},{}));
    reject(pcs::valid_fold(8,2,{1,0,0},{0,P,0}));
    uint64_t scalar=0;
    reject(pcs::weight_scalar(INT16_MIN,scalar));
    for(int value:{-32767,-1,0,1,32767}) {
        assert(pcs::weight_scalar(int16_t(value),scalar));
        assert(scalar==(value<0 ? P-uint64_t(-value) : uint64_t(value))); ++counts.codec;
    }
    uint8_t byte=0;
    assert(c71_byte::encode(INT16_MIN,2,1,byte) && byte==0); ++counts.codec;
    reject(c71_byte::encode(int64_t{1}<<47,6,5,byte));
    reject(c71_byte::encode(-(int64_t{1}<<47)-1,6,5,byte));
    reject(c71_byte::encode(INT64_MIN,6,0,byte));
    uint64_t a[8]{},b[8]{},c[8]{},high[8]{};
    pcs::E reduced[128]{},powers_low[16]{},powers_high[8]{};
    const pcs::Output retain{{a,b,c},nullptr,nullptr},singleton{{},nullptr,reduced},cosets{{},a,nullptr};
    assert(pcs::valid_output(pcs::Phase::retention,retain));
    reject(pcs::valid_output(pcs::Phase::retention,{{a,a,c},nullptr,nullptr}));
    reject(pcs::valid_output(pcs::Phase::retention,{{a,b,c},a,nullptr}));
    reject(pcs::valid_output(pcs::Phase::singleton,{{a,b,c},nullptr,reduced}));
    reject(pcs::valid_output(pcs::Phase::cosets,{{},a,reduced}));
    reject(pcs::valid_output(static_cast<pcs::Phase>(99),singleton));
    assert(pcs::valid_arguments(shape,pcs::Phase::retention,retain,eq.chunks.data(),eq.values.data(),{},nullptr,{},nullptr,nullptr));
    reject(pcs::valid_arguments(shape,pcs::Phase::retention,retain,eq.chunks.data(),eq.values.data(),{},high,{},nullptr,nullptr));
    reject(pcs::valid_arguments(shape,pcs::Phase::retention,retain,nullptr,eq.values.data(),{},nullptr,{},nullptr,nullptr));
    reject(pcs::valid_arguments(shape,pcs::Phase::ood,singleton,eq.chunks.data(),eq.values.data(),{},nullptr,{7,4,0,0},powers_low,powers_low));
    assert(pcs::valid_arguments(shape,pcs::Phase::ood,singleton,eq.chunks.data(),eq.values.data(),{},nullptr,{7,4,0,0},powers_low,powers_high));
    auto geometry=pcs::CosetShape{8,13,64,62,0};
    assert(pcs::valid(geometry,shape));
    assert(pcs::valid_arguments(shape,pcs::Phase::cosets,cosets,eq.chunks.data(),eq.values.data(),geometry,high,{},nullptr,nullptr));
    ++geometry.first_coset; reject(pcs::valid(geometry,shape)); --geometry.first_coset;
    geometry.first_coset=64; reject(pcs::valid(geometry,shape)); geometry.first_coset=62;
    geometry.rows=uint64_t{1}<<24; reject(pcs::valid(geometry,shape)); geometry.rows=8;
    geometry.cosets=1; reject(pcs::valid(geometry,shape)); geometry.cosets=64;
    geometry.pad_rows=1537; reject(pcs::valid(geometry,shape));
    // Canonical metadata only. No D34/D35 vectors are allocated by this test.
    assert(pcs::valid(pcs::CosetShape{uint64_t{1}<<23,512,64,62,0},pcs::Shape{1,34,27,{7,1,128,0}}));
    assert(pcs::valid(pcs::CosetShape{uint64_t{1}<<23,512,128,126,0},pcs::Shape{1,35,28,{7,1,128,0}}));
    assert(pcs::valid_fold(uint64_t{1}<<28,2,{0,1,0},{0,0,1}));
}


void resident_and_contract_checks() {
    uint64_t mappings=0,visits=0,algebra=0,pads=0;
    for(unsigned dimension:{3u,7u,11u}) for(unsigned prefix:{0u,1u,2u})
        for(unsigned kind:{0u,1u}) for(unsigned capacity:{1u,3u,7u,64u})
            for(uint64_t live:{uint64_t{1},(uint64_t{1}<<dimension)-3,uint64_t{1}<<dimension}) {
                const unsigned remaining=dimension-prefix;
                const auto coordinates=point(prefix,2); const auto packet=prepare(coordinates);
                const auto shape=pcs::Shape{live,dimension,remaining,packet.shape};
                const uint64_t length=uint64_t{1}<<(remaining-kind);
                std::vector<unsigned> seen(live);
                uint64_t counted=0;
                for(uint64_t start=0;start<length;start+=capacity) {
                    const uint32_t count=uint32_t(std::min<uint64_t>(capacity,length-start));
                    uint64_t band_visits=0;
                    for(uint64_t task=0;task<pcs::contract_tasks(shape,kind,count);++task) {
                        const auto index=pcs::contract_index(task,shape,kind,start,count);
                        assert((index&(length-1))>=start && (index&(length-1))<start+count);
                        if(index>=live) continue;
                        ++seen[index]; ++band_visits;
                        const auto original=random_e(),lower=random_e(),upper=random_e();
                        const auto value=oracle::mul(original,oracle::eq(coordinates,index>>remaining));
                        assert(same(pcs::retained_contribution(index,native(original),shape,packet.chunks.data(),packet.values.data()),value));
                        const auto actual=pcs::contract_contribution(index,native(value),remaining,kind,native(lower),native(upper));
                        oracle::E expected0{},expected2{};
                        if(!kind) expected0=oracle::mul(value,lower);
                        else if(index&(uint64_t{1}<<(remaining-1))) expected2=oracle::mul(value,oracle::sub(upper,lower));
                        else { expected0=oracle::mul(value,lower); expected2=oracle::sub(oracle::E{},oracle::mul(value,oracle::sub(upper,lower))); }
                        assert(same(actual.value[0],expected0) && same(actual.value[1],expected2)); ++algebra;
                    }
                    assert(band_visits==pcs::contract_band_visits(shape,kind,start,count)); counted+=band_visits;
                }
                assert(counted==live); for(auto count:seen) assert(count==1);
                ++mappings; visits+=counted;
            }
    for(const auto value:{oracle::E{},oracle::E{{1,0,0}},oracle::E{{0,1,0}},oracle::E{{0,0,1}},random_e()})
        for(const auto coefficient:{oracle::E{},oracle::E{{1,0,0}},random_e()})
            for(uint64_t index:{uint64_t{0},uint64_t{1},uint64_t{127},(uint64_t{1}<<28)+1535,(uint64_t{1}<<35)+1048575}) {
                assert(same(pcs::pad_contribution(native(coefficient),native(value),index),oracle::mul(coefficient,oracle::power(value,index)))); ++pads;
            }
    // Analytic D35 bounds only: enumerate 64 public bands, no W allocation.
    const auto shape=pcs::Shape{(uint64_t{1}<<35)-1,35,28,{7,1,128,0}};
    uint64_t counted=0;
    for(uint64_t start=0;start<(uint64_t{1}<<27);start+=uint64_t{1}<<21)
        counted+=pcs::contract_band_visits(shape,1,start,1u<<21);
    assert(counted==shape.live);
    std::printf("C71_PCS_RESIDUAL_RESIDENT_CONTRACT {\"mapping_cases\":%llu,\"original_visits\":%llu,\"algebra_cases\":%llu,\"ood_pad_cases\":%llu,\"contract_shared_bytes\":%zu,\"D35_analytic_visits\":%llu,\"W_full_scans_per_round\":1,\"public_tail_reads\":0,\"gpu_execution\":false,\"credit\":false}\n",
        static_cast<unsigned long long>(mappings),static_cast<unsigned long long>(visits),static_cast<unsigned long long>(algebra),
        static_cast<unsigned long long>(pads),pcs::contract_shared_bytes,static_cast<unsigned long long>(counted));
}

int main() {
    Counters counts;
    check_arithmetic(counts);
    for(unsigned first_fold=1;first_fold<=7;++first_fold) for(unsigned variant=0;variant<3;++variant)
        check_case(first_fold+3,first_fold,variant,0,false,counts);
    for(unsigned codec=0;codec<=4;++codec) for(unsigned variant=0;variant<3;++variant)
        check_case(11,7,variant,codec,false,counts);
    for(unsigned variant=0;variant<3;++variant) check_case(7,7,variant,1,false,counts);
    check_case(15,7,2,0,true,counts);
    check_case(17,7,2,3,true,counts);
    rejections(counts);
    resident_and_contract_checks();
    std::printf("C71_PCS_RESIDUAL_HOST {\"arithmetic_cases\":%llu,\"equality_cases\":%llu,\"phase_cases\":%llu,\"original_scans\":%llu,\"input_word_loads\":%llu,\"original_visits\":%llu,\"singleton_outputs\":%llu,\"retained_outputs\":%llu,\"ood_outputs\":%llu,\"coset_prefft_words\":%llu,\"fold_outputs\":%llu,\"codec_checks\":%llu,\"rejections\":%llu,\"named_heap_upper_max_bytes\":%llu,\"singleton_shared_bytes\":%zu,\"ood_shared_bytes\":%zu,\"PCS_basis_v3_v1\":true,\"max_dimension\":35,\"max_coset_log_rows\":23,\"gpu_execution\":false,\"integrated\":false,\"credit\":false}\n",
        static_cast<unsigned long long>(counts.arithmetic),static_cast<unsigned long long>(counts.equality),static_cast<unsigned long long>(counts.cases),
        static_cast<unsigned long long>(counts.scans),static_cast<unsigned long long>(counts.loads),static_cast<unsigned long long>(counts.original_visits),
        static_cast<unsigned long long>(counts.singleton),static_cast<unsigned long long>(counts.retained),static_cast<unsigned long long>(counts.ood),
        static_cast<unsigned long long>(counts.ring),static_cast<unsigned long long>(counts.fold),static_cast<unsigned long long>(counts.codec),
        static_cast<unsigned long long>(counts.rejected),static_cast<unsigned long long>(counts.max_named_heap),pcs::singleton_shared_bytes,pcs::ood_shared_bytes);
}
