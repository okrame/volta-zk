// Independent dense original/folded products; no CUDA execution or scheduling.
#include "c71_linear_native.cuh"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <vector>

namespace oracle {
using Wide=unsigned __int128;
uint64_t plus(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+b)%P); }
uint64_t minus(uint64_t a,uint64_t b) { return uint64_t((Wide(a)+P-b)%P); }
uint64_t times(uint64_t a,uint64_t b) { return uint64_t((Wide(a)*b)%P); }
Fp3 add(Fp3 a,Fp3 b) { return {plus(a.c0,b.c0),plus(a.c1,b.c1),plus(a.c2,b.c2)}; }
Fp3 sub(Fp3 a,Fp3 b) { return {minus(a.c0,b.c0),minus(a.c1,b.c1),minus(a.c2,b.c2)}; }
Fp3 mul(Fp3 a,Fp3 b) {
    const uint64_t left[]={a.c0,a.c1,a.c2},right[]={b.c0,b.c1,b.c2};
    uint64_t out[3]{};
    for(unsigned i=0;i<3;++i) for(unsigned j=0;j<3;++j) {
        uint64_t term=times(left[i],right[j]);
        if(i+j>=3) term=plus(term,term);
        out[(i+j)%3]=plus(out[(i+j)%3],term);
    }
    return {out[0],out[1],out[2]};
}
Fp3 eq(const std::vector<Fp3>& point,uint64_t index) {
    Fp3 value{1,0,0};
    for(size_t i=0;i<point.size();++i)
        value=oracle::mul(value,((index>>(point.size()-1-i))&1) ? point[i] : oracle::sub(Fp3{1,0,0},point[i]));
    return value;
}
void fold(std::vector<Fp3>& values,Fp3 r) {
    const size_t half=values.size()/2;
    for(size_t i=0;i<half;++i) values[i]=oracle::add(values[i],oracle::mul(r,oracle::sub(values[i+half],values[i])));
    values.resize(half);
}
}
bool same(Fp3 a,Fp3 b) { return a.c0==b.c0 && a.c1==b.c1 && a.c2==b.c2; }
struct Cube { uint64_t offset; std::vector<Fp3> point; Fp3 coefficient; };
struct Prepared {
    c71_linear::Shape shape{};
    std::vector<c71_linear::Chunk> chunks;
    std::vector<Fp3> tables,points;
    std::vector<c71_linear::Group> groups;
    std::vector<c71_linear::Interval> intervals;
};
Prepared prepare(unsigned bits,uint64_t live,const std::vector<Fp3>& prefix,
    const std::vector<Cube>& cubes) {
    Prepared p;
    const unsigned remaining=bits-unsigned(prefix.size());
    p.shape={live,bits,remaining,0,0,0,0};
    for(size_t first=0;first<prefix.size();first+=8) {
        const size_t count=std::min<size_t>(8,prefix.size()-first);
        std::vector<Fp3> chunk(prefix.begin()+first,prefix.begin()+first+count);
        p.chunks.push_back({unsigned(prefix.size()-first-count),unsigned(count),unsigned(p.tables.size()),0});
        for(uint64_t i=0;i<(uint64_t{1}<<count);++i) p.tables.push_back(oracle::eq(chunk,i));
    }
    const uint64_t half=uint64_t{1}<<(remaining-1);
    std::vector<std::vector<c71_linear::Interval>> levels(remaining);
    for(const auto& cube:cubes) {
        const size_t fixed=bits-cube.point.size();
        Fp3 gamma=cube.coefficient;
        for(size_t i=0;i<std::min(prefix.size(),fixed);++i)
            gamma=oracle::mul(gamma,(cube.offset>>(bits-1-i))&1 ? prefix[i] : oracle::sub(Fp3{1,0,0},prefix[i]));
        for(size_t i=fixed;i<prefix.size();++i) {
            const Fp3 r=prefix[i],q=cube.point[i-fixed];
            gamma=oracle::mul(gamma,oracle::add(oracle::mul(oracle::sub(Fp3{1,0,0},r),oracle::sub(Fp3{1,0,0},q)),oracle::mul(r,q)));
        }
        if(same(gamma,Fp3{})) continue;
        std::vector<Fp3> point;
        Fp3 lower{},upper{};
        uint64_t offset=0;
        if(prefix.size()>=fixed) {
            const size_t next=prefix.size()-fixed;
            const Fp3 q=cube.point[next];
            point.assign(cube.point.begin()+next+1,cube.point.end());
            lower=oracle::mul(gamma,oracle::sub(Fp3{1,0,0},q)); upper=oracle::mul(gamma,q);
        } else {
            point=cube.point; offset=cube.offset&(half-1);
            if(cube.offset&half) upper=gamma; else lower=gamma;
        }
        c71_linear::Interval interval{offset>>point.size(),unsigned(p.points.size()),unsigned(point.size()),lower,upper};
        p.points.insert(p.points.end(),point.begin(),point.end());
        levels[point.size()].push_back(interval);
    }
    for(unsigned level=0;level<remaining;++level) {
        auto& intervals=levels[level];
        if(intervals.empty()) continue;
        std::sort(intervals.begin(),intervals.end(),[](const auto& a,const auto& b) { return a.index<b.index; });
        p.groups.push_back({level,unsigned(p.intervals.size()),unsigned(intervals.size()),0});
        p.intervals.insert(p.intervals.end(),intervals.begin(),intervals.end());
    }
    p.shape.chunks=unsigned(p.chunks.size()); p.shape.groups=unsigned(p.groups.size());
    p.shape.intervals=unsigned(p.intervals.size()); p.shape.points=unsigned(p.points.size());
    assert(c71_linear::valid(p.shape));
    assert(c71_linear::valid_packet(p.shape,p.chunks.data(),p.tables.data(),unsigned(p.tables.size()),
        p.groups.data(),p.intervals.data(),p.points.data()));
    return p;
}
uint64_t state=0x9033c64;
uint64_t random_word() { state^=state<<13; state^=state>>7; state^=state<<17; return state<P ? state : state-P; }
Fp3 random_field() { return {random_word(),random_word(),random_word()}; }
void check(unsigned bits,uint64_t live,const std::vector<Cube>& cubes,std::vector<Fp3> prefix,
    uint64_t& cases,uint64_t& visits,bool benchmark=false) {
    const auto started=std::chrono::steady_clock::now();
    const size_t length=size_t{1}<<bits;
    std::vector<Fp3> original(length),weights(length);
    for(size_t i=0;i<live;++i) original[i]={i%11==0 ? 0 : random_word(),0,0};
    for(const auto& cube:cubes) for(size_t i=0;i<(size_t{1}<<cube.point.size());++i)
        weights[cube.offset+i]=oracle::add(weights[cube.offset+i],oracle::mul(cube.coefficient,oracle::eq(cube.point,i)));
    auto folded=original;
    for(const auto r:prefix) { oracle::fold(folded,r); oracle::fold(weights,r); }
    c71_linear::Result expected{};
    const size_t half=folded.size()/2;
    for(size_t i=0;i<half;++i) {
        const Fp3 a=folded[i],delta=oracle::sub(folded[i+half],a);
        const Fp3 b=weights[i],difference=oracle::sub(weights[i+half],b);
        expected.values[0]=oracle::add(expected.values[0],oracle::mul(a,b));
        expected.values[1]=oracle::add(expected.values[1],oracle::add(oracle::mul(a,difference),oracle::mul(delta,b)));
        expected.values[2]=oracle::add(expected.values[2],oracle::mul(delta,difference));
    }
    if(half==1) { expected.values[3]=folded[0]; expected.values[4]=folded[1]; }
    const auto oracle_done=std::chrono::steady_clock::now();
    const auto prepared=prepare(bits,live,prefix,cubes);
    c71_linear::Result got{};
    // An odd multiplier permutes the domain; public zero suffix is not emitted.
    for(size_t j=0;j<length;++j) {
        const size_t i=(j*37)&(length-1);
        if(i>=live) continue;
        got=c71_linear::sum(got,c71_linear::contribution(i,original[i].c0,prepared.shape,
            prepared.chunks.data(),prepared.tables.data(),prepared.groups.data(),prepared.intervals.data(),prepared.points.data()));
        ++visits;
    }
    for(unsigned i=0;i<5;++i) assert(same(got.values[i],expected.values[i]));
    ++cases;
    if(benchmark) {
        const auto done=std::chrono::steady_clock::now();
        std::printf("C71_LINEAR_NATIVE_BENCH {\"dimension\":%u,\"live\":%llu,\"prefix_bits\":%zu,\"public_cubes\":%zu,\"dense_oracle_host_s\":%.9f,\"helper_prepare_and_scan_host_s\":%.9f,\"gpu_execution\":false,\"credit\":false}\n",
            bits,static_cast<unsigned long long>(live),prefix.size(),cubes.size(),
            std::chrono::duration<double>(oracle_done-started).count(),
            std::chrono::duration<double>(done-oracle_done).count());
    }
}
int main() {
    uint64_t cases=0,visits=0;
    for(unsigned bits=1;bits<=10;++bits) for(unsigned variant=0;variant<3;++variant) {
        std::vector<Cube> cubes;
        for(unsigned i=0;i<8;++i) {
            const unsigned size=i%(bits+1),choices=bits-size;
            Cube cube{(random_word()&((uint64_t{1}<<choices)-1))<<size,{},random_field()};
            for(unsigned j=0;j<size;++j) cube.point.push_back(variant==0 ? Fp3{} : variant==1 ? Fp3{1,0,0} : random_field());
            cubes.push_back(cube);
            if(i==3) cubes.push_back(cube); // repeated and overlapping public forms
        }
        std::vector<Fp3> prefix;
        for(unsigned round=0;round<bits;++round) {
            const uint64_t length=uint64_t{1}<<bits;
            check(bits,length>variant+1 ? length-(variant+1) : 1,cubes,prefix,cases,visits);
            prefix.push_back(variant==0 ? Fp3{} : variant==1 ? Fp3{1,0,0} : random_field());
        }
    }
    for(unsigned bits: {9u,17u,25u,35u}) {
        std::vector<Fp3> prefix(bits-1,Fp3{P-1,P-2,P-3});
        const auto p=prepare(bits,3,prefix,{});
        assert(p.shape.chunks==(bits+6)/8 && p.groups.empty());
        for(uint64_t i=0;i<3;++i) {
            const Fp3 expected=oracle::eq(prefix,i>>1);
            assert(same(c71_linear::prefix_weight(i>>1,p.chunks.data(),p.shape.chunks,p.tables.data()),expected));
        }
    }
    for(unsigned bits: {15u,17u}) {
        std::vector<Cube> cubes;
        for(unsigned i=0;i<8;++i) {
            Cube cube{0,{},random_field()};
            for(unsigned j=0;j<bits-i/2;++j) cube.point.push_back(random_field());
            cubes.push_back(cube);
        }
        std::vector<Fp3> prefix(6);
        for(auto& point:prefix) point=random_field();
        check(bits,(uint64_t{1}<<bits)-3,cubes,prefix,cases,visits,true);
    }
    // Metadata only: every CPU-admitted cube may retain 34 coordinates in D35.
    assert(c71_linear::valid({1,35,35,0,1,524288,524288u*34}));
    auto packet=prepare(3,8,{Fp3{2,3,4}},{{0,{Fp3{5,6,7},Fp3{8,9,10},Fp3{11,12,13}},Fp3{1,0,0}}});
    auto packet_valid=[&]() {
        return c71_linear::valid_packet(packet.shape,packet.chunks.data(),packet.tables.data(),unsigned(packet.tables.size()),
            packet.groups.data(),packet.intervals.data(),packet.points.data());
    };
    assert(packet_valid());
    packet.chunks[0].reserved=1; assert(!packet_valid()); packet.chunks[0].reserved=0;
    ++packet.chunks[0].shift; assert(!packet_valid()); --packet.chunks[0].shift;
    packet.tables[0].c0=P; assert(!packet_valid()); packet.tables[0].c0=0;
    packet.groups[0].reserved=1; assert(!packet_valid()); packet.groups[0].reserved=0;
    ++packet.groups[0].first; assert(!packet_valid()); --packet.groups[0].first;
    ++packet.intervals[0].bits; assert(!packet_valid()); --packet.intervals[0].bits;
    packet.intervals[0].first=packet.shape.points+1; assert(!packet_valid()); packet.intervals[0].first=0;
    packet.intervals[0].index=2; assert(!packet_valid()); packet.intervals[0].index=0;
    packet.intervals[0].lower.c2=P; assert(!packet_valid()); packet.intervals[0].lower.c2=0;
    packet.points[0].c0=P; assert(!packet_valid()); packet.points[0].c0=0;
    assert(c71_linear::shared_bytes==30720);
    assert(!c71_linear::valid({1,0,1,0,0,0,0}));
    assert(!c71_linear::valid({1,36,1,0,0,0,0}));
    assert(!c71_linear::valid({3,1,1,0,0,0,0}));
    assert(!c71_linear::valid({1,1,0,0,0,0,0}));
    assert(!c71_linear::valid({1,1,1,6,0,0,0}));
    assert(!c71_linear::valid({1,1,1,0,2,1,0}));
    std::printf("C71_LINEAR_NATIVE_HOST {\"cases\":%llu,\"original_visits\":%llu,\"max_dimension\":35,\"shared_bytes\":30720,\"rejections\":16,\"MAC_basis_u3_2\":true,\"gpu_execution\":false,\"credit\":false}\n",
        static_cast<unsigned long long>(cases),static_cast<unsigned long long>(visits));
}
