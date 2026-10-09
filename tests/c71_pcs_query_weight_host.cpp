// Independent signed-W loader parity and reduced host benchmark.
// CUDA, the owner and production remainder arithmetic are not executed here.
#include "c71_pcs_query.cuh"
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>
using c71_pcs::QueryBlock;
using c71_pcs::WeightTile;
static constexpr uint64_t modulus=0xffffffff00000001ULL;
namespace oracle {
uint64_t add(uint64_t a,uint64_t b) {
    return uint64_t((static_cast<unsigned __int128>(a)+b)%modulus);
}
uint64_t mul(uint64_t a,uint64_t b) {
    return uint64_t((static_cast<unsigned __int128>(a)*b)%modulus);
}
uint64_t signed_value(int16_t value) {
    const int64_t original=value;
    return original<0 ? uint64_t(static_cast<__int128>(modulus)+original) : uint64_t(original);
}
uint64_t decode(const std::vector<int16_t>& weights,const std::vector<WeightTile>& tiles,uint64_t logical) {
    for(const auto& tile:tiles) if(logical>=tile.first && logical-tile.first<tile.count) {
        const auto local=logical-tile.first;
        const auto address=tile.packed_first+local/tile.columns*tile.packed_stride+local%tile.columns;
        assert(address<weights.size());return signed_value(weights[size_t(address)]);
    }
    assert(false);return 0;
}
uint64_t horner(const std::vector<uint64_t>& coefficients,uint64_t point) {
    uint64_t result=0;
    for(auto it=coefficients.rbegin();it!=coefficients.rend();++it)result=add(mul(result,point),*it);
    return result;
}
}
struct Counts {
    uint64_t cases=0,outputs=0,reads=0,pads=0,zeros=0,horner=0,blocks=0,rejections=0;
    uint64_t named_heap=0;
} counts;
void exercise(const std::vector<int16_t>& weights,const std::vector<WeightTile>& tiles,
    uint64_t n,unsigned columns,unsigned pad_rows,unsigned capacity,bool split) {
    const uint64_t live=weights.size();std::vector<uint64_t> pads(uint64_t(columns)*pad_rows),low(capacity),
        original(live),expected(n+pad_rows),actual(n+pad_rows);
    for(size_t i=0;i<original.size();++i)original[i]=oracle::decode(weights,tiles,i);
    for(size_t i=0;i<pads.size();++i)pads[i]=i%5==0?0:i%5==1?1:i%5==2?modulus-1:i%5==3?uint64_t{1}<<32:19+i;
    const uint64_t heap=weights.capacity()*sizeof(int16_t)+tiles.capacity()*sizeof(WeightTile)+
        (pads.capacity()+low.capacity()+original.capacity()+expected.capacity()+actual.capacity())*sizeof(uint64_t);
    counts.named_heap=std::max(counts.named_heap,heap);
    const uint64_t read_before=counts.reads;
    for(unsigned column=0;column<columns;++column) {
        const uint64_t first=uint64_t(column)*n;
        const uint64_t active=std::min(n,live>first?live-first:0);
        std::fill(expected.begin(),expected.end(),0);std::fill(actual.begin(),actual.end(),0);
        for(uint64_t row=0;row<active;++row)expected[row]=original[first+row];
        for(unsigned row=0;row<pad_rows;++row)expected[n+row]=pads[uint64_t(column)*pad_rows+row];
        const auto load=[&](uint64_t source_rows,bool pad_only,uint64_t destination) {
            for(uint64_t block=0;block<(source_rows+capacity-1)/capacity;++block) {
                const QueryBlock shape{block*capacity,source_rows,n,pad_only?0:active,first,0,uint64_t(column)*pad_rows,pad_rows,uint32_t(pad_only)};
                assert(c71_pcs::valid_query_weight_low(shape,capacity,live,pads.size()));++counts.blocks;
                for(unsigned i=0;i<capacity;++i) {
                    const auto row=shape.first+i;
                    low[i]=c71_pcs::query_weight_low_at(weights.data(),tiles.data(),tiles.size(),live,pads.data(),shape,row);
                    uint64_t reference=0;
                    if(row<source_rows) {
                        if(pad_only) { reference=pads[uint64_t(column)*pad_rows+row];++counts.pads; }
                        else if(row<active) { reference=original[first+row];++counts.reads; }
                        else if(row>=n) { reference=pads[uint64_t(column)*pad_rows+row-n];++counts.pads; }
                        else ++counts.zeros;
                        actual[destination+row]=low[i];
                    } else ++counts.zeros;
                    assert(low[i]==reference && low[i]<modulus);++counts.outputs;
                }
            }
        };
        if(split) { load(active,false,0);load(pad_rows,true,n); }
        else load(n+pad_rows,false,0);
        assert(actual==expected);
        // Every block is reassembled in protocol coefficient order. Horner uses
        // only the independently decoded coefficients and integer modulo oracle.
        for(uint64_t point:{uint64_t{0},uint64_t{1},modulus-1,uint64_t{7}}) {
            assert(oracle::horner(actual,point)==oracle::horner(expected,point));++counts.horner;
        }
        ++counts.cases;
    }
    assert(counts.reads-read_before==std::min(live,uint64_t(columns)*n));
}
void guard_checks() {
    QueryBlock good{0,11,8,8,0,0,0,3,0};
    assert(c71_pcs::valid_query_weight_low(good,8,12,128*3));
    for(unsigned fault=0;fault<25;++fault) {
        auto shape=good;uint64_t capacity=8,live=12,pad_count=128*3;
        switch(fault) {
        case 0:capacity=0;break;case 1:capacity=3;break;case 2:capacity=uint64_t{1}<<21;break;
        case 3:shape.message_rows=0;break;case 4:shape.message_rows=3;break;
        case 5:shape.message_rows=uint64_t{1}<<29;break;case 6:live=0;break;case 7:live=128*8+1;break;
        case 8:shape.pad_only=2;break;case 9:shape.window_first=1;break;case 10:shape.pad_rows=0;break;
        case 11:shape.pad_rows=1537;break;case 12:shape.byte_first=1;break;
        case 13:shape.byte_first=128*8;shape.pad_first=128*3;shape.active=0;break;
        case 14:shape.pad_first=1;break;case 15:pad_count=2;break;case 16:shape.first=1;break;
        case 17:shape.first=16;break;case 18:shape.active=9;break;case 19:shape.active=0;break;
        case 20:shape.source_rows=9;break;case 21:shape.pad_only=1;shape.source_rows=3;break;
        case 22:shape.pad_only=1;shape.active=0;shape.source_rows=4;break;
        case 23:shape.byte_first=8;shape.pad_first=3;shape.active=8;break;
        case 24:shape.source_rows=0;break;
        }
        assert(!c71_pcs::valid_query_weight_low(shape,capacity,live,pad_count));++counts.rejections;
    }
}
void sparse_domain35() {
    constexpr uint64_t n=uint64_t{1}<<28,live=8;
    const std::vector<int16_t> weights{0,1,-1,32767,-32767,2,-2,3};
    const WeightTile tiles[]{ {0,8,0,2,2} };const uint64_t pads[]{0,1,modulus-1};
    // Last column uses a separate logical pad array offset; no actual read is
    // made because the checked block lies wholly in the public zero suffix.
    for(unsigned capacity:{1u,8u,512u,1u<<20}) {
        for(unsigned column:{0u,127u}) {
            QueryBlock shape{0,n+3,n,column?0:live,uint64_t(column)*n,0,uint64_t(column)*3,3,0};
            assert(c71_pcs::valid_query_weight_low(shape,capacity,live,128*3));
            for(uint64_t row:{uint64_t{0},uint64_t{7},uint64_t{8},n-1}) {
                const auto got=c71_pcs::query_weight_low_at(weights.data(),tiles,1,live,pads,shape,row);
                assert(got==(column==0 && row<live?oracle::signed_value(weights[row]):0));++counts.outputs;
            }
            shape.first=n;
            assert(c71_pcs::valid_query_weight_low(shape,capacity,live,128*3));
            if(column==0)for(unsigned row=0;row<3;++row)
                assert(c71_pcs::query_weight_low_at(nullptr,nullptr,0,live,pads,shape,n+row)==pads[row]);
            assert(c71_pcs::query_weight_low_at(nullptr,nullptr,0,live,nullptr,shape,n+3)==0);
        }
    }
}
int main() {
    guard_checks();sparse_domain35();
    // Ragged original live length and interleaved packed matrices, including
    // public zero columns, signed extrema and the pad-only split path.
    const std::vector<int16_t> small{0,1,-1,32767,-32767,2,-2,3,5,-5,7,-7};
    const std::vector<WeightTile> small_tiles{{0,8,0,2,2},{8,4,8,2,2}};
    for(unsigned n:{1u,2u,4u,8u,16u})for(unsigned capacity:{1u,8u,32u})for(bool split:{false,true})
        exercise(small,small_tiles,n,16,3,capacity,split);
    const auto start=std::chrono::steady_clock::now();
    for(unsigned dimension:{15u,17u}) {
        const uint64_t size=uint64_t{1}<<dimension;std::vector<int16_t> weights(size);
        const std::array<int16_t,8> edges{{0,1,-1,32767,-32767,2,-2,3}};
        for(uint64_t i=0;i<size;++i)weights[i]=i%17<8?edges[i%17]:int16_t(int((i*31337+53)%65535)-32767);
        const std::vector<WeightTile> tiles{{0,size/2,0,4,2},{size/2,size/2,2,4,2}};
        exercise(weights,tiles,size/128,128,1536,256,false);
        exercise(weights,tiles,size/128,128,19,512,true);
    }
    const double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::printf("C71_PCS_QUERY_WEIGHT_HOST {\"column_cases\":%llu,\"loader_outputs\":%llu,\"expected_W_reads\":%llu,\"pad_outputs\":%llu,\"zero_outputs\":%llu,\"horner_checks\":%llu,\"loader_blocks\":%llu,\"geometry_rejections\":%llu,\"named_fixture_heap_upper_bytes\":%llu,\"host_component_s\":%.9f,\"max_low_payload_bytes\":8388608,\"loader_extra_device_bytes\":0,\"loader_shared_bytes\":0,\"loader_launches_per_block\":1,\"D35_sparse_geometry\":true,\"gpu_execution\":false,\"integrated\":false,\"credit\":false}\n",
        (unsigned long long)counts.cases,(unsigned long long)counts.outputs,(unsigned long long)counts.reads,
        (unsigned long long)counts.pads,(unsigned long long)counts.zeros,(unsigned long long)counts.horner,
        (unsigned long long)counts.blocks,(unsigned long long)counts.rejections,(unsigned long long)counts.named_heap,elapsed);
}
