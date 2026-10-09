// Exact short PCS leaves, original leaves, replay bands and every Merkle
// node compared with stdin vectors from pinned independent Rust BLAKE3.
// Host component only: no owner, CUDA execution or performance credit.
#include "c71_pcs_hash.cuh"
#include "c71_pcs_salts.cuh"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <vector>

using c71_pcs::Hash32;
static uint64_t read_le(unsigned n) {
    uint64_t x=0;
    for(unsigned i=0;i<n;++i) { const int b=std::getchar(); assert(b!=EOF); x|=uint64_t(b)<<(8*i); }
    return x;
}
static Hash32 read_hash() {
    Hash32 h{}; for(auto& w:h.w) w=uint32_t(read_le(4)); return h;
}
static bool equal(Hash32 a,Hash32 b) {
    for(unsigned i=0;i<8;++i) if(a.w[i]!=b.w[i]) return false;
    return true;
}
static uint64_t guard_checks() {
    uint64_t checks=0;
    auto check=[&](bool value) { assert(value); ++checks; };
    const uint64_t r=uint64_t{1}<<23;
    check(c71_pcs::valid_short_leaf_span(1,0,2));
    check(c71_pcs::valid_short_leaf_span(r,0,65536));
    check(c71_pcs::valid_short_leaf_span(r,2*r-1,1));
    check(!c71_pcs::valid_short_leaf_span(0,0,1));
    check(!c71_pcs::valid_short_leaf_span(3,0,1));
    check(!c71_pcs::valid_short_leaf_span(2*r,0,1));
    check(!c71_pcs::valid_short_leaf_span(r,0,0));
    check(!c71_pcs::valid_short_leaf_span(r,0,65537));
    check(!c71_pcs::valid_short_leaf_span(r,2*r,1));
    check(!c71_pcs::valid_short_leaf_span(r,2*r-1,2));
    check(!c71_pcs::valid_short_leaf_span(UINT64_MAX,UINT64_MAX,1));
    check(c71_salts::valid_replay_span(r,2*r-1,1));
    check(!c71_salts::valid_replay_span(r,2*r,1));
    check(!c71_salts::valid_replay_span(r,0,65537));
    check(c71_pcs::valid_short_pair_span(1,0,1));
    check(c71_pcs::valid_short_pair_span(1,1,1));
    check(!c71_pcs::valid_short_pair_span(1,0,2));
    check(c71_pcs::valid_short_pair_span(2,0,2));
    check(c71_pcs::valid_short_pair_span(2,2,2));
    check(!c71_pcs::valid_short_pair_span(2,1,2));
    check(!c71_pcs::valid_short_pair_span(r,r-1,2));
    check(c71_pcs::valid_short_pair_span(r,r,65536));
    return checks;
}

int main() {
    uint64_t guards=guard_checks(),leaves=0,nodes=0,bands=0,replay_bytes=0;
    uint64_t max_heap=0,canonical_rejects=0,large_row_replay_cases=0;
    uint64_t paired_leaves=0,paired_nodes=0,paired_bands=0,paired_replay_bytes=0;
    double replay_seconds=0,hash_seconds=0,node_seconds=0,paired_seconds=0;
    const unsigned cases=unsigned(read_le(4));
    for(unsigned test=0;test<cases;++test) {
        uint8_t seed[32]; for(auto& b:seed) b=uint8_t(read_le(1));
        const auto descriptor=c71_salts::descriptor(seed);
        const uint64_t origin=read_le(8),rows=read_le(4);
        const unsigned cosets=unsigned(read_le(4)),band=unsigned(read_le(4));
        assert(c71_salts::power_two(rows) && rows<=1024 && c71_salts::power_two(cosets));
        assert(cosets>=2 && cosets<=64 && band && band<=65536);
        const uint64_t height=rows*cosets;
        std::vector<uint64_t> values(12*height),expected_salts(4*height),positions(height+1);
        for(auto& x:values) { x=read_le(8); assert(x<c71_pcs::MODULUS); }
        for(auto& x:expected_salts) { x=read_le(8); assert(x<c71_pcs::MODULUS); }
        for(auto& x:positions) x=read_le(8);
        assert(positions.front()==origin && positions.back()<=c71_salts::CAP);
        if(!test) {
            // Exercise R23 arithmetic across a lane boundary and at the
            // terminal leaf using only two row cursors and eight words.
            // Expected salts/cursors remain the independent input vectors.
            const uint64_t r23=uint64_t{1}<<23;
            uint64_t sparse[8]{},cursor=positions[0],bytes=0;
            assert(c71_salts::replay_row(descriptor,cursor,r23,r23-1,2,r23-1,sparse,bytes));
            assert(cursor==positions[1] && bytes==positions[1]-positions[0]);
            cursor=positions[1];
            assert(c71_salts::replay_row(descriptor,cursor,r23,r23-1,2,0,sparse,bytes));
            assert(cursor==positions[2] && bytes==positions[2]-positions[1]);
            for(unsigned col=0;col<4;++col) {
                assert(sparse[2*col]==expected_salts[col]);
                assert(sparse[2*col+1]==expected_salts[4+col]);
            }
            ++large_row_replay_cases;
            cursor=positions[0];
            assert(c71_salts::replay_row(descriptor,cursor,r23,2*r23-1,1,r23-1,sparse,bytes));
            assert(cursor==positions[1] && bytes==positions[1]-positions[0]);
            for(unsigned col=0;col<4;++col) assert(sparse[col]==expected_salts[col]);
            ++large_row_replay_cases;
        }
        std::vector<Hash32> expected_leaves(height);
        for(auto& x:expected_leaves) x=read_hash();
        unsigned levels=0; for(unsigned c=cosets;c>1;c>>=1) ++levels;
        std::vector<std::vector<Hash32>> expected_nodes;
        for(unsigned level=1;level<=levels;++level) {
            expected_nodes.emplace_back(height>>level);
            for(auto& x:expected_nodes.back()) x=read_hash();
        }
        std::vector<Hash32> expected_row_nodes;
        for(uint64_t width=rows/2;width;width>>=1)
            for(uint64_t i=0;i<width;++i) expected_row_nodes.push_back(read_hash());
        const Hash32 expected_root=read_hash();
        std::vector<uint64_t> current(rows),pair_current(rows),ring(24*rows),salts(4*std::min(uint64_t(band),2*rows));
        std::vector<Hash32> group_hashes(2*rows),roots(rows),frontier((levels-1)*rows);
        std::vector<Hash32> pair_roots(rows);
        for(uint64_t row=0;row<rows;++row) current[row]=pair_current[row]=positions[row*cosets];
        // Payload capacities for every simultaneously live named vector;
        // allocator metadata, libc, executable and RSS remain extra.
        const uint64_t named_heap=8*(values.capacity()+expected_salts.capacity()+positions.capacity()
            +current.capacity()+pair_current.capacity()+ring.capacity()+salts.capacity())
            +32*(expected_leaves.capacity()+expected_row_nodes.capacity()+group_hashes.capacity()
                +roots.capacity()+pair_roots.capacity()+frontier.capacity());
        uint64_t node_capacity=0;
        for(const auto& v:expected_nodes) node_capacity+=32*v.capacity();
        max_heap=std::max(max_heap,named_heap+node_capacity
            +expected_nodes.capacity()*sizeof(std::vector<Hash32>));
        for(unsigned group=0;group<cosets/2;++group) {
            for(unsigned col=0;col<12;++col) for(unsigned lane=0;lane<2;++lane)
                for(uint64_t row=0;row<rows;++row)
                    ring[(col*2+lane)*rows+row]=values[(uint64_t(col)*cosets+2*group+lane)*rows+row];
            for(uint64_t first=0;first<2*rows;) {
                // Alternate uneven band lengths to cross the lane boundary
                // and exercise a row cursor shared by both cosets.
                const uint64_t requested=(bands&1) ? std::max(1u,band-1) : band;
                const uint64_t count=std::min(2*rows-first,requested);
                assert(c71_pcs::valid_short_leaf_span(rows,first,count));
                assert(c71_salts::valid_replay_span(rows,first,count));
                const auto replay_start=std::chrono::steady_clock::now();
                uint64_t consumed=0;
                for(uint64_t row=0;row<rows;++row) {
                    uint64_t bytes=0;
                    assert(c71_salts::replay_row(descriptor,current[row],rows,first,count,
                        row,salts.data(),bytes)); consumed+=bytes;
                }
                replay_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-replay_start).count();
                replay_bytes+=consumed;
                const auto hash_start=std::chrono::steady_clock::now();
                for(uint64_t local=0;local<count;++local) {
                    const uint64_t leaf=first+local,row=leaf%rows,lane=leaf/rows;
                    const uint64_t natural=row*cosets+2*group+lane;
                    for(unsigned col=0;col<4;++col)
                        assert(salts[col*count+local]==expected_salts[4*natural+col]);
                    const uint64_t* base=ring.data()+lane*rows;
                    assert(c71_pcs::canonical_short_leaf(base,2*rows,row,salts.data(),count,local));
                    const Hash32 h=c71_pcs::short_leaf(base,2*rows,row,salts.data(),count,local);
                    assert(equal(h,expected_leaves[(2*group+lane)*rows+row]));
                    group_hashes[leaf]=h; ++leaves;
                    // Reject either a value or a salt equal to p. Restoring
                    // the word must recover the same byte-exact hash.
                    if(!local) {
                        const uint64_t index=(11*2+lane)*rows+row,original=ring[index];
                        ring[index]=c71_pcs::MODULUS;
                        assert(!c71_pcs::canonical_short_leaf(base,2*rows,row,salts.data(),count,local));
                        ring[index]=original; ++canonical_rejects;
                        const uint64_t saved=salts[local]; salts[local]=c71_pcs::MODULUS;
                        assert(!c71_pcs::canonical_short_leaf(base,2*rows,row,salts.data(),count,local));
                        salts[local]=saved; ++canonical_rejects;
                        assert(equal(c71_pcs::short_leaf(base,2*rows,row,salts.data(),count,local),h));
                    }
                }
                hash_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-hash_start).count();
                first+=count; ++bands;
            }
            const auto pair_start=std::chrono::steady_clock::now();
            for(uint64_t first=0;first<2*rows;) {
                // All lane-zero bands precede lane one. A single launch may
                // not read a state written by another thread in that launch.
                const uint64_t requested=(paired_bands&1) ? std::max(1u,band-1) : band;
                const uint64_t count=std::min(std::min(2*rows-first,requested),rows-first%rows);
                assert(c71_pcs::valid_short_pair_span(rows,first,count));
                for(uint64_t row=0;row<rows;++row) {
                    uint64_t bytes=0;
                    assert(c71_salts::replay_row(descriptor,pair_current[row],rows,first,count,
                        row,salts.data(),bytes)); paired_replay_bytes+=bytes;
                }
                for(uint64_t local=0;local<count;++local) {
                    const uint64_t leaf=first+local,lane=leaf/rows,row=leaf%rows;
                    const uint64_t* base=ring.data()+lane*rows;
                    const uint64_t natural=row*cosets+2*group+lane;
                    for(unsigned col=0;col<4;++col)
                        assert(salts[col*count+local]==expected_salts[4*natural+col]);
                    assert(c71_pcs::canonical_short_leaf(base,2*rows,row,salts.data(),count,local));
                    const auto digest=c71_pcs::short_leaf(base,2*rows,row,salts.data(),count,local);
                    if(!lane) {
                        pair_roots[row]=digest;
                        assert(equal(pair_roots[row],expected_leaves[uint64_t(2*group)*rows+row]));
                    } else {
                        pair_roots[row]=c71_pcs::short_pair_finish(pair_roots[row],digest);
                        assert(equal(pair_roots[row],expected_nodes[0][uint64_t(group)*rows+row]));
                        ++paired_nodes;
                    }
                    ++paired_leaves;
                }
                first+=count; ++paired_bands;
            }
            paired_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-pair_start).count();
            const auto node_start=std::chrono::steady_clock::now();
            for(uint64_t row=0;row<rows;++row) {
                assert(pair_current[row]==current[row]);
                roots[row]=c71_pcs::node(group_hashes[row],group_hashes[rows+row]);
                assert(equal(roots[row],expected_nodes[0][uint64_t(group)*rows+row])); ++nodes;
                assert(equal(roots[row],pair_roots[row]));
                if(levels==1) continue;
                Hash32 current_hash=roots[row]; unsigned level=0;
                while((group>>level)&1) {
                    current_hash=c71_pcs::node(frontier[uint64_t(level)*rows+row],current_hash);
                    assert(equal(current_hash,expected_nodes[level+1][uint64_t(group>>(level+1))*rows+row]));
                    ++nodes; ++level;
                }
                c71_pcs::merge_group(frontier.data(),roots.data(),rows,row,group,levels-1);
                assert(equal(level==levels-1 ? roots[row] : frontier[uint64_t(level)*rows+row],current_hash));
            }
            node_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-node_start).count();
        }
        for(uint64_t row=0;row<rows;++row) {
            assert(current[row]==positions[(row+1)*cosets]);
            assert(equal(roots[row],expected_nodes.back()[row]));
        }
        const auto node_start=std::chrono::steady_clock::now();
        uint64_t at=0;
        for(uint64_t width=rows;width>1;width>>=1)
            for(uint64_t i=0;i<width/2;++i) {
                roots[i]=c71_pcs::node(roots[2*i],roots[2*i+1]);
                assert(equal(roots[i],expected_row_nodes[at++])); ++nodes;
            }
        node_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-node_start).count();
        assert(at==expected_row_nodes.size() && equal(roots[0],expected_root));
    }
    const unsigned original_cases=unsigned(read_le(4));
    for(unsigned i=0;i<original_cases;++i) {
        uint64_t values[128],salts[4];
        for(auto& x:values) x=read_le(8);
        for(auto& x:salts) x=read_le(8);
        const Hash32 expected=read_hash();
        auto cv=c71_pcs::leaf_start(values,1,0);
        for(unsigned first=4;first<=116;first+=8)
            cv=c71_pcs::leaf_step(cv,values+first,values+first+4,1,0,first);
        assert(equal(c71_pcs::leaf_finish(cv,values+124,salts,1,0,1,0),expected));
    }
    assert(std::getchar()==EOF);
    std::printf("C71_PCS_SHORT_HASH_HOST {\"cases\":%u,\"leaves\":%llu,\"nodes\":%llu,"
        "\"bands\":%llu,\"replay_logical_bytes\":%llu,\"original128_cases\":%u,"
        "\"span_guard_checks\":%llu,\"canonical_rejections\":%llu,\"large_row_replay_cases\":%llu,"
        "\"named_heap_peak_bytes\":%llu,"
        "\"paired_leaves\":%llu,\"paired_nodes\":%llu,\"paired_bands\":%llu,"
        "\"paired_replay_logical_bytes\":%llu,\"host_paired_fixture_seconds\":%.9f,"
        "\"largest_fixture_stack_arrays_bytes\":1056,\"host_replay_seconds\":%.9f,"
        "\"host_hash_fixture_seconds\":%.9f,\"host_nodes_fixture_seconds\":%.9f,"
        "\"short_leaf_bytes\":160,\"short_leaf_compressions\":3,\"gpu_execution\":false,"
        "\"integrated\":false,\"credit\":false}\n",
        cases,(unsigned long long)leaves,(unsigned long long)nodes,(unsigned long long)bands,
        (unsigned long long)replay_bytes,original_cases,(unsigned long long)guards,
        (unsigned long long)canonical_rejects,(unsigned long long)large_row_replay_cases,
        (unsigned long long)max_heap,(unsigned long long)paired_leaves,(unsigned long long)paired_nodes,
        (unsigned long long)paired_bands,(unsigned long long)paired_replay_bytes,paired_seconds,
        replay_seconds,hash_seconds,node_seconds);
}
