// Shared XOF/mask/replay helpers compared with bytes and samples from the
// pinned Rust BLAKE3/Goldilocks implementations. This does not execute CUDA.
#include "c71_pcs_salts.cuh"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <vector>

using namespace c71_salts;
static uint64_t read_le(unsigned bytes) {
    uint64_t value=0;
    for(unsigned i=0;i<bytes;++i) { const int b=std::getchar(); assert(b!=EOF); value|=uint64_t(b)<<(8*i); }
    return value;
}
static Descriptor read_descriptor() {
    uint8_t seed[32]; for(auto& x:seed) x=uint8_t(read_le(1));
    return descriptor(seed);
}
static uint32_t load32(const uint8_t* bytes) {
    uint32_t value=0; for(unsigned i=0;i<4;++i) value|=uint32_t(bytes[i])<<(8*i); return value;
}
static uint64_t aligned(uint64_t bytes) { return (bytes+255)&~uint64_t{255}; }

// An independent serial prefix/select oracle. Only mask and selected-boundary
// helpers are shared with the CUDA passes; this is not a kernel simulation.
static Progress select_chunk(Chunk c,Geometry g,const std::vector<uint8_t>& masks,
    std::vector<uint64_t>& starts,std::vector<uint64_t>& offsets) {
    assert(valid(c,g));
    assert(masks.size()==chunk_blocks(c));
    std::vector<uint32_t> prefix(masks.size()+1);
    for(uint32_t i=0;i<masks.size();++i) prefix[i+1]=prefix[i]+popcount(masks[i]);
    const uint64_t take=std::min(uint64_t(prefix.back()),c.target-c.accepted);
    auto boundary=[&](uint64_t k) {
        assert(k>c.accepted && k<=c.accepted+take);
        const uint32_t local=uint32_t(k-c.accepted);
        const auto at=std::lower_bound(prefix.begin()+1,prefix.end(),local)-prefix.begin()-1;
        return after_accepted(c,uint32_t(at),masks[at],local-prefix[at]);
    };
    if(!c.accepted && c.cursor==g.origin) { starts[0]=g.origin; offsets[0]=g.origin; }
    for(uint64_t i=1;i<starts.size();++i) {
        const uint64_t k=4*i*g.cosets;
        if(k>c.accepted && k<=c.accepted+take) starts[i]=boundary(k);
    }
    for(uint64_t i=1;i<offsets.size();++i) {
        const uint64_t k=4*i*g.cut;
        if(k>c.accepted && k<=c.accepted+take) offsets[i]=boundary(k);
    }
    const bool complete=c.accepted+take==c.target;
    const uint64_t cursor=complete && take ? boundary(c.target) : c.cursor+8*uint64_t(c.candidates);
    const bool failed=!complete && CAP-cursor<8;
    return {cursor,c.accepted+take,cursor-g.origin,physical_blocks(c),uint32_t(failed),uint32_t(complete)};
}
static Progress chunk(const Descriptor& d,Chunk c,Geometry g,
    std::vector<uint64_t>& starts,std::vector<uint64_t>& offsets) {
    std::vector<uint8_t> masks(chunk_blocks(c));
    for(uint32_t i=0;i<masks.size();++i) masks[i]=block_mask(d,c,i);
    return select_chunk(c,g,masks,starts,offsets);
}

static uint64_t masks_and_boundaries() {
    uint64_t checks=0;
    for(uint64_t cursor=0;cursor<72;++cursor) for(unsigned pattern=0;pattern<256;++pattern) {
        Chunk c{cursor,0,4,8,8};
        for(uint32_t block=0;block<chunk_blocks(c);++block) {
            uint8_t bytes[128]{};
            for(unsigned lane=0;lane<8;++lane) {
                const uint64_t value=(pattern>>lane)&1 ? uint64_t(lane)+7
                    : lane%3==0 ? MODULUS : lane%3==1 ? MODULUS+1 : UINT64_MAX;
                for(unsigned b=0;b<8;++b) bytes[(cursor&7)+8*lane+b]=uint8_t(value>>(8*b));
            }
            uint32_t words[16],next[16];
            for(unsigned i=0;i<16;++i) { words[i]=load32(bytes+4*i); next[i]=load32(bytes+64+4*i); }
            uint8_t expected=0;
            std::vector<uint64_t> boundaries;
            for(unsigned lane=0;lane<8;++lane) {
                const uint64_t at=(cursor/64+block)*64+(cursor&7)+8*lane;
                if(at>=cursor && at<cursor+64 && (pattern>>lane)&1) {
                    expected|=uint8_t(1u<<lane); boundaries.push_back(at+8);
                }
            }
            const uint8_t mask=candidate_mask(c,block,words,next);
            assert(mask==expected && popcount(mask)==boundaries.size());
            assert(after_accepted(c,block,mask,0)==CAP+1);
            for(unsigned rank=1;rank<=boundaries.size();++rank)
                assert(after_accepted(c,block,mask,rank)==boundaries[rank-1]);
            assert(after_accepted(c,block,mask,unsigned(boundaries.size()+1))==CAP+1);
            ++checks;
        }
    }
    // Exact cap boundaries, all-rejected chunks, and global accepted counters
    // beyond 2^32. No full-size values or GPU scratch are allocated here.
    const Geometry g{uint64_t{1}<<20,32,4096,4096};
    const uint64_t accepted=(uint64_t{1}<<32)+17;
    Chunk large{32+8*accepted,accepted,accepted+25,64,64};
    assert(valid(large,g));
    assert(after_accepted(large,2,255,8)==(large.cursor/64)*64+192);
    std::vector<uint64_t> starts(1,0),offsets(1,0);
    std::vector<uint8_t> masks(chunk_blocks(large),255);
    // The first block excludes candidates preceding the logical cursor.
    masks[0]=uint8_t(255u<<((large.cursor&63)/8));
    const Progress high=select_chunk(large,g,masks,starts,offsets);
    assert(high.accepted==accepted+25 && high.complete && high.cursor==large.cursor+200);
    const Geometry rejected_geometry{1,0,16,1};
    Chunk rejected{0,0,4,8,8};
    const Progress empty=select_chunk(rejected,rejected_geometry,{0},starts,offsets);
    assert(empty.accepted==0 && empty.cursor==64 && !empty.failed && !empty.complete);
    const Progress next=select_chunk(Chunk{64,0,4,8,8},rejected_geometry,{15},starts,offsets);
    assert(next.accepted==4 && next.cursor==96 && next.complete && starts[0]==0 && offsets[0]==0);
    const Progress cap=select_chunk(Chunk{CAP-8,0,4,1,8},Geometry{1,CAP-8,1,1},{0},starts,offsets);
    assert(cap.cursor==CAP && cap.failed && !cap.complete);
    assert(valid(Chunk{CAP,0,0,0,8},Geometry{1,CAP,1,1}));
    assert(valid(Chunk{CAP-7,0,4,0,8},Geometry{1,CAP-7,1,1}));
    assert(valid(Chunk{CAP-8,0,4,1,8},Geometry{1,CAP-8,1,1}));
    assert(after_accepted(Chunk{CAP-8,0,4,1,8},0,128,1)==CAP);
    assert(!valid(Chunk{0,0,4,0,8},Geometry{1,0,1,1}));
    assert(!valid(Chunk{1,0,4,8,8},Geometry{1,0,1,1}));
    assert(!valid(Chunk{0,0,4,8,7},Geometry{1,0,1,1}));
    assert(!valid(Chunk{0,0,5,8,8},Geometry{1,0,1,1}));
    assert(!valid(Chunk{CAP-7,0,4,1,8},Geometry{1,CAP-7,1,1}));
    assert(!valid(Geometry{3,0,1,1}) && !valid(Geometry{1,CAP+1,1,1}));
    assert(!valid_capacity(4) && !valid_capacity(MAX_CANDIDATES+8));
    // Metadata-only S1 R23 admission. Every original R20 shape remains
    // valid; larger rows require the explicit construction's cut/height.
    const uint64_t r23=uint64_t{1}<<23;
    assert(valid(Geometry{r23,63,64,4096}));
    assert(valid(Geometry{r23,63,128,4096}));
    assert(valid(Geometry{r23,63,512,4096}));
    assert(!valid(Geometry{r23,63,1024,4096}));
    assert(!valid(Geometry{r23,63,1,4096}));
    assert(!valid(Geometry{r23,63,64,2048}));
    assert(!valid(Geometry{r23*2,63,64,4096}));
    assert(valid(Geometry{uint64_t{1}<<20,63,1,1}));
    assert(valid(Geometry{uint64_t{1}<<20,63,4096,1}));
    const uint64_t s1_accepted=(uint64_t{1}<<32)+17;
    assert(valid(Chunk{63+8*s1_accepted,s1_accepted,s1_accepted+25,64,64},
        Geometry{r23,63,512,4096}));
    assert(valid_replay_span(r23,0,65536));
    assert(valid_replay_span(r23,2*r23-1,1));
    assert(!valid_replay_span(r23,2*r23,1));
    assert(!valid_replay_span(r23,0,65537));
    assert(!valid_replay_span(r23,0,0));
    assert(valid_replay_span(uint64_t{1}<<20,32*(uint64_t{1}<<20)-1,1));
    assert(!valid_replay_span(r23*2,0,1));
    return checks;
}

int main() {
    const uint64_t forced_checks=masks_and_boundaries();
    const unsigned vector_cases=unsigned(read_le(4));
    uint64_t byte_checks=0;
    for(unsigned i=0;i<vector_cases;++i) {
        const Descriptor d=read_descriptor();
        const uint64_t offset=read_le(8); const unsigned length=unsigned(read_le(4));
        assert(offset<=CAP && length<=CAP-offset);
        BlockCache cache;
        for(unsigned j=0;j<length;++j) {
            uint32_t words[16]; const uint64_t at=offset+j;
            xof_block(d,at/64,words);
            assert(uint8_t(words[(at%64)/4]>>(8*(at%4)))==read_le(1));
            if(j+8<=length) {
                uint64_t value; assert(candidate(d,at,cache,value));
                uint64_t expected=0;
                for(unsigned b=0;b<8;++b) {
                    uint32_t independent[16]; xof_block(d,(at+b)/64,independent);
                    expected|=uint64_t(uint8_t(independent[((at+b)%64)/4]>>(8*((at+b)%4))))<<(8*b);
                }
                assert(value==expected);
            }
            ++byte_checks;
        }
        uint64_t value;
        assert(!candidate(d,CAP-7,cache,value) && !candidate(d,CAP,cache,value));
    }
    const unsigned stream_cases=unsigned(read_le(4));
    uint64_t leaves=0,chunk_calls=0,physical=0,max_scratch=0;
    double scan_seconds=0,replay_seconds=0;
    for(unsigned i=0;i<stream_cases;++i) {
        const Descriptor d=read_descriptor();
        const uint64_t origin=read_le(8),rows=read_le(4);
        const uint32_t cosets=uint32_t(read_le(4)),cut=uint32_t(read_le(4));
        const Geometry g{rows,origin,cosets,cut}; assert(valid(g));
        const uint64_t height=rows*cosets;
        std::vector<uint64_t> expected(4*height),positions(height+1);
        for(auto& x:expected) x=read_le(8);
        for(auto& x:positions) x=read_le(8);
        assert(positions[0]==origin);
        std::vector<uint64_t> starts(rows,CAP+1),offsets(height/cut,CAP+1);
        const auto scan_started=std::chrono::steady_clock::now();
        Progress p{origin,0,0,0,0,0};
        const uint32_t capacity=i%2?64:512;
        while(!p.complete) {
            const uint32_t candidates=uint32_t(std::min(uint64_t(capacity),(CAP-p.cursor)/8));
            const Chunk c{p.cursor,p.accepted,4*height,candidates,capacity};
            const uint64_t scratch=aligned(chunk_blocks(c))+aligned(4*chunk_blocks(c))
                +aligned(4*block_sum_slots(c))+aligned(4*group_sum_slots(c));
            max_scratch=std::max(max_scratch,scratch);
            p=chunk(d,c,g,starts,offsets); assert(!p.failed);
            physical+=p.physical_blocks; ++chunk_calls;
        }
        scan_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-scan_started).count();
        assert(p.cursor==positions.back() && p.accepted==4*height && p.logical_bytes==positions.back()-origin);
        for(uint64_t r=0;r<rows;++r) assert(starts[r]==positions[r*cosets]);
        for(uint64_t t=0;t<height/cut;++t) assert(offsets[t]==positions[t*cut]);
        std::vector<uint64_t> current=starts;
        uint64_t total=0;
        const auto replay_started=std::chrono::steady_clock::now();
        for(uint64_t first=0;first<height;) {
            const uint64_t count=std::min(height-first,i%2?3*rows+1:std::max(uint64_t{1},rows/2));
            std::vector<uint64_t> salts(4*count,CAP+1);
            for(uint64_t r=0;r<rows;++r) {
                uint64_t consumed=0; assert(replay_row(d,current[r],rows,first,count,r,salts.data(),consumed)); total+=consumed;
            }
            for(uint64_t j=0;j<count;++j) for(unsigned col=0;col<4;++col) {
                const uint64_t physical_leaf=first+j;
                const uint64_t natural=(physical_leaf%rows)*cosets+physical_leaf/rows;
                assert(salts[col*count+j]==expected[4*natural+col]);
            }
            first+=count;
        }
        replay_seconds+=std::chrono::duration<double>(std::chrono::steady_clock::now()-replay_started).count();
        assert(total==positions.back()-origin);
        for(uint64_t r=0;r<rows;++r) assert(current[r]==positions[(r+1)*cosets]);
        uint64_t exhausted=CAP-7; BlockCache cache; uint64_t salts[4]{};
        assert(!sample4(d,exhausted,cache,salts) && exhausted==CAP-7);
        leaves+=height;
    }
    assert(std::getchar()==EOF);
    // Max shape accounting, with no max-shape allocation.
    const Chunk max{63,0,4*(uint64_t{1}<<32),MAX_CANDIDATES,MAX_CANDIDATES};
    const uint64_t scratch=aligned(chunk_blocks(max))+aligned(4*uint64_t(chunk_blocks(max)))
        +aligned(4*block_sum_slots(max))+aligned(4*group_sum_slots(max))
        +aligned(sizeof(Descriptor))+aligned(sizeof(Progress))+aligned(4);
    assert(scratch==10520320);
    std::printf("C71_PCS_SALTS_HOST {\"vector_cases\":%u,\"byte_checks\":%llu,\"stream_cases\":%u,"
        "\"forced_mask_checks\":%llu,\"leaves\":%llu,\"chunk_calls\":%llu,\"physical_blocks\":%llu,"
        "\"fixture_scratch_bytes\":%llu,\"max_shape_scratch_bytes\":%llu,"
        "\"host_prescan_seconds\":%.9f,\"host_replay_seconds\":%.9f,\"s1_metadata_checks\":17,"
        "\"gpu_execution\":false,\"credit\":false}\n",
        vector_cases,(unsigned long long)byte_checks,stream_cases,(unsigned long long)forced_checks,
        (unsigned long long)leaves,(unsigned long long)chunk_calls,(unsigned long long)physical,
        (unsigned long long)max_scratch,(unsigned long long)scratch,scan_seconds,replay_seconds);
}
