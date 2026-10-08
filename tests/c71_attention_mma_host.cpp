// Finite host fragment/shuffle model, not CUDA execution or scheduling.
#include "c71_attention_mma.cuh"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace c71_dense;
using namespace c71_attention;
using Clock=std::chrono::steady_clock;
using Attention=c71_nonlinear::Attention;
struct Guard {
    std::vector<int16_t> words;
    std::vector<uint8_t> seen;
    uint64_t initialized;
    uint64_t reads=0;
    Guard(size_t capacity,size_t prefix):words(capacity,INT16_MIN),seen(capacity),initialized(prefix) {}
    int16_t get(uint64_t index,bool& failed,bool pi=false) {
        if(index==PAD) return 0;
        assert(index<initialized); // Includes the unread KV-capacity canary.
        seen[index]=1; ++reads;
        return load(words.data(),index,failed,pi);
    }
    size_t bytes() const { return words.capacity()*2+seen.capacity(); }
};
static int16_t value(size_t index) {
    constexpr int16_t values[]={-32767,-257,-256,-129,-128,-1,0,1,127,128,255,256,32767};
    return values[(index*7+index/13)%13];
}
static int byte_at(uint32_t x,unsigned b) {
    const unsigned v=(x>>(8*b))&255; return v<128 ? int(v) : int(v)-256;
}
static uint64_t max_accumulator=0;

static bool model(Attention s,bool is_pv,unsigned head,Guard& a,Guard& b,
    std::vector<int64_t>& output,std::vector<uint8_t>& visits) {
    bool failed=false;
    s.head=head;
    const unsigned columns=is_pv ? s.lanes : s.old+150;
    for(unsigned row0=0;row0<s.rows;row0+=16) for(unsigned col0=0;col0<columns;col0+=8) {
        if(!is_pv && col0>=tile_live(s,row0)) {
            for(unsigned row=row0;row<std::min(row0+16,s.rows);++row)
                for(unsigned col=col0;col<std::min(col0+8,columns);++col) {
                    const auto i=output_index(s,is_pv,head,row,col);
                    assert(++visits[i]==1); output[i]=0;
                }
            continue;
        }
        const unsigned bound=is_pv ? padded(tile_live(s,row0)) : padded(s.lanes);
        int32_t accum[32][4][4]{},sx[32][2]{},sw[32]{};
        for(unsigned first=0;first<bound;first+=32) {
            int ah[16][32]{},al[16][32]{},bh[8][32]{},bl[8][32]{};
            uint8_t ac[16][32]{},bc[8][32]{};
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<4;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned byte=0;byte<4;++byte) {
                        const unsigned row=row0+a_row(lane,r),k=first+a_k(lane,r,byte);
                        const auto index=is_pv ? pv_a_index(s,row,k) : qk_a_index(s,row,k);
                        const int16_t x=a.get(index,failed,is_pv);
                        sx[lane][r%2]+=x; pack(x,byte,hi,lo);
                    }
                    for(unsigned byte=0;byte<4;++byte) {
                        const unsigned row=a_row(lane,r),k=a_k(lane,r,byte);
                        assert(++ac[row][k]==1); ah[row][k]=byte_at(hi,byte); al[row][k]=byte_at(lo,byte);
                    }
                }
                for(unsigned r=0;r<2;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned byte=0;byte<4;++byte) {
                        const unsigned col=col0+w_row(lane),k=first+w_k(lane,r,byte);
                        const auto index=is_pv ? pv_b_index(s,head,row0,col,k) : qk_b_index(s,row0,col,k);
                        const int16_t x=b.get(index,failed);
                        sw[lane]+=x; pack(x,byte,hi,lo);
                    }
                    for(unsigned byte=0;byte<4;++byte) {
                        const unsigned col=w_row(lane),k=w_k(lane,r,byte);
                        assert(++bc[col][k]==1); bh[col][k]=byte_at(hi,byte); bl[col][k]=byte_at(lo,byte);
                    }
                }
            }
            for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
                const unsigned row=out_row(lane,r),col=out_col(lane,r);
                for(unsigned k=0;k<32;++k) {
                    accum[lane][r][0]+=ah[row][k]*bh[col][k];
                    accum[lane][r][1]+=ah[row][k]*bl[col][k];
                    accum[lane][r][2]+=al[row][k]*bh[col][k];
                    accum[lane][r][3]+=al[row][k]*bl[col][k];
                }
                for(int32_t x:accum[lane][r]) {
                    const uint64_t magnitude=x<0 ? uint64_t(-int64_t(x)) : uint64_t(x);
                    assert(magnitude<=uint64_t(bound)*128*128);
                    max_accumulator=std::max(max_accumulator,magnitude);
                }
            }
        }
        for(unsigned shift=1;shift<=2;shift*=2) {
            int32_t oldx[32][2],oldw[32];
            std::memcpy(oldx,sx,sizeof(sx)); std::memcpy(oldw,sw,sizeof(sw));
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<2;++r) sx[lane][r]+=oldx[lane^shift][r];
                sw[lane]+=oldw[lane^shift];
            }
        }
        uint8_t coverage[16][8]{};
        for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
            const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
            assert(++coverage[out_row(lane,r)][out_col(lane,r)]==1);
            const auto* d=accum[lane][r];
            const int64_t raw=compose(d[0],d[1],d[2],d[3],sx[lane][r/2],sw[4*out_col(lane,r)],bound);
            if(output_live(s,is_pv,row,col)) {
                const auto index=output_index(s,is_pv,head,row,col);
                assert(++visits[index]==1);
                output[index]=output_value(s,is_pv,row,col,raw);
            }
        }
    }
    return failed;
}
static bool reference(Attention s,bool is_pv,unsigned head,const Guard& a,const Guard& b,
    std::vector<int64_t>& output) {
    bool failed=false;
    const unsigned columns=s.old+150,g=head/(32/s.groups);
    for(unsigned row=0;row<s.rows;++row) for(unsigned col=0;col<(is_pv ? s.lanes : columns);++col) {
        __int128 sum=0;
        if(is_pv || col<=s.old+s.first+row)
            for(unsigned k=0;k<(is_pv ? s.old+s.first+row+1 : s.lanes);++k) {
                const uint64_t ai=is_pv ? uint64_t(row)*columns+k : (uint64_t(row)*32+head)*s.lanes+k;
                const uint64_t bi=is_pv ? (uint64_t(k)*s.groups+g)*s.lanes+col : (uint64_t(col)*s.groups+g)*s.lanes+k;
                assert(ai<a.initialized && bi<b.initialized);
                const int16_t x=a.words[ai],y=b.words[bi];
                failed |= (is_pv ? x<0 || x>16384 : x==INT16_MIN) || y==INT16_MIN;
                sum+=__int128(x)*y;
            }
        assert(sum>=-(__int128{1}<<47) && sum<(__int128{1}<<47));
        output[output_index(s,is_pv,head,row,col)]=int64_t(sum);
    }
    return failed;
}
static double seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now()-start).count(); }
static void check_rne(int64_t raw,int shift) {
    const __int128 magnitude=raw<0 ? -__int128(raw) : __int128(raw),divisor=__int128{1}<<shift;
    const __int128 q=magnitude/divisor,r=magnitude%divisor;
    const __int128 rounded=q+(2*r>divisor || (2*r==divisor && (q&1)));
    const __int128 expected=raw<0 ? -rounded : rounded;
    int16_t actual=123;
    const bool ok=expected>=-32767 && expected<=32767;
    assert(quantize(raw,shift,actual)==ok);
    assert(ok ? actual==expected : actual==123);
}
static size_t peak_payload=0;
static unsigned qk_cases=0,pv_cases=0;
static void fixture(Attention s,bool all_heads,unsigned id) {
    assert(c71_nonlinear::valid(s));
    const unsigned columns=s.old+150,prefix=s.old+s.first+s.rows;
    Guard query(uint64_t(s.rows)*32*s.lanes,uint64_t(s.rows)*32*s.lanes);
    Guard kv(450*uint64_t(s.groups)*s.lanes,uint64_t(prefix)*s.groups*s.lanes);
    for(size_t i=0;i<query.words.size();++i) query.words[i]=value(i+17);
    for(size_t i=0;i<kv.initialized;++i) kv.words[i]=value(i+31);
    const std::vector<unsigned> qheads=all_heads ? [] { std::vector<unsigned> h; for(unsigned i=0;i<32;++i) h.push_back(i); return h; }()
        : std::vector<unsigned>{0,7,31};
    double naive=0,fragment=0;
    uint64_t products=0;
    for(unsigned head:qheads) {
        std::vector<int64_t> want(uint64_t(s.rows)*columns,INT64_MIN),got(want.size(),INT64_MIN);
        std::vector<uint8_t> visits(want.size());
        auto start=Clock::now(); assert(!reference(s,false,head,query,kv,want)); naive+=seconds(start);
        start=Clock::now(); assert(!model(s,false,head,query,kv,got,visits)); fragment+=seconds(start);
        assert(got==want && std::all_of(visits.begin(),visits.end(),[](uint8_t v) { return v==1; }));
        for(unsigned row=0;row<s.rows;++row) products+=uint64_t(s.old+s.first+row+1)*s.lanes;
        peak_payload=std::max(peak_payload,query.bytes()+kv.bytes()+want.capacity()*8+got.capacity()*8+visits.capacity());
        check_rne(got.front(),30); check_rne(got.back(),30); ++qk_cases;
    }
    for(unsigned row=0;row<s.rows;++row) for(unsigned head=0;head<32;++head)
        for(unsigned lane=0;lane<s.lanes;++lane) {
            const bool expected=std::find(qheads.begin(),qheads.end(),head)!=qheads.end();
            assert(bool(query.seen[(uint64_t(row)*32+head)*s.lanes+lane])==expected);
        }
    std::printf("C71_ATTENTION_MMA_CASE {\"id\":%u,\"op\":\"qk\",\"rows\":%u,\"old\":%u,\"first\":%u,\"groups\":%u,\"lanes\":%u,\"heads\":%zu,\"signed_products\":%llu,\"naive_i128_seconds\":%.9f,\"fragment_model_seconds\":%.9f}\n",
        id,s.rows,s.old,s.first,s.groups,s.lanes,qheads.size(),static_cast<unsigned long long>(products),naive,fragment);
    std::fill(kv.seen.begin(),kv.seen.end(),0);
    std::vector<Guard> pis;
    for(unsigned head=0;head<32;++head) {
        pis.emplace_back(uint64_t(s.rows)*columns,uint64_t(s.rows)*columns);
        constexpr int16_t probabilities[]={0,1,127,128,255,256,16383,16384};
        for(unsigned row=0;row<s.rows;++row) for(unsigned key=0;key<s.old+s.first+row+1;++key)
            pis.back().words[uint64_t(row)*columns+key]=probabilities[(head+row+3*key)%8];
    }
    std::vector<unsigned> pheads;
    if(all_heads) for(unsigned h=0;h<32;++h) pheads.push_back(h);
    else for(unsigned g=0;g<s.groups;++g) pheads.push_back(g*(32/s.groups));
    std::vector<int64_t> want(uint64_t(s.rows)*32*s.lanes,INT64_MIN),got(want.size(),INT64_MIN);
    std::vector<uint8_t> visits(want.size());
    naive=0; fragment=0; products=0;
    for(unsigned head:pheads) {
        auto start=Clock::now(); assert(!reference(s,true,head,pis[head],kv,want)); naive+=seconds(start);
        start=Clock::now(); assert(!model(s,true,head,pis[head],kv,got,visits)); fragment+=seconds(start);
        for(unsigned row=0;row<s.rows;++row) products+=uint64_t(s.old+s.first+row+1)*s.lanes;
        ++pv_cases;
    }
    assert(got==want);
    for(unsigned row=0;row<s.rows;++row) for(unsigned head=0;head<32;++head) {
        const bool selected=std::find(pheads.begin(),pheads.end(),head)!=pheads.end();
        for(unsigned lane=0;lane<s.lanes;++lane)
            assert(visits[(uint64_t(row)*32+head)*s.lanes+lane]==unsigned(selected));
        for(unsigned key=0;key<columns;++key)
            assert(bool(pis[head].seen[uint64_t(row)*columns+key])==(selected && key<s.old+s.first+row+1));
    }
    // All GQA groups are exercised, and no unread capacity cell is visited.
    assert(std::all_of(kv.seen.begin(),kv.seen.begin()+kv.initialized,[](uint8_t v) { return v==1; }));
    assert(std::all_of(kv.seen.begin()+kv.initialized,kv.seen.end(),[](uint8_t v) { return v==0; }));
    size_t bytes=query.bytes()+kv.bytes()+want.capacity()*8+got.capacity()*8+visits.capacity();
    for(const auto& pi:pis) bytes+=pi.bytes();
    bytes+=pis.capacity()*sizeof(Guard)+pheads.capacity()*sizeof(unsigned)+qheads.capacity()*sizeof(unsigned);
    peak_payload=std::max(peak_payload,bytes);
    std::printf("C71_ATTENTION_MMA_CASE {\"id\":%u,\"op\":\"pv\",\"rows\":%u,\"old\":%u,\"first\":%u,\"groups\":%u,\"lanes\":%u,\"heads\":%zu,\"signed_products\":%llu,\"naive_i128_seconds\":%.9f,\"fragment_model_seconds\":%.9f}\n",
        id,s.rows,s.old,s.first,s.groups,s.lanes,pheads.size(),static_cast<unsigned long long>(products),naive,fragment);
}
static unsigned rejections() {
    Attention s{1,0,31,0,1,1};
    Guard query(32,32),kv(450,1),pi(150,150);
    std::fill(query.words.begin(),query.words.end(),1); kv.words[0]=2; pi.words[0]=3;
    unsigned cases=0;
    for(unsigned which=0;which<6;++which) {
        const int16_t oldq=query.words[31],oldv=kv.words[0],oldp=pi.words[0];
        if(which==0) query.words[31]=INT16_MIN;
        if(which==1 || which==5) kv.words[0]=INT16_MIN;
        if(which==2) pi.words[0]=-1;
        if(which==3) pi.words[0]=16385;
        if(which==4) pi.words[0]=32767;
        const bool is_pv=which>=2;
        std::vector<int64_t> want(is_pv ? 32 : 150,INT64_MIN),got(want.size(),INT64_MIN);
        std::vector<uint8_t> visits(want.size());
        auto& a=is_pv ? pi : query;
        assert(reference(s,is_pv,31,a,kv,want));
        assert(model(s,is_pv,31,a,kv,got,visits)); assert(want==got); ++cases;
        query.words[31]=oldq; kv.words[0]=oldv; pi.words[0]=oldp;
    }
    bool failed=false;
    assert(load(nullptr,PAD,failed)==0 && !failed);
    return cases;
}
int main() {
    fixture({1,0,0,0,8,512},true,0);
    fixture({15,135,0,0,16,256},false,1);
    fixture({16,134,0,150,8,512},false,2);
    fixture({17,133,0,300,4,512},false,3);
    const unsigned negative=rejections();
    for(int shift:{1,15,30}) for(int q:{-3,-2,-1,0,1,2,3})
        for(int delta:{-1,0,1}) check_rne(int64_t(q)*(int64_t{1}<<shift)+(int64_t{1}<<(shift-1))+delta,shift);
    std::printf("C71_ATTENTION_MMA_HOST {\"qk_head_cases\":%u,\"pv_head_cases\":%u,\"rejections\":%u,\"max_keys\":450,\"max_lanes\":512,\"canary_reads\":0,\"output_coverage_exact\":true,\"host_named_capacity_bytes\":%zu,\"mma_named_register_integer_bytes_per_thread\":124,\"mma_shared_bytes\":0,\"new_global_staging_bytes\":0,\"max_observed_int8_accumulator\":%llu,\"gpu_execution\":false,\"credit\":false}\n",
        qk_cases,pv_cases,negative,peak_payload,static_cast<unsigned long long>(max_accumulator));
}
