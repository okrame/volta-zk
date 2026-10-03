// Host-only fragment/shuffle model. Does NOT emulate GPU scheduling or prove
// PTX execution. Reference uses direct original signed i16 dot products.
#include "c71_dense_i16.cuh"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace c71_dense;
static int byte_at(uint32_t x,unsigned b) { const unsigned v=(x>>(8*b))&255; return v<128?int(v):int(v)-256; }

static bool model(const std::vector<int16_t>& x,const std::vector<int16_t>& w,Shape s,std::vector<int64_t>& out) {
    bool failed=false;
    for(unsigned row0=0;row0<s.m;row0+=16) for(unsigned col0=0;col0<s.n;col0+=8) {
        int32_t accum[32][4][4]{},sx[32][2]{},sw[32]{};
        for(unsigned first=0;first<s.k;first+=32) {
            int ah[16][32]{},al[16][32]{},bh[8][32]{},bl[8][32]{};
            unsigned ac[16][32]{},bc[8][32]{};
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<4;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned b=0;b<4;++b) {
                        const unsigned row=row0+a_row(lane,r),k=first+a_k(lane,r,b);
                        const int16_t v=row<s.m && k<s.k?x[size_t(row)*s.k+k]:0;
                        failed|=v==INT16_MIN; sx[lane][r%2]+=v; pack(v,b,hi,lo);
                    }
                    for(unsigned b=0;b<4;++b) {
                        const auto row=a_row(lane,r),k=a_k(lane,r,b);
                        assert(++ac[row][k]==1); ah[row][k]=byte_at(hi,b); al[row][k]=byte_at(lo,b);
                    }
                }
                for(unsigned r=0;r<2;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned b=0;b<4;++b) {
                        const unsigned row=col0+w_row(lane),k=first+w_k(lane,r,b);
                        const int16_t v=row<s.n && k<s.k?w[size_t(row)*s.k+k]:0;
                        failed|=v==INT16_MIN; sw[lane]+=v; pack(v,b,hi,lo);
                    }
                    for(unsigned b=0;b<4;++b) {
                        const auto row=w_row(lane),k=w_k(lane,r,b);
                        assert(++bc[row][k]==1); bh[row][k]=byte_at(hi,b); bl[row][k]=byte_at(lo,b);
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
                for(auto v:accum[lane][r]) assert(int64_t(v)>=-352321536 && int64_t(v)<=352321536);
            }
        }
        for(unsigned shift=1;shift<=2;shift*=2) {
            int32_t oldx[32][2],oldw[32];
            std::memcpy(oldx,sx,sizeof(sx));
            std::copy(sw,sw+32,oldw);
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<2;++r) sx[lane][r]+=oldx[lane^shift][r];
                sw[lane]+=oldw[lane^shift];
            }
        }
        unsigned visits[16][8]{};
        for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
            const unsigned row=row0+out_row(lane,r),col=col0+out_col(lane,r);
            assert(++visits[out_row(lane,r)][out_col(lane,r)]==1);
            const auto* d=accum[lane][r];
            const auto value=compose(d[0],d[1],d[2],d[3],sx[lane][r/2],sw[4*out_col(lane,r)],(s.k+31)&~31u);
            if(row<s.m && col<s.n) out[size_t(row)*s.n+col]=value;
        }
    }
    return failed;
}
int main() {
    unsigned cases=0;
    for(int v=-32767;v<=32767;++v) {
        assert(high(int16_t(v))>=-128 && high(int16_t(v))<=127);
        assert(low(int16_t(v))>=-128 && low(int16_t(v))<=127);
        assert(256*high(int16_t(v))+low(int16_t(v))+128==v);
    }
    const Shape shapes[]={{1,1,1},{1,1,31},{3,7,32},{9,9,33},{17,35,65},
        {33,17,127},{1,1,5376},{1,1,21503},{1,1,21504},{150,9,3}};
    const int16_t edge[]={-32767,-32766,-257,-256,-129,-128,-1,0,1,127,128,255,256,32766,32767};
    for(const auto s:shapes) for(unsigned pattern=0;pattern<4;++pattern) {
        std::vector<int16_t> x(size_t(s.m)*s.k),w(size_t(s.n)*s.k);
        for(size_t i=0;i<x.size();++i) x[i]=pattern==0?0:pattern==1?-32767:pattern==2?32767:edge[(i*7+i/11)%15];
        for(size_t i=0;i<w.size();++i) w[i]=pattern==0?0:pattern==1?-32767:pattern==2?-32767:edge[(i*11+i/7)%15];
        std::vector<int64_t> out(size_t(s.m)*s.n);
        assert(valid(s,x.size(),w.size(),out.size()));
        assert(!model(x,w,s,out));
        for(unsigned row=0;row<s.m;++row) for(unsigned col=0;col<s.n;++col) {
            __int128 reference=0;
            for(unsigned k=0;k<s.k;++k) reference+=__int128(x[size_t(row)*s.k+k])*w[size_t(col)*s.k+k];
            assert(reference==out[size_t(row)*s.n+col]);
        }
        ++cases;
    }
    std::vector<int16_t> x(33,1),w(33,1); std::vector<int64_t> out(1);
    x.back()=INT16_MIN; assert(model(x,w,{1,1,33},out));
    x.back()=1; w.back()=INT16_MIN; assert(model(x,w,{1,1,33},out));
    for(auto s:{Shape{0,1,1},Shape{151,1,1},Shape{1,262145,1},Shape{1,1,0},Shape{1,1,21505}})
        assert(!valid(s,UINT64_MAX,UINT64_MAX,UINT64_MAX));
    assert(!valid({2,3,4},7,12,6) && !valid({2,3,4},8,11,6) && !valid({2,3,4},8,12,5));
    assert(valid({150,262144,21504},150ULL*21504,262144ULL*21504,150ULL*262144)); // descriptors only
    alignas(8) int16_t a[16]{},b[16]{}; int64_t c[16]{}; uint32_t failed=0;
    assert(valid_buffers(a,16,b,16,c,16,&failed,{2,2,8}));
    assert(valid_buffers(a,16,a,16,c,16,&failed,{2,2,8})); // Read-only input alias allowed.
    assert(!valid_buffers(nullptr,16,b,16,c,16,&failed,{2,2,8}));
    assert(!valid_buffers(a,16,b,16,c,16,nullptr,{2,2,8}));
    assert(!valid_buffers(a,16,b,16,reinterpret_cast<int64_t*>(a),16,&failed,{2,2,8}));
    assert(!valid_buffers(a,16,b,16,reinterpret_cast<int64_t*>(b),16,&failed,{2,2,8}));
    assert(!valid_buffers(a,16,b,16,c,16,reinterpret_cast<uint32_t*>(a),{2,2,8}));
    assert(!valid_buffers(a,16,b,16,c,16,reinterpret_cast<uint32_t*>(b),{2,2,8}));
    assert(!valid_buffers(a,16,b,16,c,16,reinterpret_cast<uint32_t*>(c),{2,2,8}));
    assert(!valid_buffers(a,16,b,16,reinterpret_cast<int64_t*>(reinterpret_cast<unsigned char*>(c)+2),16,&failed,{2,2,8}));
    assert(!valid_buffers(reinterpret_cast<int16_t*>(UINTPTR_MAX-7),16,b,16,c,16,&failed,{2,2,8}));
    std::printf("C71_DENSE_I16_HOST {\"matrix_cases\":%u,\"split_values\":65535,\"max_k_executed\":21504,\"gpu_execution\":false,\"credit\":false}\n",cases);
}
