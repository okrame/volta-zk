// Small semantic check only: does not load CUDA or execute GPU kernels.
#include "c71_range_native.cuh"
#include <cassert>
#include <iostream>
#include <vector>
using namespace c71_range;

bool equal(Fp3 a,Fp3 b) { return a.c0==b.c0 && a.c1==b.c1 && a.c2==b.c2; }
Pair reference(const int16_t* v,size_t n,Fp3 alpha) {
    if(n==1) return {{1,0,0},sub(alpha,integer(v[0]))};
    const Pair a=reference(v,n/2,alpha),b=reference(v+n/2,n/2,alpha);
    return {add(mul(a.p,b.q),mul(b.p,a.q)),mul(a.q,b.q)};
}
Fp3 evaluate(Cubic c,Fp3 x) {
    Fp3 result{};
    for(int j=3;j>=0;--j) result=add(mul(result,x),c.c[j]);
    return result;
}
Fp3 relation(Children a,Fp3 lambda) {
    return add(mul(lambda,add(mul(a.v[0],a.v[3]),mul(a.v[2],a.v[1]))),mul(a.v[1],a.v[3]));
}

int main() {
    const Fp3 alpha{3,5,7},lambda{11,13,17};
    const Fp3 coins[]={{0,0,0},{1,0,0},{19,23,29}};
    size_t cases=0,max_shared=0;
    for(bool signed_words:{false,true}) for(unsigned bottom=1;bottom<=11;++bottom) {
        const unsigned n=1u<<bottom;
        std::vector<int16_t> values(n);
        const int16_t w[]={-32767,-1,0,32767},a[]={0,1,128,255};
        for(unsigned i=0;i<n;++i) values[i]=(signed_words?w:a)[i%4];
        std::vector<Pair> pairs(n/2);
        for(unsigned i=0;i<n/2;++i) pairs[i]=leaf_pair(values[2*i],values[2*i+1],alpha);
        for(unsigned stride=1;stride<n/2;stride*=2)
            for(unsigned j=0;j<n/2;j+=2*stride) pairs[j]=merge(pairs[j],pairs[j+stride]);
        const Pair expected=reference(values.data(),n,alpha);
        assert(equal(pairs[0].p,expected.p) && equal(pairs[0].q,expected.q));
        ++cases;
    }
    for(unsigned bottom=1;bottom<=11;++bottom) for(unsigned width=0;width<=5;++width)
    for(unsigned prefix=0;prefix<=10;++prefix) {
        if(bottom+width+prefix>11) continue;
        Group g{};
        g.bottom=bottom;g.width=width;g.prefix_bits=prefix;g.tail_bits=24;g.buckets=256;
        const size_t bytes=group_shared_bytes(g,256);
        assert(bytes>0 && bytes<=52224);
        if(bytes>max_shared) max_shared=bytes;
        g.first_tail=(1u<<24)-255;
        assert(group_shared_bytes(g,256)==0);
    }
    assert(max_shared==52224);
    Group invalid{};
    assert(group_shared_bytes(invalid,1)==0);
    invalid.bottom=1;invalid.width=6;
    assert(group_shared_bytes(invalid,1)==0);

    // The same H bilinear form gives the direct cubic for every tested point,
    // including extension-field, zero and one coordinates and all Gram widths.
    for(unsigned bits=1;bits<=5;++bits) for(Fp3 r:coins) {
        const unsigned n=1u<<bits,half=n/2;
        std::vector<Children> children(n);
        for(unsigned i=0;i<n;++i) for(unsigned j=0;j<4;++j)
            children[i].v[j]={i*7+j+1,i+j*3,i*11+j*5};
        Round round{};round.bits=bits;round.prefix_equality=r;round.lambda=lambda;
        for(unsigned j=0;j<bits;++j) round.point[j]=coins[j%3];
        std::vector<Fp3> h(n*n),folded(half*half);
        for(unsigned i=0;i<n;++i) for(unsigned j=0;j<n;++j)
            h[i*n+j]=gram(children[i],children[j],lambda,Fp3{1,0,0});
        Cubic direct{};
        for(unsigned i=0;i<half;++i) {
            const Fp3 e0=mul(r,equality(round.point,bits,i));
            const Fp3 e1=mul(r,equality(round.point,bits,i+half));
            direct=sum(direct,coefficients(children[i],children[i+half],lambda,e0,e1));
        }
        const Cubic contracted=h_coefficients(h.data(),half,round);
        for(unsigned j=0;j<4;++j) assert(equal(direct.c[j],contracted.c[j]));
        for(Fp3 x:coins) {
            Fp3 expected{};
            for(unsigned i=0;i<half;++i) {
                const Fp3 e=mul(r,fold(equality(round.point,bits,i),equality(round.point,bits,i+half),x));
                expected=add(expected,mul(e,relation(fold(children[i],children[i+half],x),lambda)));
            }
            assert(equal(evaluate(contracted,x),expected));
        }
        for(unsigned i=0;i<half;++i) for(unsigned j=0;j<half;++j) {
            folded[i*half+j]=fold(fold(h[i*n+j],h[i*n+j+half],r),
                                  fold(h[(i+half)*n+j],h[(i+half)*n+j+half],r),r);
            const Fp3 expected=gram(fold(children[i],children[i+half],r),
                                    fold(children[j],children[j+half],r),lambda,Fp3{1,0,0});
            assert(equal(folded[i*half+j],expected));
        }
        ++cases;
    }
    std::cout << "C71_NATIVE_RANGE_HOST {\"cases\":" << cases
              << ",\"max_original_words\":2048,\"max_shared_payload_bytes\":" << max_shared
              << ",\"gpu_execution\":false,\"credit\":false}\n";
}
