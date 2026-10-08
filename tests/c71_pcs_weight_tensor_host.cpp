// Exact host fragment/shuffle model; not PTX execution or GPU scheduling.
// The oracle uses direct signed __int128 dots and independent integer % p.
#include "c71_pcs_weight_tensor.cuh"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

using I128=__int128;
using U128=unsigned __int128;
constexpr uint64_t prime=0xffffffff00000001ULL;
static_assert(prime==P);
struct Work {
    uint64_t mma=0,high_loads=0,w_loads=0,outputs=0,prefix_checks=0;
};
static uint64_t modulo(I128 value) {
    I128 r=value%I128(prime); if(r<0) r+=prime;
    return uint64_t(r);
}
static uint64_t product(uint64_t a,uint64_t b) { return uint64_t((U128(a)*b)%prime); }
static uint64_t plus(uint64_t a,uint64_t b) { return uint64_t((U128(a)+b)%prime); }
static uint64_t exponent(uint64_t base,uint64_t n) {
    uint64_t result=1;
    for(;n;n/=2,base=product(base,base)) if(n%2) result=product(result,base);
    return result;
}
static void wide_equals(c71_pcs::SignedWide got,I128 expected) {
    const U128 encoded=U128(expected);
    assert(got.lo==uint64_t(encoded) && got.hi==uint64_t(encoded>>64));
    assert(got.residue()==modulo(expected));
}
static int byte_at(uint32_t word,unsigned b) {
    const unsigned x=(word>>(8*b))&255;
    return x<128?int(x):int(x)-256;
}
static void prefix_add(int32_t& value,int term,unsigned k,Work& work) {
    const int64_t next=int64_t(value)+term, bound=int64_t(k)*128*128;
    assert(next>=-bound && next<=bound && next>=INT32_MIN && next<=INT32_MAX);
    value=int32_t(next); ++work.prefix_checks;
}

// Same pack/mapping/compose and two XOR shuffles as the candidate. Only the
// MMA's dense integer dot is emulated, after reconstructing fragments and
// proving that every A/B position and every output has exactly one owner.
static std::vector<c71_pcs::SignedWide> fragments(const std::vector<int16_t>& original,
    const std::vector<uint64_t>& high,unsigned k,Work& work) {
    using namespace c71_dense;
    using namespace c71_pcs_tensor;
    assert(k<=max_q && original.size()==mma_rows*max_q && high.size()>=uint64_t(k)*32);
    const unsigned padded=(k+31)&~31u;
    std::vector<c71_pcs::SignedWide> out(mma_rows*32);
    for(unsigned warp=0;warp<4;++warp) for(unsigned limb=0;limb<limbs;++limb) {
        int32_t accum[32][4][4]{},sx[32][2]{},sw[32]{};
        for(unsigned first=0;first<padded;first+=32) {
            int ah[16][32]{},al[16][32]{},bh[8][32]{},bl[8][32]{};
            unsigned ac[16][32]{},bc[8][32]{};
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<4;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned b=0;b<4;++b) {
                        const int16_t v=original[a_row(lane,r)*max_q+first+a_k(lane,r,b)];
                        assert(v!=INT16_MIN); sx[lane][r%2]+=v; pack(v,b,hi,lo);
                    }
                    for(unsigned b=0;b<4;++b) {
                        const unsigned row=a_row(lane,r),q=a_k(lane,r,b);
                        assert(++ac[row][q]==1); ah[row][q]=byte_at(hi,b); al[row][q]=byte_at(lo,b);
                    }
                }
                for(unsigned r=0;r<2;++r) {
                    uint32_t hi=0,lo=0;
                    for(unsigned b=0;b<4;++b) {
                        const unsigned q=first+w_k(lane,r,b),coset=warp*8+w_row(lane);
                        const int16_t v=q<k?digit(high[q*32+coset],limb):0;
                        if(q<k) ++work.high_loads;
                        sw[lane]+=v; pack(v,b,hi,lo);
                    }
                    for(unsigned b=0;b<4;++b) {
                        const unsigned col=w_row(lane),q=w_k(lane,r,b);
                        assert(++bc[col][q]==1); bh[col][q]=byte_at(hi,b); bl[col][q]=byte_at(lo,b);
                    }
                }
            }
            for(unsigned row=0;row<16;++row) for(unsigned q=0;q<32;++q) assert(ac[row][q]==1);
            for(unsigned col=0;col<8;++col) for(unsigned q=0;q<32;++q) assert(bc[col][q]==1);
            for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
                const unsigned row=out_row(lane,r),col=out_col(lane,r);
                for(unsigned q=0;q<32;++q) {
                    prefix_add(accum[lane][r][0],ah[row][q]*bh[col][q],first+q+1,work);
                    prefix_add(accum[lane][r][1],ah[row][q]*bl[col][q],first+q+1,work);
                    prefix_add(accum[lane][r][2],al[row][q]*bh[col][q],first+q+1,work);
                    prefix_add(accum[lane][r][3],al[row][q]*bl[col][q],first+q+1,work);
                }
            }
            work.mma+=4;
        }
        for(unsigned shift=1;shift<=2;shift*=2) {
            int32_t oldx[32][2],oldw[32];
            std::memcpy(oldx,sx,sizeof(sx)); std::copy(sw,sw+32,oldw);
            for(unsigned lane=0;lane<32;++lane) {
                for(unsigned r=0;r<2;++r) sx[lane][r]+=oldx[lane^shift][r];
                sw[lane]+=oldw[lane^shift];
            }
        }
        unsigned visits[16][8]{};
        for(unsigned lane=0;lane<32;++lane) for(unsigned r=0;r<4;++r) {
            const unsigned row=out_row(lane,r),col=warp*8+out_col(lane,r);
            assert(++visits[row][out_col(lane,r)]==1);
            const int32_t* a=accum[lane][r];
            const int64_t dot=compose(a[0],a[1],a[2],a[3],sx[lane][r/2],sw[4*out_col(lane,r)],padded);
            I128 signed_reference=0,partial_reference=0; int32_t sum_reference=0;
            const uint64_t mask=limb==3?UINT64_MAX:(uint64_t{1}<<(16*(limb+1)))-1;
            for(unsigned q=0;q<k;++q) {
                const int16_t weight=original[row*max_q+q];
                const uint64_t factor=high[q*32+col];
                const int32_t d=int32_t((factor>>(16*limb))&65535)-32768;
                signed_reference+=I128(weight)*d; sum_reference+=weight;
                partial_reference+=I128(weight)*(factor&mask);
            }
            assert(dot==signed_reference && sx[lane][r/2]==sum_reference);
            assert(add_dot(out[row*32+col],dot,sx[lane][r/2],limb));
            wide_equals(out[row*32+col],partial_reference);
        }
        for(unsigned row=0;row<16;++row) for(unsigned col=0;col<8;++col) assert(visits[row][col]==1);
    }
    return out;
}

static void digits() {
    using namespace c71_pcs_tensor;
    for(unsigned value=0;value<65536;++value) for(unsigned limb=0;limb<limbs;++limb) {
        const uint64_t input=uint64_t(value)<<(16*limb);
        const int16_t d=digit(input,limb);
        assert(d==int(value)-32768);
        assert(256*c71_dense::high(d)+c71_dense::low(d)+128==d);
        U128 recovered=0;
        for(unsigned l=0;l<limbs;++l) recovered+=U128(int32_t(digit(input,l))+32768)<<(16*l);
        assert(recovered==input);
    }
    for(uint64_t value: {uint64_t{0},uint64_t{1},uint64_t{65535},uint64_t{65536},
        (uint64_t{1}<<32)-1,uint64_t{1}<<32,(uint64_t{1}<<48)-1,uint64_t{1}<<48,
        prime/2,prime-2,prime-1}) {
        U128 recovered=0;
        for(unsigned l=0;l<limbs;++l) recovered+=U128(int32_t(digit(value,l))+32768)<<(16*l);
        assert(recovered==value && value<prime);
    }
    // Rejections preserve the previous exact accumulator; no partial append.
    for(unsigned bad=0;bad<5;++bad) {
        c71_pcs::SignedWide sum{17,29};
        const int64_t dot=bad==1?-(int64_t{1}<<38):bad==2?(int64_t{1}<<38):0;
        const int32_t source_sum=bad==3?-(int32_t{1}<<23):bad==4?(int32_t{1}<<23):0;
        assert(!add_dot(sum,dot,source_sum,bad==0?4:0) && sum.lo==17 && sum.hi==29);
    }
}

static unsigned brute_needed(c71_pcs::WeightShape s,uint64_t live,uint64_t row0) {
    unsigned needed=0;
    for(unsigned q=0;q<s.message_rows/s.rows;++q) for(unsigned a=0;a<16;++a) {
        const uint64_t index=(uint64_t(s.first_column)+a/4)*s.message_rows+uint64_t(q)*s.rows+row0+a%4;
        if(index<live) needed=q+1;
    }
    return needed;
}
static void suffixes() {
    for(const auto& geometry: {std::pair<uint64_t,uint64_t>{4,1},{4,256},{16,4},{64,1}}) {
        c71_pcs::WeightShape s{geometry.first*geometry.second,geometry.first,11,64,0,0,0};
        const uint64_t m=s.message_rows;
        std::vector<uint64_t> limits{0,1,m-1,m,m+1,2*m-1,3*m+3,4*m-1,128*m-1,128*m};
        if(m==4) { limits.clear(); for(uint64_t live=0;live<=128*m;++live) limits.push_back(live); }
        for(uint64_t live:limits) for(unsigned column=0;column<128;column+=4) {
            s.first_column=column;
            for(uint64_t row0=0;row0<s.rows;row0+=4)
                assert(c71_pcs_tensor::needed_q(s,live,row0)==brute_needed(s,live,row0));
        }
    }
    // Pinned geometry metadata only: no D35 values or buffers are allocated.
    c71_pcs::WeightShape pinned{uint64_t{1}<<28,uint64_t{1}<<20,1536,4096,4064,0,4};
    for(unsigned column: {0u,112u,116u,124u}) for(uint64_t row: {uint64_t{0},pinned.rows/2,pinned.rows-4}) {
        pinned.first_column=column; assert(c71_pcs::valid(pinned));
        assert(c71_pcs_tensor::needed_q(pinned,30697345280ULL,row)==brute_needed(pinned,30697345280ULL,row));
    }
}

struct Packed {
    std::vector<int16_t> words,logical;
    std::vector<uint64_t> logical_address;
    std::vector<c71_pcs::WeightTile> tiles;
};
static uint64_t largest_power(uint64_t n) { uint64_t p=1; while(p<=n/2) p*=2; return p; }
static Packed ragged(uint64_t m) {
    Packed data;
    const int16_t edges[]={-32767,-257,-128,-1,0,1,127,256,32767};
    for(const auto& source: {std::pair<uint64_t,uint64_t>{3*(m/8)+1,5},{m/16+3,3},{1,7},{m/32+1,11},{1,1}}) {
        const uint64_t rows=source.first,columns=source.second,base=data.words.size();
        for(uint64_t i=0;i<rows*columns;++i) data.words.push_back(edges[(base+i*7+i/11)%9]);
        for(uint64_t r=0;r<rows;) {
            const uint64_t height=largest_power(rows-r);
            for(uint64_t c=0;c<columns;) {
                const uint64_t width=largest_power(columns-c);
                data.tiles.push_back({data.logical.size(),height*width,base+r*columns+c,columns,width});
                for(uint64_t rr=r;rr<r+height;++rr) for(uint64_t cc=c;cc<c+width;++cc) {
                    const uint64_t address=base+rr*columns+cc;
                    data.logical.push_back(data.words[address]); data.logical_address.push_back(address);
                }
                c+=width;
            }
            r+=height;
        }
    }
    assert(data.logical.size()==data.words.size());
    return data;
}

static Work pcs_case(uint64_t rows,unsigned q,unsigned pad_rows,unsigned first_coset) {
    using namespace c71_pcs_tensor;
    c71_pcs::WeightShape s{rows*q,rows,pad_rows,64,first_coset,0,0};
    assert(c71_pcs::valid(s));
    const auto data=ragged(s.message_rows); const uint64_t live=data.logical.size();
    assert(live<=128*s.message_rows);
    std::vector<unsigned> visits(live),packed_visits(live);
    std::vector<uint64_t> high(c71_pcs::high_rows(s)*32),low(rows*32),pads(128*pad_rows);
    const uint64_t omega=exponent(7,(prime-1)/(rows*s.cosets));
    assert(omega==c71_pcs::power(7,(P-1)/(rows*s.cosets)));
    for(unsigned coset=0;coset<32;++coset) {
        const uint64_t l=exponent(omega,first_coset+coset),h=exponent(l,rows);
        uint64_t value=1;
        for(uint64_t r=0;r<rows;++r,value=product(value,l)) low[coset*rows+r]=value;
        value=1;
        for(uint64_t n=0;n<c71_pcs::high_rows(s);++n,value=product(value,h)) high[n*32+coset]=value;
    }
    for(uint64_t i=0;i<pads.size();++i) pads[i]=i%5==0?prime-1:i%5==1?0:i%5==2?1:(i*123456789+987654321)%prime;
    Work work;
    for(unsigned column0=0;column0<128;column0+=4) {
        s.first_column=column0; s.slots=(column0/4)%2?4:0;
        std::vector<uint64_t> ring(8*32*rows,UINT64_MAX),expected(4*32*rows);
        std::vector<I128> raw(expected.size()); std::vector<unsigned> stores(ring.size());
        // Independent polynomial oracle: original coefficients, then original
        // pad positions M+j, scatter to their residue class modulo R.
        for(unsigned c=0;c<4;++c) for(unsigned n=0;n<q;++n) for(uint64_t r=0;r<rows;++r) {
            const uint64_t index=uint64_t(column0+c)*s.message_rows+uint64_t(n)*rows+r;
            if(index<live) for(unsigned coset=0;coset<32;++coset)
                raw[(c*32+coset)*rows+r]+=I128(data.logical[index])*high[n*32+coset];
        }
        for(uint64_t i=0;i<raw.size();++i) expected[i]=modulo(raw[i]);
        for(unsigned c=0;c<4;++c) for(unsigned j=0;j<pad_rows;++j) {
            const uint64_t position=s.message_rows+j,r=position%rows,n=position/rows;
            for(unsigned coset=0;coset<32;++coset) {
                const uint64_t i=(c*32+coset)*rows+r;
                expected[i]=plus(expected[i],product(pads[uint64_t(column0+c)*pad_rows+j],high[n*32+coset]));
            }
        }
        for(unsigned c=0;c<4;++c) for(unsigned coset=0;coset<32;++coset) for(uint64_t r=0;r<rows;++r) {
            const uint64_t i=(c*32+coset)*rows+r; expected[i]=product(expected[i],low[coset*rows+r]);
        }
        for(uint64_t row0=0;row0<rows;row0+=4) {
            const unsigned needed=needed_q(s,live,row0),padded=(needed+31)&~31u;
            assert(needed==brute_needed(s,live,row0));
            std::vector<int16_t> original(mma_rows*max_q);
            for(unsigned a=0;a<16;++a) for(unsigned n=0;n<padded;++n) {
                const uint64_t index=(uint64_t(column0)+a/4)*s.message_rows+uint64_t(n)*rows+row0+a%4;
                if(n<needed && index<live) {
                    const uint64_t address=c71_pcs::packed_address(data.tiles.data(),data.tiles.size(),index,live);
                    assert(address==data.logical_address[index]);
                    original[a*max_q+n]=data.words[address];
                    assert(++visits[index]==1 && ++packed_visits[address]==1); ++work.w_loads;
                }
            }
            const uint64_t old_mma=work.mma,old_high=work.high_loads;
            const auto sums=fragments(original,high,needed,work);
            assert(work.mma-old_mma==64*((needed+31)/32) && work.high_loads-old_high==128*needed);
            for(unsigned a=0;a<16;++a) for(unsigned coset=0;coset<32;++coset) {
                const unsigned column=column0+a/4; const uint64_t row=row0+a%4;
                uint64_t value=sums[a*32+coset].residue();
                for(uint64_t j=row;j<pad_rows;j+=rows)
                    value=fp_add(value,fp_mul(pads[uint64_t(column)*pad_rows+j],high[((s.message_rows+j)/rows)*32+coset]));
                const uint64_t index=(s.slots+a/4)*32*rows+coset*rows+row;
                assert(++stores[index]==1); ring[index]=fp_mul(value,low[coset*rows+row]); ++work.outputs;
            }
        }
        for(uint64_t i=0;i<ring.size();++i) {
            if(i>=s.slots*32*rows && i<(s.slots+4)*32*rows) {
                assert(stores[i]==1 && ring[i]==expected[i-s.slots*32*rows]);
            } else assert(stores[i]==0 && ring[i]==UINT64_MAX);
        }
    }
    for(unsigned v:visits) assert(v==1);
    for(unsigned v:packed_visits) assert(v==1);
    assert(work.w_loads==live && work.outputs==128*32*rows);
    return work;
}

int main() {
    digits(); suffixes(); Work dots,pcs;
    const uint64_t edges[]={0,1,65535,65536,(uint64_t{1}<<32)-1,uint64_t{1}<<32,
        (uint64_t{1}<<48)-1,uint64_t{1}<<48,prime/2,prime-2,prime-1};
    unsigned cases=0;
    for(unsigned k: {1u,31u,32u,33u,128u,255u,256u}) for(unsigned pattern=0;pattern<4;++pattern) {
        std::vector<int16_t> original(16*c71_pcs_tensor::max_q);
        std::vector<uint64_t> high(k*32);
        for(unsigned a=0;a<16;++a) for(unsigned q=0;q<k;++q)
            original[a*c71_pcs_tensor::max_q+q]=pattern==0?0:pattern==1?-32767:pattern==2?32767:int((a*71+q*1237)%65535)-32767;
        for(unsigned q=0;q<k;++q) for(unsigned c=0;c<32;++c)
            high[q*32+c]=pattern==1?prime-1:edges[(q*7+c*3)%11];
        const uint64_t before=dots.mma,loads=dots.high_loads;
        const auto out=fragments(original,high,k,dots);
        assert(dots.mma-before==64*((k+31)/32) && dots.high_loads-loads==128*k);
        for(unsigned a=0;a<16;++a) for(unsigned c=0;c<32;++c) {
            I128 reference=0;
            for(unsigned q=0;q<k;++q) reference+=I128(original[a*c71_pcs_tensor::max_q+q])*high[q*32+c];
            wide_equals(out[a*32+c],reference); ++dots.outputs;
        }
        ++cases;
    }
    for(unsigned first_coset: {0u,32u}) for(unsigned geometry=0;geometry<4;++geometry) {
        const uint64_t rows[]={4,4,16,64}; const unsigned q[]={1,256,4,1},pads[]={11,1536,17,65};
        const Work w=pcs_case(rows[geometry],q[geometry],pads[geometry],first_coset);
        pcs.mma+=w.mma; pcs.high_loads+=w.high_loads; pcs.w_loads+=w.w_loads;
        pcs.outputs+=w.outputs; pcs.prefix_checks+=w.prefix_checks;
    }
    assert(c71_pcs_tensor::shared_bytes==8448 && pcs.w_loads==5808 && pcs.outputs==720896);
    std::printf("C71_PCS_TENSOR_HOST {\"digit_values\":65536,\"digit_checks\":262144,\"canonical_edges\":11,"
        "\"dot_cases\":%u,\"dot_outputs\":%llu,\"max_k\":256,\"pcs_cases\":8,\"source_scans\":8,"
        "\"w_loads\":%llu,\"pcs_outputs\":%llu,\"mma\":%llu,\"high_loads\":%llu,"
        "\"prefix_checks\":%llu,\"shared_bytes\":8448,\"rejections\":5,\"gpu_execution\":false,\"credit\":false}\n",
        cases,static_cast<unsigned long long>(dots.outputs),static_cast<unsigned long long>(pcs.w_loads),
        static_cast<unsigned long long>(pcs.outputs),static_cast<unsigned long long>(pcs.mma),
        static_cast<unsigned long long>(pcs.high_loads),static_cast<unsigned long long>(pcs.prefix_checks+dots.prefix_checks));
}
