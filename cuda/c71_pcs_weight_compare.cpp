// Future authorized H100 component diagnostic, not the canonical runner.
// Link against the REAL CUDA common-owner library. Never execute on a CPU
// stub or treat these reduced timings as a pinned W/proof speedup.
#include "c71_range_runtime.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/resource.h>

// A test-only owner library is deliberately rejected even if its ABI matches.
extern "C" void c71_range_test_failure(unsigned) __attribute__((weak));

namespace {
using U128=unsigned __int128;
using I128=__int128;
using Clock=std::chrono::steady_clock;
constexpr uint64_t prime=0xffffffff00000001ULL;
#ifdef C71_PCS_COMPARE_LARGE
constexpr unsigned log_rows=12;
#else
constexpr unsigned log_rows=6;
#endif
constexpr uint64_t rows=uint64_t{1}<<log_rows,q_count=256,message_rows=rows*q_count,group_rows=32*rows;
constexpr unsigned columns=128,pad_rows=1536,cosets=4096,replicas=3;
constexpr uint64_t temporary_limit=(log_rows==6?16ULL:512ULL)<<20,physical_reserve=256ULL<<20;
static_assert(prime==P && columns*message_rows*sizeof(int16_t)==(uint64_t{1}<<(log_rows+16)));
C71RangeContext* owner=nullptr;
uint64_t native_charge=0,host_charge=0,joint_peak=0;

void admission_peak() {
    if(native_charge>temporary_limit || host_charge>temporary_limit-native_charge)
        throw std::runtime_error("diagnostic joint temporary budget exhausted");
    if(native_charge+host_charge>joint_peak) joint_peak=native_charge+host_charge;
}
int account(int64_t delta) {
    if(delta>=0) {
        const uint64_t amount=uint64_t(delta);
        if(amount>temporary_limit || native_charge>temporary_limit-amount ||
           host_charge>temporary_limit-native_charge-amount) return -1;
        native_charge+=amount;
        if(native_charge+host_charge>joint_peak) joint_peak=native_charge+host_charge;
    } else {
        const uint64_t amount=uint64_t(-(delta+1))+1;
        if(amount>native_charge) return -1;
        native_charge-=amount;
    }
    return 0;
}
void check(int status,const char* label) {
    if(status) throw std::runtime_error(std::string(label)+": "+c71_range_error(owner));
}
void require(bool valid,const char* label) { if(!valid) throw std::runtime_error(label); }
C71RangeStats stats() { C71RangeStats s{}; check(c71_range_stats(owner,&s),"stats"); return s; }
uint64_t allocate(uint32_t kind,uint64_t count) {
    uint64_t handle=0; check(c71_range_alloc(owner,kind,count,&handle),"allocate"); return handle;
}
void release(uint64_t handle) { check(c71_range_release(owner,handle),"release"); }
double seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now()-start).count(); }
uint64_t multiply(uint64_t a,uint64_t b) { return uint64_t(U128(a)*b%prime); }
uint64_t add(uint64_t a,uint64_t b) { return uint64_t((U128(a)+b)%prime); }
uint64_t subtract(uint64_t a,uint64_t b) { return a>=b?a-b:prime-(b-a); }
uint64_t residue(I128 a) { const I128 r=a%I128(prime); return uint64_t(r<0?r+prime:r); }
uint64_t power(uint64_t a,uint64_t n) {
    uint64_t out=1;
    for(;n;n/=2,a=multiply(a,a)) if(n%2) out=multiply(out,a);
    return out;
}

// Independent radix-2 integer DFT, without five-pass/SignedWide helpers.
void reference_fft(uint64_t* values,uint64_t root) {
    for(uint64_t i=1,j=0;i<rows;++i) {
        uint64_t bit=rows/2;
        for(;j&bit;bit/=2) j^=bit;
        j^=bit;
        if(i<j) { const uint64_t value=values[i]; values[i]=values[j]; values[j]=value; }
    }
    for(uint64_t width=2;width<=rows;width*=2) {
        const uint64_t step=power(root,rows/width);
        for(uint64_t first=0;first<rows;first+=width) {
            uint64_t factor=1;
            for(uint64_t j=0;j<width/2;++j,factor=multiply(factor,step)) {
                const uint64_t a=values[first+j],b=multiply(values[first+j+width/2],factor);
                values[first+j]=add(a,b); values[first+j+width/2]=subtract(a,b);
            }
        }
    }
}
uint64_t packed_address(uint64_t index) {
    // Original W[M,128], public dyadic tessellation into 32 strips of width4.
    const uint64_t strip=index/(4*message_rows),local=index%(4*message_rows);
    return (local/4)*columns+strip*4+local%4;
}
struct Delta {
    uint64_t allocations=0,releases=0,h2d=0,d2h=0,zeroed=0,launches=0,fences=0,d2d=0;
    void append(C71RangeStats before,C71RangeStats after) {
        allocations+=after.allocations-before.allocations; releases+=after.releases-before.releases;
        h2d+=after.h2d_bytes-before.h2d_bytes; d2h+=after.d2h_bytes-before.d2h_bytes;
        zeroed+=after.zeroed_bytes-before.zeroed_bytes; launches+=after.launches-before.launches;
        fences+=after.fences-before.fences; d2d+=after.d2d_bytes-before.d2d_bytes;
    }
};
struct Sample { double calls[2]{},whole=0; Delta backend[2],all; uint64_t compared_words=0; };
struct Diagnostic {
    std::vector<int16_t> weights;
    std::vector<uint64_t> pads,salts,reference;
    std::vector<c71_pcs::WeightTile> tiles;
    std::vector<c71_pcs::Hash32> cpu_nodes;
    std::array<std::vector<c71_pcs::Hash32>,3> published;
    uint64_t pads_handle=0,salts_handle=0,tiles_handle=0,twiddles=0;
    std::array<uint64_t,3> rings{};
    uint64_t host_vectors() const {
        uint64_t count=pads.capacity()*8+salts.capacity()*8+reference.capacity()*8+
            tiles.capacity()*sizeof(c71_pcs::WeightTile)+cpu_nodes.capacity()*sizeof(c71_pcs::Hash32);
        for(const auto& values:published) count+=values.capacity()*sizeof(c71_pcs::Hash32);
        return count; // ONLY the immutable synthetic packed W payload excluded
    }
    void prepare_inputs() {
        weights.resize(columns*message_rows); pads.resize(columns*pad_rows);
        salts.resize(4*group_rows); reference.resize(columns*group_rows); tiles.resize(32);
        cpu_nodes.resize(group_rows); for(auto& values:published) values.resize(group_rows);
        host_charge=host_vectors()+sizeof(*this); admission_peak();
        for(uint64_t i=0;i<weights.size();++i) {
            const int32_t value=i%8==0?-32767:i%8==1?32767:i%8==2?0:
                int32_t((i*131+(i/128)*31)%65535)-32767;
            weights[i]=int16_t(value);
        }
        for(uint64_t i=0;i<pads.size();++i) pads[i]=i%7==0?prime-1:i%7==1?0:(i*123456789+97)%prime;
        for(uint64_t i=0;i<salts.size();++i) salts[i]=i%5==0?prime-1:(i*987654321+71)%prime;
        for(uint64_t strip=0;strip<tiles.size();++strip)
            tiles[strip]={strip*4*message_rows,4*message_rows,strip*4,columns,4};
    }
    void install() {
        check(c71_dense_weights_begin(owner,weights.size()),"weights_begin");
        check(c71_dense_weights_upload(owner,0,weights.data(),weights.size()),"weights_upload");
        check(c71_dense_weights_seal(owner),"weights_seal");
        tiles_handle=allocate(C71_PCS_WEIGHT_TILES,tiles.size());
        check(c71_pcs_tiles_upload(owner,tiles_handle,tiles.data(),tiles.size()),"tiles_upload");
        pads_handle=allocate(C71_PCS_BASE,pads.size()); salts_handle=allocate(C71_PCS_BASE,salts.size());
        check(c71_pcs_words_upload(owner,pads_handle,0,pads.data(),pads.size()),"pads_upload");
        check(c71_pcs_words_upload(owner,salts_handle,0,salts.data(),salts.size()),"salts_upload");
        twiddles=allocate(C71_PCS_POWERS,rows); check(c71_pcs_twiddles(owner,twiddles,log_rows),"twiddles");
        for(auto& ring:rings) { ring=allocate(C71_PCS_BASE,8*group_rows); check(c71_pcs_ring_zero(owner,ring),"ring_zero"); }
    }
    void reference_group(unsigned first_coset) {
        const uint64_t omega=power(7,(prime-1)/(rows*cosets)),root=power(7,(prime-1)/rows);
        require(power(omega,rows*cosets)==1 && power(omega,rows*cosets/2)!=1 &&
            power(root,rows)==1 && power(root,rows/2)!=1,"independent root order differs");
        for(unsigned lane=0;lane<32;++lane) {
            std::array<uint64_t,q_count+(pad_rows+rows-1)/rows> high{};
            std::array<uint64_t,rows> low{};
            const uint64_t l=power(omega,first_coset+lane),h=power(l,rows);
            high[0]=low[0]=1;
            for(uint64_t i=1;i<high.size();++i) high[i]=multiply(high[i-1],h);
            for(uint64_t i=1;i<low.size();++i) low[i]=multiply(low[i-1],l);
            for(unsigned column=0;column<columns;++column) {
                uint64_t* values=reference.data()+(column*32+lane)*rows;
                for(uint64_t row=0;row<rows;++row) {
                    // |sum| <= 256*32767*(p-1) < 2^87, so every
                    // signed __int128 prefix is exact before ONE reduction.
                    I128 signed_sum=0;
                    for(uint64_t q=0;q<q_count;++q) {
                        const uint64_t index=uint64_t(column)*message_rows+q*rows+row;
                        signed_sum+=I128(weights[packed_address(index)])*high[q];
                    }
                    uint64_t value=residue(signed_sum);
                    for(uint64_t j=row;j<pad_rows;j+=rows)
                        value=add(value,multiply(pads[column*pad_rows+j],high[(message_rows+j)/rows]));
                    values[row]=multiply(value,low[row]);
                }
                // Four transforms additionally checked against direct DFT.
                const bool direct=(column==0 || column==127) && (lane==0 || lane==31);
                std::array<uint64_t,rows> before{};
                if(direct) std::memcpy(before.data(),values,rows*8);
                reference_fft(values,root);
                if(direct) for(uint64_t k=0;k<rows;++k) {
                    uint64_t out=0,factor=1; const uint64_t step=power(root,k);
                    for(uint64_t v:before) { out=add(out,multiply(v,factor)); factor=multiply(factor,step); }
                    require(out==values[k],"independent FFT/direct DFT mismatch");
                }
            }
        }
        // B12 hash codec is shared with the CUDA kernels and separately
        // checked against Rust elsewhere; the field oracle above is independent.
        for(uint64_t row=0;row<group_rows;++row) {
            auto cv=c71_pcs::leaf_start(reference.data(),group_rows,row);
            for(unsigned first=4;first<=116;first+=8)
                cv=c71_pcs::leaf_step(cv,reference.data()+first*group_rows,
                    reference.data()+(first+4)*group_rows,group_rows,row,first);
            cpu_nodes[row]=c71_pcs::leaf_finish(cv,reference.data()+124*group_rows,salts.data(),
                group_rows,row,group_rows,row);
        }
    }
    void compare_nodes(std::array<uint64_t,3>& handles) {
        uint64_t count=group_rows;
        for(;;) {
            for(unsigned backend=0;backend<3;++backend) {
                check(c71_pcs_read_digests(owner,handles[backend],0,count,published[backend].data()),"read_digests");
                require(std::memcmp(published[backend].data(),cpu_nodes.data(),count*sizeof(c71_pcs::Hash32))==0,
                    "GPU leaf/node digest differs from CPU polynomial reference");
            }
            if(count==1) break;
            const uint64_t stride=count>rows?rows:1;
            for(uint64_t i=0;i<count/2;++i) {
                const uint64_t left=2*(i/stride)*stride+i%stride;
                cpu_nodes[i]=c71_pcs::node(cpu_nodes[left],cpu_nodes[left+stride]);
            }
            for(auto& handle:handles) {
                const uint64_t next=allocate(C71_PCS_DIGEST,count/2);
                check(c71_pcs_nodes(owner,handle,next,stride),"nodes"); release(handle); handle=next;
            }
            count/=2;
        }
        for(uint64_t handle:handles) release(handle);
    }
    Sample run(c71_pcs::WeightShape shape,uint64_t low,uint64_t high,bool tensor_first) {
        Sample sample; const auto started=Clock::now(); const auto initial=stats();
        std::array<uint64_t,3> states{};
        auto fill=[&](unsigned column,unsigned slots) {
            shape.first_column=column; shape.slots=slots;
            // Upload drains any preceding async hash work BEFORE timing either
            // kernel path; each measured C ABI call includes its FFT+flag fence.
            check(c71_pcs_words_upload(owner,rings[2],slots*group_rows,
                reference.data()+column*group_rows,4*group_rows),"reference_upload");
            for(unsigned order=0;order<2;++order) {
                const unsigned backend=tensor_first?(1-order):order;
                const auto before=stats(); const auto call_start=Clock::now();
                const int status=backend?c71_pcs_weight_tensor(owner,tiles_handle,pads_handle,low,high,twiddles,rings[1],shape):
                    c71_pcs_weight(owner,tiles_handle,pads_handle,low,high,twiddles,rings[0],shape);
                sample.calls[backend]+=seconds(call_start); check(status,"weight+FFT+fence");
                sample.backend[backend].append(before,stats());
            }
            check(c71_pcs_compare_words(owner,rings[0],rings[1]),"ordinary/tensor exact words");
            check(c71_pcs_compare_words(owner,rings[0],rings[2]),"ordinary/reference exact words");
            sample.compared_words+=2*8*group_rows;
        };
        fill(0,0); fill(4,4);
        for(unsigned backend=0;backend<3;++backend) {
            states[backend]=allocate(C71_PCS_HASH_PENDING,group_rows);
            check(c71_pcs_leaf_start(owner,rings[backend],states[backend]),"leaf_start");
        }
        for(unsigned first=4;first<=116;first+=8) {
            fill(first+4,0);
            for(unsigned backend=0;backend<3;++backend)
                check(c71_pcs_leaf_step(owner,rings[backend],states[backend],first),"leaf_step");
            if(first<116) fill(first+8,4);
        }
        fill(124,0);
        for(unsigned backend=0;backend<3;++backend)
            check(c71_pcs_leaf_finish(owner,rings[backend],salts_handle,states[backend],0,group_rows),"leaf_finish");
        compare_nodes(states);
        sample.whole=seconds(started); sample.all.append(initial,stats());
        for(const auto& delta:sample.backend)
            require(delta.h2d==0 && delta.d2h==128 && delta.launches==192 && delta.fences==32 && delta.d2d==0,
                "weight+FFT+fence accounting differs");
        return sample;
    }
    void cleanup() {
        for(uint64_t ring:rings) release(ring);
        for(uint64_t handle: {pads_handle,salts_handle,tiles_handle,twiddles}) release(handle);
    }
};
void print_delta(const Delta& d) {
    std::printf("{\"allocations\":%llu,\"releases\":%llu,\"h2d_bytes\":%llu,\"d2h_bytes\":%llu,"
        "\"zeroed_bytes\":%llu,\"launches\":%llu,\"fences\":%llu,\"d2d_bytes\":%llu}",
        static_cast<unsigned long long>(d.allocations),static_cast<unsigned long long>(d.releases),
        static_cast<unsigned long long>(d.h2d),static_cast<unsigned long long>(d.d2h),
        static_cast<unsigned long long>(d.zeroed),static_cast<unsigned long long>(d.launches),
        static_cast<unsigned long long>(d.fences),static_cast<unsigned long long>(d.d2d));
}
}

int main() {
    try {
        require(!c71_range_test_failure,"fake CUDA owner forbidden");
        require(c71_range_runtime_abi()==4,"common-owner ABI differs");
        Diagnostic d; d.prepare_inputs();
        const auto setup=Clock::now();
        check(c71_range_create(0,temporary_limit+physical_reserve,physical_reserve,account,&owner),"create CUDA owner");
        const auto created=stats();
        d.install(); const double install_s=seconds(setup);
        Delta install_delta; install_delta.append(created,stats());
        for(unsigned first_coset: {0u,4064u}) {
            const auto reference_start=Clock::now(); d.reference_group(first_coset);
            const double reference_s=seconds(reference_start);
            c71_pcs::WeightShape shape{message_rows,rows,pad_rows,cosets,first_coset,0,0};
            const uint64_t low=allocate(C71_PCS_POWERS,32*rows);
            const uint64_t high=allocate(C71_PCS_POWERS,32*c71_pcs::high_rows(shape));
            check(c71_pcs_powers(owner,low,high,shape),"coset powers");
            // One checked warm pair, then alternate pair order. Rebuild the CPU
            // digest layer after each destructive reference Merkle reduction.
            {
                const auto saved=d.cpu_nodes;
                host_charge=d.host_vectors()+sizeof(d)+saved.capacity()*sizeof(c71_pcs::Hash32); admission_peak();
                const Sample warm=d.run(shape,low,high,false);
                std::printf("C71_PCS_WEIGHT_COMPARE_WARM {\"first_coset\":%u,\"timing_credit\":false,\"complete_diagnostic_delta\":",first_coset);
                print_delta(warm.all); std::printf("}\n");
                for(unsigned replica=0;replica<replicas;++replica) {
                    std::copy(saved.begin(),saved.end(),d.cpu_nodes.begin());
                    const Sample sample=d.run(shape,low,high,replica%2!=0);
                    std::printf("C71_PCS_WEIGHT_COMPARE_SAMPLE {\"first_coset\":%u,\"replica\":%u,\"tensor_first\":%s,"
                        "\"ordinary_call_s\":%.9f,\"tensor_call_s\":%.9f,\"all_validation_s\":%.9f,"
                        "\"cpu_reference_s\":%.9f,\"words_compared\":%llu,\"ordinary_delta\":",
                        first_coset,replica,replica%2?"true":"false",sample.calls[0],sample.calls[1],sample.whole,
                        reference_s,static_cast<unsigned long long>(sample.compared_words));
                    print_delta(sample.backend[0]); std::printf(",\"tensor_delta\":"); print_delta(sample.backend[1]);
                    std::printf(",\"complete_diagnostic_delta\":"); print_delta(sample.all);
                    std::printf(",\"all_post_fft_words_equal\":true,\"all_leaf_node_digests_equal\":true,"
                        "\"canonical_workload\":false,\"credit\":false}\n");
                }
            }
            release(low); release(high);
            host_charge=d.host_vectors()+sizeof(d); admission_peak();
        }
        const auto peak=stats(); d.cleanup();
        C71RangeStats final{};
        const int close_status=c71_range_close(owner,&final); owner=nullptr;
        // close destroys the context even on failure; never read its error or
        // repeat cleanup through the expired pointer.
        require(close_status==0,"CUDA owner close failed");
        require(final.arena_bytes==0 && final.weights_bytes==0 && final.cleanup_failed==0 && native_charge==0,"cleanup incomplete");
        rusage usage{}; require(getrusage(RUSAGE_SELF,&usage)==0,"getrusage failed");
        std::printf("C71_PCS_WEIGHT_COMPARE_RESOURCES {\"rows\":%llu,\"q\":256,\"pad_rows\":1536,\"columns\":128,"
            "\"cosets\":4096,\"groups\":2,\"replicas_per_group\":3,\"setup_install_s\":%.9f,"
            "\"immutable_host_w_excluded_bytes\":%llu,\"immutable_device_w_excluded_bytes\":%llu,"
            "\"host_vector_capacity_bytes\":%llu,\"host_object_bytes\":%zu,\"native_host_owner_bytes\":%llu,"
            "\"native_device_capacity_peak_bytes\":%llu,\"joint_named_capacity_peak_bytes\":%llu,"
            "\"runtime_allocator_stack_shared_reserve_bytes\":268435456,\"joint_temporary_with_reserve_bytes\":%llu,"
            "\"all_named_with_w_and_reserve_bytes\":%llu,"
            "\"rss_max_bytes\":%llu,\"tensor_cta_shared_bytes\":8448,\"fft_transpose_cta_shared_bytes\":16896,"
            "\"field_download_bytes\":0,\"physical_gpu_peak_measured\":false,\"canonical_workload\":false,\"credit\":false,\"install_delta\":",
            static_cast<unsigned long long>(rows),install_s,
            static_cast<unsigned long long>(d.weights.capacity()*sizeof(int16_t)),
            static_cast<unsigned long long>(peak.weights_bytes),
            static_cast<unsigned long long>(d.host_vectors()),sizeof(d),static_cast<unsigned long long>(peak.host_owner_bytes),
            static_cast<unsigned long long>(peak.peak_capacity_bytes),static_cast<unsigned long long>(joint_peak),
            static_cast<unsigned long long>(joint_peak+physical_reserve),
            static_cast<unsigned long long>(joint_peak+physical_reserve+d.weights.capacity()*sizeof(int16_t)+peak.weights_bytes),
            static_cast<unsigned long long>(usage.ru_maxrss)*1024);
        print_delta(install_delta);
        Delta all_delta; all_delta.append(created,final);
        std::printf(",\"complete_run_delta\":"); print_delta(all_delta);
        std::printf(",\"complete\":true}\n");
        return 0;
    } catch(const std::exception& e) {
        std::fprintf(stderr,"C71_PCS_WEIGHT_COMPARE_FAILED %s\n",e.what());
        if(owner) { c71_range_abort(owner); C71RangeStats final{}; c71_range_close(owner,&final); owner=nullptr; }
        return 1;
    }
}
