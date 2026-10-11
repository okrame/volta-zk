// Simulated VMM and real owner/kernels on the CPU; no GPU credit.
#define main archived_range_host_main
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#include "c71_range_runtime_host.cpp"
#pragma GCC diagnostic pop
#undef main
#include "c71_source_tail.h"
#include <sys/mman.h>
#include <string>
static std::string fault;
static uint64_t physical=0;
struct Handle { size_t bytes; CUdeviceptr address; bool live; };
static std::vector<Handle> handles(1);
static bool bad(const char* name) { return fault==name; }
CUresult cuDeviceGetAttribute(int* out,int attribute,int device) {
    assert(attribute==CU_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED && device==0);
    *out=!bad("unsupported"); return bad("capability");
}
CUresult cuMemGetAllocationGranularity(size_t* out,const CUmemAllocationProp* p,int flag) {
    assert(p->type==CU_MEM_ALLOCATION_TYPE_PINNED && !p->location.id && !flag);
    *out=bad("large_granularity")?4ULL<<20:65536; return bad("granularity");
}
CUresult cuMemAddressReserve(CUdeviceptr* out,size_t bytes,size_t alignment,CUdeviceptr hint,unsigned long long flags) {
    assert(alignment==(2ULL<<20) && !hint && !flags); if(bad("reserve")) return 1;
    void* p=mmap(nullptr,bytes,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); assert(p!=MAP_FAILED);
    *out=reinterpret_cast<CUdeviceptr>(p); return 0;
}
CUresult cuMemCreate(CUmemGenericAllocationHandle* out,size_t bytes,const CUmemAllocationProp*,unsigned long long flags) {
    assert(!flags && bytes && bytes%65536==0); if(bad("create")) return 1;
    *out=handles.size(); handles.push_back({bytes,0,true}); physical+=bytes; fake_free-=bytes; return 0;
}
CUresult cuMemMap(CUdeviceptr address,size_t bytes,size_t offset,CUmemGenericAllocationHandle id,unsigned long long flags) {
    assert(!offset && !flags && id<handles.size()); auto& h=handles[id];
    assert(h.live && !h.address && h.bytes==bytes); if(bad("map")) return 1;
    assert(mmap(reinterpret_cast<void*>(address),bytes,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=MAP_FAILED);
    h.address=address; return 0;
}
CUresult cuMemSetAccess(CUdeviceptr address,size_t bytes,const CUmemAccessDesc* p,size_t count) {
    assert(count==1 && p->flags==CU_MEM_ACCESS_FLAGS_PROT_READWRITE); if(bad("access")) return 1;
    return mprotect(reinterpret_cast<void*>(address),bytes,PROT_READ|PROT_WRITE);
}
CUresult cuMemUnmap(CUdeviceptr address,size_t bytes) {
    if(bad("unmap")) return 1;
    for(auto& h:handles) if(h.live && h.address==address) {
        assert(h.bytes==bytes); h.address=0;
        assert(mmap(reinterpret_cast<void*>(address),bytes,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)!=MAP_FAILED); return 0;
    }
    assert(false); return 1;
}
CUresult cuMemRelease(CUmemGenericAllocationHandle id) {
    assert(id<handles.size() && handles[id].live && !handles[id].address); if(bad("release")) return 1;
    auto& h=handles[id]; h.live=false; physical-=h.bytes; fake_free+=h.bytes; return 0;
}
CUresult cuMemAddressFree(CUdeviceptr address,size_t bytes) {
    if(bad("address_free")) return 1;
    for(const auto& h:handles) assert(!h.live || !h.address || h.address<address || h.address>=address+bytes);
    return munmap(reinterpret_cast<void*>(address),bytes);
}
static void source_parity(C71RangeContext* c) {
    const c71_pcs::SourceShape shape{256,256,67*256,3,16,0};
    const auto lo=alloc(c,C71_PCS_POWERS,4*shape.rows),hi=alloc(c,C71_PCS_POWERS,4*c71_pcs::high_rows(shape));
    assert(!c71_pcs_source_powers(c,lo,hi,shape));
    const auto tw=alloc(c,C71_PCS_POWERS,shape.rows);
    assert(!c71_pcs_twiddles(c,tw,8));
    const auto pads=alloc(c,C71_PCS_BASE,128*shape.pad_rows);
    std::vector<uint64_t> coins(128*shape.pad_rows); for(size_t i=0;i<coins.size();++i) coins[i]=i*i+7;
    assert(!c71_pcs_words_upload(c,pads,0,coins.data(),coins.size()));
    std::vector<int16_t> data(shape.live/2); for(size_t i=0;i<data.size();++i) data[i]=int(i%60001)-30000;
    const auto in=alloc(c,C71_I16,data.size()); assert(!c71_range_upload(c,in,data.data(),data.size()*2));
    uint64_t outputs[2][2]{};
    for(unsigned pass=0;pass<2;++pass) {
        auto* out=outputs[pass];
        if(!pass) { out[0]=alloc(c,C71_PCS_SOURCE_PENDING,256*shape.rows); out[1]=alloc(c,C71_PCS_SOURCE_PENDING,256*shape.rows); }
        else {
            const auto before=stats(c).arena_bytes;
            assert(!c71_pcs_source_allocate(c,shape,out,out+1));
            assert(stats(c).arena_bytes-before==256*shape.rows*8+65536);
        }
        assert(!c71_pcs_source_begin(c,out[0],out[1],lo,hi,0,shape));
        const c71_pcs::SourceTile tile{0,data.size(),1,data.size(),0,0,2,2};
        assert(!c71_pcs_source_tile(c,in,&tile));
        assert(!c71_pcs_source_finish(c,out[0],out[1],0,pads,tw));
    }
    for(unsigned half=0;half<2;++half) assert(!c71_pcs_compare_words(c,outputs[0][half],outputs[1][half]));
}
int main(int argc,char** argv) {
    assert(argc==2); const std::string scenario=argv[1]; joint_limit=16ULL<<20;
    uint64_t owner=0;
    if(scenario=="source" || scenario.rfind("kv",0)==0) {
        C71RangeContext* c=nullptr; assert(!c71_range_create(0,8ULL<<20,256,joint_account,&c)); owner=stats(c).host_owner_bytes;
        if(scenario=="source") source_parity(c);
        else {
            uint64_t tail=0; assert(!c71_dense_kv_capacity(c,1024,&tail));
            assert(stats(c).arena_bytes==327680);
            const auto input=alloc(c,C71_I16,150*1024); std::vector<int16_t> data(150*1024,7);
            assert(!c71_range_upload(c,input,data.data(),data.size()*2));
            if(scenario=="kv_upload") { data.resize(450*1024); assert(c71_range_upload(c,tail,data.data(),data.size()*2)); }
            else if(scenario=="kv_numeric") {
                const auto raw=alloc(c,C71_I64,450*1024);
                assert(!c71_dense_pointwise(c,0,0,0,0,{0,0,0},raw));
                assert(c71_dense_quantize(c,raw,0,tail));
            } else {
                assert(!c71_signed_append_at(c,input,0,data.size(),tail,0));
                assert(physical==327680);
                int16_t value=0; assert(!c71_original_read(c,tail,C71_I16,data.size()-1,1,&value) && value==7);
                if(scenario=="kv_duplicate") assert(c71_signed_append_at(c,input,0,data.size(),tail,0));
                else if(scenario=="kv_fence") { fail_fence=true; assert(c71_signed_append_at(c,input,0,data.size(),tail,data.size())); }
                else {
                    assert(!c71_signed_append_at(c,input,0,data.size(),tail,data.size())); assert(physical==983040);
                    assert(!c71_signed_append_at(c,input,0,data.size(),tail,2*data.size()));
                    assert(!c71_original_read(c,tail,C71_I16,3*data.size()-1,1,&value) && value==7);
                }
            }
        }
        C71RangeStats final{}; const auto closed=c71_range_close(c,&final);
        assert((closed!=0)==(scenario=="kv_fence"));
        assert(joint_live==(scenario=="kv_fence"?327680:0));
        assert(physical==joint_live);
    } else {
        C71SourceTail tail;
        if(scenario=="capability" || scenario=="unsupported" || scenario=="granularity" || scenario=="large_granularity") {
            fault=scenario; assert(!tail.prepare(0,262144,65536));
        } else {
            assert(tail.prepare(0,262144,65536));
            const bool initial=scenario=="reserve" || scenario=="create" || scenario=="map" || scenario=="access" || scenario=="budget";
            if(initial) { fault=scenario; if(scenario=="budget") joint_limit=0; assert(!tail.create(joint_account)); }
            else {
                assert(tail.create(joint_account)); assert(joint_live==65536 && physical==65536);
                if(scenario.rfind("grow_",0)==0) {
                    fault=scenario.substr(5); if(fault=="budget") joint_limit=joint_live;
                    assert(!tail.grow());
                } else { assert(tail.grow()); assert(joint_live==262144 && physical==262144); }
            }
            const bool uncertain=scenario=="unmap" || scenario=="release" || scenario=="address_free";
            fault=uncertain?scenario:""; const auto debt=joint_live;
            assert(tail.release()!=uncertain); assert(joint_live==(uncertain?debt:0));
            if(uncertain) { fault=""; assert(!tail.release()); assert(joint_live==debt); }
            else assert(!physical);
        }
    }
    std::printf("C71_SOURCE_TAIL_HOST {\"scenario\":\"%s\",\"owner_bytes\":%llu,\"tail_metadata_bytes\":%zu,\"final_joint_debt_bytes\":%llu,\"gpu_execution\":false,\"credit\":false}\n",scenario.c_str(),(unsigned long long)owner,sizeof(C71SourceTail),(unsigned long long)joint_live);
}
