// One A/KV tail, backed in at most two public-lifetime segments.
// The caller fences before growth/release and charges this owner's metadata.
#pragma once
#include <cuda.h>
#include <algorithm>
#include <cstdint>

struct C71SourceTail {
    CUdeviceptr address=0;
    uint64_t full=0, prefix=0, charged=0;
    CUmemGenericAllocationHandle handles[2]{};
    bool mapped[2]{}, release_attempted=false;
    int device=0;
    C71RangeAccount account=nullptr;
    const char* error=nullptr;

    bool reject(const char* message) {
        if(!error) error=message;
        return false;
    }
    bool check(CUresult result,const char* message) {
        return result==CUDA_SUCCESS || reject(message);
    }
    CUmemAllocationProp properties() const {
        CUmemAllocationProp prop{};
        prop.type=CU_MEM_ALLOCATION_TYPE_PINNED;
        prop.location.type=CU_MEM_LOCATION_TYPE_DEVICE;
        prop.location.id=device;
        return prop;
    }
    bool prepare(int selected,uint64_t logical,uint64_t initial) {
        if(full || address || charged || !logical || initial>logical)
            return reject("source tail geometry or owner overlap");
        device=selected;
        int supported=0;
        if(!check(cuDeviceGetAttribute(&supported,CU_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED,device),
            "source tail capability query failed") || !supported)
            return reject("source tail VMM unavailable");
        const auto prop=properties(); size_t granularity=0;
        if(!check(cuMemGetAllocationGranularity(&granularity,&prop,CU_MEM_ALLOC_GRANULARITY_MINIMUM),
            "source tail granularity query failed")) return false;
        if(!granularity || (granularity&(granularity-1)) || granularity>(2ULL<<20) || logical>UINT64_MAX-granularity)
            return reject("source tail granularity exceeds bounded layout");
        full=(logical+granularity-1)&~uint64_t(granularity-1);
        prefix=std::max(uint64_t(granularity),(initial+granularity-1)&~uint64_t(granularity-1));
        return true;
    }
    bool segment(unsigned index,uint64_t offset,uint64_t size) {
        const auto prop=properties();
        if(!check(cuMemCreate(&handles[index],size,&prop,0),"source tail physical allocation failed") ||
           !check(cuMemMap(address+offset,size,0,handles[index],0),"source tail map failed")) return false;
        mapped[index]=true;
        CUmemAccessDesc access{};
        access.location=prop.location;
        access.flags=CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
        return check(cuMemSetAccess(address+offset,size,&access,1),"source tail access failed");
    }
    bool create(C71RangeAccount callback) {
        if(!full || charged || address) return reject("source tail create state");
        account=callback;
        if(account && account(int64_t(prefix))) return reject("source tail joint budget exhausted");
        charged=prefix;
        if(!check(cuMemAddressReserve(&address,full,2ULL<<20,0,0),"source tail address reserve failed")) return false;
        return segment(0,0,prefix);
    }
    bool grow() {
        if(error || !address || !mapped[0] || charged!=prefix || handles[1])
            return reject("source tail growth state");
        if(prefix==full) return true;
        const auto extra=full-prefix;
        if(account && account(int64_t(extra))) return reject("source tail growth budget exhausted");
        charged=full;
        return segment(1,prefix,extra);
    }
    bool release() {
        if(release_attempted) return reject("source tail release ownership uncertain");
        release_attempted=true;
        for(unsigned i=0;i<2;++i) {
            const auto offset=i?prefix:0, size=i?full-prefix:prefix;
            if(mapped[i]) {
                if(!check(cuMemUnmap(address+offset,size),"source tail unmap failed")) return false;
                mapped[i]=false;
            }
            if(handles[i]) {
                if(!check(cuMemRelease(handles[i]),"source tail handle release failed")) return false;
                handles[i]=0;
            }
        }
        if(address && !check(cuMemAddressFree(address,full),"source tail address release failed")) return false;
        if(account && charged) account(-int64_t(charged));
        *this={};
        return true;
    }
};
