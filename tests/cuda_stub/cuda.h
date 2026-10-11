#pragma once
#include <cstddef>
#include <cstdint>
using CUdeviceptr=uintptr_t;
using CUmemGenericAllocationHandle=uint64_t;
using CUresult=int;
constexpr int CUDA_SUCCESS=0, CU_DEVICE_ATTRIBUTE_VIRTUAL_ADDRESS_MANAGEMENT_SUPPORTED=1;
constexpr int CU_MEM_ALLOCATION_TYPE_PINNED=1, CU_MEM_LOCATION_TYPE_DEVICE=1;
constexpr int CU_MEM_ALLOC_GRANULARITY_MINIMUM=0, CU_MEM_ACCESS_FLAGS_PROT_READWRITE=3;
struct CUmemLocation { int type,id; };
struct CUmemAllocationProp { int type; CUmemLocation location; };
struct CUmemAccessDesc { CUmemLocation location; unsigned long long flags; };
CUresult cuDeviceGetAttribute(int*,int,int);
CUresult cuMemGetAllocationGranularity(size_t*,const CUmemAllocationProp*,int);
CUresult cuMemAddressReserve(CUdeviceptr*,size_t,size_t,CUdeviceptr,unsigned long long);
CUresult cuMemCreate(CUmemGenericAllocationHandle*,size_t,const CUmemAllocationProp*,unsigned long long);
CUresult cuMemMap(CUdeviceptr,size_t,size_t,CUmemGenericAllocationHandle,unsigned long long);
CUresult cuMemSetAccess(CUdeviceptr,size_t,const CUmemAccessDesc*,size_t);
CUresult cuMemUnmap(CUdeviceptr,size_t);
CUresult cuMemRelease(CUmemGenericAllocationHandle);
CUresult cuMemAddressFree(CUdeviceptr,size_t);
