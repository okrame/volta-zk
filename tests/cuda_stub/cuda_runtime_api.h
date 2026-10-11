// Test-only CUDA ABI subset. Never include this directory in a GPU build.
#pragma once
#include <cstddef>
struct FakeStream;
using cudaStream_t=FakeStream*;
struct FakePool;
using cudaMemPool_t=FakePool*;
enum cudaMemPoolAttr { cudaMemPoolAttrReleaseThreshold, cudaMemPoolAttrReservedMemCurrent, cudaMemPoolAttrUsedMemCurrent };
using cudaError_t=int;
constexpr int cudaSuccess=0, cudaErrorInvalidValue=1;
constexpr unsigned cudaStreamNonBlocking=1;
constexpr unsigned cudaHostRegisterMapped=2,cudaHostRegisterReadOnly=8;
enum cudaDeviceAttr { cudaDevAttrHostRegisterSupported,cudaDevAttrHostRegisterReadOnlySupported,cudaDevAttrCanMapHostMemory };
cudaError_t cudaDeviceGetAttribute(int*,cudaDeviceAttr,int);
cudaError_t cudaHostRegister(void*,size_t,unsigned);
cudaError_t cudaHostGetDevicePointer(void**,void*,unsigned);
cudaError_t cudaHostUnregister(void*);
enum cudaMemcpyKind { cudaMemcpyHostToDevice, cudaMemcpyDeviceToHost, cudaMemcpyDeviceToDevice };
enum cudaLimit { cudaLimitStackSize };
cudaError_t cudaSetDevice(int);
cudaError_t cudaDeviceSetLimit(cudaLimit,size_t);
cudaError_t cudaDeviceGetLimit(size_t*,cudaLimit);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t*,unsigned);
cudaError_t cudaStreamSynchronize(cudaStream_t);
cudaError_t cudaStreamDestroy(cudaStream_t);
cudaError_t cudaMalloc(void**,size_t);
cudaError_t cudaDeviceGetDefaultMemPool(cudaMemPool_t*,int);
cudaError_t cudaMemPoolSetAttribute(cudaMemPool_t,cudaMemPoolAttr,void*);
cudaError_t cudaMemPoolGetAttribute(cudaMemPool_t,cudaMemPoolAttr,void*);
cudaError_t cudaMemPoolTrimTo(cudaMemPool_t,size_t);
cudaError_t cudaMallocFromPoolAsync(void**,size_t,cudaMemPool_t,cudaStream_t);
cudaError_t cudaFreeAsync(void*,cudaStream_t);
cudaError_t cudaMemGetInfo(size_t*,size_t*);
cudaError_t cudaFree(void*);
cudaError_t cudaMemcpyAsync(void*,const void*,size_t,cudaMemcpyKind,cudaStream_t);
cudaError_t cudaMemsetAsync(void*,int,size_t,cudaStream_t);
const char* cudaGetErrorString(cudaError_t);
