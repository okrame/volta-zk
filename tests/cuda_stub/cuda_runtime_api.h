// Test-only CUDA ABI subset. Never include this directory in a GPU build.
#pragma once
#include <cstddef>
struct FakeStream;
using cudaStream_t=FakeStream*;
using cudaError_t=int;
constexpr int cudaSuccess=0, cudaErrorInvalidValue=1;
constexpr unsigned cudaStreamNonBlocking=1;
enum cudaMemcpyKind { cudaMemcpyHostToDevice, cudaMemcpyDeviceToHost, cudaMemcpyDeviceToDevice };
enum cudaLimit { cudaLimitStackSize };
cudaError_t cudaSetDevice(int);
cudaError_t cudaDeviceSetLimit(cudaLimit,size_t);
cudaError_t cudaDeviceGetLimit(size_t*,cudaLimit);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t*,unsigned);
cudaError_t cudaStreamSynchronize(cudaStream_t);
cudaError_t cudaStreamDestroy(cudaStream_t);
cudaError_t cudaMalloc(void**,size_t);
cudaError_t cudaMemGetInfo(size_t*,size_t*);
cudaError_t cudaFree(void*);
cudaError_t cudaMemcpyAsync(void*,const void*,size_t,cudaMemcpyKind,cudaStream_t);
cudaError_t cudaMemsetAsync(void*,int,size_t,cudaStream_t);
const char* cudaGetErrorString(cudaError_t);
