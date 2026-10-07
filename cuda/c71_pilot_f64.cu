// Offline floating initializer only; no protocol producer or integer admission.
// cuBLAS FP64 GEMV: https://docs.nvidia.com/cuda/cublas/index.html#cublas-t-gemv
#include <cuda_runtime.h>
#include <cublas_v2.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <new>
#include <initializer_list>

using Clock = std::chrono::steady_clock;
static double seconds(Clock::time_point t) { return std::chrono::duration<double>(Clock::now()-t).count(); }
struct Pilot {
    cudaStream_t stream{};
    cublasHandle_t blas{};
    int16_t* weights{};
    double *block{}, *input{}, *output{};
    void* workspace{};
    uint64_t words{}, loaded{}, h2d{}, d2h{};
    double upload_seconds{}, convert_seconds{}, dot_seconds{}, download_seconds{};
    bool sealed=false, stopped=false;
};
static int reject(Pilot* c) { if(c) c->stopped=true; return -1; }
static constexpr uint64_t block_cells=128ULL*21504, workspace_bytes=8ULL<<20;
static constexpr uint64_t scratch_bytes=8*(block_cells+21504+128)+workspace_bytes;
#define CUDA(call) do { if((call)!=cudaSuccess) { c->stopped=true; return -1; } } while(0)
#define BLAS(call) do { if((call)!=CUBLAS_STATUS_SUCCESS) { c->stopped=true; return -1; } } while(0)
extern "C" int c71_pilot_cuda_close(Pilot* c) {
    if(!c) return 0;
    int failure=0;
    if(c->stream && cudaStreamSynchronize(c->stream)!=cudaSuccess) failure=1;
    if(c->blas && cublasDestroy(c->blas)!=CUBLAS_STATUS_SUCCESS) failure=1;
    for(void* p: {static_cast<void*>(c->weights),static_cast<void*>(c->block),
                 static_cast<void*>(c->input),static_cast<void*>(c->output),c->workspace})
        if(p && cudaFree(p)!=cudaSuccess) failure=1;
    if(c->stream && cudaStreamDestroy(c->stream)!=cudaSuccess) failure=1;
    delete c;
    return failure?-1:0;
}
extern "C" int c71_pilot_cuda_create(uint64_t words, Pilot** result) {
    if(!result || !words || words>61394690560ULL/2) return -1;
    Pilot* c=new(std::nothrow) Pilot;
    *result=c;
    if(!c) return -1;
    c->words=words;
    cudaDeviceProp properties{};
    CUDA(cudaSetDevice(0)); CUDA(cudaGetDeviceProperties(&properties,0));
    if(properties.major!=9) { c->stopped=true; return -1; }
    size_t free=0,total=0; CUDA(cudaMemGetInfo(&free,&total));
    if(free<2*words+scratch_bytes+(1ULL<<30)) { c->stopped=true; return -1; }
    CUDA(cudaStreamCreateWithFlags(&c->stream,cudaStreamNonBlocking));
    BLAS(cublasCreate(&c->blas)); BLAS(cublasSetStream(c->blas,c->stream));
    BLAS(cublasSetMathMode(c->blas,CUBLAS_PEDANTIC_MATH));
    BLAS(cublasSetAtomicsMode(c->blas,CUBLAS_ATOMICS_NOT_ALLOWED));
    CUDA(cudaMalloc(reinterpret_cast<void**>(&c->weights),2*words));
    CUDA(cudaMalloc(reinterpret_cast<void**>(&c->block),8*block_cells));
    CUDA(cudaMalloc(reinterpret_cast<void**>(&c->input),8*21504));
    CUDA(cudaMalloc(reinterpret_cast<void**>(&c->output),8*128));
    CUDA(cudaMalloc(&c->workspace,workspace_bytes));
    BLAS(cublasSetWorkspace(c->blas,c->workspace,workspace_bytes));
    CUDA(cudaMemGetInfo(&free,&total));
    if(free<(1ULL<<30)) { c->stopped=true; return -1; }
    return 0;
}
extern "C" int c71_pilot_cuda_upload(Pilot* c,const int16_t* input,uint64_t words) {
    if(!c || c->stopped || c->sealed || !input || !words || words>(1ULL<<27)
       || words>c->words-c->loaded) return reject(c);
    auto start=Clock::now();
    for(uint64_t i=0;i<words;++i) if(input[i]==INT16_MIN) { c->stopped=true; return -1; }
    CUDA(cudaMemcpyAsync(c->weights+c->loaded,input,2*words,cudaMemcpyHostToDevice,c->stream));
    CUDA(cudaStreamSynchronize(c->stream));
    c->loaded+=words; c->h2d+=2*words; c->upload_seconds+=seconds(start);
    return 0;
}
extern "C" int c71_pilot_cuda_seal(Pilot* c) {
    if(!c || c->stopped || c->sealed || c->loaded!=c->words) return reject(c);
    c->sealed=true; return 0;
}
__global__ void convert(const int16_t* weights,double* output,uint64_t count,int exponent) {
    uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<count) output[i]=ldexp(double(weights[i]),exponent);
}
extern "C" int c71_pilot_cuda_product(Pilot* c,uint64_t offset,uint32_t rows,uint32_t columns,
                                      int exponent,const double* input,double* output) {
    if(!c || c->stopped || !c->sealed || !input || !output || !rows || rows>262144
       || !columns || columns>21504 || exponent < -128 || exponent > 128
       || offset>c->words || uint64_t(rows)*columns>c->words-offset) return reject(c);
    for(unsigned i=0;i<columns;++i) if(!std::isfinite(input[i])) { c->stopped=true; return -1; }
    auto start=Clock::now();
    CUDA(cudaMemcpyAsync(c->input,input,8*columns,cudaMemcpyHostToDevice,c->stream));
    CUDA(cudaStreamSynchronize(c->stream));
    c->h2d+=8*columns; c->upload_seconds+=seconds(start);
    const double one=1,zero=0;
    for(unsigned first=0;first<rows;first+=128) {
        unsigned count=std::min(128u,rows-first);
        start=Clock::now();
        convert<<<(uint64_t(count)*columns+255)/256,256,0,c->stream>>>(
            c->weights+offset+uint64_t(first)*columns,c->block,uint64_t(count)*columns,exponent);
        CUDA(cudaGetLastError()); CUDA(cudaStreamSynchronize(c->stream));
        c->convert_seconds+=seconds(start);
        start=Clock::now();
        BLAS(cublasDgemv(c->blas,CUBLAS_OP_T,columns,count,&one,c->block,columns,c->input,1,&zero,c->output,1));
        CUDA(cudaStreamSynchronize(c->stream)); c->dot_seconds+=seconds(start);
        start=Clock::now();
        CUDA(cudaMemcpyAsync(output+first,c->output,8*count,cudaMemcpyDeviceToHost,c->stream));
        CUDA(cudaStreamSynchronize(c->stream));
        c->d2h+=8*count; c->download_seconds+=seconds(start);
        for(unsigned i=first;i<first+count;++i) if(!std::isfinite(output[i])) { c->stopped=true; return -1; }
    }
    return 0;
}
extern "C" int c71_pilot_cuda_stats(Pilot* c,uint64_t* bytes,double* times) {
    if(!c || !bytes || !times) return -1;
    bytes[0]=2*c->words; bytes[1]=scratch_bytes; bytes[2]=c->h2d; bytes[3]=c->d2h;
    times[0]=c->upload_seconds; times[1]=c->convert_seconds;
    times[2]=c->dot_seconds; times[3]=c->download_seconds;
    return 0;
}
