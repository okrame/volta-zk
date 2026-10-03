#include "c71_nonlinear.cuh"
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" cudaError_t c71_lookup_launch(cudaStream_t,const int16_t*,const int16_t*,int16_t*,int64_t*,uint64_t,uint32_t*);
extern "C" cudaError_t c71_histogram_seal_launch(cudaStream_t,int64_t*,uint32_t*);
extern "C" cudaError_t c71_rope_launch(cudaStream_t,const int16_t*,const int32_t*,int64_t*,c71_nonlinear::Rope,uint32_t*);
extern "C" cudaError_t c71_argmax_select_launch(cudaStream_t,const int16_t*,uint32_t*,unsigned,unsigned,uint32_t*);
extern "C" cudaError_t c71_argmax_slack_launch(cudaStream_t,const int16_t*,const uint32_t*,int16_t*,unsigned,unsigned,uint32_t*);

static void require(bool valid) { if(!valid) { std::fputs("C71 nonlinear parity failed\n",stderr); std::exit(1); } }
static void check(cudaError_t status) { if(status!=cudaSuccess) { std::fprintf(stderr,"CUDA: %s\n",cudaGetErrorString(status)); std::exit(1); } }
template<class Value> static Value* device(size_t count) {
    Value* buffer=nullptr; check(cudaMalloc(reinterpret_cast<void**>(&buffer),count*sizeof(Value))); return buffer;
}
template<class Value> static void upload(Value* output,const std::vector<Value>& input) {
    check(cudaMemcpy(output,input.data(),input.size()*sizeof(Value),cudaMemcpyHostToDevice));
}
template<class Value> static std::vector<Value> read(Value* input,size_t count,cudaStream_t stream) {
    std::vector<Value> output(count);
    check(cudaMemcpyAsync(output.data(),input,count*sizeof(Value),cudaMemcpyDeviceToHost,stream));
    check(cudaStreamSynchronize(stream)); return output;
}
int main() {
    cudaDeviceProp properties{}; check(cudaSetDevice(0)); check(cudaGetDeviceProperties(&properties,0));
    require(properties.major==9);
    cudaStream_t stream; check(cudaStreamCreateWithFlags(&stream,cudaStreamNonBlocking));
    auto* failed=device<uint32_t>(1);
    auto reset=[&] { check(cudaMemsetAsync(failed,0,4,stream)); };
    auto flag=[&] { return read(failed,1,stream)[0]; };
    std::vector<int16_t> input(2*65535),table(65535);
    for(size_t index=0;index<table.size();++index) {
        table[index]=int16_t((int(index)-32767)/2);
        input[index]=input[index+65535]=int16_t(int(index)-32767);
    }
    auto* source=device<int16_t>(input.size());
    auto* lookup_table=device<int16_t>(table.size());
    auto* output=device<int16_t>(input.size());
    auto* histogram=device<int64_t>(65535);
    upload(source,input); upload(lookup_table,table); reset();
    check(cudaMemsetAsync(histogram,0,65535*8,stream));
    check(c71_lookup_launch(stream,source,lookup_table,output,histogram,input.size(),failed));
    check(c71_histogram_seal_launch(stream,histogram,failed)); require(flag()==0);
    const auto selected=read(output,input.size(),stream);
    for(size_t index=0;index<input.size();++index) require(selected[index]==table[index%65535]);
    for(auto count:read(histogram,65535,stream)) require(count==2);
    input[13]=INT16_MIN; upload(source,input); reset();
    check(c71_lookup_launch(stream,source,lookup_table,output,histogram,input.size(),failed)); require(flag()!=0);
    input[13]=-32754; table[13]=INT16_MIN; upload(source,input); upload(lookup_table,table); reset();
    check(c71_lookup_launch(stream,source,lookup_table,output,histogram,input.size(),failed)); require(flag()!=0);
    check(cudaMemsetAsync(histogram,255,65535*8,stream)); reset();
    check(c71_histogram_seal_launch(stream,histogram,failed)); require(flag()!=0);
    check(cudaFree(histogram)); check(cudaFree(lookup_table));

    unsigned rope_cases=0;
    for(unsigned pairs:{64u,128u}) {
        const c71_nonlinear::Rope shape{3,2,512,pairs};
        input.resize(shape.rows*shape.heads*shape.width);
        for(size_t index=0;index<input.size();++index) input[index]=int16_t(int(index*19%65535)-32767);
        std::vector<int32_t> coefficients(shape.rows*pairs*2);
        for(size_t index=0;index<coefficients.size();++index) coefficients[index]=(index%3==0?-(1<<30):index%3==1?1<<30:0);
        auto* device_coefficients=device<int32_t>(coefficients.size());
        auto* raw=device<int64_t>(input.size());
        upload(source,input); upload(device_coefficients,coefficients); reset();
        check(c71_rope_launch(stream,source,device_coefficients,raw,shape,failed)); require(flag()==0);
        const auto actual=read(raw,input.size(),stream);
        for(unsigned row=0;row<shape.rows;++row) for(unsigned head=0;head<shape.heads;++head) for(unsigned pair=0;pair<shape.width/2;++pair) {
            const size_t first=(row*shape.heads+head)*shape.width+pair,second=first+shape.width/2;
            const int64_t cosine=pair<pairs?coefficients[(row*pairs+pair)*2]:1<<30;
            const int64_t sine=pair<pairs?coefficients[(row*pairs+pair)*2+1]:0;
            require(actual[first]==cosine*input[first]-sine*input[second]);
            require(actual[second]==sine*input[first]+cosine*input[second]);
        }
        coefficients[0]=INT32_MAX; upload(device_coefficients,coefficients); reset();
        check(c71_rope_launch(stream,source,device_coefficients,raw,shape,failed)); require(flag()!=0);
        check(cudaFree(raw)); check(cudaFree(device_coefficients)); ++rope_cases;
    }

    constexpr unsigned rows=3,columns=513;
    input.assign(rows*columns,-32767);
    input[511]=input[512]=32767;
    std::fill(input.begin()+columns,input.begin()+2*columns,17);
    input[2*columns+255]=input[2*columns+256]=-100;
    auto* tokens=device<uint32_t>(rows);
    upload(source,input); reset();
    check(c71_argmax_select_launch(stream,source,tokens,rows,columns,failed));
    check(c71_argmax_slack_launch(stream,source,tokens,output,rows,columns,failed)); require(flag()==0);
    require(read(tokens,rows,stream)==std::vector<uint32_t>({511,0,255}));
    const auto slack=read(output,input.size(),stream);
    for(unsigned row=0;row<rows;++row) {
        const auto begin=input.begin()+row*columns;
        const unsigned best=std::max_element(begin,begin+columns)-begin;
        for(unsigned column=0;column<columns;++column)
            require(slack[row*columns+column]==int(begin[best])-begin[column]-int(column<best)-32768);
    }
    input[7]=INT16_MIN; upload(source,input); reset();
    check(c71_argmax_select_launch(stream,source,tokens,rows,columns,failed)); require(flag()!=0);
    check(cudaFree(tokens)); check(cudaFree(output)); check(cudaFree(source)); check(cudaFree(failed));
    check(cudaStreamDestroy(stream));
    std::printf("C71_NONLINEAR_CUDA_PARITY {\"lookup_entries\":65535,\"rope_cases\":%u,\"argmax_rows\":3,\"rejections\":6,\"gpu_execution\":true,\"credit\":false}\n",rope_cases);
}
