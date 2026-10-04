#include "c71_nonlinear.cuh"
#include "c71_dense_i16.cuh"
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
extern "C" cudaError_t c71_rms_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,int64_t*,int16_t*,c71_nonlinear::Rms,uint32_t*);
extern "C" cudaError_t c71_qk_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
extern "C" cudaError_t c71_pv_launch(cudaStream_t,const int16_t* const*,const int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
extern "C" cudaError_t c71_softmax_launch(cudaStream_t,const int16_t*,const int32_t*,int16_t*,int16_t*,int64_t*,int64_t*,int16_t*,int64_t*,c71_nonlinear::Attention,uint32_t*);
extern "C" cudaError_t c71_dense_rne_launch(cudaStream_t,const int64_t*,int16_t*,uint64_t,int32_t,uint32_t*);
extern "C" cudaError_t c71_dense_i16_launch(cudaStream_t,const int16_t*,uint64_t,const int16_t*,uint64_t,int64_t*,uint64_t,uint32_t*,c71_dense::Shape);
extern "C" cudaError_t c71_dense_pointwise_launch(cudaStream_t,const int16_t*,const int16_t*,int64_t*,uint64_t,c71_dense::Pointwise,uint32_t*);

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
    for(const auto shape: {c71_dense::Shape{1,17,33},c71_dense::Shape{17,35,65},c71_dense::Shape{2,7,21504}}) {
        std::vector<int16_t> activations(size_t(shape.m)*shape.k),weights(size_t(shape.n)*shape.k);
        const int16_t extremes[]={-32767,-256,-129,-128,-1,0,1,127,128,255,256,32767};
        for(size_t index=0;index<activations.size();++index) activations[index]=extremes[(index*7+1)%12];
        for(size_t index=0;index<weights.size();++index) weights[index]=extremes[(index*5+3)%12];
        auto* left=device<int16_t>(activations.size()); auto* right=device<int16_t>(weights.size());
        auto* product=device<int64_t>(size_t(shape.m)*shape.n);
        upload(left,activations); upload(right,weights); reset();
        check(c71_dense_i16_launch(stream,left,activations.size(),right,weights.size(),product,size_t(shape.m)*shape.n,failed,shape));
        require(flag()==0); const auto actual=read(product,size_t(shape.m)*shape.n,stream);
        for(unsigned row=0;row<shape.m;++row) for(unsigned column=0;column<shape.n;++column) {
            int64_t expected=0;
            for(unsigned inner=0;inner<shape.k;++inner) expected+=int64_t(activations[size_t(row)*shape.k+inner])*weights[size_t(column)*shape.k+inner];
            require(actual[size_t(row)*shape.n+column]==expected);
        }
        check(cudaFree(left)); check(cudaFree(right)); check(cudaFree(product));
    }
    {
        const std::vector<int16_t> left={-32767,-256,-1,0,1,255,32767},right={32767,1,-1,7,-1,128,-32767};
        auto* first=device<int16_t>(left.size()); auto* second=device<int16_t>(right.size());
        auto* product=device<int64_t>(left.size()); upload(first,left); upload(second,right);
        for(const auto operation: {c71_dense::Pointwise{17,-29,0},c71_dense::Pointwise{1,1,1}}) {
            reset(); check(c71_dense_pointwise_launch(stream,first,second,product,left.size(),operation,failed)); require(flag()==0);
            const auto actual=read(product,left.size(),stream);
            for(size_t index=0;index<left.size();++index) require(actual[index]==(operation.multiply?int64_t(left[index])*right[index]:17*int64_t(left[index])-29*int64_t(right[index])));
        }
        check(cudaFree(first)); check(cudaFree(second)); check(cudaFree(product));
    }
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

    auto* norm_weights=device<int16_t>(2);
    auto* norm_product=device<int64_t>(4);
    auto* norm_statistic=device<int64_t>(2);
    upload(source,std::vector<int16_t>{1,1,-1,-1}); upload(norm_weights,std::vector<int16_t>{1,3}); reset();
    c71_nonlinear::Rms norm{2,1,2,1,{1,0,2,0,1,0}};
    check(c71_rms_launch(stream,source,norm_weights,norm_product,norm_statistic,output,norm,failed)); require(flag()==0);
    require(read(output,4,stream)==std::vector<int16_t>({0,2,0,-2}));
    require(read(norm_product,4,stream)==std::vector<int64_t>({1,3,-1,-3}));
    require(read(norm_statistic,2,stream)==std::vector<int64_t>({2,2}));
    upload(source,std::vector<int16_t>{3,4,-3,-4}); reset();
    norm={2,1,2,0,{1000000,0,1,0,500000,0}};
    check(c71_rms_launch(stream,source,nullptr,nullptr,norm_statistic,output,norm,failed)); require(flag()==0);
    require(read(output,4,stream)==std::vector<int16_t>({1,1,-1,-1}));
    norm={2,1,2,0,{1000000000000ULL,0,1,0,1,0}}; reset();
    check(c71_rms_launch(stream,source,nullptr,nullptr,norm_statistic,output,norm,failed)); require(flag()!=0);
    check(cudaFree(norm_weights)); check(cudaFree(norm_product)); check(cudaFree(norm_statistic));

    for(unsigned old:{0u,150u,300u}) {
        const c71_nonlinear::Attention shape{2,0,31,old,2,4};
        const unsigned columns=old+150,count=2*columns;
        input.resize(2*32*4);
        for(size_t index=0;index<input.size();++index) input[index]=int16_t(int(index%3)-1);
        std::vector<int16_t> history(columns*2*4,INT16_MIN);
        for(unsigned key=0;key<old+2;++key) for(unsigned column=0;column<8;++column) history[key*8+column]=int16_t(int((key+column)%5)-2);
        auto* tail=device<int16_t>(history.size()); upload(tail,history); upload(source,input);
        auto* raw=device<int64_t>(count); reset();
        check(c71_qk_launch(stream,source,tail,raw,shape,failed)); require(flag()==0);
        const auto scores=read(raw,count,stream);
        for(unsigned row=0;row<2;++row) for(unsigned key=0;key<columns;++key) {
            int64_t expected=0;
            if(key<=old+row) for(unsigned lane=0;lane<4;++lane) expected+=int64_t(input[(row*32+31)*4+lane])*history[key*8+4+lane];
            require(scores[row*columns+key]==expected);
        }
        check(c71_dense_rne_launch(stream,raw,output,count,0,failed)); require(flag()==0);
        auto* maxima=device<int16_t>(2); auto* differences=device<int16_t>(count);
        auto* exponentials=device<int64_t>(count); auto* denominators=device<int64_t>(2);
        auto* probabilities=device<int16_t>(count); auto* counts=device<int64_t>(65535);
        std::vector<int32_t> exponent_table(65535);
        for(unsigned entry=0;entry<65535;++entry) exponent_table[entry]=(1<<30)/(entry+1);
        auto* exp_table=device<int32_t>(65535); upload(exp_table,exponent_table);
        check(cudaMemsetAsync(counts,0,65535*8,stream)); reset();
        check(c71_softmax_launch(stream,output,exp_table,maxima,differences,exponentials,denominators,probabilities,counts,shape,failed)); require(flag()==0);
        const auto actual_maxima=read(maxima,2,stream),actual_differences=read(differences,count,stream),actual_probabilities=read(probabilities,count,stream);
        const auto actual_exponentials=read(exponentials,count,stream),actual_denominators=read(denominators,2,stream);
        std::vector<int64_t> visits(65535,0);
        for(unsigned row=0;row<2;++row) {
            const unsigned live=old+row+1;
            const int64_t maximum=*std::max_element(scores.begin()+row*columns,scores.begin()+row*columns+live);
            require(actual_maxima[row]==maximum); int64_t denominator=0;
            for(unsigned column=0;column<columns;++column) {
                const unsigned delta=column<live?unsigned(maximum-scores[row*columns+column]):0;
                require(actual_differences[row*columns+column]==int(delta)-32767);
                require(actual_exponentials[row*columns+column]==exponent_table[delta]);
                ++visits[delta]; if(column<live) denominator+=exponent_table[delta];
            }
            require(actual_denominators[row]==denominator);
            for(unsigned column=0;column<columns;++column) {
                const int64_t numerator=16384*actual_exponentials[row*columns+column],quotient=numerator/denominator,remainder=numerator%denominator;
                const int16_t expected=column<live?int16_t(quotient+(2*remainder>denominator || (2*remainder==denominator && (quotient&1)))):0;
                require(actual_probabilities[row*columns+column]==expected);
            }
        }
        require(read(counts,65535,stream)==visits);
        const int16_t* head_probabilities[32]; std::fill(head_probabilities,head_probabilities+32,probabilities);
        auto* product=device<int64_t>(256); reset();
        check(c71_pv_launch(stream,head_probabilities,tail,product,shape,failed)); require(flag()==0);
        const auto actual_product=read(product,256,stream);
        for(unsigned row=0;row<2;++row) for(unsigned head=0;head<32;++head) for(unsigned lane=0;lane<4;++lane) {
            int64_t expected=0;
            for(unsigned key=0;key<=old+row;++key) expected+=int64_t(actual_probabilities[row*columns+key])*history[key*8+(head/16)*4+lane];
            require(actual_product[(row*32+head)*4+lane]==expected);
        }
        std::vector<int16_t> invalid(scores.begin(),scores.end()); invalid[columns-1]=1; upload(output,invalid); reset();
        check(c71_softmax_launch(stream,output,exp_table,maxima,differences,exponentials,denominators,probabilities,counts,shape,failed)); require(flag()!=0);
        check(cudaFree(product)); check(cudaFree(exp_table)); check(cudaFree(counts)); check(cudaFree(probabilities));
        check(cudaFree(denominators)); check(cudaFree(exponentials)); check(cudaFree(differences)); check(cudaFree(maxima)); check(cudaFree(raw)); check(cudaFree(tail));
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
    std::printf("C71_NONLINEAR_CUDA_PARITY {\"dense_cases\":3,\"pointwise_cases\":2,\"lookup_entries\":65535,\"rope_cases\":%u,\"argmax_rows\":3,\"rms_cases\":3,\"attention_contexts\":3,\"rejections\":10,\"gpu_execution\":true,\"credit\":false}\n",rope_cases);
}
