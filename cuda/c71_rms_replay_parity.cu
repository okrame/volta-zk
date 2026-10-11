// Native compiler plans versus ORIGINAL layered Boolean reference bitplanes.
// Reconstructs twelve original bytes per cell; no CPU-folded field rows.
#include <cuda_runtime.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "c71_rms_prefix.cuh"
namespace r=c71_rms_prefix;
void require(cudaError_t status) { if(status!=cudaSuccess) throw std::runtime_error(cudaGetErrorString(status)); }
struct Memory {
    std::vector<void*> pointers;
    uint64_t requested=0,h2d=0,d2h=0;
    template<class T> T* allocate(size_t count) {
        void* pointer=nullptr;require(cudaMalloc(&pointer,std::max<size_t>(1,count)*sizeof(T)));
        pointers.push_back(pointer);requested+=std::max<size_t>(1,count)*sizeof(T);return static_cast<T*>(pointer);
    }
    template<class T> void upload(T* pointer,const std::vector<T>& input) {
        if(input.empty()) return;
        require(cudaMemcpy(pointer,input.data(),input.size()*sizeof(T),cudaMemcpyHostToDevice));h2d+=input.size()*sizeof(T);
    }
    void release() {
        require(cudaDeviceSynchronize());
        for(auto p:pointers) require(cudaFree(p));pointers.clear();
    }
    ~Memory() { for(auto p:pointers) (void)cudaFree(p); }
};
int main(int argc,char** argv) {
    try {
        if(argc!=2) throw std::runtime_error("one original native fixture required");
        std::ifstream file(argv[1],std::ios::binary);file.exceptions(std::ios::failbit|std::ios::badbit);
        file.seekg(0,std::ios::end);const auto bytes=file.tellg();file.seekg(0);
        if(bytes<20 || bytes>(256<<20)) throw std::runtime_error("bounded native fixture size");
        char magic[8];file.read(magic,8);if(std::string(magic,8)!="C71RMD01") throw std::runtime_error("native fixture magic");
        auto read32=[&]() { unsigned char b[4];file.read(reinterpret_cast<char*>(b),4);
            return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24); };
        auto read64=[&]() { const uint64_t low=read32();return low|(uint64_t(read32())<<32); };
        const unsigned programs=read32(),width=read32(),depth=read32(),capacity=256;
        if(programs!=159 || !width || width>16384 || width&(width-1) || depth>99)
            throw std::runtime_error("original RMS fixture geometry");
        int device=0;require(cudaGetDevice(&device));cudaDeviceProp properties{};
        require(cudaGetDeviceProperties(&properties,device));if(properties.major!=9) throw std::runtime_error("Hopper required");
        Memory global;
        auto* df=global.allocate<uint8_t>(16*capacity*12);
        auto* da=global.allocate<uint16_t>(16*capacity);
        auto* stage=global.allocate<uint64_t>(width*capacity/4);
        std::vector<uint8_t> frames(16*capacity*12);
        std::vector<uint16_t> assignments(16*capacity);
        std::vector<uint32_t> got(width*capacity/2);
        uint64_t requested_peak=global.requested,h2d=0,comparisons=0,cases=0;
        for(unsigned p=0;p<programs;++p) {
            const unsigned index=read32(),ports=read32(),slots=read32(),stages=read32(),nodes_count=read32(),wires=read32();
            if(index!=p || ports<2 || ports>98 || slots<ports || slots>16384 || stages>99 || nodes_count>(1<<20) || wires>width)
                throw std::runtime_error("native plan bounds");
            std::vector<uint32_t> boundaries(stages+1),outputs(wires);
            std::vector<r::Node> nodes(nodes_count);
            for(auto& n:boundaries) n=read32();
            for(auto& g:nodes) {g.op=read32();g.z=read32();g.x=read32();g.y=read32();}
            for(auto& n:outputs) {n=read32();if(n>=slots) throw std::runtime_error("native output bounds");}
            if(boundaries.front()!=0 || boundaries.back()!=nodes_count) throw std::runtime_error("native stage endpoints");
            std::vector<unsigned> written(slots),initialized(slots);
            std::fill(initialized.begin(),initialized.begin()+ports,1);
            for(unsigned s=0;s<stages;++s) {
                if(boundaries[s]>boundaries[s+1] || boundaries[s+1]>nodes_count) throw std::runtime_error("native stage order");
                for(unsigned i=boundaries[s];i<boundaries[s+1];++i) {
                    const auto g=nodes[i];
                    if(g.op>1 || g.z>=slots || g.x>=slots || g.y>=slots || written[g.z]==s+1)
                        throw std::runtime_error("native gate or duplicate stage write");
                    written[g.z]=s+1;
                }
                for(unsigned i=boundaries[s];i<boundaries[s+1];++i) {
                    const auto g=nodes[i];
                    if(!initialized[g.x] || !initialized[g.y] || written[g.x]==s+1 || written[g.y]==s+1)
                        throw std::runtime_error("native stage read race or uninitialized operand");
                }
                for(unsigned i=boundaries[s];i<boundaries[s+1];++i) initialized[nodes[i].z]=1;
            }
            for(auto n:outputs) if(!initialized[n]) throw std::runtime_error("native output not initialized");
            const std::vector<r::Program> packet={{ports,slots,stages,0,0,0,wires}};
            Memory local;
            auto* dp=local.allocate<r::Program>(1);local.upload(dp,packet);
            auto* dn=local.allocate<r::Node>(nodes_count);local.upload(dn,nodes);
            auto* db=local.allocate<uint32_t>(stages+1);local.upload(db,boundaries);
            auto* dout=local.allocate<uint32_t>(wires);local.upload(dout,outputs);
            requested_peak=std::max(requested_peak,global.requested+local.requested);
            for(unsigned trial=0;trial<3;++trial) {
                const uint64_t live=read64();std::vector<uint64_t> inputs(ports),expected(wires);
                for(auto& n:inputs) {n=read64();if(n&~live) throw std::runtime_error("native input liveness");}
                for(auto& n:expected) {n=read64();if(n&~live) throw std::runtime_error("original output liveness");}
                if(inputs[0]!=0 || inputs[1]!=live) throw std::runtime_error("original constants");
                std::fill(frames.begin(),frames.end(),0);std::fill(assignments.begin(),assignments.end(),65535);
                for(unsigned lane=0;lane<64;++lane) if(live>>lane&1) {
                    const unsigned at=(lane%16)*capacity+lane/16;assignments[at]=0;
                    for(unsigned bit=0;bit<ports-2;++bit)
                        frames[at*12+bit/8]|=uint8_t((inputs[bit+2]>>lane&1)<<(bit%8));
                }
                global.upload(df,frames);global.upload(da,assignments);
                require(r::replay(nullptr,df,da,dp,dn,db,dout,1,width,capacity,4,slots,stage));
                require(cudaDeviceSynchronize());
                require(cudaMemcpy(got.data(),stage,got.size()*4,cudaMemcpyDeviceToHost));global.d2h+=got.size()*4;
                for(unsigned wire=0;wire<width;++wire) for(unsigned row=0;row<16;++row) for(unsigned word=0;word<8;++word) {
                    uint32_t wanted=0;
                    if(word==0 && wire<wires) for(unsigned k=0;k<4;++k)
                        wanted|=uint32_t(expected[wire]>>(k*16+row)&1)<<k;
                    if(got[wire*128+row*8+word]!=wanted) {
                        std::cerr<<"depth "<<depth<<" program "<<p<<" trial "<<trial<<" wire "<<wire<<"\n";
                        throw std::runtime_error("GPU replay differs from original layered circuit");
                    }
                    ++comparisons;
                }
                ++cases;
            }
            h2d+=local.h2d;local.release();
        }
        if(file.tellg()!=bytes) throw std::runtime_error("native fixture trailing bytes");
        global.release();
        std::cout<<"{\"original_layered_RMS_replay\":true,\"gpu_execution\":true,\"credit\":false,\"joint_admitted\":false,"
            <<"\"depth\":"<<depth<<",\"programs\":"<<programs<<",\"cases\":"<<cases
            <<",\"u32_comparisons\":"<<comparisons<<",\"device_requested_peak_bytes\":"<<requested_peak
            <<",\"h2d_bytes\":"<<h2d+global.h2d<<",\"d2h_bytes\":"<<global.d2h
            <<",\"complete_capacity\":false,\"canonical_certificates\":0,"
            <<"\"scope\":\"159 original compiler plans at one depth, three liveness patterns,64 raw-frame positions; no canonical source/model, common owner/caller, Eq/moments, tail fold/core, wire/PCS or complete resources\"}\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<"\n";return 1;}
}
