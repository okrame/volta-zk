// Bounded original-frame GPU pipeline parity. No canonical caller admission.
#include <cuda_runtime.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "c71_rms_prefix.cuh"
namespace r=c71_rms_prefix;

void require(cudaError_t status) {
    if(status!=cudaSuccess) throw std::runtime_error(cudaGetErrorString(status));
}
struct Device {
    std::vector<void*> allocations;
    uint64_t bytes=0,h2d=0,d2h=0;
    template<class T> T* allocate(size_t count) {
        void* ptr=nullptr;require(cudaMalloc(&ptr,count*sizeof(T)));
        allocations.push_back(ptr);bytes+=count*sizeof(T);return static_cast<T*>(ptr);
    }
    template<class T> void upload(T* ptr,const std::vector<T>& data) {
        require(cudaMemcpy(ptr,data.data(),data.size()*sizeof(T),cudaMemcpyHostToDevice));
        h2d+=data.size()*sizeof(T);
    }
    void release() {
        require(cudaDeviceSynchronize());
        for(auto p:allocations) require(cudaFree(p));
        allocations.clear();
    }
    ~Device() { for(auto p:allocations) (void)cudaFree(p); }
};
bool same(Fp3 a,Fp3 b) { return a.c0==b.c0 && a.c1==b.c1 && a.c2==b.c2; }
Fp3 original_eq(const std::vector<Fp3>& point,unsigned index) {
    Fp3 value{1,0,0};
    for(unsigned i=0;i<point.size();++i)
        value=mul(value,(index>>(point.size()-1-i))&1?point[i]:sub(Fp3{1,0,0},point[i]));
    return value; // Direct9-product arithmetic, independent of mul6 kernel.
}
// Literal original circuits, deliberately independent of native slot plans.
std::array<unsigned,4> literal(unsigned program,const uint8_t* frame) {
    const unsigned a=frame[0]&1,b=(frame[0]>>1)&1,c=(frame[0]>>2)&1,d=(frame[0]>>3)&1;
    if(program==0) return {a&b,c^d,1,0};
    if(program==1) return {a^b,c&d,1,0};
    return {1,0,0,0}; // Short program/fallback Copy0 and width padding.
}
int main() {
    try {
        int device=0;require(cudaGetDevice(&device));cudaDeviceProp properties{};
        require(cudaGetDeviceProperties(&properties,device));
        if(properties.major!=9) throw std::runtime_error("Hopper GPU required");
        const unsigned capacity=4096,width=4;
        Device memory;
        const std::vector<r::Program> programs={{6,8,1,0,0,0,3},{6,8,1,2,2,3,3},{2,2,0,4,4,6,1}};
        const std::vector<r::Node> nodes={{0,6,2,3},{1,7,4,5},{1,6,2,3},{0,7,4,5}};
        const std::vector<uint32_t> boundaries={0,2,0,2,0},outputs={6,7,1,6,7,1,1};
        auto* dp=memory.allocate<r::Program>(programs.size());memory.upload(dp,programs);
        auto* dn=memory.allocate<r::Node>(nodes.size());memory.upload(dn,nodes);
        auto* db=memory.allocate<uint32_t>(boundaries.size());memory.upload(db,boundaries);
        auto* dout=memory.allocate<uint32_t>(outputs.size());memory.upload(dout,outputs);
        auto* df=memory.allocate<uint8_t>(16*capacity*12);
        auto* da=memory.allocate<uint16_t>(16*capacity);
        auto* stage=memory.allocate<uint64_t>(width*capacity/4);
        auto* point_device=memory.allocate<Fp3>(14);
        auto* eq=memory.allocate<uint32_t>(192*(capacity/256)*8);
        auto* gates_device=memory.allocate<r::Gate>(r::gate_chunk);
        auto* chunk=memory.allocate<Fp3>(r::gate_chunk*r::moments);
        auto* aggregate=memory.allocate<Fp3>(3*r::moments);
        const unsigned ids[16]={0,1,2,65535,1,0,2,0,1,65535,2,0,1,2,1,0};
        std::vector<uint8_t> frames(16*capacity*12);
        std::vector<uint16_t> assignments(16*capacity,65535);
        std::vector<Fp3> got(3*r::moments),expected(3*r::moments);
        uint64_t original_frames=0,test_windows=0,chunk_calls=0,zeroed_bytes=0;
        // 17/257 exercise incomplete quads/K tiles;4096 exercises maximum
        // register count bounds. Boundary points include zero/one and P-1.
        for(unsigned n:{17u,257u,4096u}) for(unsigned boundary=0;boundary<3;++boundary) {
            std::vector<Fp3> point(14);
            for(unsigned i=0;i<point.size();++i)
                point[i]=boundary<2?Fp3{boundary,0,0}:Fp3{P-7-i,13+i,P-29-i};
            memory.upload(point_device,point);
            require(cudaMemset(aggregate,0,got.size()*sizeof(Fp3)));
            zeroed_bytes+=got.size()*sizeof(Fp3);
            std::fill(expected.begin(),expected.end(),Fp3{});
            std::array<std::vector<r::Gate>,3> gates;
            // Original gate-index Eq; no late replacement of its coordinates.
            const std::vector<Fp3> gate_point={Fp3{P-11,31,47}};
            const Fp3 w0=original_eq(gate_point,0),w1=original_eq(gate_point,1);
            gates[0]={{1,0,1,0,w0},{2,2,2,0,w1}};
            gates[1]={{0,0,1,0,w0},{2,0,0,0,w1}};
            gates[2]={{2,0,0,0,w0}};
            // A second chunk must add to the same aggregate without clearing.
            if(n==17 && boundary==2) gates[0].resize(513,gates[0][0]);
            for(unsigned window=0;window<2;++window) {
                const unsigned first=boundary==0?window*n:boundary==1?
                    (1u<<point.size())-2*n+window*n:73+window*n;
                if(first+n>(1u<<point.size())) throw std::runtime_error("original domain bound");
                std::fill(frames.begin(),frames.end(),0);std::fill(assignments.begin(),assignments.end(),65535);
                for(unsigned row=0;row<16;++row) for(unsigned k=0;k<n;++k) if(ids[row]!=65535) {
                    const unsigned index=row*capacity+k;assignments[index]=uint16_t(ids[row]);
                    for(unsigned byte=0;byte<12;++byte)
                        frames[index*12+byte]=uint8_t((row*13+(first+k)*7+byte*17)^((first+k)>>3));
                    ++original_frames;
                }
                memory.upload(df,frames);memory.upload(da,assignments);
                require(r::replay(nullptr,df,da,dp,dn,db,dout,3,width,capacity,n,8,stage));
                zeroed_bytes+=uint64_t(width)*capacity*2;
                require(r::suffix_eq(nullptr,point_device,14,first,capacity,n,eq));
                for(unsigned p=0;p<3;++p) for(unsigned start=0;start<gates[p].size();start+=r::gate_chunk) {
                    const unsigned count=std::min<unsigned>(r::gate_chunk,gates[p].size()-start);
                    const std::vector<r::Gate> part(gates[p].begin()+start,gates[p].begin()+start+count);
                    memory.upload(gates_device,part);
                    require(r::consume(nullptr,reinterpret_cast<uint32_t*>(stage),eq,gates_device,count,capacity,chunk,aggregate+p*r::moments));
                    ++chunk_calls;
                }
                require(cudaDeviceSynchronize());++test_windows;
                // Each program's mask restricts the selector only. The source
                // wires used here include EVERY program's original positions.
                for(unsigned k=0;k<n;++k) {
                    std::array<std::array<unsigned,4>,16> wires{};
                    for(unsigned row=0;row<16;++row) if(ids[row]!=65535)
                        wires[row]=literal(ids[row],frames.data()+(row*capacity+k)*12);
                    const Fp3 suffix_weight=original_eq(point,first+k);
                    for(unsigned p=0;p<3;++p) for(const auto g:gates[p]) {
                        const Fp3 weight=mul(suffix_weight,g.weight);
                        const Fp3 quadratic=g.op==1?sub(Fp3{},add(weight,weight)):weight;
                        for(unsigned i=0;i<16;++i) {
                            auto& linear=expected[p*r::moments+256+i];
                            if(g.op!=0 && wires[i][g.x]) linear=add(linear,weight);
                            if(g.op==1 && wires[i][g.y]) linear=add(linear,weight);
                            if(g.op!=2) for(unsigned j=0;j<16;++j) if(wires[i][g.x] && wires[j][g.y])
                                expected[p*r::moments+i*16+j]=add(expected[p*r::moments+i*16+j],quadratic);
                        }
                    }
                }
            }
            require(cudaMemcpy(got.data(),aggregate,got.size()*sizeof(Fp3),cudaMemcpyDeviceToHost));
            memory.d2h+=got.size()*sizeof(Fp3);
            for(unsigned i=0;i<got.size();++i) if(!same(got[i],expected[i])) {
                std::cerr<<"moment "<<i<<" n "<<n<<" boundary "<<boundary<<"\n";
                throw std::runtime_error("original literal RMS moments differ");
            }
        }
        memory.release();
        std::cout<<"{\"original_literal_mixed_moments\":true,\"gpu_execution\":true,\"credit\":false,"
            <<"\"joint_admitted\":false,\"canonical_certificates\":0,\"test_windows\":"<<test_windows
            <<",\"chunk_calls\":"<<chunk_calls<<",\"original_frames\":"<<original_frames
            <<",\"device_requested_bytes\":"<<memory.bytes<<",\"h2d_bytes\":"<<memory.h2d
            <<",\"d2h_bytes\":"<<memory.d2h<<",\"zeroed_bytes\":"<<zeroed_bytes
            <<",\"complete_capacity\":false"
            <<",\"scope\":\"Bounded three-program raw-frame GPU pipeline; no canonical recipes, common runtime/caller, tail fold/core or complete capacity credit\"}\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<"\n";return 1; }
}
