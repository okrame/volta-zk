namespace c71_rms_prefix {
cudaError_t source_frames_fold(cudaStream_t,const uint8_t*,const SourceNorm*,const SourceTile*,
    unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,uint8_t*,uint16_t*,unsigned*);
cudaError_t replay_raw(cudaStream_t,const uint8_t*,const uint16_t*,const Program*,const Node*,
    const uint32_t*,const uint32_t*,unsigned,unsigned,unsigned,unsigned,unsigned,uint64_t*,unsigned*,uint64_t*);
}
namespace {
namespace tail=c71_rms_tail;
void rms_tail_shadow_release(C71RangeContext* c) {
    auto& t=c->rms_tail;
    if(t.shadow) {
        delete[] t.shadow;t.shadow=nullptr;c->stats.host_owner_bytes-=t.shadow_bytes;
        if(c->account)c->account(-int64_t(t.shadow_bytes));
        t.shadow_bytes=0;
    }
    if(t.publication) {
        delete[] t.publication;t.publication=nullptr;c->stats.host_owner_bytes-=t.publication_bytes;
        if(c->account)c->account(-int64_t(t.publication_bytes));
        t.publication_bytes=0;
    }
}
int rms_tail_start(C71RangeContext* c,uint64_t source,const Fp3* point,uint32_t bits) {
    auto& s=c->rms;auto& t=c->rms_tail;const auto& src=c->rms_source;
    uintptr_t end=0;
    if(!rms_source_session(c,source) || t.active || s.active!=1 || bits!=s.shape.suffix_bits+4 || bits>29 ||
       src.shape.programs!=s.shape.programs || src.shape.padded!=(1u<<bits) ||
       !point || reinterpret_cast<uintptr_t>(point)%8 || !c71_dense::span(point,uint64_t(bits)*24,end))
        return fail(c,"RMS tail original geometry or point span");
    for(unsigned i=0;i<bits;++i)if(!canonical(point[i]))return fail(c,"RMS tail original point");
    for(unsigned i=4;i<bits;++i) {
        const auto a=point[i],b=rms_original_suffix(s)[i-4];
        if(a.c0!=b.c0 || a.c1!=b.c1 || a.c2!=b.c2)return fail(c,"RMS tail original suffix point differs");
    }
    t.active=1;t.source=source;t.bits=bits;t.round=4;
    t.capacity=std::min(s.shape.capacity/16,1u<<(bits-5));
    const uint64_t shadow_bytes=tail::point_slots*24;
    if(c->account && c->account(int64_t(shadow_bytes)))return fail(c,"RMS tail public point budget");
    t.shadow=new(std::nothrow) Fp3[tail::point_slots]{};
    if(!t.shadow) {if(c->account)c->account(-int64_t(shadow_bytes));return fail(c,"RMS tail public point allocation");}
    t.shadow_bytes=shadow_bytes;c->stats.host_owner_bytes+=shadow_bytes;
    std::memcpy(t.shadow,point,uint64_t(bits)*24);
    if(rms_retire(c,s.aggregate) || rms_retire(c,s.eq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(2)*t.capacity*(s.shape.width+s.shape.programs)*24,&t.fold) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(tail::table_slots)*24,&t.tables) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(rms::gate_chunk)*t.capacity*3*24,&t.gate_values))return -1;
    s.active=2;return 0;
}
bool rms_tail_session(C71RangeContext* c,uint64_t token) {
    if(!token || c->rms.active!=2 || !c->rms_tail.active || token!=c->rms.meta ||
       !full(buffer(c,token),C71_RMS_PRIVATE) || !rms_source_session(c,c->rms_tail.source)) {
        fail(c,"RMS cell tail capability differs");return false;
    }
    return true;
}
bool rms_tail_zero(C71RangeContext* c,void* output,uint64_t bytes) {
    if(checked(c,cudaMemsetAsync(output,0,bytes,c->stream)))return false;
    c->stats.zeroed_bytes+=bytes;return true;
}
}
extern "C" int c71_rms_tail_round(C71RangeContext* c,uint64_t token,const Fp3* prefix,uint32_t round,
    Fp3* coefficients,Fp3* terminal,uint32_t terminal_count) {
    if(!ready(c) || !rms_tail_session(c,token))return -1;
    auto& s=c->rms;auto& t=c->rms_tail;const auto& src=c->rms_source;
    const bool last=round+1==t.bits;const uint32_t terminal_values=last?2*(s.shape.width+s.shape.programs):0;
    uintptr_t prefix_end=0,out_end=0,terminal_end=0;
    if(round!=t.round || round<4 || round>=t.bits || !prefix || reinterpret_cast<uintptr_t>(prefix)%8 ||
       !c71_dense::span(prefix,uint64_t(round)*24,prefix_end) || !coefficients || reinterpret_cast<uintptr_t>(coefficients)%8 ||
       !c71_dense::span(coefficients,96,out_end) || terminal_count!=terminal_values ||
       (terminal_values ? (!terminal || reinterpret_cast<uintptr_t>(terminal)%8 ||
        !c71_dense::span(terminal,uint64_t(terminal_values)*24,terminal_end) ||
        c71_dense::overlaps(coefficients,out_end,terminal,terminal_end)) : terminal!=nullptr))
        return fail(c,"RMS cell tail round coverage or publication span");
    for(unsigned i=0;i<round;++i)if(!canonical(prefix[i]))return fail(c,"RMS cell tail challenge");
    std::memcpy(t.shadow+29,prefix,uint64_t(round)*24);
    const uint64_t bytes=uint64_t(4+terminal_values)*24;
    if(c->account && c->account(int64_t(bytes)))return fail(c,"RMS tail publication budget");
    t.publication=new(std::nothrow) Fp3[4+terminal_values];
    if(!t.publication) {if(c->account)c->account(-int64_t(bytes));return fail(c,"RMS tail publication allocation");}
    t.publication_bytes=bytes;c->stats.host_owner_bytes+=bytes;
    auto* tables=ptr<Fp3>(c,buffer(c,t.tables));auto* folded=ptr<Fp3>(c,buffer(c,t.fold));
    auto* gate_values=ptr<Fp3>(c,buffer(c,t.gate_values));auto* u=ptr<Fp3>(c,buffer(c,s.chunk));
    auto* result=u+3*t.capacity;
    const uint64_t point_bytes=tail::point_slots*24;
    bool error=checked(c,cudaMemcpyAsync(tables,t.shadow,point_bytes,cudaMemcpyHostToDevice,c->stream))!=0;
    if(!error)c->stats.h2d_bytes+=point_bytes;
    if(!error && !rms_tail_zero(c,result,96))error=true;
    tail::Shape shape{s.shape.width,s.shape.programs,s.shape.capacity,t.bits,round,0};
    if(!error) {
        unsigned attempted=0;const auto status=tail::prepare(c->stream,shape,tables,&attempted);
        c->stats.launches+=attempted;error=checked(c,status)!=0;
    }
    const unsigned active=1u<<(t.bits-round),half=active/2,groups=1u<<(round-4);
    auto* source_meta=ptr<uint8_t>(c,buffer(c,src.meta));
    for(unsigned first=0;!error && first<half;first+=shape.n) {
        shape.n=std::min(t.capacity,half-first);
        if(!rms_tail_zero(c,folded,uint64_t(2)*shape.n*(shape.width+shape.programs)*24)) {error=true;break;}
        if(launched(c,tail::suffix_weights(c->stream,shape,first,tables))) {error=true;break;}
        for(unsigned group=0;!error && group<groups;) {
            const unsigned count=std::min(groups-group,shape.capacity/shape.n);
            for(unsigned side=0;!error && side<2;++side) {
                unsigned attempted=0;uint64_t zeroed=0;
                auto status=rms::source_frames_fold(c->stream,src.device,reinterpret_cast<rms::SourceNorm*>(source_meta),
                    reinterpret_cast<rms::SourceTile*>(source_meta+src.offsets[1]),src.shape.tiles,active,first,
                    shape.capacity,shape.n,side,group,count,ptr<uint8_t>(c,buffer(c,s.frames)),
                    ptr<uint16_t>(c,buffer(c,s.assignments)),&attempted);
                c->stats.launches+=attempted;
                if(checked(c,status)) {error=true;break;}
                status=rms::replay_raw(c->stream,ptr<uint8_t>(c,buffer(c,s.frames)),ptr<uint16_t>(c,buffer(c,s.assignments)),
                    rms_meta<rms::Program>(c,0),rms_meta<rms::Node>(c,1),rms_meta<uint32_t>(c,2),rms_meta<uint32_t>(c,3),
                    shape.programs,shape.width,shape.capacity,count*shape.n,s.slots,
                    ptr<uint64_t>(c,buffer(c,s.stage)),&attempted,&zeroed);
                c->stats.launches+=attempted;c->stats.zeroed_bytes+=zeroed;
                if(checked(c,status)) {error=true;break;}
                if(launched(c,tail::fold(c->stream,shape,side,group,count,ptr<uint64_t>(c,buffer(c,s.stage)),
                    ptr<uint16_t>(c,buffer(c,s.assignments)),tables,folded)))error=true;
            }
            group+=count;
        }
        for(unsigned p=0;!error && p<shape.programs;++p) {
            if(!rms_tail_zero(c,u,uint64_t(3)*shape.n*24)) {error=true;break;}
            const auto range=rms_ranges(s)[p];
            for(unsigned first_gate=0;!error && first_gate<range.count;first_gate+=rms::gate_chunk) {
                const auto count=std::min(rms::gate_chunk,range.count-first_gate);
                if(launched(c,tail::gates(c->stream,shape,p,rms_meta<rms::Gate>(c,4)+range.first+first_gate,count,folded,gate_values)) ||
                   launched(c,tail::sum_gates(c->stream,shape.n,count,gate_values,u)))error=true;
            }
            if(!error && launched(c,tail::selector(c->stream,shape,p,tables,folded,u,result)))error=true;
        }
    }
    if(!error && last && launched(c,tail::terminal_selectors(c->stream,shape,tables,folded)))error=true;
    if(!error) {
        if(checked(c,cudaMemcpyAsync(t.publication,result,96,cudaMemcpyDeviceToHost,c->stream)))error=true;
        else c->stats.d2h_bytes+=96;
    }
    if(!error && last) {
        const auto terminal_bytes=uint64_t(terminal_values)*24;
        if(checked(c,cudaMemcpyAsync(t.publication+4,folded,terminal_bytes,cudaMemcpyDeviceToHost,c->stream)))error=true;
        else c->stats.d2h_bytes+=terminal_bytes;
    }
    const int synced=fence(c);
    if(error || synced)return -1; // Owned H2D/D2H staging survives a failed fence.
    for(unsigned i=0;i<4+terminal_values;++i)if(!canonical(t.publication[i]))return fail(c,"RMS tail noncanonical publication");
    if(last) {
        for(auto* id:{&t.gate_values,&t.tables,&t.fold,&s.chunk,&s.stage,&s.assignments,&s.frames,&s.meta})
            if(rms_retire(c,*id))return -1;
        delete[] s.shadow;c->stats.host_owner_bytes-=s.shadow_bytes;
        if(c->account)c->account(-int64_t(s.shadow_bytes));
        s={};
    }
    auto* staged=t.publication;t.publication=nullptr;t.publication_bytes=0;
    std::memcpy(coefficients,staged,96);
    if(last)std::memcpy(terminal,staged+4,uint64_t(terminal_values)*24);
    delete[] staged;c->stats.host_owner_bytes-=bytes;
    if(c->account)c->account(-int64_t(bytes));
    if(last) {rms_tail_shadow_release(c);t={};}else ++t.round;
    return 0;
}
