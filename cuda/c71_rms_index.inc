namespace {
namespace index_rms=c71_rms_index;
bool rms_index_span(const void* p,uint64_t bytes,unsigned alignment=8) {
    uintptr_t end=0;return p && reinterpret_cast<uintptr_t>(p)%alignment==0 && c71_dense::span(p,bytes,end);
}
void rms_index_publication_release(C71RangeContext* c) {
    auto& t=c->rms_tail;
    delete[] t.publication;t.publication=nullptr;c->stats.host_owner_bytes-=t.publication_bytes;
    if(c->account)c->account(-int64_t(t.publication_bytes));
    t.publication_bytes=0;
}
int rms_index_publication(C71RangeContext* c,uint64_t fields) {
    auto& t=c->rms_tail;const auto bytes=fields*24;
    if(c->account && c->account(int64_t(bytes)))return fail(c,"RMS index staging budget");
    t.publication=new(std::nothrow) Fp3[fields]{};
    if(!t.publication) {if(c->account)c->account(-int64_t(bytes));return fail(c,"RMS index staging allocation");}
    t.publication_bytes=bytes;c->stats.host_owner_bytes+=bytes;return 0;
}
}
extern "C" int c71_rms_index_begin(C71RangeContext* c,uint32_t width,uint32_t programs,uint32_t count,
    const rms::Gate* gates,const rms::GateRange* ranges,const Fp3* previous,const Fp3* selectors,uint64_t* token) {
    if(!ready(c))return -1;
    if(!power2(width) || width>(1u<<14) || !programs || programs>421 || !count || count>programs*(1u<<14) ||
       c->rms.active || c->rms_tail.active || c->salts.phase || c->linear.phase || c->residual.active ||
       c->contract.active || c->residual_query.phase || c->source.values[0] ||
       !rms_index_span(gates,uint64_t(count)*sizeof(*gates)) || !rms_index_span(ranges,uint64_t(programs)*sizeof(*ranges),4) ||
       !rms_index_span(previous,uint64_t(width)*24) || !rms_index_span(selectors,uint64_t(programs)*24) || !rms_index_span(token,8))
        return fail(c,"RMS index original geometry or owner span");
    const void* inputs[]={gates,ranges,previous,selectors};
    const uint64_t lengths[]={uint64_t(count)*sizeof(*gates),uint64_t(programs)*sizeof(*ranges),uint64_t(width)*24,uint64_t(programs)*24};
    uintptr_t token_end=0;c71_dense::span(token,8,token_end);
    for(unsigned i=0;i<4;++i) {
        uintptr_t end=0;c71_dense::span(inputs[i],lengths[i],end);
        if(c71_dense::overlaps(inputs[i],end,token,token_end))return fail(c,"RMS index token aliases input");
    }
    unsigned cursor=0;
    for(unsigned p=0;p<programs;++p) {
        const auto r=ranges[p];
        if(r.first!=cursor || !r.count || r.count>(1u<<14) || r.count>count-cursor)return fail(c,"RMS index program gate coverage");
        cursor+=r.count;if(!canonical(selectors[p]))return fail(c,"RMS index terminal selector");
    }
    if(cursor!=count)return fail(c,"RMS index complete gate coverage");
    for(unsigned i=0;i<count;++i) {
        const auto g=gates[i];
        if(g.op>2 || g.reserved || g.x>=width || g.y>=width || (g.op==2 && g.x!=g.y) || !canonical(g.weight))
            return fail(c,"RMS index original weighted gate");
    }
    for(unsigned i=0;i<width;++i)if(!canonical(previous[i]))return fail(c,"RMS index original terminal wire");
    auto& s=c->rms;auto& t=c->rms_tail;s.active=3;t.active=3;t.capacity=width;
    s.shape.width=width;s.shape.programs=programs;s.shape.gates=count;
    while((1u<<t.bits)<width)++t.bits;
    s.offsets[0]=uint64_t(count)*sizeof(*gates);
    s.offsets[1]=s.offsets[0]+uint64_t(programs)*sizeof(*ranges);
    const uint64_t meta=s.offsets[1]+uint64_t(programs)*24,values=uint64_t(width)*24;
    const uint64_t staging=(meta+values+23)/24;
    if(rms_index_publication(c,staging))return -1;
    auto* shadow=reinterpret_cast<uint8_t*>(t.publication);
    std::memcpy(shadow,gates,s.offsets[0]);std::memcpy(shadow+s.offsets[0],ranges,uint64_t(programs)*sizeof(*ranges));
    std::memcpy(shadow+s.offsets[1],selectors,uint64_t(programs)*24);std::memcpy(shadow+meta,previous,values);
    const uint64_t shadow_bytes=32*24;
    if(c->account && c->account(int64_t(shadow_bytes)))return fail(c,"RMS index public challenge budget");
    t.shadow=new(std::nothrow) Fp3[32]{};
    if(!t.shadow) {if(c->account)c->account(-int64_t(shadow_bytes));return fail(c,"RMS index public challenge allocation");}
    t.shadow_bytes=shadow_bytes;c->stats.host_owner_bytes+=shadow_bytes;
    const unsigned blocks=(count+index_rms::threads-1)/index_rms::threads;
    if(allocate(c,C71_RMS_PRIVATE,meta,&t.gate_values) || allocate(c,C71_RMS_PRIVATE,2*values,&t.fold) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(6+3*blocks)*24,&t.tables))return -1;
    auto* device=ptr<uint8_t>(c,buffer(c,t.gate_values));auto* folded=ptr<Fp3>(c,buffer(c,t.fold));
    bool error=checked(c,cudaMemcpyAsync(device,shadow,meta,cudaMemcpyHostToDevice,c->stream))!=0;
    if(!error)c->stats.h2d_bytes+=meta;
    if(!error) {error=checked(c,cudaMemcpyAsync(folded,shadow+meta,values,cudaMemcpyHostToDevice,c->stream))!=0;if(!error)c->stats.h2d_bytes+=values;}
    if(!error) {error=checked(c,cudaMemcpyAsync(folded+width,folded,values,cudaMemcpyDeviceToDevice,c->stream))!=0;if(!error)c->stats.d2d_bytes+=values;}
    if(!error && !rms_tail_zero(c,ptr<Fp3>(c,buffer(c,t.tables)),uint64_t(6+3*blocks)*24))error=true;
    if(!error && launched(c,index_rms::start(c->stream,count,programs,reinterpret_cast<rms::Gate*>(device),
        reinterpret_cast<rms::GateRange*>(device+s.offsets[0]),reinterpret_cast<Fp3*>(device+s.offsets[1]))))error=true;
    const int synced=fence(c);if(error || synced)return -1;
    for(auto id:{t.gate_values,t.fold,t.tables})buffer(c,id)->initialized=buffer(c,id)->count;
    rms_index_publication_release(c);*token=t.gate_values;return 0;
}
extern "C" int c71_rms_index_step(C71RangeContext* c,uint64_t token,const Fp3* prefix,uint32_t round,Fp3* output) {
    if(!ready(c))return -1;
    auto& s=c->rms;auto& t=c->rms_tail;
    if(s.active!=3 || t.active!=3 || !token || token!=t.gate_values || !full(buffer(c,token),C71_RMS_PRIVATE) ||
       round!=t.round || round>2*t.bits || !rms_index_span(output,6*24) ||
       (round ? !rms_index_span(prefix,uint64_t(round)*24) : prefix!=nullptr))return fail(c,"RMS index round capability or coverage");
    if(round) {
        uintptr_t end=0,out_end=0;c71_dense::span(prefix,uint64_t(round)*24,end);c71_dense::span(output,6*24,out_end);
        if(c71_dense::overlaps(prefix,end,output,out_end))return fail(c,"RMS index publication aliases challenge");
    }
    for(unsigned i=0;i<round;++i) {
        if(!canonical(prefix[i]))return fail(c,"RMS index noncanonical challenge");
        if(i+1<round) {const auto a=prefix[i],b=t.shadow[i+1];
            if(a.c0!=b.c0 || a.c1!=b.c1 || a.c2!=b.c2)return fail(c,"RMS index challenge history differs");}
    }
    const bool terminal=round==2*t.bits;const unsigned width=t.capacity,count=s.shape.gates;
    const unsigned blocks=(count+index_rms::threads-1)/index_rms::threads;
    auto* gates=ptr<rms::Gate>(c,buffer(c,t.gate_values));auto* folded=ptr<Fp3>(c,buffer(c,t.fold));
    auto* scratch=ptr<Fp3>(c,buffer(c,t.tables));bool error=false;
    if(rms_index_publication(c,6))return -1;
    if(round) {
        t.shadow[0]=t.shadow[round]=prefix[round-1];
        error=checked(c,cudaMemcpyAsync(scratch+5,t.shadow,24,cudaMemcpyHostToDevice,c->stream))!=0;
        if(!error)c->stats.h2d_bytes+=24;
        const unsigned previous_round=(round-1)%t.bits,half=width>>(previous_round+1);
        if(!error && launched(c,index_rms::advance(c->stream,count,width,half,round>t.bits,scratch+5,gates,folded)))error=true;
    }
    if(!error && round==t.bits) {
        if(launched(c,index_rms::left(c->stream,scratch,folded+width)))error=true;
        if(!error) {error=checked(c,cudaMemcpyAsync(folded+width,folded,uint64_t(width)*24,cudaMemcpyDeviceToDevice,c->stream))!=0;if(!error)c->stats.d2d_bytes+=uint64_t(width)*24;}
    }
    const unsigned active=terminal?1:width>>(round%t.bits);
    if(!error && launched(c,index_rms::coefficients(c->stream,count,active,width,round>=t.bits,terminal,gates,folded,scratch)))error=true;
    if(!error && launched(c,index_rms::reduce(c->stream,blocks,terminal,folded+width,scratch)))error=true;
    if(!error) {error=checked(c,cudaMemcpyAsync(t.publication,scratch,6*24,cudaMemcpyDeviceToHost,c->stream))!=0;if(!error)c->stats.d2h_bytes+=6*24;}
    const int synced=fence(c);if(error || synced)return -1;
    for(unsigned i=0;i<6;++i)if(!canonical(t.publication[i]))return fail(c,"RMS index noncanonical publication");
    if(terminal)for(auto* id:{&t.tables,&t.fold,&t.gate_values})if(rms_retire(c,*id))return -1;
    std::memcpy(output,t.publication,6*24);rms_index_publication_release(c);
    if(terminal) {rms_tail_shadow_release(c);t={};s={};}else ++t.round;
    return 0;
}
