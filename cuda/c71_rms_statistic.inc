namespace c71_rms_statistic {
cudaError_t factors(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t regenerate(cudaStream_t,Shape,const uint8_t*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t fold_state(cudaStream_t,unsigned,Fp3,Fp3*);
cudaError_t coefficients(cudaStream_t,Shape,const uint8_t*,const Fp3*,const Fp3*,const Fp3*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t reduce(cudaStream_t,const Fp3*,unsigned,Fp3*);
}
namespace {
namespace stat_rms=c71_rms_statistic;
struct RmsStatisticState {
    stat_rms::Shape shape{};
    uint64_t meta=0,peq=0,seq=0,state=0,partials=0,result=0,slack=0;
    const uint8_t* host=nullptr;
    const uint8_t* device=nullptr;
    uint32_t registered=0,unregister_failed=0,initialized=0;
};
static_assert(std::is_trivially_destructible<RmsStatisticState>::value);
constexpr unsigned stat_meta_bytes=2*stat_rms::max_bits*24;
RmsStatisticState& stat_state(C71RangeContext* c) {return *reinterpret_cast<RmsStatisticState*>(c->rms.window);}
int rms_statistic_close(C71RangeContext* c,bool drained) {
    if(c->rms.active!=4 || !c->rms.window)return 0;
    if(!drained)return -1;
    auto& t=stat_state(c);
    if(t.unregister_failed)return fail(c,"RMS statistic unregister ownership uncertain");
    if(t.registered) {
        if(checked(c,cudaHostUnregister(const_cast<uint8_t*>(t.host)))) {t.unregister_failed=1;return -1;}
        t.registered=0;t.device=nullptr;
    }
    if(t.slack) {c->stats.host_owner_bytes-=t.slack;if(c->account)c->account(-int64_t(t.slack));t.slack=0;}
    return 0;
}
bool stat_session(C71RangeContext* c,uint64_t token) {
    if(c->rms.active!=4 || !c->rms.window)return fail(c,"RMS statistic inactive owner"),false;
    const auto& t=stat_state(c);
    if(!token || token!=t.meta || !t.registered || t.unregister_failed || !full(buffer(c,token),C71_RMS_PRIVATE))
        return fail(c,"RMS statistic capability differs"),false;
    return true;
}
bool stat_host(C71RangeContext* c,uint8_t*& output,uint64_t& charged,uint64_t bytes) {
    if(c->account && c->account(int64_t(bytes)))return fail(c,"RMS statistic host budget"),false;
    output=new(std::nothrow) uint8_t[bytes]{};
    if(!output) {if(c->account)c->account(-int64_t(bytes));return fail(c,"RMS statistic host allocation"),false;}
    charged=bytes;c->stats.host_owner_bytes+=bytes;return true;
}
bool stat_prefix(C71RangeContext* c,const Fp3* point,unsigned count,Fp3* output,unsigned outputs) {
    uintptr_t out_end=0,point_end=0,source_end=0;const auto& t=stat_state(c);
    if(!output || !byte_span(output,uint64_t(outputs)*24) || !c71_dense::span(output,uint64_t(outputs)*24,out_end) ||
       (count && (!byte_span(point,uint64_t(count)*24) || !c71_dense::span(point,uint64_t(count)*24,point_end) ||
        c71_dense::overlaps(point,point_end,output,out_end))))return fail(c,"RMS statistic publication or prefix span"),false;
    if(!c71_dense::span(t.host,uint64_t(t.shape.rows)*t.shape.columns*2,source_end) ||
       c71_dense::overlaps(t.host,source_end,output,out_end))return fail(c,"RMS statistic output aliases immutable source"),false;
    const auto* previous=reinterpret_cast<Fp3*>(c->rms.shadow)+stat_rms::prefix;
    for(unsigned i=0;i<count;++i)if(!canonical(point[i]) || (i+1<count && !byte_equal(previous[i],point[i])))
        return fail(c,"RMS statistic emitted prefix differs"),false;
    return true;
}
bool stat_initialize(C71RangeContext* c) {
    auto& t=stat_state(c);auto* eq=ptr<Fp3>(c,buffer(c,t.peq));
    for(unsigned first=0;first<t.shape.stride;first+=stat_rms::batch_pairs) {
        const unsigned n=std::min(stat_rms::batch_pairs,t.shape.stride-first);
        if(launched(c,stat_rms::regenerate(c->stream,t.shape,t.device,eq,first,n,ptr<Fp3>(c,buffer(c,t.state)))))return false;
    }
    t.initialized=1;return true;
}
}
extern "C" int c71_rms_statistic_begin(C71RangeContext* c,uint32_t rows,uint32_t columns,const uint8_t* source,
    uint64_t bytes,const Fp3* point,uint32_t count,uint64_t* token,uint32_t* checkpoint) {
    if(!ready(c))return -1;
    if(c->rms.active || c->rms_source.host || c->linear.phase || c->salts.phase || c->source.values[0] ||
       c->residual.active || c->contract.active || c->residual_query.phase)return fail(c,"RMS statistic overlaps a consumer");
#ifdef C71_ASYNC_ALLOCATOR_EXPERIMENT
    if(c->async_phase)return fail(c,"RMS statistic overlaps source pool");
#endif
    if(!rows || rows>8192 || !columns || columns>5376 || bytes!=uint64_t(rows)*columns*2 ||
       !byte_span(source,bytes,1) || !byte_span(token,8) || !byte_span(checkpoint,4,4))return fail(c,"RMS statistic source geometry");
    unsigned rb=0,cb=0;while((1u<<rb)<rows)++rb;while((1u<<cb)<columns)++cb;
    if(rb+cb>26 || count!=rb+cb || (count && !byte_span(point,uint64_t(count)*24)))return fail(c,"RMS statistic point geometry");
    uintptr_t token_end=0,cp_end=0,source_end=0,point_end=0;
    if(!c71_dense::span(token,8,token_end) || !c71_dense::span(checkpoint,4,cp_end) ||
       !c71_dense::span(source,bytes,source_end) || c71_dense::overlaps(token,token_end,checkpoint,cp_end) ||
       c71_dense::overlaps(source,source_end,token,token_end) || c71_dense::overlaps(source,source_end,checkpoint,cp_end) ||
       (count && (!c71_dense::span(point,uint64_t(count)*24,point_end) ||
        c71_dense::overlaps(point,point_end,token,token_end) || c71_dense::overlaps(point,point_end,checkpoint,cp_end))))
        return fail(c,"RMS statistic outputs alias inputs");
    for(unsigned i=0;i<count;++i)if(!canonical(point[i]))return fail(c,"RMS statistic point canonicality");
    for(auto attribute:{cudaDevAttrHostRegisterSupported,cudaDevAttrHostRegisterReadOnlySupported,cudaDevAttrCanMapHostMemory}) {
        int supported=0;if(checked(c,cudaDeviceGetAttribute(&supported,attribute,c->device)))return -1;
        if(!supported)return fail(c,"RMS statistic immutable mapping unavailable");
    }
    c->rms.active=4;
    if(!stat_host(c,c->rms.window,c->rms.window_bytes,sizeof(RmsStatisticState)))return -1;
    auto& t=*new(c->rms.window) RmsStatisticState;t.shape={rows,columns,rb,cb,rb+cb,0,0,1u<<(rb+cb),1u<<(rb+cb)};
    t.host=source;
    const auto page=sysconf(_SC_PAGESIZE);if(page<=0 || !power2(uint64_t(page)))return fail(c,"RMS statistic page geometry");
    const auto address=reinterpret_cast<uintptr_t>(source);
    const uint64_t slack=address%uint64_t(page)+(uint64_t(page)-(address+bytes)%uint64_t(page))%uint64_t(page);
    if(c->account && c->account(int64_t(slack)))return fail(c,"RMS statistic page budget");
    t.slack=slack;c->stats.host_owner_bytes+=slack;
    if(checked(c,cudaHostRegister(const_cast<uint8_t*>(source),bytes,cudaHostRegisterMapped|cudaHostRegisterReadOnly)))return -1;
    t.registered=1;void* device=nullptr;
    if(checked(c,cudaHostGetDevicePointer(&device,const_cast<uint8_t*>(source),0)))return -1;
    if(!device)return fail(c,"RMS statistic null mapping");
    t.device=static_cast<const uint8_t*>(device);
    if(!stat_host(c,c->rms.shadow,c->rms.shadow_bytes,stat_meta_bytes))return -1;
    if(c->account && c->account(96))return fail(c,"RMS statistic publication budget");
    c->rms.publication=new(std::nothrow) Fp3[4]{};
    if(!c->rms.publication) {if(c->account)c->account(-96);return fail(c,"RMS statistic publication allocation");}
    c->rms.publication_bytes=96;c->stats.host_owner_bytes+=96;
    if(count)std::memcpy(c->rms.shadow,point,uint64_t(count)*24);
    while(uint64_t(1u<<(t.shape.bits-t.shape.checkpoint))*24>stat_rms::state_bytes)++t.shape.checkpoint;
    t.shape.stride=1u<<(t.shape.bits-t.shape.checkpoint);t.shape.remaining=t.shape.stride;
    if(allocate(c,C71_RMS_PRIVATE,stat_meta_bytes,&t.meta) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(stat_rms::factor_slots)*24,&t.peq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(stat_rms::factor_slots)*24,&t.seq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(t.shape.stride)*24,&t.state) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t((stat_rms::batch_pairs+127)/128)*96,&t.partials) ||
       allocate(c,C71_RMS_PRIVATE,96,&t.result))return -1;
    const bool copied=byte_upload(c,ptr<void>(c,buffer(c,t.meta)),c->rms.shadow,stat_meta_bytes);
    const int synced=fence(c);if(!copied || synced)return -1;
    if(!t.shape.bits) {
        if(launched(c,stat_rms::factors(c->stream,ptr<Fp3>(c,buffer(c,t.meta))+stat_rms::prefix,0,ptr<Fp3>(c,buffer(c,t.peq)))) ||
           !stat_initialize(c) || fence(c))return -1;
    }
    buffer(c,t.meta)->initialized=buffer(c,t.meta)->count;*token=t.meta;*checkpoint=t.shape.checkpoint;return 0;
}
extern "C" int c71_rms_statistic_coefficients(C71RangeContext* c,uint64_t token,const Fp3* prefix,uint32_t round,Fp3* output) {
    if(!ready(c) || !stat_session(c,token))return -1;
    auto& t=stat_state(c);
    if(round!=t.shape.round || round>=t.shape.bits || !stat_prefix(c,prefix,round,output,4))return fail(c,"RMS statistic round differs");
    if(round)std::memcpy(c->rms.shadow+stat_rms::prefix*24,prefix,uint64_t(round)*24);
    auto* meta=ptr<Fp3>(c,buffer(c,t.meta));auto* peq=ptr<Fp3>(c,buffer(c,t.peq));auto* seq=ptr<Fp3>(c,buffer(c,t.seq));
    auto* state=ptr<Fp3>(c,buffer(c,t.state));auto* out=ptr<Fp3>(c,buffer(c,t.result));auto* partials=ptr<Fp3>(c,buffer(c,t.partials));
    if(!byte_upload(c,meta+stat_rms::prefix,c->rms.shadow+stat_rms::prefix*24,stat_rms::max_bits*24) ||
       launched(c,stat_rms::factors(c->stream,meta+stat_rms::prefix,round,peq)) ||
       launched(c,stat_rms::factors(c->stream,meta+round+1,t.shape.bits-round-1,seq)))return -1;
    if(round==t.shape.checkpoint) {if(!stat_initialize(c))return -1;}
    else if(round>t.shape.checkpoint) {
        if(launched(c,stat_rms::fold_state(c->stream,t.shape.remaining,prefix[round-1],state)))return -1;
        t.shape.remaining/=2;
    }
    if(!byte_zero(c,out,96))return -1;
    const unsigned half=1u<<(t.shape.bits-round-1);
    for(unsigned first=0;first<half;first+=stat_rms::batch_pairs) {
        const unsigned n=std::min(stat_rms::batch_pairs,half-first);
        if(launched(c,stat_rms::coefficients(c->stream,t.shape,t.device,meta,peq,seq,state,first,n,partials)) ||
           launched(c,stat_rms::reduce(c->stream,partials,(n+127)/128,out)))return -1;
    }
    if(checked(c,cudaMemcpyAsync(c->rms.publication,out,96,cudaMemcpyDeviceToHost,c->stream)))return -1;
    c->stats.d2h_bytes+=96;if(fence(c))return -1;
    for(auto value:std::initializer_list<Fp3>{c->rms.publication[0],c->rms.publication[1],c->rms.publication[2],c->rms.publication[3]})
        if(!canonical(value))return fail(c,"RMS statistic noncanonical coefficients");
    std::memcpy(output,c->rms.publication,96);++t.shape.round;return 0;
}
extern "C" int c71_rms_statistic_terminal(C71RangeContext* c,uint64_t token,const Fp3* point,uint32_t count,Fp3* output) {
    if(!ready(c) || !stat_session(c,token))return -1;
    auto& t=stat_state(c);
    if(count!=t.shape.bits || t.shape.round!=count || !t.initialized ||
       !stat_prefix(c,point,count,output,1))return fail(c,"RMS statistic terminal coverage differs");
    if(count && (t.shape.remaining!=2 || launched(c,stat_rms::fold_state(c->stream,2,point[count-1],ptr<Fp3>(c,buffer(c,t.state))))))return -1;
    if(checked(c,cudaMemcpyAsync(c->rms.publication,ptr<Fp3>(c,buffer(c,t.state)),24,cudaMemcpyDeviceToHost,c->stream)))return -1;
    c->stats.d2h_bytes+=24;if(fence(c))return -1;
    const auto value=c->rms.publication[0];if(!canonical(value))return fail(c,"RMS statistic noncanonical terminal");
    for(auto* id:{&t.meta,&t.peq,&t.seq,&t.state,&t.partials,&t.result})if(byte_retire(c,*id))return -1;
    if(rms_statistic_close(c,true))return -1;
    delete[] c->rms.shadow;delete[] c->rms.publication;delete[] c->rms.window;
    const auto bytes=c->rms.shadow_bytes+c->rms.publication_bytes+c->rms.window_bytes;
    c->stats.host_owner_bytes-=bytes;if(c->account)c->account(-int64_t(bytes));c->rms={};
    *output=value;return 0;
}
