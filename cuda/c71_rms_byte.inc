namespace c71_rms_byte {
cudaError_t factors(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t cell_baseline(cudaStream_t,Shape,const Fp3*,Fp3*);
cudaError_t regenerate(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,const FeatureRange*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t fold_state(cudaStream_t,Shape,Fp3,Fp3*);
cudaError_t cell_coefficients(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,const FeatureRange*,const Fp3*,const Fp3*,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t sum_partials(cudaStream_t,const Fp3*,unsigned,Fp3*);
cudaError_t histogram(cudaStream_t,Shape,const uint8_t*,const c71_rms_prefix::SourceNorm*,const c71_rms_prefix::SourceTile*,unsigned,unsigned,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t histogram_sum(cudaStream_t,const Fp3*,unsigned,unsigned,Fp3*);
cudaError_t histogram_padding(cudaStream_t,Shape,const Fp3*,unsigned,Fp3*);
cudaError_t recover(cudaStream_t,Shape,const Fp3*,const Fp3*,Fp3*);
cudaError_t fold_children(cudaStream_t,unsigned,Fp3,Fp3*);
cudaError_t child_coefficients(cudaStream_t,Shape,const Fp3*,const Fp3*,Fp3*);
}
struct RmsByteTransaction {
    c71_rms_byte::Shape shape{};
    uint64_t source=0,meta=0,prefix_eq=0,suffix_eq=0,partials=0,result=0,state=0,children=0,histogram=0,histogram_partials=0;
    uint8_t* shadow=nullptr;
    uint64_t shadow_bytes=0;
    Fp3 publication[4]{};
    uint32_t next_layer=0,has_layer=0,recovered=0;
};
namespace {
namespace byte_rms=c71_rms_byte;
constexpr uint64_t byte_meta_fields=byte_rms::feature_lut+uint64_t(byte_rms::max_features)*257;
constexpr uint64_t byte_ranges_offset=(byte_meta_fields*24+255)&~uint64_t{255};
constexpr uint64_t byte_meta_bytes=byte_ranges_offset+byte_rms::lanes*sizeof(byte_rms::FeatureRange);
bool byte_span(const void* p,uint64_t bytes,unsigned alignment=8) {
    uintptr_t end=0;return p && !(reinterpret_cast<uintptr_t>(p)%alignment) && c71_dense::span(p,bytes,end);
}
bool byte_equal(Fp3 a,Fp3 b) {return a.c0==b.c0 && a.c1==b.c1 && a.c2==b.c2;}
Fp3* byte_shadow(RmsByteTransaction& t) {return reinterpret_cast<Fp3*>(t.shadow);}
byte_rms::FeatureRange* byte_ranges(RmsByteTransaction& t) {
    return reinterpret_cast<byte_rms::FeatureRange*>(t.shadow+byte_ranges_offset);
}
bool byte_session(C71RangeContext* c,uint64_t token) {
    if(!c->rms_byte || c->rms.active!=3 || token!=c->rms_byte->meta || !token ||
       !full(buffer(c,token),C71_RMS_PRIVATE) || !rms_source_session(c,c->rms_byte->source)) {
        fail(c,"RMS byte capability or source differs");return false;
    }
    return true;
}
int rms_byte_close(C71RangeContext* c,bool drained) {
    auto* t=c->rms_byte;if(!t)return 0;
    if(!drained)return -1; // Owned upload/publication and charge survive uncertainty.
    if(t->shadow) {delete[] t->shadow;c->stats.host_owner_bytes-=t->shadow_bytes;
        if(c->account)c->account(-int64_t(t->shadow_bytes));}
    c->stats.host_owner_bytes-=sizeof(*t);if(c->account)c->account(-int64_t(sizeof(*t)));
    delete t;c->rms_byte=nullptr;c->rms.active=0;return 0;
}
int byte_retire(C71RangeContext* c,uint64_t& id) {return id?rms_retire(c,id):0;}
bool byte_upload(C71RangeContext* c,void* device,const void* host,uint64_t bytes) {
    if(checked(c,cudaMemcpyAsync(device,host,bytes,cudaMemcpyHostToDevice,c->stream)))return false;
    c->stats.h2d_bytes+=bytes;return true;
}
bool byte_zero(C71RangeContext* c,void* device,uint64_t bytes) {
    if(checked(c,cudaMemsetAsync(device,0,bytes,c->stream)))return false;
    c->stats.zeroed_bytes+=bytes;return true;
}
bool byte_prefix(C71RangeContext* c,const Fp3* values,unsigned count,Fp3* output) {
    auto& t=*c->rms_byte;const auto s=t.shape;const auto* old=byte_shadow(t)+byte_rms::prefix;
    uintptr_t input_end=0,out_end=0;
    if(!output || reinterpret_cast<uintptr_t>(output)%8 || !c71_dense::span(output,96,out_end) ||
       (count && (!byte_span(values,uint64_t(count)*24) ||
        !c71_dense::span(values,uint64_t(count)*24,input_end) || c71_dense::overlaps(values,input_end,output,out_end))))
        return fail(c,"RMS byte publication or prefix span"),false;
    for(unsigned i=0;i<count;++i)if(!canonical(values[i]) || (i+1<count && !byte_equal(old[i],values[i])))
        return fail(c,"RMS byte emitted prefix differs"),false;
    (void)s;return true;
}
bool byte_publish(C71RangeContext* c,Fp3* output) {
    auto& t=*c->rms_byte;
    if(checked(c,cudaMemcpyAsync(t.publication,ptr<Fp3>(c,buffer(c,t.result)),96,cudaMemcpyDeviceToHost,c->stream)))return false;
    c->stats.d2h_bytes+=96;
    if(fence(c))return false;
    for(auto v:t.publication)if(!canonical(v))return fail(c,"RMS byte noncanonical publication"),false;
    std::memcpy(output,t.publication,96);return true;
}
bool byte_recover(C71RangeContext* c) {
    auto& t=*c->rms_byte;auto s=t.shape;const auto& src=c->rms_source;
    // Last cell-round publication fenced the state; it is disjoint from the histogram.
    if(byte_retire(c,t.state))return false;
    if(allocate(c,C71_RMS_PRIVATE,uint64_t(byte_rms::lanes)*256*24,&t.histogram) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(byte_rms::lanes)*byte_rms::histogram_groups*256*24,&t.histogram_partials) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(byte_rms::lanes)*(4u<<s.layer)*24,&t.children))return false;
    auto* meta=ptr<Fp3>(c,buffer(c,t.meta));auto* eq=ptr<Fp3>(c,buffer(c,t.prefix_eq));
    auto* hist=ptr<Fp3>(c,buffer(c,t.histogram));auto* partial=ptr<Fp3>(c,buffer(c,t.histogram_partials));
    auto* source_meta=ptr<uint8_t>(c,buffer(c,src.meta));
    if(!byte_zero(c,hist,uint64_t(byte_rms::lanes)*256*24) ||
       launched(c,byte_rms::factors(c->stream,meta+byte_rms::prefix,s.bits,eq)))return false;
    const unsigned capacity=byte_rms::histogram_groups*256;
    for(unsigned first=0;first<src.shape.live;first+=capacity) {
        const unsigned n=std::min(capacity,src.shape.live-first);
        if(launched(c,byte_rms::histogram(c->stream,s,src.device,reinterpret_cast<rms::SourceNorm*>(source_meta),
            reinterpret_cast<rms::SourceTile*>(source_meta+src.offsets[1]),src.shape.tiles,src.shape.live,eq,first,n,partial)) ||
           launched(c,byte_rms::histogram_sum(c->stream,partial,(n+255)/256,s.live_lanes,hist)))return false;
    }
    if(launched(c,byte_rms::histogram_padding(c->stream,s,meta+byte_rms::prefix,src.shape.live,hist)) ||
       launched(c,byte_rms::recover(c->stream,s,meta,hist,ptr<Fp3>(c,buffer(c,t.children)))) || fence(c))return false;
    if(byte_retire(c,t.histogram) || byte_retire(c,t.histogram_partials))return false;
    t.shape.rows=byte_rms::lanes*(1u<<s.layer);t.recovered=1;return true;
}
}
extern "C" int c71_rms_byte_begin(C71RangeContext* c,uint64_t source,uint32_t bits,uint32_t live_lanes,
    const Fp3* coefficients,uint64_t* token) {
    if(!ready(c) || !rms_source_session(c,source))return -1;
    if(c->rms.active || c->rms_byte || c->linear.phase || c->salts.phase || c->source.values[0] ||
       c->residual.active || c->contract.active || c->residual_query.phase)
        return fail(c,"RMS byte overlaps an active consumer");
#ifdef C71_ASYNC_ALLOCATOR_EXPERIMENT
    if(c->async_phase)return fail(c,"RMS byte overlaps the source pool");
#endif
    if(!bits || bits>29 || c->rms_source.shape.padded!=(1u<<bits) || !live_lanes || live_lanes>16 ||
       !byte_span(coefficients,16*256*24) || !byte_span(token,8))return fail(c,"RMS byte original geometry or span");
    uintptr_t coefficients_end=0,token_end=0;
    if(!c71_dense::span(coefficients,16*256*24,coefficients_end) || !c71_dense::span(token,8,token_end) ||
       c71_dense::overlaps(coefficients,coefficients_end,token,token_end))return fail(c,"RMS byte token aliases public coefficients");
    const auto* norms=reinterpret_cast<const rms::SourceNorm*>(c->rms_source.shadow);
    for(unsigned i=0;i<c->rms_source.shape.norms;++i)if(norms[i].pbytes+8>live_lanes)
        return fail(c,"RMS byte truncates an original source lane");
    for(unsigned i=0;i<16*256;++i)if(!canonical(coefficients[i]))return fail(c,"RMS byte original coefficient");
    if(c->account && c->account(int64_t(sizeof(RmsByteTransaction))))return fail(c,"RMS byte owner budget");
    c->rms_byte=new(std::nothrow) RmsByteTransaction;
    if(!c->rms_byte) {if(c->account)c->account(-int64_t(sizeof(RmsByteTransaction)));return fail(c,"RMS byte owner allocation");}
    auto& t=*c->rms_byte;c->rms.active=3;c->stats.host_owner_bytes+=sizeof(t);
    t.source=source;t.shape.bits=bits;t.shape.live_lanes=live_lanes;
    if(c->account && c->account(int64_t(byte_meta_bytes)))return fail(c,"RMS byte public shadow budget");
    t.shadow=new(std::nothrow) uint8_t[byte_meta_bytes]{};
    if(!t.shadow) {if(c->account)c->account(-int64_t(byte_meta_bytes));return fail(c,"RMS byte public shadow allocation");}
    t.shadow_bytes=byte_meta_bytes;c->stats.host_owner_bytes+=byte_meta_bytes;
    std::memcpy(byte_shadow(t)+byte_rms::coefficients,coefficients,16*256*24);
    if(allocate(c,C71_RMS_PRIVATE,byte_meta_bytes,&t.meta) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(byte_rms::factor_slots)*24,&t.prefix_eq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(byte_rms::factor_slots)*24,&t.suffix_eq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t((byte_rms::batch_pairs*live_lanes+3)/4)*96,&t.partials) ||
       allocate(c,C71_RMS_PRIVATE,96,&t.result))return -1;
    const bool copied=byte_upload(c,ptr<void>(c,buffer(c,t.meta)),t.shadow,t.shadow_bytes);
    const int synced=fence(c);if(!copied || synced)return -1;
    buffer(c,t.meta)->initialized=buffer(c,t.meta)->count;*token=t.meta;return 0;
}
extern "C" int c71_rms_byte_layer(C71RangeContext* c,uint64_t token,uint32_t layer,const Fp3* point,
    uint32_t count,Fp3 lambda,const byte_rms::FeatureRange* ranges,const Fp3* features,uint32_t feature_count,uint32_t* checkpoint) {
    if(!ready(c) || !byte_session(c,token))return -1;
    auto& t=*c->rms_byte;
    const unsigned width=layer<8?std::min(4u<<layer,(1u<<(7-layer))+1):0;
    if(layer!=t.next_layer || layer>=8 || t.has_layer || count!=t.shape.bits+4+layer ||
       !byte_span(point,uint64_t(count)*24) || !canonical(lambda) || !byte_span(ranges,16*8,4) ||
       feature_count>byte_rms::max_features || !byte_span(checkpoint,4,4) ||
       (feature_count && !byte_span(features,uint64_t(feature_count)*257*24)))
        return fail(c,"RMS byte original layer geometry or spans");
    unsigned cursor=0;
    for(unsigned lane=0;lane<16;++lane) {const auto r=ranges[lane];
        if(r.first!=cursor || r.count>width || r.count>feature_count-cursor)return fail(c,"RMS byte feature coverage");cursor+=r.count;}
    if(cursor!=feature_count)return fail(c,"RMS byte incomplete features");
    for(unsigned i=0;i<count;++i)if(!canonical(point[i]))return fail(c,"RMS byte query point");
    for(uint64_t i=0;i<uint64_t(feature_count)*257;++i)if(!canonical(features[i]))return fail(c,"RMS byte feature value");
    auto* shadow=byte_shadow(t);std::memcpy(shadow,point,uint64_t(count)*24);
    std::fill(shadow+byte_rms::prefix,shadow+byte_rms::prefix+byte_rms::max_bits,Fp3{});
    shadow[byte_rms::lambda]=lambda;std::memcpy(byte_ranges(t),ranges,16*8);
    if(feature_count)std::memcpy(shadow+byte_rms::feature_lut,features,uint64_t(feature_count)*257*24);
    for(unsigned lane=0;lane<16;++lane) {
        Fp3 baseline{};const auto r=ranges[lane];
        for(unsigned j=0;j<r.count;++j) {const auto* f=features+uint64_t(r.first+j)*257;baseline=add(baseline,mul6(f[0],mul6(f[1],f[1])));}
        shadow[byte_rms::baseline+lane]=baseline;shadow[byte_rms::lane_eq+lane]=equality(point+t.shape.bits,4,lane);
    }
    t.shape.layer=layer;t.shape.round=0;t.shape.features=feature_count;t.shape.checkpoint=0;
    unsigned live_features=0;for(unsigned lane=0;lane<t.shape.live_lanes;++lane)live_features+=ranges[lane].count;
    while(t.shape.checkpoint<t.shape.bits-1 && uint64_t(live_features)*(1u<<(t.shape.bits-t.shape.checkpoint))*24>byte_rms::state_bytes)
        ++t.shape.checkpoint;
    t.shape.stride=1u<<(t.shape.bits-t.shape.checkpoint);t.shape.rows=t.shape.stride;
    // Retained rows contain only live-lane features; inactive lanes have the
    // public zero-byte baseline. Feature indices of live lanes are contiguous.
    if(live_features && allocate(c,C71_RMS_PRIVATE,uint64_t(live_features)*t.shape.stride*24,&t.state))return -1;
    t.has_layer=1;t.recovered=0;
    const bool copied=byte_upload(c,ptr<void>(c,buffer(c,t.meta)),t.shadow,t.shadow_bytes);
    const int synced=fence(c);if(!copied || synced)return -1;
    *checkpoint=t.shape.checkpoint;return 0;
}
extern "C" int c71_rms_byte_coefficients(C71RangeContext* c,uint64_t token,const Fp3* prefix,uint32_t round,Fp3* output) {
    if(!ready(c) || !byte_session(c,token))return -1;
    auto& t=*c->rms_byte;const auto& src=c->rms_source;
    if(!t.has_layer || round!=t.shape.round || round>=t.shape.bits+4+t.shape.layer ||
       !byte_prefix(c,prefix,round,output))return fail(c,"RMS byte coefficient round differs");
    if(round)std::memcpy(byte_shadow(t)+byte_rms::prefix,prefix,uint64_t(round)*24);
    auto* meta=ptr<Fp3>(c,buffer(c,t.meta));auto* source_meta=ptr<uint8_t>(c,buffer(c,src.meta));
    if(!byte_upload(c,meta+byte_rms::prefix,byte_shadow(t)+byte_rms::prefix,byte_rms::max_bits*24))return -1;
    const auto* ranges=reinterpret_cast<const byte_rms::FeatureRange*>(reinterpret_cast<uint8_t*>(meta)+byte_ranges_offset);
    auto* peq=ptr<Fp3>(c,buffer(c,t.prefix_eq));auto* seq=ptr<Fp3>(c,buffer(c,t.suffix_eq));
    auto* result=ptr<Fp3>(c,buffer(c,t.result));auto* partials=ptr<Fp3>(c,buffer(c,t.partials));
    auto shape=t.shape;
    if(round<shape.bits) {
        if(launched(c,byte_rms::factors(c->stream,meta+byte_rms::prefix,round,peq)) ||
           launched(c,byte_rms::factors(c->stream,meta+round+1,shape.bits-round-1,seq)) ||
           launched(c,byte_rms::cell_baseline(c->stream,shape,meta,result)))return -1;
        unsigned live_features=0;for(unsigned lane=0;lane<shape.live_lanes;++lane)live_features+=byte_ranges(t)[lane].count;
        shape.features=live_features;auto* state=t.state?ptr<Fp3>(c,buffer(c,t.state)):nullptr;
        if(live_features && round==shape.checkpoint) {
            for(unsigned first=0;first<shape.stride;first+=byte_rms::batch_pairs) {
                const auto n=std::min(byte_rms::batch_pairs,shape.stride-first);
                if(launched(c,byte_rms::regenerate(c->stream,shape,src.device,reinterpret_cast<rms::SourceNorm*>(source_meta),
                    reinterpret_cast<rms::SourceTile*>(source_meta+src.offsets[1]),src.shape.tiles,src.shape.live,meta,ranges,peq,first,n,state)))return -1;
            }
        } else if(live_features && round>shape.checkpoint) {
            if(launched(c,byte_rms::fold_state(c->stream,shape,prefix[round-1],state)))return -1;
            t.shape.rows/=2;shape.rows=t.shape.rows;
        }
        const unsigned half=1u<<(shape.bits-round-1);
        for(unsigned first=0;first<half;first+=byte_rms::batch_pairs) {
            const auto n=std::min(byte_rms::batch_pairs,half-first);
            if(launched(c,byte_rms::cell_coefficients(c->stream,shape,src.device,reinterpret_cast<rms::SourceNorm*>(source_meta),
                reinterpret_cast<rms::SourceTile*>(source_meta+src.offsets[1]),src.shape.tiles,src.shape.live,meta,ranges,peq,seq,state,first,n,partials)) ||
               launched(c,byte_rms::sum_partials(c->stream,partials,(n*shape.live_lanes+3)/4,result)))return -1;
        }
    } else {
        if(!t.recovered) {if(!byte_recover(c))return -1;}
        else {
            if(launched(c,byte_rms::fold_children(c->stream,t.shape.rows,prefix[round-1],ptr<Fp3>(c,buffer(c,t.children)))))return -1;
            t.shape.rows/=2;
        }
        if(!byte_zero(c,result,96) || launched(c,byte_rms::child_coefficients(c->stream,t.shape,meta,ptr<Fp3>(c,buffer(c,t.children)),partials)) ||
           launched(c,byte_rms::sum_partials(c->stream,partials,(t.shape.rows/2+127)/128,result)))return -1;
    }
    if(!byte_publish(c,output))return -1;++t.shape.round;return 0;
}
extern "C" int c71_rms_byte_terminal(C71RangeContext* c,uint64_t token,const Fp3* point,uint32_t count,Fp3* output) {
    if(!ready(c) || !byte_session(c,token))return -1;
    auto& t=*c->rms_byte;
    if(!t.has_layer || !t.recovered || count!=t.shape.bits+4+t.shape.layer || count!=t.shape.round ||
       t.shape.rows!=2 || !byte_prefix(c,point,count,output))return fail(c,"RMS byte terminal coverage differs");
    if(launched(c,byte_rms::fold_children(c->stream,2,point[count-1],ptr<Fp3>(c,buffer(c,t.children)))))return -1;
    if(checked(c,cudaMemcpyAsync(t.publication,ptr<Fp3>(c,buffer(c,t.children)),96,cudaMemcpyDeviceToHost,c->stream)))return -1;
    c->stats.d2h_bytes+=96;if(fence(c))return -1;
    for(auto value:t.publication)if(!canonical(value))return fail(c,"RMS byte terminal noncanonical");
    if(byte_retire(c,t.children) || byte_retire(c,t.state))return -1;
    const auto layer=t.shape.layer;
    if(layer==7) {
        for(auto* id:{&t.meta,&t.prefix_eq,&t.suffix_eq,&t.partials,&t.result})if(byte_retire(c,*id))return -1;
        const auto values=t.publication;Fp3 saved[4];std::memcpy(saved,values,96);
        if(rms_byte_close(c,true))return -1;std::memcpy(output,saved,96);
    } else {std::memcpy(output,t.publication,96);t.has_layer=0;t.next_layer=layer+1;}
    return 0;
}
