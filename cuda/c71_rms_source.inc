// A single immutable, already charged Rust checkpoint. Registration adds only
// page-rounding slack; driver metadata is part of the measured runtime premise.
namespace c71_rms_prefix {
cudaError_t source_frames(cudaStream_t,const uint8_t*,const SourceNorm*,const SourceTile*,
    unsigned,unsigned,unsigned,unsigned,unsigned,uint8_t*,uint16_t*,unsigned*);
}
namespace {
const rms::SourceTile* rms_source_tiles(const RmsMappedSource& s) {
    return reinterpret_cast<const rms::SourceTile*>(s.shadow+s.offsets[1]);
}
bool rms_source_session(C71RangeContext* c,uint64_t token) {
    const auto& s=c->rms_source;
    if(!token || token!=s.meta || !s.registered || s.unregister_failed ||
       !full(buffer(c,token),C71_RMS_PRIVATE)) {
        fail(c,"RMS mapped source capability differs");return false;
    }
    return true;
}
void rms_source_shadow_release(C71RangeContext* c) {
    auto& s=c->rms_source;
    if(s.shadow) {
        delete[] s.shadow;s.shadow=nullptr;
        c->stats.host_owner_bytes-=s.shadow_bytes;
        if(c->account)c->account(-int64_t(s.shadow_bytes));
        s.shadow_bytes=0;
    }
}
int rms_source_unpin(C71RangeContext* c) {
    auto& s=c->rms_source;
    if(s.unregister_failed)return fail(c,"RMS source unregister ownership uncertain");
    if(s.registered) {
        if(checked(c,cudaHostUnregister(const_cast<uint8_t*>(s.host)))) {
            s.unregister_failed=1;return -1;
        }
        s.registered=0;s.device=nullptr;
    }
    if(s.page_slack) {
        c->stats.host_owner_bytes-=s.page_slack;
        if(c->account)c->account(-int64_t(s.page_slack));
        s.page_slack=0;
    }
    return 0;
}
bool rms_dyadic_part(uint32_t first,uint32_t count,uint32_t total) {
    uint32_t cursor=0;
    while(total) {
        uint32_t size=1;while(size<=total/2)size*=2;
        if(cursor==first)return size==count;
        cursor+=size;total-=size;
    }
    return false;
}
unsigned rms_source_tile_at(const RmsMappedSource& s,uint32_t cell) {
    const auto* tiles=rms_source_tiles(s);unsigned lo=0,hi=s.shape.tiles;
    while(lo<hi) {const auto mid=(lo+hi)/2;if(tiles[mid].end<=cell)lo=mid+1;else hi=mid;}
    return lo;
}
}
extern "C" int c71_rms_source_begin(C71RangeContext* c,rms::SourceShape shape,const uint8_t* payload,
    const rms::SourceNorm* norms,const rms::SourceTile* tiles,uint64_t* token) {
    if(!ready(c))return -1;
    if(c->rms_source.host || c->rms.active || c->linear.phase || c->salts.phase || c->source.values[0] ||
       c->residual.active || c->contract.active || c->residual_query.phase)
        return fail(c,"RMS source overlaps an active consumer");
#ifdef C71_ASYNC_ALLOCATOR_EXPERIMENT
    if(c->async_phase)return fail(c,"RMS source overlaps the source pool");
#endif
    if(!shape.bytes || shape.bytes>(uint64_t{1}<<31) || !shape.live || !power2(shape.padded) ||
       shape.padded>(1u<<29) || shape.live>shape.padded || (shape.padded>1 && shape.live<=shape.padded/2) ||
       !shape.norms || shape.norms>16384 || !shape.tiles || shape.tiles>16384 ||
       !shape.programs || shape.programs>421 || shape.reserved)return fail(c,"RMS source shape");
    uintptr_t token_end=0;
    if(!token || reinterpret_cast<uintptr_t>(token)%8 || !c71_dense::span(token,8,token_end))
        return fail(c,"RMS source token span");
    const void* arrays[]={payload,norms,tiles};
    const uint64_t lengths[]={shape.bytes,uint64_t(shape.norms)*48,uint64_t(shape.tiles)*32};
    const unsigned aligns[]={1,8,4};
    for(unsigned i=0;i<3;++i) {
        uintptr_t end=0;
        if(!arrays[i] || reinterpret_cast<uintptr_t>(arrays[i])%aligns[i] ||
           !c71_dense::span(arrays[i],lengths[i],end) || c71_dense::overlaps(arrays[i],end,token,token_end))
            return fail(c,"RMS source span or token alias");
    }
    uint64_t cursor=0,cells=0;
    for(unsigned i=0;i<shape.norms;++i) {
        const auto s=norms[i];
        if(!s.rows || !s.columns || uint64_t(s.rows)*s.columns!=s.cells || s.cells>shape.live ||
           (s.pbytes!=2 && s.pbytes!=4) || s.program>=shape.programs || s.product!=cursor)
            return fail(c,"RMS source norm geometry");
        cursor+=s.cells*s.pbytes;
        if(s.statistic!=cursor)return fail(c,"RMS source statistic offset");
        cursor+=uint64_t(s.rows)*6;
        if(s.output!=cursor)return fail(c,"RMS source output offset");
        cursor+=s.cells*2;cells+=s.cells;
        if(cursor>shape.bytes || cells>shape.live)return fail(c,"RMS source norm coverage");
    }
    if(cursor!=shape.bytes || cells!=shape.live)return fail(c,"RMS source complete payload coverage");
    uint32_t first=0;
    for(unsigned i=0;i<shape.tiles;++i) {
        const auto t=tiles[i];
        if(t.first!=first || t.end<=first || t.end>shape.live || t.norm>=shape.norms ||
           !t.cols || (t.end-t.first)%t.cols || t.reserved)return fail(c,"RMS source tile bounds");
        const auto s=norms[t.norm];const auto rows=(t.end-t.first)/t.cols;
        if(t.program!=s.program || !rms_dyadic_part(t.row,rows,s.rows) ||
           !rms_dyadic_part(t.col,t.cols,s.columns))return fail(c,"RMS source original dyadic tile");
        if(i) {
            const auto p=tiles[i-1];const auto a=p.end-p.first,b=t.end-t.first;
            if(a<b || (a==b && (p.norm>t.norm || (p.norm==t.norm &&
               (p.row>t.row || (p.row==t.row && p.col>=t.col))))))
                return fail(c,"RMS source tile order or duplicate");
        }
        first=t.end;
    }
    if(first!=shape.live)return fail(c,"RMS source live tile coverage");
    for(auto attribute:{cudaDevAttrHostRegisterSupported,cudaDevAttrHostRegisterReadOnlySupported,cudaDevAttrCanMapHostMemory}) {
        int supported=0;
        if(checked(c,cudaDeviceGetAttribute(&supported,attribute,c->device)))return -1;
        if(!supported)return fail(c,"RMS immutable host mapping unavailable");
    }
    const auto page=sysconf(_SC_PAGESIZE);
    if(page<=0 || !power2(uint64_t(page)))return fail(c,"RMS source host page geometry");
    const uint64_t address=reinterpret_cast<uintptr_t>(payload);
    const uint64_t slack=(address%uint64_t(page))+((uint64_t(page)-(address+shape.bytes)%uint64_t(page))%uint64_t(page));
    auto& s=c->rms_source;s.shape=shape;s.host=payload;
    if(c->account && c->account(int64_t(slack)))return fail(c,"RMS source page slack budget");
    s.page_slack=slack;c->stats.host_owner_bytes+=slack;
    if(checked(c,cudaHostRegister(const_cast<uint8_t*>(payload),shape.bytes,cudaHostRegisterMapped|cudaHostRegisterReadOnly)))return -1;
    s.registered=1;void* device=nullptr;
    if(checked(c,cudaHostGetDevicePointer(&device,const_cast<uint8_t*>(payload),0)))return -1;
    if(!device)return fail(c,"RMS source null mapping");
    s.device=static_cast<const uint8_t*>(device);s.offsets[1]=aligned(lengths[1]);
    const uint64_t bytes=s.offsets[1]+lengths[2];
    if(c->account && c->account(int64_t(bytes)))return fail(c,"RMS source metadata budget");
    s.shadow=new(std::nothrow) uint8_t[bytes]{};
    if(!s.shadow) {if(c->account)c->account(-int64_t(bytes));return fail(c,"RMS source metadata allocation");}
    s.shadow_bytes=bytes;c->stats.host_owner_bytes+=bytes;
    std::memcpy(s.shadow,norms,lengths[1]);std::memcpy(s.shadow+s.offsets[1],tiles,lengths[2]);
    if(allocate(c,C71_RMS_PRIVATE,bytes,&s.meta))return -1;
    const bool error=checked(c,cudaMemcpyAsync(ptr<void>(c,buffer(c,s.meta)),s.shadow,bytes,cudaMemcpyHostToDevice,c->stream))!=0;
    if(!error)c->stats.h2d_bytes+=bytes;
    const int synced=fence(c);
    if(error || synced)return -1;
    buffer(c,s.meta)->initialized=buffer(c,s.meta)->count;*token=s.meta;return 0;
}
extern "C" int c71_rms_source_retire(C71RangeContext* c,uint64_t token) {
    if(!ready(c) || !rms_source_session(c,token))return -1;
    if(c->rms.active)return fail(c,"RMS source has an active reader");
    if(fence(c) || rms_source_unpin(c) || rms_retire(c,c->rms_source.meta))return -1;
    rms_source_shadow_release(c);c->rms_source={};return 0;
}
extern "C" int c71_rms_prefix_window_from_source(C71RangeContext* c,uint64_t prefix,uint64_t source,
    uint32_t first,uint32_t n,const uint16_t* mask_ids) {
    if(!ready(c) || !rms_session(c,prefix) || !rms_source_session(c,source))return -1;
    auto& s=c->rms;const auto& src=c->rms_source;
    if(src.shape.programs!=s.shape.programs || src.shape.padded!=(1u<<(s.shape.suffix_bits+4)))
        return fail(c,"RMS source and prefix domains differ");
    unsigned section=0;
    if(!rms_window_coverage(c,first,n,mask_ids,section))return -1;
    const uint32_t suffix=src.shape.padded/16;const auto* tiles=rms_source_tiles(src);
    uint16_t assignments[16]{};bool live=false;
    for(unsigned row=0;row<16;++row) {
        const uint32_t cell=row*suffix+first;const auto tile=rms_source_tile_at(src,cell);
        assignments[row]=0xffff;
        if(tile<src.shape.tiles) {
            if(n>tiles[tile].end-cell)return fail(c,"RMS source window crosses original tile");
            assignments[row]=uint16_t(tiles[tile].program);live=true;
        }
    }
    if(!live)return fail(c,"RMS mapped empty support window");
    for(unsigned p=0;p<s.shape.programs;++p) {
        unsigned mask=0;
        for(unsigned row=0;row<16;++row)if(assignments[row]==p)mask|=1u<<row;
        const auto id=mask_ids[p];
        if(mask ? (id>=s.shape.masks || rms_masks(s)[id]!=mask) : id!=0xffff)
            return fail(c,"RMS mapped original selector mask");
    }
    auto* meta=ptr<uint8_t>(c,buffer(c,src.meta));unsigned attempted=0;
    const auto status=rms::source_frames(c->stream,src.device,reinterpret_cast<rms::SourceNorm*>(meta),
        reinterpret_cast<rms::SourceTile*>(meta+src.offsets[1]),src.shape.tiles,suffix,first,s.shape.capacity,n,
        ptr<uint8_t>(c,buffer(c,s.frames)),ptr<uint16_t>(c,buffer(c,s.assignments)),&attempted);
    c->stats.launches+=attempted;
    return rms_consume_window(c,first,n,mask_ids,section,checked(c,status)!=0);
}
