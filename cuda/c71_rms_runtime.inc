// The common owner retains the public plan and merged moments for one depth.
namespace c71_rms_prefix {
cudaError_t replay(cudaStream_t,const uint8_t*,const uint16_t*,const Program*,const Node*,
    const uint32_t*,const uint32_t*,unsigned,unsigned,unsigned,unsigned,unsigned,uint64_t*,unsigned*,uint64_t*);
cudaError_t suffix_eq(cudaStream_t,const Fp3*,unsigned,unsigned,unsigned,unsigned,uint32_t*,unsigned*);
cudaError_t consume(cudaStream_t,const uint32_t*,const uint32_t*,const Gate*,unsigned,unsigned,Fp3*,Fp3*,unsigned*);
}
namespace {
namespace rms=c71_rms_prefix;
template<class T> T* rms_meta(C71RangeContext* c,unsigned i) {
    return reinterpret_cast<T*>(ptr<uint8_t>(c,buffer(c,c->rms.meta))+c->rms.offsets[i]);
}
const rms::GateRange* rms_ranges(const RmsPrefixTransaction& s) {
    return reinterpret_cast<const rms::GateRange*>(s.shadow);
}
const uint16_t* rms_masks(const RmsPrefixTransaction& s) {
    return reinterpret_cast<const uint16_t*>(s.shadow+uint64_t(s.shape.programs)*8);
}
const rms::Section* rms_sections(const RmsPrefixTransaction& s) {
    const auto offset=(uint64_t(s.shape.programs)*8+uint64_t(s.shape.masks)*2+3)&~uint64_t{3};
    return reinterpret_cast<const rms::Section*>(s.shadow+offset);
}
bool rms_session(C71RangeContext* c,uint64_t token) {
    if(!token || !c->rms.active || token!=c->rms.meta || !full(buffer(c,token),C71_RMS_PRIVATE)) {
        fail(c,"RMS prefix capability differs"); return false;
    }
    return true;
}
int rms_retire(C71RangeContext* c,uint64_t& id) {
    auto* b=buffer(c,id);
    if(!b || b->kind!=C71_RMS_PRIVATE) return fail(c,"RMS prefix retirement type");
    C71_TRACE_BUFFER(c,b);
    if(C71_TRACE_EVENT(c,"before",0)) return -1;
    const auto status=release_allocation(c,b->allocation,b->pooled,b->deferred_index);
    if(checked(c,status)) { b->release_failed=true; (void)C71_TRACE_EVENT(c,"after",status); return -1; }
    if(c->account) c->account(-int64_t(b->capacity));
    *b={}; id=0; ++c->stats.releases; recount(c);
    return C71_TRACE_EVENT(c,"after",status)?-1:0;
}
}
extern "C" int c71_rms_prefix_begin(C71RangeContext* c,rms::Shape shape,
    const rms::Program* programs,const rms::Node* nodes,const uint32_t* boundaries,const uint32_t* outputs,
    const rms::Gate* gates,const Fp3* point,const rms::GateRange* ranges,const uint16_t* masks,
    const rms::Section* sections,uint64_t* token) {
    if(!ready(c)) return -1;
    if(c->rms.active || c->linear.phase || c->salts.phase || c->source.values[0] || c->residual.active ||
       c->contract.active || c->residual_query.phase) return fail(c,"RMS prefix overlaps an active consumer");
#ifdef C71_ASYNC_ALLOCATOR_EXPERIMENT
    if(c->async_phase) return fail(c,"RMS prefix overlaps the source pool");
#endif
    if(!shape.programs || shape.programs>421 || !power2(shape.width) || shape.width>16384 ||
       !power2(shape.capacity) || shape.capacity<256 || shape.capacity>4096 ||
       !shape.suffix_bits || shape.suffix_bits>25 || !shape.nodes || shape.nodes>(1u<<24) ||
       !shape.boundaries || shape.boundaries>421*129 || !shape.outputs || shape.outputs>421*16384 ||
       !shape.gates || shape.gates>421*16384 || !shape.masks || shape.masks>65535 ||
       !shape.sections || shape.sections>16384) return fail(c,"RMS prefix shape");
    const void* inputs[]={programs,nodes,boundaries,outputs,gates,point,ranges,masks,sections};
    const uint64_t lengths[]={uint64_t(shape.programs)*28,uint64_t(shape.nodes)*16,uint64_t(shape.boundaries)*4,
        uint64_t(shape.outputs)*4,uint64_t(shape.gates)*40,uint64_t(shape.suffix_bits)*24,
        uint64_t(shape.programs)*8,uint64_t(shape.masks)*2,uint64_t(shape.sections)*8};
    const unsigned aligns[]={4,4,4,4,8,8,4,2,4};
    uintptr_t token_end=0;
    if(!token || reinterpret_cast<uintptr_t>(token)%8 || !c71_dense::span(token,8,token_end))
        return fail(c,"RMS prefix token span");
    for(unsigned i=0;i<9;++i) {
        uintptr_t end=0;
        if(!inputs[i] || reinterpret_cast<uintptr_t>(inputs[i])%aligns[i] ||
           !c71_dense::span(inputs[i],lengths[i],end) || c71_dense::overlaps(inputs[i],end,token,token_end))
            return fail(c,"RMS prefix public span");
    }
    for(unsigned i=0;i<shape.suffix_bits;++i) if(!canonical(point[i])) return fail(c,"RMS prefix point");
    for(unsigned i=0;i<shape.masks;++i) if(!masks[i] || (i && masks[i]<=masks[i-1])) return fail(c,"RMS prefix mask dictionary");
    for(unsigned i=0;i<shape.sections;++i) if(sections[i].first>=sections[i].end || sections[i].end>(1u<<shape.suffix_bits) ||
        (i && sections[i].first<sections[i-1].end)) return fail(c,"RMS prefix support sections");
    unsigned slots=0,gate_cursor=0;
    for(unsigned p=0;p<shape.programs;++p) {
        const auto& plan=programs[p]; const auto range=ranges[p];
        if(plan.ports<2 || plan.ports>98 || plan.slots<plan.ports || plan.slots>16384 || plan.stages>128 ||
           plan.nodes_first>shape.nodes || plan.boundaries_first>=shape.boundaries ||
           plan.stages+1>shape.boundaries-plan.boundaries_first || plan.outputs_first>shape.outputs ||
           !plan.outputs_count || plan.outputs_count>shape.width || plan.outputs_count>shape.outputs-plan.outputs_first ||
           range.first!=gate_cursor || !range.count || range.count>shape.gates-gate_cursor)
            return fail(c,"RMS prefix program bounds");
        gate_cursor+=range.count; slots=std::max(slots,plan.slots);
        const uint64_t scratch_bytes=uint64_t(plan.slots)*8;
        if(c->account && c->account(int64_t(scratch_bytes))) return fail(c,"RMS prefix validator budget");
        auto* scratch=new(std::nothrow) uint32_t[uint64_t(plan.slots)*2]{};
        if(!scratch) { if(c->account)c->account(-int64_t(scratch_bytes)); return fail(c,"RMS prefix validator allocation"); }
        c->stats.host_owner_bytes+=scratch_bytes;
        auto* initialized=scratch; auto* written=scratch+plan.slots;
        std::fill(initialized,initialized+plan.ports,1);
        bool valid=boundaries[plan.boundaries_first]==0;
        for(unsigned stage=0;valid && stage<plan.stages;++stage) {
            const auto first=boundaries[plan.boundaries_first+stage],end=boundaries[plan.boundaries_first+stage+1];
            valid=first<=end && end<=shape.nodes-plan.nodes_first;
            std::fill(written,written+plan.slots,0);
            for(unsigned i=first;valid && i<end;++i) {
                const auto g=nodes[plan.nodes_first+i];
                valid=g.op<=1 && g.z<plan.slots && g.x<plan.slots && g.y<plan.slots;
                if(valid) { valid=initialized[g.x] && initialized[g.y] && !written[g.z]; written[g.z]=1; }
            }
            for(unsigned i=first;valid && i<end;++i) {
                const auto g=nodes[plan.nodes_first+i]; valid=!written[g.x] && !written[g.y];
            }
            for(unsigned i=0;valid && i<plan.slots;++i) initialized[i]|=written[i];
        }
        for(unsigned i=0;valid && i<plan.outputs_count;++i) {
            const auto z=outputs[plan.outputs_first+i]; valid=z<plan.slots && initialized[z];
        }
        delete[] scratch; c->stats.host_owner_bytes-=scratch_bytes;
        if(c->account)c->account(-int64_t(scratch_bytes));
        if(!valid) return fail(c,"RMS prefix parallel plan dependency");
    }
    if(gate_cursor!=shape.gates) return fail(c,"RMS prefix gate coverage");
    for(unsigned i=0;i<shape.gates;++i) if(gates[i].op>2 || gates[i].reserved || gates[i].x>=shape.width ||
        gates[i].y>=shape.width || (gates[i].op==2 && gates[i].x!=gates[i].y) || !canonical(gates[i].weight))
            return fail(c,"RMS prefix weighted gate");
    auto& s=c->rms; s.active=1; s.shape=shape; s.slots=slots; s.cursor=sections[0].first;
    const uint64_t section_offset=(lengths[6]+lengths[7]+3)&~uint64_t{3};
    const auto shadow_bytes=section_offset+lengths[8];
    if(c->account && c->account(int64_t(shadow_bytes))) return fail(c,"RMS prefix host metadata budget");
    s.shadow=new(std::nothrow) uint8_t[shadow_bytes];
    if(!s.shadow) { if(c->account)c->account(-int64_t(shadow_bytes)); return fail(c,"RMS prefix host metadata allocation"); }
    s.shadow_bytes=shadow_bytes; c->stats.host_owner_bytes+=shadow_bytes;
    std::memcpy(s.shadow,ranges,lengths[6]); std::memcpy(s.shadow+lengths[6],masks,lengths[7]);
    std::memcpy(s.shadow+section_offset,sections,lengths[8]);
    uint64_t meta_bytes=0;
    for(unsigned i=0;i<6;++i) { s.offsets[i]=meta_bytes; meta_bytes+=aligned(lengths[i]); }
    if(allocate(c,C71_RMS_PRIVATE,meta_bytes,&s.meta) || allocate(c,C71_RMS_PRIVATE,uint64_t(16)*shape.capacity*12,&s.frames) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(16)*shape.capacity*2,&s.assignments) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(shape.width)*shape.capacity*2,&s.stage) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(192)*shape.capacity/8,&s.eq) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(rms::gate_chunk)*rms::moments*24,&s.chunk) ||
       allocate(c,C71_RMS_PRIVATE,uint64_t(shape.masks)*rms::moments*24,&s.aggregate)) return -1;
    bool error=false;
    for(unsigned i=0;i<6;++i) {
        if(checked(c,cudaMemcpyAsync(rms_meta<uint8_t>(c,i),inputs[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) { error=true;break; }
        c->stats.h2d_bytes+=lengths[i];
    }
    if(!error) {
        const auto bytes=uint64_t(shape.masks)*rms::moments*24;
        if(checked(c,cudaMemsetAsync(ptr<void>(c,buffer(c,s.aggregate)),0,bytes,c->stream))) error=true;
        else c->stats.zeroed_bytes+=bytes;
    }
    const int synced=fence(c); // Borrowed packet survives every submitted copy.
    if(error || synced) return -1;
    buffer(c,s.meta)->initialized=buffer(c,s.meta)->count;
    buffer(c,s.aggregate)->initialized=buffer(c,s.aggregate)->count;
    *token=s.meta; return 0;
}
extern "C" int c71_rms_prefix_window(C71RangeContext* c,uint64_t token,uint32_t first,uint32_t n,
    const uint8_t* frames,const uint16_t* assignments,const uint16_t* mask_ids) {
    if(!ready(c) || !rms_session(c,token)) return -1;
    auto& s=c->rms; const auto shape=s.shape; const auto* sections=rms_sections(s);
    unsigned lower=0,upper=shape.sections;
    while(lower<upper) { const auto mid=(lower+upper)/2; if(sections[mid].end<=first) lower=mid+1; else upper=mid; }
    if(lower==shape.sections || first!=s.cursor || first<sections[lower].first || !n || n>shape.capacity ||
       n>sections[lower].end-first) return fail(c,"RMS prefix window coverage");
    const void* inputs[]={frames,assignments,mask_ids};
    const uint64_t lengths[]={uint64_t(16)*shape.capacity*12,uint64_t(16)*shape.capacity*2,uint64_t(shape.programs)*2};
    for(unsigned i=0;i<3;++i) {
        uintptr_t end=0;
        if(!inputs[i] || (i && reinterpret_cast<uintptr_t>(inputs[i])%2) || !c71_dense::span(inputs[i],lengths[i],end))
            return fail(c,"RMS prefix window span");
    }
    for(unsigned row=0;row<16;++row) {
        const auto p=assignments[uint64_t(row)*shape.capacity];
        if(p!=0xffff && p>=shape.programs) return fail(c,"RMS prefix assignment");
        for(unsigned k=1;k<n;++k) if(assignments[uint64_t(row)*shape.capacity+k]!=p) return fail(c,"RMS prefix assignment changes within window");
        for(unsigned k=n;k<shape.capacity;++k) if(assignments[uint64_t(row)*shape.capacity+k]!=0xffff) return fail(c,"RMS prefix padding assignment");
    }
    bool live=false;
    for(unsigned p=0;p<shape.programs;++p) {
        unsigned mask=0;
        for(unsigned row=0;row<16;++row) if(assignments[uint64_t(row)*shape.capacity]==p) mask|=1u<<row;
        const auto id=mask_ids[p];
        if(mask ? (id>=shape.masks || rms_masks(s)[id]!=mask) : id!=0xffff) return fail(c,"RMS prefix original selector mask");
        live|=mask!=0;
    }
    if(!live) return fail(c,"RMS prefix empty support window");
    bool error=false;
    for(unsigned i=0;i<2;++i) {
        const auto id=i?s.assignments:s.frames;
        if(checked(c,cudaMemcpyAsync(ptr<void>(c,buffer(c,id)),inputs[i],lengths[i],cudaMemcpyHostToDevice,c->stream))) { error=true; break; }
        c->stats.h2d_bytes+=lengths[i];
    }
    unsigned attempted=0; uint64_t zeroed=0;
    if(!error) {
        const auto status=rms::replay(c->stream,ptr<uint8_t>(c,buffer(c,s.frames)),ptr<uint16_t>(c,buffer(c,s.assignments)),
            rms_meta<rms::Program>(c,0),rms_meta<rms::Node>(c,1),rms_meta<uint32_t>(c,2),rms_meta<uint32_t>(c,3),
            shape.programs,shape.width,shape.capacity,n,s.slots,ptr<uint64_t>(c,buffer(c,s.stage)),&attempted,&zeroed);
        c->stats.launches+=attempted; c->stats.zeroed_bytes+=zeroed; error=checked(c,status)!=0;
    }
    if(!error) {
        const auto status=rms::suffix_eq(c->stream,rms_meta<Fp3>(c,5),shape.suffix_bits,first,shape.capacity,n,
            ptr<uint32_t>(c,buffer(c,s.eq)),&attempted);
        c->stats.launches+=attempted; error=checked(c,status)!=0;
    }
    for(unsigned p=0;!error && p<shape.programs;++p) if(mask_ids[p]!=0xffff) {
        const auto range=rms_ranges(s)[p];
        for(unsigned k=0;!error && k<range.count;k+=rms::gate_chunk) {
            const auto status=rms::consume(c->stream,ptr<uint32_t>(c,buffer(c,s.stage)),ptr<uint32_t>(c,buffer(c,s.eq)),
                rms_meta<rms::Gate>(c,4)+range.first+k,std::min(rms::gate_chunk,range.count-k),shape.capacity,
                ptr<Fp3>(c,buffer(c,s.chunk)),ptr<Fp3>(c,buffer(c,s.aggregate))+uint64_t(mask_ids[p])*rms::moments,&attempted);
            c->stats.launches+=attempted; error=checked(c,status)!=0;
        }
    }
    const int synced=fence(c); // Host windows may be refilled even after submit errors.
    if(error || synced) return -1;
    s.cursor=first+n;
    if(s.cursor==sections[lower].end) s.cursor=lower+1<shape.sections?sections[lower+1].first:(1u<<shape.suffix_bits);
    ++s.windows; return 0;
}
extern "C" int c71_rms_prefix_finish(C71RangeContext* c,uint64_t token,Fp3* output,uint32_t count) {
    if(!ready(c) || !rms_session(c,token)) return -1;
    auto& s=c->rms; uintptr_t end=0;
    if(!s.windows || s.cursor!=(1u<<s.shape.suffix_bits) || count!=uint64_t(s.shape.masks)*rms::moments ||
       !output || reinterpret_cast<uintptr_t>(output)%8 || !c71_dense::span(output,uint64_t(count)*24,end))
        return fail(c,"RMS prefix finish coverage or output span");
    const uint64_t bytes=uint64_t(count)*24;
    if(c->account && c->account(int64_t(bytes))) return fail(c,"RMS prefix publication budget");
    auto* staged=new(std::nothrow) Fp3[count];
    if(!staged) {if(c->account)c->account(-int64_t(bytes));return fail(c,"RMS prefix publication allocation");}
    c->stats.host_owner_bytes+=bytes;
    const auto cleanup=[&](int status) {
        delete[] staged; c->stats.host_owner_bytes-=bytes;
        if(c->account)c->account(-int64_t(bytes));
        return status;
    };
    const bool error=checked(c,cudaMemcpyAsync(staged,ptr<void>(c,buffer(c,s.aggregate)),bytes,cudaMemcpyDeviceToHost,c->stream))!=0;
    if(!error)c->stats.d2h_bytes+=bytes;
    const int synced=fence(c);
    if(error || synced)return cleanup(-1);
    for(unsigned i=0;i<count;++i)if(!canonical(staged[i]))return cleanup(fail(c,"RMS prefix noncanonical moments"));
    for(auto* id:{&s.aggregate,&s.chunk,&s.eq,&s.stage,&s.assignments,&s.frames,&s.meta})if(rms_retire(c,*id))return cleanup(-1);
    delete[] s.shadow; c->stats.host_owner_bytes-=s.shadow_bytes;
    if(c->account)c->account(-int64_t(s.shadow_bytes));
    s={}; std::memcpy(output,staged,bytes);return cleanup(0);
}
