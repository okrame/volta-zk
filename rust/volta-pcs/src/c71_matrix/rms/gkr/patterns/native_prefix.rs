//! Original mixed frames enter the explicit common GPU owner in bounded windows.
use super::*;
use crate::c71_matrix::range::windowed::native::{self,Runtime};

fn assignment(spans:&[(u32,u32,u16)],cell:usize)->Option<usize> {
    let i=spans.partition_point(|&(_,end,_)|end as usize<=cell);
    spans.get(i).filter(|&&(first,_,_)|first as usize<=cell).map(|&(_,_,p)|p as usize)
}

pub(in super::super) fn build(s:&Statement<'_>,depth:usize,point:&[Fp3],weights:&[Fp3],
    read:&dyn Fn(usize)->[u8;12],work:&mut Work,runtime:&mut Runtime,
    public_spans:&[(u32,u32,u16)],capacity:usize)->Result<Option<Prefix>,String> {
    if point.len()<=4 {return Ok(None);}
    if point.len()>29 || !(256..=4096).contains(&capacity) || !capacity.is_power_of_two() ||
        s.programs.is_empty() || s.programs.len()>421 || depth==0 {
        return runtime.abort("native RMS public geometry differs");
    }
    let mut dense_spans=Vec::<(u32,u32,u16)>::new();
    let spans=if public_spans.is_empty() && s.assignments.len()<=512 {
        for i in 0..s.assignments.len() {
            if let Some(p)=s.assignments.get(i) {
                if let Some(last)=dense_spans.last_mut().filter(|last|last.1==i as u32 && last.2==p as u16) {
                    last.1+=1;
                } else {dense_spans.push((i as u32,i as u32+1,p as u16));}
            }
        }
        &dense_spans[..]
    } else {public_spans};
    if spans.is_empty() || spans.len()>16384 || spans.iter().any(|&(first,end,p)|
        first>=end || end as usize>s.assignments.len() || p as usize>=s.programs.len()) ||
        spans.windows(2).any(|pair|pair[0].1>pair[1].0) {
        return runtime.abort("native RMS requires original ordered program support");
    }
    let suffix=s.assignments.len()/16;
    let mut boundaries=vec![0,suffix as u32];
    for &(first,end,_) in spans {
        for row in first as usize/suffix..=(end as usize-1)/suffix {
            boundaries.push((first as usize).saturating_sub(row*suffix).min(suffix) as u32);
            boundaries.push((end as usize-row*suffix).min(suffix) as u32);
        }
    }
    boundaries.sort_unstable();boundaries.dedup();
    let mut sections=Vec::new();let mut mask_set=std::collections::BTreeSet::new();
    for window in boundaries.windows(2) {
        let mut masks=vec![0u16;s.programs.len()];
        for row in 0..16 {if let Some(p)=assignment(spans,row*suffix+window[0] as usize) {masks[p]|=1<<row;}}
        if masks.iter().any(|&mask|mask!=0) {
            sections.push(native::RmsSection {first:window[0],end:window[1]});
            mask_set.extend(masks.into_iter().filter(|&mask|mask!=0));
        }
    }
    if sections.len()>16384 || mask_set.len()>65535 {return runtime.abort("native RMS projected support cap");}
    let masks=mask_set.into_iter().collect::<Vec<_>>();
    let width=super::super::widths(s.programs)?[depth-1];
    let mut packet=native::RmsPacket {
        shape:native::RmsShape::default(),programs:Vec::new(),nodes:Vec::new(),boundaries:Vec::new(),
        outputs:Vec::new(),gates:Vec::new(),point:point[4..].iter().copied().map(Into::into).collect(),
        ranges:Vec::new(),masks,sections,
    };
    for program in s.programs {
        let plan=ReplayPlan::new(program,(depth-1).min(program.levels.len()))?;
        let parallel=plan.parallel(program.ports);
        let selected=gates(program,depth);
        if selected.len()>weights.len() {return runtime.abort("native RMS gate weights differ");}
        packet.programs.push(native::RmsProgram {
            ports:program.ports as u32,slots:parallel.slots as u32,stages:(parallel.boundaries.len()-1) as u32,
            nodes_first:packet.nodes.len() as u32,boundaries_first:packet.boundaries.len() as u32,
            outputs_first:packet.outputs.len() as u32,outputs_count:parallel.outputs.len() as u32,
        });
        packet.nodes.extend(parallel.ops);packet.boundaries.extend(parallel.boundaries);packet.outputs.extend(parallel.outputs);
        packet.ranges.push(native::RmsRange {first:packet.gates.len() as u32,count:selected.len() as u32});
        packet.gates.extend(selected.iter().zip(weights).map(|(g,&weight)|native::RmsGate {
            op:match g.op {Op::And=>0,Op::Xor=>1,Op::Copy=>2},x:g.x as u32,y:g.y as u32,reserved:0,weight:weight.into(),
        }));
    }
    // Programs containing only aliases still have a nonempty public node span.
    if packet.nodes.is_empty() {packet.nodes.push([0;4]);}
    packet.shape=native::RmsShape {
        programs:packet.programs.len() as u32,width:width as u32,capacity:capacity as u32,suffix_bits:(point.len()-4) as u32,
        nodes:packet.nodes.len() as u32,boundaries:packet.boundaries.len() as u32,outputs:packet.outputs.len() as u32,
        gates:packet.gates.len() as u32,masks:packet.masks.len() as u32,sections:packet.sections.len() as u32,
    };
    let token=runtime.rms_prefix_begin(&packet)?;
    let mut frames=vec![0u8;16*capacity*12];let mut ids=vec![u16::MAX;16*capacity];
    let mut mask_ids=vec![u16::MAX;s.programs.len()];let mut local_masks=vec![0u16;s.programs.len()];
    for section in &packet.sections {
        let mut first=section.first as usize;
        while first<section.end as usize {
            let n=capacity.min(section.end as usize-first);
            ids.fill(u16::MAX);local_masks.fill(0);mask_ids.fill(u16::MAX);
            for row in 0..16 {
                let p=assignment(spans,row*suffix+first);
                if let Some(p)=p {local_masks[p]|=1<<row;}
                for k in 0..n {
                    let cell=row*suffix+first+k;
                    if s.assignments.get(cell)!=p {return runtime.abort("native RMS support disagrees with original assignment");}
                    if let Some(p)=p {
                        let index=row*capacity+k;ids[index]=p as u16;
                        frames[index*12..index*12+12].copy_from_slice(&read(cell));work.original_frames+=1;
                    }
                }
            }
            for (p,&mask) in local_masks.iter().enumerate() {if mask!=0 {
                mask_ids[p]=packet.masks.binary_search(&mask).map_err(|_|"native RMS mask missing")? as u16;
            }}
            runtime.rms_prefix_window(&token,first,n,&frames,&ids,&mask_ids)?;first+=n;
        }
    }
    let values=runtime.rms_prefix_finish(token)?;
    work.histogram_payload_peak=work.histogram_payload_peak.max(values.capacity()*core::mem::size_of::<Fp3>());
    Prefix::from_native_moments(point,&packet.masks,values).map(Some)
}
