//! Original private byte coefficients/children on the mapped RMS checkpoint.
//! Public basis changes stay CPU; source bytes, states and recovery stay GPU.
use super::*;
use crate::c71_matrix::range::windowed::native::{Runtime,RmsSourceToken,RmsByteToken};

pub(in crate::c71_matrix) struct Prover<'a> {
    runtime:&'a mut Runtime,
    token:RmsByteToken,
    trees:&'a ByteTrees,
    cells:usize,
    features:Vec<Vec<(Fp3,[Fp3;256])>>,
    heap_peak:usize,
    checkpoint_max:usize,
}
impl<'a> Prover<'a> {
    pub(in super::super) fn new(runtime:&'a mut Runtime,source:&RmsSourceToken,trees:&'a ByteTrees,
        cells:usize,live_lanes:usize,coefficients:&[[Fp3;256]])->Result<Self,String> {
        let token=runtime.rms_byte_begin(source,cells,live_lanes,coefficients)?;
        Ok(Self {runtime,token,trees,cells,features:Vec::new(),heap_peak:0,checkpoint_max:0})
    }
    pub(in super::super) fn coefficients(&mut self,layer:usize,point:&[Fp3],lambda:Fp3,prefix:&[Fp3])
        ->Result<[Fp3;4],String> {
        if prefix.is_empty() {
            let node_eq=eq(&point[self.cells+4..]);
            self.features=(0..16).map(|lane|contract(self.trees,lane,layer,&node_eq,lambda)).collect();
            let bytes=self.features.capacity()*core::mem::size_of::<Vec<(Fp3,[Fp3;256])>>()
                +self.features.iter().map(|v|v.capacity()*core::mem::size_of::<(Fp3,[Fp3;256])>()).sum::<usize>();
            self.heap_peak=self.heap_peak.max(bytes);
            let checkpoint=self.runtime.rms_byte_layer(&mut self.token,layer,point,lambda,&self.features)?;
            self.checkpoint_max=self.checkpoint_max.max(checkpoint);
        }
        self.runtime.rms_byte_coefficients(&mut self.token,prefix)
    }
    pub(in super::super) fn terminal(&mut self,_layer:usize,point:&[Fp3])->Result<[Fp3;4],String> {
        self.runtime.rms_byte_terminal(&mut self.token,point)
    }
    pub(in super::super) fn heap_capacity(&self)->usize {self.heap_peak}
    pub(in super::super) fn checkpoint_max(&self)->usize {self.checkpoint_max}
}
