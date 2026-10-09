//! Bounded sourcewise residual state, with explicit CPU and native PCS owners.
//! The native extension query is pending; no private getter fallback is allowed.
use super::replay::{inverse_series, multiply_polynomials, BaseScan,NativeOriginal};
use crate::c71_matrix::range::windowed::native as device;
use super::*;
use p3_dft::TwoAdicSubgroupDft;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use std::sync::{
    atomic::{AtomicBool,AtomicU64, Ordering},
    Arc,Mutex,OnceLock,RwLock,
};

pub(in crate::c71_matrix) type Getter = Arc<dyn Fn(usize) -> E + Send + Sync>;

const POWER_BLOCK_CAP: usize = 1 << 21;

fn geometry(dimension: usize, first_fold: usize) -> Result<(), String> {
    if !(1..=35).contains(&dimension)
        || first_fold == 0
        || first_fold > dimension
        || (dimension > 16 && first_fold > 7)
    {
        return Err("sourcewise geometry exceeds bounded prefix/state domain".into());
    }
    Ok(())
}

struct PowerBlocks {
    size: usize,
    denominators: Vec<Vec<Vec<E>>>,
    inverse_spectrum: Vec<E>,
    advances: Vec<E>,
    dft: Radix2DFTSmallBatch<Goldilocks>,
}

impl PowerBlocks {
    fn new(terms: &[(E, E)], size: usize) -> Self {
        assert!(size.is_power_of_two() && size <= POWER_BLOCK_CAP);
        let dft = Radix2DFTSmallBatch::default();
        let mut leaves: Vec<_> = terms.iter().map(|&(point, _)| vec![E::ONE, -point]).collect();
        leaves.resize(terms.len().next_power_of_two(), vec![E::ONE]);
        let mut denominators = vec![leaves];
        while denominators.last().unwrap().len() > 1 {
            let level = denominators
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let mut product = multiply_polynomials(pair[0].clone(), pair[1].clone(), &dft);
                    product.truncate(size);
                    product
                })
                .collect();
            denominators.push(level);
        }
        let mut inverse = inverse_series(&denominators.last().unwrap()[0], size, &dft);
        inverse.resize(2 * size, E::ZERO);
        Self {
            size,
            denominators,
            inverse_spectrum: dft.dft_algebra(inverse),
            advances: terms.iter().map(|&(point, _)| point.exp_u64(size as u64)).collect(),
            dft,
        }
    }

    fn numerator(&self, amplitudes: &[E]) -> Vec<E> {
        assert_eq!(amplitudes.len(), self.advances.len());
        let mut numerators: Vec<_> = amplitudes.iter().map(|&scale| vec![scale]).collect();
        numerators.resize(self.denominators[0].len(), vec![E::ZERO]);
        for level in &self.denominators[..self.denominators.len() - 1] {
            numerators = numerators
                .chunks_exact(2)
                .zip(level.chunks_exact(2))
                .map(|(pair, factors)| {
                    let mut left =
                        multiply_polynomials(pair[0].clone(), factors[1].clone(), &self.dft);
                    let right =
                        multiply_polynomials(pair[1].clone(), factors[0].clone(), &self.dft);
                    left.resize(left.len().max(right.len()).min(self.size), E::ZERO);
                    for (value, contribution) in left.iter_mut().zip(right) {
                        *value += contribution;
                    }
                    left
                })
                .collect();
        }
        let mut numerator = numerators.pop().unwrap();
        numerator.resize(2 * self.size, E::ZERO);
        numerator
    }

    fn next(&self, amplitudes: &mut [E]) -> Vec<E> {
        let mut spectrum = self.dft.dft_algebra(self.numerator(amplitudes));
        for (value, &factor) in spectrum.iter_mut().zip(&self.inverse_spectrum) {
            *value *= factor;
        }
        let mut values = self.dft.idft_algebra(spectrum);
        values.truncate(self.size);
        for (amplitude, &advance) in amplitudes.iter_mut().zip(&self.advances) {
            *amplitude *= advance;
        }
        values
    }

    // Retained coefficient capacities/descriptors and an upper for both P3
    // twiddle payloads. Not allocator/runtime overhead or transient FFT peak.
    fn named_bytes(&self) -> usize {
        self.denominators.capacity() * size_of::<Vec<Vec<E>>>()
            + self
                .denominators
                .iter()
                .map(|level| {
                    level.capacity() * size_of::<Vec<E>>()
                        + level
                            .iter()
                            .map(|values| values.capacity() * size_of::<E>())
                            .sum::<usize>()
                })
                .sum::<usize>()
            + (self.inverse_spectrum.capacity() + self.advances.capacity()) * size_of::<E>()
            + 16 * (2 * self.size).max(4)
    }
}

fn equality(point: &[E], index: usize) -> E {
    point.iter().enumerate().fold(E::ONE, |v, (bit, &r)| {
        v * if index >> (point.len() - 1 - bit) & 1 == 1 { r } else { E::ONE - r }
    })
}

fn equality_lookup(point: &[E], scale: E) -> impl Fn(usize) -> E {
    let split = point.len() / 2;
    let prefix = Poly::new_from_point(&point[..split], scale);
    let suffix = Poly::new_from_point(&point[split..], E::ONE);
    let suffix_bits = point.len() - split;
    move |index| {
        prefix.as_slice()[index >> suffix_bits]
            * suffix.as_slice()[index & ((1 << suffix_bits) - 1)]
    }
}

pub(super) fn power_lookup<F: p3_field::Field>(point: F, length: usize) -> impl Fn(usize) -> F {
    let bits = length.next_power_of_two().ilog2() as usize;
    let low_bits = bits / 2;
    let low: Vec<_> = point.powers().take(1 << low_bits).collect();
    let high: Vec<_> = point.exp_u64(1 << low_bits).powers().take(1 << (bits - low_bits)).collect();
    move |i| low[i & (low.len() - 1)] * high[i >> low_bits]
}

fn native_packet(dimension:usize,live:usize,remaining:usize,point:&[E])->device::ResidualPacket {
    let mut chunks=Vec::with_capacity(point.len().div_ceil(8));
    let mut tables=Vec::new();
    for (index,part) in point.chunks(8).enumerate() {
        chunks.push(device::ResidualChunk {shift:(point.len()-8*index-part.len()) as u32,
            bits:part.len() as u32,first:tables.len() as u32,reserved:0});
        tables.extend(Poly::new_from_point(part,E::ONE).as_slice().iter().copied().map(device::PcsField::from));
    }
    device::ResidualPacket {shape:device::ResidualShape {live:live as u64,dimension:dimension as u32,
        remaining:remaining as u32,equality:device::ResidualEq {bits:point.len() as u32,
            chunks:chunks.len() as u32,entries:tables.len() as u32,reserved:0}},chunks,tables}
}

pub(super) struct NativeOriginalStage {
    original:NativeOriginal,
    tiles:Mutex<Option<device::Buffer>>,
    released:AtomicBool,
    reads:Arc<AtomicU64>,
}
impl NativeOriginalStage {
    fn owner(&self)->&Arc<Mutex<device::Runtime>> {
        match &self.original {NativeOriginal::Source(source)=>&source.runtime,NativeOriginal::Weights(weights)=>&weights.runtime}
    }
    fn live(&self)->usize {
        match &self.original {NativeOriginal::Source(source)=>source.live,NativeOriginal::Weights(weights)=>weights.weights.len()}
    }
    fn new(original:NativeOriginal,reads:Arc<AtomicU64>)->Result<Arc<Self>,String> {
        let tiles=match &original {NativeOriginal::Source(_)=>None,NativeOriginal::Weights(weights)=>Some(
            weights.runtime.lock().map_err(|_|"native PCS owner poisoned")?
                .pcs_weight_tiles(&weights.weights,weights.layout,&weights.tiles)?) };
        Ok(Arc::new(Self {original,tiles:Mutex::new(tiles),released:AtomicBool::new(false),reads}))
    }
    pub(super) fn release_initial(&self) {self.released.store(true,Ordering::Release);}
    pub(super) fn close(&self)->Result<(),String> {
        let mut tiles=self.tiles.lock().map_err(|_|"native PCS mapping lock poisoned")?;
        if let Some(tiles)=tiles.take() {self.owner().lock().map_err(|_|"native PCS owner poisoned")?.release_buffer(tiles)?;}
        Ok(())
    }
    fn run(&self,packet:&device::ResidualPacket,phase:device::ResidualPhase,cosets:device::ResidualCosets,
        pads:&[device::PcsField],point:E)->Result<device::ResidualResult,String> {
        let result=(|| {
            let token=self.owner().lock().map_err(|_|"native PCS owner poisoned")?.residual_begin(packet,phase,cosets,pads,point)?;
            match &self.original {
                NativeOriginal::Source(source)=>{
                    let mut visited=0u64;
                    (source.scan)(&mut |runtime,input,tile| {
                        runtime.residual_source_tile(&token,input,tile)?;
                        let count=tile.rows.checked_mul(tile.columns).and_then(|count|count.checked_mul(u64::from(tile.width)))
                            .ok_or("native PCS original visit overflow")?;
                        visited=visited.checked_add(count).ok_or("native PCS original visit overflow")?;
                        Ok(())
                    })?;
                    if visited!=self.live() as u64 {return Err("native PCS original scan incomplete".into());}
                }
                NativeOriginal::Weights(weights)=>{
                    let tiles=self.tiles.lock().map_err(|_|"native PCS mapping lock poisoned")?;
                    let mut runtime=self.owner().lock().map_err(|_|"native PCS owner poisoned")?;
                    runtime.require_weights(&weights.weights,weights.layout)?;
                    runtime.residual_weights(&token,tiles.as_ref().ok_or("native PCS mapping retired")?)?;
                }
            }
            let output=self.owner().lock().map_err(|_|"native PCS owner poisoned")?.residual_finish(token)?;
            self.reads.fetch_add(self.live() as u64,Ordering::Relaxed);
            Ok(output)
        })();
        if let Err(error)=&result {if let Ok(mut runtime)=self.owner().lock(){let _=runtime.abort::<()>(error);}}
        result
    }
}

// Views capture a holder and an immutable prefix, never pre-commit buffer IDs.
// This keeps an S2 opening valid both before and after its late promotion.
#[derive(Clone)]
pub(super) enum NativeView {
    Original {stage:Arc<NativeOriginalStage>,dimension:usize,prefix:Vec<E>},
    Retained {stage:Arc<Retained>,prefix:Vec<E>},
}
impl NativeView {
    pub(super) fn owner(&self)->Arc<Mutex<device::Runtime>> {
        match self {Self::Original {stage,..}=>stage.owner().clone(),
            Self::Retained {stage,..}=>stage.owner.as_ref().expect("native retained owner").clone()}
    }
    pub(super) fn run(&self,phase:device::ResidualPhase,cosets:device::ResidualCosets,
        pads:&[device::PcsField],point:E)->Result<device::ResidualResult,String> {
        let result=(|| match self {
            Self::Original {stage,dimension,prefix}=>stage.run(&native_packet(*dimension,stage.live(),dimension-prefix.len(),prefix),phase,cosets,pads,point),
            Self::Retained {stage,prefix}=>{
                let data=stage.data.read().map_err(|_|"retained lock poisoned")?;
                if prefix.len()>data.variables || !prefix.starts_with(&data.applied) {return Err("native retained view prefix differs".into());}
                match &data.values {
                    Some(RetainedValues::Native(planes))=>{
                        let suffix=&prefix[data.applied.len()..];
                        if suffix.len()>2 {return Err("native retained virtual prefix exceeds two folds".into());}
                        let dimension=data.variables-data.applied.len();
                        let packet=native_packet(dimension,planes.count(),data.variables-prefix.len(),suffix);
                        let mut runtime=stage.owner.as_ref().ok_or("native retained owner missing")?.lock().map_err(|_|"native PCS owner poisoned")?;
                        let token=runtime.residual_begin(&packet,phase,cosets,pads,point)?;
                        runtime.residual_resident(&token,planes)?;
                        let result=runtime.residual_finish(token)?;
                        stage.reads.fetch_add(planes.count() as u64,Ordering::Relaxed);Ok(result)
                    }
                    None=>{
                        let (original,original_prefix)=data.native_original.as_ref().ok_or("native retained source unavailable")?;
                        let mut full=original_prefix.clone();full.extend_from_slice(prefix);
                        let dimension=data.variables+original_prefix.len();
                        original.run(&native_packet(dimension,original.live(),data.variables-prefix.len(),&full),phase,cosets,pads,point)
                    }
                    _=>Err("native PCS view reached host retained values".into()),
                }
            }
        })();
        if let Err(error)=&result {if let Ok(mut runtime)=self.owner().lock(){let _=runtime.abort::<()>(error);}}
        result
    }
    pub(super) fn contract(&self,kind:u32,length:usize,size:usize,
        mut band:impl FnMut(usize)->Result<(Vec<device::PcsField>,Vec<device::PcsField>),String>)->Result<[E;2],String> {
        let result=(|| match self {
            Self::Original {stage,dimension,prefix}=>{
                let NativeOriginal::Weights(weights)=&stage.original else {return Err("native A must be retained before contraction".into());};
                let packet=native_packet(*dimension,stage.live(),dimension-prefix.len(),prefix);
                let tiles=stage.tiles.lock().map_err(|_|"native PCS mapping lock poisoned")?;
                let mut runtime=stage.owner().lock().map_err(|_|"native PCS owner poisoned")?;
                runtime.require_weights(&weights.weights,weights.layout)?;
                let token=runtime.residual_contract_begin(&packet,kind,size)?;
                for start in (0..length).step_by(size) {
                    let (left,right)=band(start)?;
                    if left.len()!=(length-start).min(size) {return runtime.abort("native PCS public band length differs");}
                    runtime.residual_contract_weights(&token,tiles.as_ref().ok_or("native PCS mapping retired")?,start,&left,&right)?;
                }
                let result=runtime.residual_contract_finish(token)?;
                stage.reads.fetch_add(stage.live() as u64,Ordering::Relaxed);Ok(result)
            }
            Self::Retained {stage,prefix}=>{
                let data=stage.data.read().map_err(|_|"retained lock poisoned")?;
                if prefix.len()>data.variables || !prefix.starts_with(&data.applied) {return Err("native retained contraction prefix differs".into());}
                let Some(RetainedValues::Native(planes))=&data.values else {return Err("native retained contraction unavailable".into());};
                let suffix=&prefix[data.applied.len()..];
                if suffix.len()>2 {return Err("native retained contraction exceeds two folds".into());}
                let dimension=data.variables-data.applied.len();
                let packet=native_packet(dimension,planes.count(),data.variables-prefix.len(),suffix);
                let mut runtime=stage.owner.as_ref().ok_or("native retained owner missing")?.lock().map_err(|_|"native PCS owner poisoned")?;
                let token=runtime.residual_contract_begin(&packet,kind,size)?;
                for start in (0..length).step_by(size) {
                    let (left,right)=band(start)?;
                    if left.len()!=(length-start).min(size) {return runtime.abort("native PCS public band length differs");}
                    runtime.residual_contract_resident(&token,planes,start,&left,&right)?;
                }
                let result=runtime.residual_contract_finish(token)?;
                stage.reads.fetch_add(planes.count() as u64,Ordering::Relaxed);Ok(result)
            }
        })();
        if let Err(error)=&result {if let Ok(mut runtime)=self.owner().lock(){let _=runtime.abort::<()>(error);}}
        result
    }
    fn final_values(&self)->Result<Vec<E>,String> {
        // A bounded temporary preserves the committed predecessor planes for
        // final openings. The terminal read consumes only this temporary.
        let device::ResidualResult::Planes(temporary)=self.run(device::ResidualPhase::Retention,device::ResidualCosets::default(),&[],E::ZERO)?
            else {return Err("native PCS final temporary differs".into());};
        self.owner().lock().map_err(|_|"native PCS owner poisoned")?.residual_final_read(temporary)
    }
}

pub(super) enum NativeQueryInput<'a> {Weights(&'a device::Buffer),Planes(&'a device::ResidualPlanes)}
impl NativeView {
    // Resolve after materialization/promotion, then hold the generation while
    // the consumer completes one column; the numerical producer is not called.
    pub(super) fn with_query<R>(&self,consume:impl FnOnce(&mut device::Runtime,&device::ResidualPacket,
        NativeQueryInput<'_>)->Result<R,String>)->Result<R,String> {
        let result=(||match self {
            Self::Original {stage,dimension,prefix}=>{
                let NativeOriginal::Weights(weights)=&stage.original else {return Err("native E query A must be retained first".into());};
                let packet=native_packet(*dimension,stage.live(),dimension-prefix.len(),prefix);
                let tiles=stage.tiles.lock().map_err(|_|"native PCS mapping lock poisoned")?;
                let mut runtime=stage.owner().lock().map_err(|_|"native PCS owner poisoned")?;
                runtime.require_weights(&weights.weights,weights.layout)?;
                consume(&mut runtime,&packet,NativeQueryInput::Weights(tiles.as_ref().ok_or("native PCS mapping retired")?))
            }
            Self::Retained {stage,prefix}=>{
                let data=stage.data.read().map_err(|_|"retained lock poisoned")?;
                if prefix.len()>data.variables || !prefix.starts_with(&data.applied) {return Err("native E query retained prefix differs".into());}
                let suffix=&prefix[data.applied.len()..];
                if suffix.len()>2 {return Err("native E query virtual prefix exceeds two folds".into());}
                let Some(RetainedValues::Native(planes))=&data.values else {return Err("native E query before retained materialization".into());};
                let packet=native_packet(data.variables-data.applied.len(),planes.count(),data.variables-prefix.len(),suffix);
                let mut runtime=stage.owner.as_ref().ok_or("native retained owner missing")?.lock().map_err(|_|"native PCS owner poisoned")?;
                consume(&mut runtime,&packet,NativeQueryInput::Planes(planes))
            }
        })();
        if let Err(error)=&result {if let Ok(mut runtime)=self.owner().lock(){let _=runtime.abort::<()>(error);}}
        result
    }
}

enum RetainedValues {Host(Vec<E>),Native(device::ResidualPlanes)}

// One retained generation. Only a consumed replay handle permits folding
// and shrinking its capacity; committed predecessors remain immutable.
struct RetainedData {
    fallback: Option<Getter>,
    values: Option<RetainedValues>,
    native_original:Option<(Arc<NativeOriginalStage>,Vec<E>)>,
    variables: usize,
    applied: Vec<E>,
    current: u8, // 0 unregistered, 1 live, 2 released
    successor: Option<(Vec<E>, u8)>,
    fold_interpolations: u64,
}
pub(super) struct Retained {
    owner:Option<Arc<Mutex<device::Runtime>>>,
    data: RwLock<RetainedData>,
    reads: Arc<AtomicU64>,
}
pub(super) struct Lease {
    stage: Arc<Retained>,
    prefix: Vec<E>,
}
impl Lease {
    pub(super) fn release(self) -> Result<(), String> {
        let mut data = self.stage.data.write().map_err(|_| "retained lock poisoned")?;
        let state = if self.prefix == data.applied {
            &mut data.current
        } else {
            let (prefix, state) = data.successor.as_mut().ok_or("unknown successor release")?;
            if *prefix != self.prefix {
                return Err("different successor release".into());
            }
            state
        };
        if *state != 1 {
            return Err("duplicate or unregistered retained release".into());
        }
        *state = 2;
        Ok(())
    }
}
impl Retained {
    fn getter(self: &Arc<Self>, prefix: Vec<E>) -> Getter {
        let stage = self.clone();
        Arc::new(move |i| {
            let data = stage.data.read().expect("retained lock poisoned");
            assert!(
                prefix.len() <= data.variables && prefix.starts_with(&data.applied),
                "stale, overlong or different retained getter"
            );
            let suffix = &prefix[data.applied.len()..];
            let variables = data.variables - prefix.len();
            assert!(i < 1 << variables);
            match &data.values {
                Some(RetainedValues::Host(values)) => {
                    stage.reads.fetch_add(1 << suffix.len(), Ordering::Relaxed);
                    (0..1 << suffix.len())
                        .map(|j| equality(suffix, j) * values[(j << variables) | i])
                        .sum()
                }
                Some(RetainedValues::Native(_))=>panic!("native retained getter fallback forbidden"),
                None => {
                    let fallback = data.fallback.as_ref().expect("retained source unavailable");
                    (0..1 << suffix.len())
                        .map(|j| equality(suffix, j) * fallback((j << variables) | i))
                        .sum()
                }
            }
        })
    }
    fn lease(self: &Arc<Self>, prefix: &[E]) -> Result<Lease, String> {
        let mut data = self.data.write().map_err(|_| "retained lock poisoned")?;
        if prefix.len() > data.variables {
            return Err("overlong retained prefix".into());
        }
        if prefix == data.applied {
            if data.current != 0 {
                return Err("retained root registered twice".into());
            }
            data.current = 1;
        } else {
            if !prefix.starts_with(&data.applied) || data.successor.is_some() {
                return Err("retained successor differs or registered twice".into());
            }
            data.successor = Some((prefix.to_vec(), 1));
        }
        Ok(Lease { stage: self.clone(), prefix: prefix.to_vec() })
    }
    pub(super) fn close_native(&self)->Result<(),String> {
        let Some(owner)=&self.owner else {return Ok(());};
        let mut data=self.data.write().map_err(|_|"retained lock poisoned")?;
        if data.current!=2 || data.successor.is_some() {return Err("native retained final lease still live".into());}
        if let Some(RetainedValues::Native(planes))=&data.values {
            owner.lock().map_err(|_|"native PCS owner poisoned")?.residual_retire_planes(planes)?;
        } else {return Err("native retained final planes unavailable".into());}
        data.values=None;
        Ok(())
    }
    fn promote(&self, prefix: &[E]) -> Result<usize, String> {
        let mut data = self.data.write().map_err(|_| "retained lock poisoned")?;
        if prefix.len() > data.variables || prefix == data.applied {
            return Err("overlong or non-advancing retained promotion".into());
        }
        if data.current != 2
            || data
                .successor
                .as_ref()
                .map(|(expected, state)| expected.as_slice() == prefix && *state == 1)
                != Some(true)
            || !prefix.starts_with(&data.applied)
        {
            return Err("retained predecessor not released or successor not fixed".into());
        }
        let done = data.applied.len();
        let suffix=&prefix[done..];
        let mut interpolations = 0;
        let capacity_bytes=match data.values.as_mut().ok_or("retained values not materialized")? {
            RetainedValues::Host(values)=>{
                for &r in suffix {
                    let half = values.len() / 2;
                    for i in 0..half {
                        let a = values[i];
                        values[i] = a + r * (values[i + half] - a);
                    }
                    values.truncate(half);
                    interpolations += half as u64;
                }
                values.shrink_to_fit();
                values.capacity()*size_of::<E>()
            }
            RetainedValues::Native(planes)=>{
                if suffix.len()>2 {return Err("native retained promotion exceeds two folds".into());}
                let mut runtime=self.owner.as_ref().ok_or("native retained owner missing")?
                    .lock().map_err(|_|"native PCS owner poisoned")?;
                let next=runtime.residual_fold(planes,suffix)?;
                // Keep both generations charged until retiring the predecessor
                // succeeds; the holder changes only after that terminal check.
                runtime.residual_retire_planes(planes)?;
                let capacity=next.count()*size_of::<E>();
                interpolations=(1..=suffix.len()).map(|n|(planes.count()>>n) as u64).sum();
                *planes=next;
                capacity
            }
        };
        data.fold_interpolations += interpolations;
        data.applied = prefix.to_vec();
        data.current = 1;
        data.successor = None;
        Ok(capacity_bytes)
    }
}

/// Root-owned immutable original getter; folds are transcript-fixed descriptors.
pub(super) struct State {
    source: Getter,
    scan: Option<BaseScan>,
    native:Option<Arc<NativeOriginalStage>>,
    dimension: usize,
    prefix: Vec<E>,
    eq_point: Vec<E>,
    eq_scale: E,
    powers: Vec<(E, E)>,
    power_blocks: OnceLock<PowerBlocks>,
    power_rounds_remaining: usize,
    prefix_acc: Vec<E>,
    prefix_remaining: usize,
    sum: E,
    retain_first: bool,
    retained_bytes: usize,
    pending_retention: Option<(Getter, Vec<E>, usize)>,
    retained: Option<Arc<Retained>>,
    retained_reads: Arc<AtomicU64>,
    pub(super) source_reads: Arc<AtomicU64>,
}

impl State {
    pub(super) fn new(
        source: Getter,
        scan: Option<(BaseScan, usize)>,
        point: &[E],
        first_fold: usize,
        target: E,
        retain_first: bool,
    ) -> Result<Self, String> {
        Self::new_with_native(source,scan,point,first_fold,target,retain_first,None)
    }
    pub(super) fn new_native(original:NativeOriginal,point:&[E],first_fold:usize,target:E,retain_first:bool)->Result<Self,String> {
        Self::new_with_native(Arc::new(|_|panic!("native source getter fallback forbidden")),None,point,first_fold,target,retain_first,Some(original))
    }
    fn new_with_native(source:Getter,scan:Option<(BaseScan,usize)>,point:&[E],first_fold:usize,target:E,
        retain_first:bool,native:Option<NativeOriginal>)->Result<Self,String> {
        geometry(point.len(), first_fold)?;
        if matches!(&native,Some(NativeOriginal::Source(_))) && !retain_first {
            return Err("native A residual requires first-stage retention".into());
        }
        if native.is_some() && first_fold>7 {return Err("native PCS first fold exceeds seven".into());}
        if scan.as_ref().is_some_and(|(_, live)| *live > 1 << point.len()) {
            return Err("sourcewise scan live prefix exceeds domain".into());
        }
        let source_reads = Arc::new(AtomicU64::new(0));
        let reads = source_reads.clone();
        let source: Getter = Arc::new(move |i| {
            reads.fetch_add(1, Ordering::Relaxed);
            source(i)
        });
        // The trusted original scanner owns uniqueness/immutability. Check its
        // domain, count and error on every pass without a dense bitset of A.
        let scan = scan.map(|(scan, live)| {
            let reads = source_reads.clone();
            Arc::new(move |emit: &mut dyn FnMut(usize, Goldilocks) -> Result<(), String>| {
                let mut count = 0;
                scan(&mut |index, value| {
                    if index >= live || count == live {
                        return Err("sourcewise scan outside live prefix or excess emission".into());
                    }
                    count += 1;
                    reads.fetch_add(1, Ordering::Relaxed);
                    emit(index, value)
                })?;
                if count != live {
                    return Err("sourcewise scan omitted original coefficients".into());
                }
                Ok(())
            }) as BaseScan
        });
        let native=native.map(|original|NativeOriginalStage::new(original,source_reads.clone())).transpose()?;
        let mut state = Self {
            native,source,
            scan,
            dimension: point.len(),
            prefix: Vec::new(),
            eq_point: point.to_vec(),
            eq_scale: E::ONE,
            powers: Vec::new(),
            power_blocks: OnceLock::new(),
            power_rounds_remaining: 0,
            prefix_acc: Vec::new(),
            prefix_remaining: first_fold,
            sum: target,
            source_reads,
            retain_first,
            retained_bytes: 0,
            pending_retention: None,
            retained: None,
            retained_reads: Arc::new(AtomicU64::new(0)),
        };
        let mut prefix_acc = vec![E::ZERO; 1 << first_fold];
        let suffix = point.len() - first_fold;
        let suffix_equality = equality_lookup(&point[first_fold..], E::ONE);
        if let Some(native)=&state.native {
            if native.live()>1usize<<point.len() {return Err("native PCS original live prefix exceeds domain".into());}
            let packet=native_packet(point.len(),native.live(),suffix,&point[first_fold..]);
            let device::ResidualResult::Reduced(values)=native.run(&packet,device::ResidualPhase::Singleton,
                device::ResidualCosets::default(),&[],E::ZERO)? else {return Err("native PCS singleton publication differs".into());};
            if values.len()!=prefix_acc.len() {return Err("native PCS singleton width differs".into());}
            prefix_acc=values;
        } else {
            state.visit(&mut |i,value| {prefix_acc[i>>suffix]+=value*suffix_equality(i&((1<<suffix)-1));Ok(())})?;
        }
        let prefix_equality = equality_lookup(&point[..first_fold], E::ONE);
        let sum: E = prefix_acc
            .iter()
            .enumerate()
            .map(|(index, &value)| value * prefix_equality(index))
            .sum();
        if sum != target {
            if let Some(native)=&state.native {let _=native.owner().lock().map_err(|_|"native PCS owner poisoned")?.abort::<()>("sourcewise original claim differs");}
            return Err("sourcewise original claim differs".into());
        }
        state.prefix_acc = prefix_acc;
        Ok(state)
    }

    /// Scatter a linear functional of the current fold. Before retention the
    /// same folded index has one contribution per original prefix; it is NOT
    /// a stream of distinct folded values. Each call is one separate FS phase.
    pub(super) fn visit(
        &self,
        emit: &mut dyn FnMut(usize, E) -> Result<(), String>,
    ) -> Result<(), String> {
        if self.native_view().is_some() {return Err("native private values cannot be emitted to a host visitor".into());}
        if self.retained.is_some() && self.pending_retention.is_none() {
            let get = self.getter();
            for i in 0..1 << self.num_variables() {
                emit(i, get(i))?;
            }
            return Ok(());
        }
        let (source, prefix, n) = match &self.pending_retention {
            Some((source, prefix, n)) => (source, prefix, *n),
            None => (&self.source, &self.prefix, self.num_variables()),
        };
        let equality = equality_lookup(prefix, E::ONE);
        let mut original = |i, value| emit(i & ((1 << n) - 1), value * equality(i >> n));
        if let Some(scan) = &self.scan {
            scan(&mut |i, value| original(i, E::from(value)))
        } else {
            for i in 0..1 << (n + prefix.len()) {
                original(i, source(i))?;
            }
            Ok(())
        }
    }

    pub(super) fn padded_ood(&self, point: E, suffix: &[E]) -> Result<E, String> {
        let length = 1 << self.num_variables();
        if let Some(view)=self.native_view() {
            let device::ResidualResult::Reduced(value)=view.run(device::ResidualPhase::Ood,device::ResidualCosets::default(),&[],point)?
                else {return Err("native PCS OOD publication differs".into());};
            if value.len()!=1 {return Err("native PCS OOD width differs".into());}
            return Ok(value[0]+suffix.iter().rev().fold(E::ZERO,|value,&x|value*point+x)*point.exp_u64(length as u64));
        }
        let power = power_lookup(point, length);
        let mut value =
            suffix.iter().rev().fold(E::ZERO, |v, &x| v * point + x) * point.exp_u64(length as u64);
        self.visit(&mut |index, contribution| {
            value += contribution * power(index);
            Ok(())
        })?;
        Ok(value)
    }

    pub(super) fn native_view(&self)->Option<NativeView> {
        if let Some(stage)=&self.retained {
            if stage.owner.is_some() {return Some(NativeView::Retained {stage:stage.clone(),prefix:self.prefix.clone()});}
        }
        self.native.as_ref().map(|stage|NativeView::Original {stage:stage.clone(),dimension:self.dimension,prefix:self.prefix.clone()})
    }
    pub(super) fn native_original_stage(&self)->Option<Arc<NativeOriginalStage>> {self.native.clone()}
    pub(super) fn native_retained_stage(&self)->Option<Arc<Retained>> {self.retained.as_ref().filter(|stage|stage.owner.is_some()).cloned()}
    pub(super) fn getter(&self) -> Getter {
        if self.native_view().is_some() {return Arc::new(|_|panic!("native private getter fallback forbidden"));}
        if let Some(stage) = &self.retained {
            return stage.getter(self.prefix.clone());
        }
        let (source, prefix, n) = (self.source.clone(), self.prefix.clone(), self.num_variables());
        let prefix_equality = equality_lookup(&prefix, E::ONE);
        Arc::new(move |i| {
            assert!(i < 1 << n);
            (0..1 << prefix.len())
                .map(|index| prefix_equality(index) * source((index << n) | i))
                .sum()
        })
    }

    // Register only after Tree::commit succeeds: errors cannot leave a live lease.
    pub(super) fn replay_lease(&self) -> Result<Option<Lease>, String> {
        self.retained.as_ref().map(|stage| stage.lease(&self.prefix)).transpose()
    }

    fn weight(&self, index: usize) -> E {
        self.eq_scale * equality(&self.eq_point, index)
            + self
                .powers
                .iter()
                .map(|&(point, scale)| scale * point.exp_u64(index as u64))
                .sum::<E>()
    }

    pub(super) fn add_powers(&mut self, terms: &[(E, E)]) -> Result<(), String> {
        if self.prefix_remaining != 0 {
            return Err("power claims before first fold boundary".into());
        }
        if self.native_view().is_some() {return self.add_native_powers(terms);}
        // Called only after the predecessor's opening/release in WHIR.
        // The already-committed S1 oracle shares this immutable-value slot.
        if self.pending_retention.is_some() {
            let mut values = vec![E::ZERO; 1 << self.num_variables()];
            self.visit(&mut |i, value| {
                values[i] += value;
                Ok(())
            })?;
            let stage = self.retained.as_ref().ok_or("retained holder missing")?;
            let mut data = stage.data.write().map_err(|_| "retained lock poisoned")?;
            if data.values.is_some() {
                return Err("S1 retained twice".into());
            }
            self.retained_bytes = values.capacity() * std::mem::size_of::<E>();
            data.values = Some(RetainedValues::Host(values));
            data.fallback = None; // original A/cuts no longer captured by this stage
            self.pending_retention = None;
            self.scan = None;
        } else if let Some(stage) = &self.retained {
            self.retained_bytes = stage.promote(&self.prefix)?;
        }
        // Never overlap an old Q/inverse/DFT owner with the new claim's setup.
        self.power_blocks.take();
        let get = self.getter();
        let length = 1 << self.num_variables();
        let size = POWER_BLOCK_CAP.min(length);
        let powers = PowerBlocks::new(terms, size);
        let mut amplitudes: Vec<_> = terms.iter().map(|&(_, scale)| scale).collect();
        for start in (0..length).step_by(size) {
            for (offset, delta) in powers.next(&mut amplitudes).into_iter().enumerate() {
                self.sum += get(start + offset) * delta;
            }
        }
        self.powers.extend_from_slice(terms);
        self.power_rounds_remaining = 2.min(self.num_variables());
        Ok(())
    }

    fn add_native_powers(&mut self,terms:&[(E,E)])->Result<(),String> {
        if self.pending_retention.is_some() {
            let stage=self.retained.as_ref().ok_or("native retained holder missing")?;
            {
                let data=stage.data.read().map_err(|_|"retained lock poisoned")?;
                let (original,_)=data.native_original.as_ref().ok_or("native retained original missing")?;
                if data.values.is_some() || data.current!=1 || !original.released.load(Ordering::Acquire) {
                    return Err("native S1 retention before predecessor release or duplicate".into());
                }
            }
            let device::ResidualResult::Planes(planes)=self.native_view().ok_or("native retained view missing")?
                .run(device::ResidualPhase::Retention,device::ResidualCosets::default(),&[],E::ZERO)?
                else {return Err("native S1 retention publication differs".into());};
            let mut data=stage.data.write().map_err(|_|"retained lock poisoned")?;
            if data.values.is_some() {return Err("native S1 retained twice".into());}
            self.retained_bytes=planes.count()*size_of::<E>();
            data.values=Some(RetainedValues::Native(planes));
            data.native_original=None;
            data.fallback=None;
            self.pending_retention=None;
            self.scan=None;
        } else if let Some(stage)=&self.retained {
            self.retained_bytes=stage.promote(&self.prefix)?;
        }
        self.power_blocks.take();
        let length=1<<self.num_variables();
        let size=POWER_BLOCK_CAP.min(length);
        let powers=PowerBlocks::new(terms,size);
        let mut amplitudes:Vec<_>=terms.iter().map(|&(_,scale)|scale).collect();
        let delta=self.native_view().ok_or("native PCS contraction view missing")?.contract(0,length,size,|_| {
            Ok((powers.next(&mut amplitudes).into_iter().map(device::PcsField::from).collect(),Vec::new()))
        })?;
        self.sum+=delta[0];
        self.powers.extend_from_slice(terms);
        self.power_rounds_remaining=2.min(self.num_variables());
        Ok(())
    }

    pub(super) fn named_bytes(&self) -> usize {
        self.retained_bytes
            + 24 * (self.prefix.capacity() + self.eq_point.capacity() + self.prefix_acc.capacity())
            + 48 * self.powers.capacity()
            + self.power_blocks.get().map_or(0, PowerBlocks::named_bytes)
    }
}

impl ResidualSumcheckProver<Goldilocks, E> for State {
    type Error = String;
    fn claimed_sum(&self) -> E {
        self.sum
    }
    fn num_variables(&self) -> usize {
        self.dimension - self.prefix.len()
    }
    fn evals(&self) -> Result<Poly<E>, String> {
        if self.num_variables() > 6 {
            return Err("dense source evals fallback forbidden".into());
        }
        if let Some(view)=self.native_view() {return Ok(Poly::new(view.final_values()?));}
        let get = self.getter();
        Ok(Poly::new((0..1 << self.num_variables()).map(|i| get(i)).collect()))
    }
    fn weights(&self) -> Result<Poly<E>, String> {
        if self.num_variables() > 6 {
            return Err("dense source weights fallback forbidden".into());
        }
        Ok(Poly::new((0..1 << self.num_variables()).map(|i| self.weight(i)).collect()))
    }
    fn eval(&self, point: &Point<E>) -> Result<E, String> {
        if point.num_variables() != self.num_variables() {
            return Err("sourcewise MLE point".into());
        }
        let equality = equality_lookup(point.as_slice(), E::ONE);
        if let Some(view)=self.native_view() {
            let length=1<<self.num_variables();let size=POWER_BLOCK_CAP.min(length);
            return Ok(view.contract(0,length,size,|start|Ok(((start..start+(length-start).min(size))
                .map(|index|device::PcsField::from(equality(index))).collect(),Vec::new())))?[0]);
        }
        let mut value = E::ZERO;
        self.visit(&mut |index, contribution| {
            value += contribution * equality(index);
            Ok(())
        })?;
        Ok(value)
    }
    fn round_coefficients(&self) -> Result<(E, E), String> {
        if self.num_variables() == 0 {
            return Err("sourcewise exhausted".into());
        }
        let (mut c0, mut c2) = (E::ZERO, E::ZERO);
        if self.prefix_remaining > 0 {
            let half = self.prefix_acc.len() / 2;
            let equality = equality_lookup(&self.eq_point[..self.prefix_remaining], self.eq_scale);
            for i in 0..half {
                let (a, b) = (self.prefix_acc[i], self.prefix_acc[i + half]);
                let x = equality(i);
                let y = equality(i + half);
                c0 += a * x;
                c2 += (b - a) * (y - x);
            }
        } else if let Some(view)=self.native_view() {
            let half=1<<(self.num_variables()-1);
            let equality=equality_lookup(&self.eq_point,self.eq_scale);
            let size=POWER_BLOCK_CAP.min(half);
            let powers=self.power_blocks.get_or_init(||PowerBlocks::new(&self.powers,size));
            let mut low:Vec<_>=self.powers.iter().map(|&(_,scale)|scale).collect();
            let mut high:Vec<_>=self.powers.iter().map(|&(point,scale)|scale*point.exp_u64(half as u64)).collect();
            let result=view.contract(1,half,size,|start| {
                let left=powers.next(&mut low);let right=powers.next(&mut high);
                let count=(half-start).min(size);
                let left=left.into_iter().take(count).enumerate()
                    .map(|(offset,value)|device::PcsField::from(equality(start+offset)+value)).collect();
                let right=right.into_iter().take(count).enumerate()
                    .map(|(offset,value)|device::PcsField::from(equality(start+offset+half)+value)).collect();
                Ok((left,right))
            })?;
            return Ok((result[0],result[1]));
        } else {
            let get = self.getter();
            let half = 1 << (self.num_variables() - 1);
            let equality = equality_lookup(&self.eq_point, self.eq_scale);
            let size = POWER_BLOCK_CAP.min(half);
            // Prefix folds/scaling change amplitudes, never the bases of Q.
            // For a smaller final block the cached inverse remains valid;
            // only its required prefix is consumed (there is just one block).
            let powers = self.power_blocks.get_or_init(|| PowerBlocks::new(&self.powers, size));
            debug_assert!(size <= powers.size);
            let mut low: Vec<_> = self.powers.iter().map(|&(_, scale)| scale).collect();
            let mut high: Vec<_> = self
                .powers
                .iter()
                .map(|&(point, scale)| scale * point.exp_u64(half as u64))
                .collect();
            for start in (0..half).step_by(size) {
                let left_powers = powers.next(&mut low);
                let right_powers = powers.next(&mut high);
                for offset in 0..size {
                    let index = start + offset;
                    let (left, right) = (get(index), get(index + half));
                    let left_weight = equality(index) + left_powers[offset];
                    let right_weight = equality(index + half) + right_powers[offset];
                    c0 += left * left_weight;
                    c2 += (right - left) * (right_weight - left_weight);
                }
            }
        }
        Ok((c0, c2))
    }
    fn fold_round_with_coefficients(&mut self, c0: E, c2: E, r: E) -> Result<(), String> {
        if self.num_variables() == 0 {
            return Err("sourcewise exhausted".into());
        }
        if self.pending_retention.is_some() {
            return Err("S1 must be retained before the next fold".into());
        }
        let half = 1 << (self.num_variables() - 1);
        self.sum = c0 * (E::ONE - r) + (self.sum - c0) * r + c2 * r * (r - E::ONE);
        let a = self.eq_point.remove(0);
        self.eq_scale *= (E::ONE - a) * (E::ONE - r) + a * r;
        for (point, scale) in &mut self.powers {
            *scale *= E::ONE - r + r * point.exp_u64(half as u64);
        }
        if self.prefix_remaining > 0 {
            let half = self.prefix_acc.len() / 2;
            for i in 0..half {
                let a = self.prefix_acc[i];
                let b = self.prefix_acc[i + half];
                self.prefix_acc[i] = a + r * (b - a);
            }
            self.prefix_acc.truncate(half);
            self.prefix_remaining -= 1;
            if self.prefix_remaining == 0 {
                self.prefix_acc = Vec::new();
            }
        }
        self.prefix.push(r);
        if self.power_rounds_remaining > 0 {
            self.power_rounds_remaining -= 1;
            if self.power_rounds_remaining == 0 {
                self.power_blocks.take();
            }
        }
        if self.retain_first && self.prefix_remaining == 0 {
            // Bind S1 now, but allocate only after the original A opening.
            // The frozen getter is shared with the S1 root, so subsequent
            // queries see identical values from the one retained allocation.
            let get = self.getter();
            let n = self.num_variables();
            let original_source = self.source.clone();
            let original_prefix = self.prefix.clone();
            let fallback=if self.native.is_some(){None}else{Some(get)};
            self.retained = Some(Arc::new(Retained {
                owner:self.native.as_ref().map(|stage|stage.owner().clone()),
                data: RwLock::new(RetainedData {
                    native_original:self.native.take().map(|stage|(stage,original_prefix.clone())),
                    fallback,values: None,
                    variables: n,
                    applied: Vec::new(),
                    current: 0,
                    successor: None,
                    fold_interpolations: 0,
                }),
                reads: self.retained_reads.clone(),
            }));
            self.source = Arc::new(|_| panic!("original source replaced by retained stage"));
            self.pending_retention = Some((original_source, original_prefix, n));
            self.dimension = n;
            self.prefix.clear();
            self.retain_first = false;
        }
        Ok(())
    }
    fn scale_weights_and_claim(&mut self, scale: E) -> Result<(), String> {
        self.eq_scale *= scale;
        self.sum *= scale;
        for (_, s) in &mut self.powers {
            *s *= scale;
        }
        Ok(())
    }
    fn accumulate_claim(&mut self, _: &[E], _: E) -> Result<(), String> {
        Err("dense source weight delta fallback forbidden".into())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use p3_sumcheck_c61::{
        product_polynomial::ProductPolynomial,
        strategy::{SumcheckProver, VariableOrder},
    };

    #[test]
    fn c71_b12_sourcewise_geometry_and_power_cache_lifetime() {
        assert_eq!(POWER_BLOCK_CAP, 1 << 21);
        for dimension in 1..=35 {
            geometry(dimension, 7.min(dimension)).unwrap();
        }
        for (dimension, first) in [(0, 1), (36, 7), (17, 8), (10, 11), (34, 0)] {
            assert!(geometry(dimension, first).is_err());
        }
        // No canonical source or allocation is executed by the shape checks.
        let source: Getter = Arc::new(|i| E::from(Goldilocks::new((i * 13 + 7) as u64)));
        let point = vec![E::from(Goldilocks::new(19)); 12];
        let target = Poly::new((0..4096).map(|i| source(i)).collect::<Vec<_>>())
            .eval_ext::<Goldilocks>(&Point::new(point.clone()));
        let mut state = State::new(source, None, &point, 7, target, false).unwrap();
        for _ in 0..7 {
            let (c0, c2) = state.round_coefficients().unwrap();
            state.fold_round_with_coefficients(c0, c2, E::from(Goldilocks::new(23))).unwrap();
        }
        state
            .add_powers(&[
                (E::ZERO, E::ONE),
                (E::ONE, E::ONE),
                (E::from(Goldilocks::new(29)), E::ONE),
            ])
            .unwrap();
        assert!(state.power_blocks.get().is_none());
        let before = state.named_bytes();
        let (c0, c2) = state.round_coefficients().unwrap();
        let cached = state.power_blocks.get().unwrap();
        let address = cached.inverse_spectrum.as_ptr();
        let size = cached.size;
        assert_eq!(state.named_bytes(), before + cached.named_bytes());
        state.fold_round_with_coefficients(c0, c2, E::from(Goldilocks::new(31))).unwrap();
        state.scale_weights_and_claim(E::from(Goldilocks::new(37))).unwrap();
        assert_eq!(state.power_blocks.get().unwrap().inverse_spectrum.as_ptr(), address);
        assert_eq!(state.power_blocks.get().unwrap().size, size);
        let get = state.getter();
        let values = (0..1 << state.num_variables()).map(|i| get(i)).collect();
        let weights = (0..1 << state.num_variables()).map(|i| state.weight(i)).collect();
        let dense: SumcheckProver<Goldilocks, E> = SumcheckProver::new(
            ProductPolynomial::new_unpacked(
                VariableOrder::Prefix,
                Poly::new(values),
                Poly::new(weights),
            ),
            state.sum,
        );
        let (c0, c2) = state.round_coefficients().unwrap();
        assert_eq!((c0, c2), ResidualSumcheckProver::round_coefficients(&dense).unwrap());
        assert_eq!(state.power_blocks.get().unwrap().inverse_spectrum.as_ptr(), address);
        state.fold_round_with_coefficients(c0, c2, E::ONE).unwrap();
        assert!(state.power_blocks.get().is_none());
        state.add_powers(&[(E::from(Goldilocks::new(41)), E::ONE)]).unwrap();
        let _ = state.round_coefficients().unwrap();
        assert_eq!(state.power_blocks.get().unwrap().advances.len(), 4);
    }

    #[test]
    fn c71_b12_scattered_residual_reductions_and_failed_retention() {
        use std::sync::atomic::AtomicBool;
        for live in [0, 1, 127, 255, 256] {
            let source = |i: usize| Goldilocks::new((i * 37 + 11) as u64);
            let values: Vec<_> =
                (0..256).map(|i| if i < live { E::from(source(i)) } else { E::ZERO }).collect();
            let point: Vec<_> = (0..8)
                .map(|i| match i % 3 {
                    0 => E::ZERO,
                    1 => E::ONE,
                    _ => E::new([Goldilocks::new(i + 3), Goldilocks::new(5), Goldilocks::new(7)]),
                })
                .collect();
            let weights: Vec<_> = (0..256).map(|i| equality(&point, i)).collect();
            let target = values.iter().zip(&weights).map(|(&x, &y)| x * y).sum();
            let fail = Arc::new(AtomicBool::new(false));
            let scans = Arc::new(AtomicU64::new(0));
            let (f, s) = (fail.clone(), scans.clone());
            let scan: BaseScan = Arc::new(move |emit| {
                s.fetch_add(1, Ordering::Relaxed);
                for k in 0..256 {
                    let i = k * 73 % 256;
                    if i < live {
                        emit(i, source(i))?;
                    }
                }
                if f.load(Ordering::Relaxed) {
                    return Err("injected scan failure after contributions".into());
                }
                Ok(())
            });
            let get: Getter = Arc::new(|_| panic!("scattered residual used scalar original"));
            let mut state = State::new(get, Some((scan, live)), &point, 3, target, true).unwrap();
            assert_eq!(scans.load(Ordering::Relaxed), 1);
            assert_eq!(state.eval(&Point::new(point)).unwrap(), target);
            let mut dense: SumcheckProver<Goldilocks, E> = SumcheckProver::new(
                ProductPolynomial::new_unpacked(
                    VariableOrder::Prefix,
                    Poly::new(values),
                    Poly::new(weights),
                ),
                target,
            );
            for round in 0..3 {
                let (c0, c2) = state.round_coefficients().unwrap();
                assert_eq!((c0, c2), ResidualSumcheckProver::round_coefficients(&dense).unwrap());
                let r = [
                    E::ZERO,
                    E::ONE,
                    E::new([Goldilocks::new(3), Goldilocks::new(5), Goldilocks::new(7)]),
                ][round];
                state.fold_round_with_coefficients(c0, c2, r).unwrap();
                ResidualSumcheckProver::fold_round_with_coefficients(&mut dense, c0, c2, r)
                    .unwrap();
            }
            assert!(state.fold_round_with_coefficients(E::ZERO, E::ZERO, E::ONE).is_err());
            let expected = dense.evals();
            let suffix = [E::ONE, -E::ONE, E::from(Goldilocks::new(17))];
            for r in [
                E::ZERO,
                E::ONE,
                E::new([Goldilocks::new(19), Goldilocks::new(23), Goldilocks::new(29)]),
            ] {
                let reference = expected
                    .as_slice()
                    .iter()
                    .chain(&suffix)
                    .rev()
                    .fold(E::ZERO, |v, &x| v * r + x);
                assert_eq!(state.padded_ood(r, &suffix).unwrap(), reference);
            }
            let mut collected = vec![E::ZERO; 32];
            state
                .visit(&mut |i, x| {
                    collected[i] += x;
                    Ok(())
                })
                .unwrap();
            assert_eq!(collected, expected.as_slice());
            let mut emissions = 0;
            let error = state.visit(&mut |_, _| {
                emissions += 1;
                Err("consumer failed".into())
            });
            assert_eq!(emissions, usize::from(live != 0));
            assert_eq!(error.is_err(), live != 0);
            fail.store(true, Ordering::Relaxed);
            assert!(state.add_powers(&[]).is_err());
            assert!(state.pending_retention.is_some());
            assert_eq!(state.retained_bytes, 0);
            assert!(state.retained.as_ref().unwrap().data.read().unwrap().values.is_none());
            fail.store(false, Ordering::Relaxed);
            state.add_powers(&[]).unwrap();
            let count = scans.load(Ordering::Relaxed);
            assert!(state.scan.is_none());
            assert!(state.pending_retention.is_none());
            assert_eq!(state.evals().unwrap(), expected);
            assert_eq!(
                state.padded_ood(E::ONE, &suffix).unwrap(),
                collected.iter().chain(&suffix).copied().sum()
            );
            assert_eq!(scans.load(Ordering::Relaxed), count);
            assert_eq!(state.retained_bytes, 32 * 24);
        }
        let point = [E::ONE; 8];
        let get: Getter = Arc::new(|_| panic!("invalid scanner used scalar original"));
        let wrong: BaseScan = Arc::new(|emit| emit(0, Goldilocks::ONE));
        assert!(
            State::new(get.clone(), Some((wrong.clone(), 257)), &point, 3, E::ZERO, true).is_err()
        );
        assert!(
            State::new(get.clone(), Some((wrong.clone(), 0)), &point, 3, E::ZERO, true).is_err()
        );
        assert!(
            State::new(get.clone(), Some((wrong.clone(), 2)), &point, 3, E::ZERO, true).is_err()
        );
        assert!(State::new(get.clone(), Some((wrong, 1)), &point, 3, E::ONE, true).is_err());
        let excess: BaseScan = Arc::new(|emit| {
            emit(0, Goldilocks::ONE)?;
            emit(0, Goldilocks::ONE)
        });
        assert!(State::new(get, Some((excess, 1)), &point, 3, E::ZERO, true).is_err());
    }

    #[test]
    fn c71_b12_retained_lifecycle_rejects_reordering_and_releases_capacity() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let keepalive = Arc::new(());
        let weak = Arc::downgrade(&keepalive);
        let captured = keepalive.clone();
        let fallback: Getter = Arc::new(move |i| {
            let _keep_source_alive = &captured;
            E::from(Goldilocks::new(i as u64 + 1))
        });
        drop(keepalive);

        let mut values = Vec::with_capacity(16);
        values.extend((0..8).map(|i| E::from(Goldilocks::new(i + 1))));
        assert_eq!(values.capacity(), 16);
        let stage = Arc::new(Retained {
            owner:None,
            data: RwLock::new(RetainedData {
                fallback: Some(fallback),
                native_original:None,
                values: None,
                variables: 3,
                applied: Vec::new(),
                current: 0,
                successor: None,
                fold_interpolations: 0,
            }),
            reads: Arc::new(AtomicU64::new(0)),
        });

        // This is the materialization transition in add_powers: the immutable
        // source capture is gone once the retained vector becomes authoritative.
        {
            let mut data = stage.data.write().unwrap();
            data.values = Some(RetainedValues::Host(values));
            data.fallback = None;
        }
        assert!(weak.upgrade().is_none());

        assert!(stage.lease(&[E::ONE; 4]).is_err());
        assert!(stage.promote(&[E::ONE; 4]).is_err());
        let overlong = stage.getter(vec![E::ONE; 4]);
        assert!(catch_unwind(AssertUnwindSafe(|| overlong(0))).is_err());
        let s1 = stage.lease(&[]).unwrap();
        assert!(stage.lease(&[]).is_err());
        assert!(stage.promote(&[]).is_err());
        let duplicate_s1 = Lease { stage: stage.clone(), prefix: Vec::new() };
        let stale_s1_getter = stage.getter(Vec::new());

        let r = E::new([Goldilocks::new(5), Goldilocks::new(7), Goldilocks::new(11)]);
        let s2_prefix = vec![r];
        let s2_getter = stage.getter(s2_prefix.clone());
        let before: Vec<_> = (0..4).map(|i| s2_getter(i)).collect();
        let s2 = stage.lease(&s2_prefix).unwrap();

        assert!(stage.promote(&s2_prefix).is_err()); // predecessor still live
        s1.release().unwrap();
        assert!(duplicate_s1.release().is_err());
        stage.promote(&s2_prefix).unwrap();

        let after: Vec<_> = (0..4).map(|i| s2_getter(i)).collect();
        assert_eq!(before, after);
        let data = stage.data.read().unwrap();
        let Some(RetainedValues::Host(values))=&data.values else {panic!("host retained fixture differs")};
        assert_eq!(values.len(),4);
        assert_eq!(values.capacity(),4);
        drop(data);

        assert!(catch_unwind(AssertUnwindSafe(|| stale_s1_getter(0))).is_err());
        s2.release().unwrap();
    }

    #[test]
    fn c71_b12_native_power_fft_vectors() {
        let terms: Vec<_> = (0..17)
            .map(|index| {
                let point = match index % 4 {
                    0 => E::ZERO,
                    1 => E::ONE,
                    _ => E::new([
                        Goldilocks::new(index + 3),
                        Goldilocks::new(7),
                        Goldilocks::new(11),
                    ]),
                };
                let scale =
                    E::new([Goldilocks::new(index + 13), Goldilocks::new(17), Goldilocks::new(19)]);
                (point, scale)
            })
            .collect();
        let planes = |values: &[E]| {
            (0..3)
                .flat_map(|limb| {
                    values.iter().map(move |value| {
                        <E as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(value)
                            [limb]
                            .as_canonical_u64()
                    })
                })
                .collect::<Vec<_>>()
        };
        for side in [2_usize, 4, 8, 16] {
            let size = side * side / 2;
            let powers = PowerBlocks::new(&terms, size);
            let mut amplitudes: Vec<_> = terms.iter().map(|&(_, scale)| scale).collect();
            for block in 0..3 {
                let numerator = powers.numerator(&amplitudes);
                let values = powers.next(&mut amplitudes);
                for (offset, value) in values.iter().enumerate() {
                    let direct: E = terms
                        .iter()
                        .map(|&(point, scale)| {
                            scale * point.exp_u64((block * size + offset) as u64)
                        })
                        .sum();
                    assert_eq!(*value, direct);
                }
                println!(
                    "C71_NATIVE_POWER {}",
                    serde_json::json!({
                        "side": side, "block": block, "basis": "v^3-v-1",
                        "numerator": planes(&numerator), "inverse": planes(&powers.inverse_spectrum),
                        "expected": planes(&values),
                    })
                );
            }
        }
    }

    #[test]
    fn c71_b12_rational_power_blocks_match_direct_extension_powers() {
        for count in [0, 1, 3, 5, 17, 513] {
            let terms: Vec<_> = (0..count)
                .map(|index| {
                    let point = match index % 5 {
                        0 => E::ZERO,
                        1 | 2 => E::ONE,
                        _ => E::new([
                            Goldilocks::new(index as u64 + 3),
                            Goldilocks::new(7),
                            Goldilocks::new(11),
                        ]),
                    };
                    let scale = if index % 4 == 3 {
                        E::ZERO
                    } else {
                        E::from(Goldilocks::new(index as u64 + 13))
                    };
                    (point, scale)
                })
                .collect();
            for size in [1, 2, 8, 32, 256, 1024] {
                let blocks = PowerBlocks::new(&terms, size);
                let mut amplitudes: Vec<_> = terms.iter().map(|&(_, scale)| scale).collect();
                for block in 0..3 {
                    let expected: Vec<E> = (0..size)
                        .map(|offset| {
                            terms
                                .iter()
                                .map(|&(point, scale)| {
                                    scale * point.exp_u64((block * size + offset) as u64)
                                })
                                .sum()
                        })
                        .collect();
                    assert_eq!(blocks.next(&mut amplitudes), expected);
                }
            }
        }
        println!("C71_RATIONAL_POW base_and_extension=true blocks=3 tested_cap=1024 configured_cap=2097152 canonical_credit=false");
    }

    #[test]
    fn c71_b12_sourcewise_adaptive_rounds_match_dense_and_forbid_fallbacks() {
        for (dimension, first, retain) in
            [(10, 1, false), (12, 1, false), (12, 7, false), (12, 7, true)]
        {
            let source: Getter =
                Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
            let point: Vec<_> = (0..dimension)
                .map(|i| match i % 5 {
                    0 => E::ZERO,
                    1 => E::ONE,
                    _ => E::new([
                        Goldilocks::new(i as u64 + 3),
                        Goldilocks::new(7),
                        Goldilocks::new(11),
                    ]),
                })
                .collect();
            let values: Vec<_> = (0..1 << dimension).map(|i| source(i)).collect();
            let weights: Vec<_> = (0..1 << dimension).map(|i| equality(&point, i)).collect();
            let target = values.iter().zip(&weights).map(|(&x, &y)| x * y).sum();
            let mut state = State::new(source, None, &point, first, target, retain).unwrap();
            let mut dense: SumcheckProver<Goldilocks, E> = SumcheckProver::new(
                ProductPolynomial::new_unpacked(
                    VariableOrder::Prefix,
                    Poly::new(values),
                    Poly::new(weights),
                ),
                target,
            );
            assert!(state.evals().is_err());
            assert!(state.weights().is_err());
            assert!(state.accumulate_claim(&[], E::ZERO).is_err());
            for round in 0..dimension {
                if round == first {
                    let frozen = state.getter();
                    let before: Vec<_> =
                        (0..1 << state.num_variables()).map(|i| frozen(i)).collect();
                    assert_eq!(state.retained_bytes, 0);
                    let terms = [
                        (E::ZERO, E::from(Goldilocks::new(17))),
                        (E::ONE, E::from(Goldilocks::new(23))),
                        (E::from(Goldilocks::new(29)), E::ZERO),
                        (E::from(Goldilocks::new(19)), E::from(Goldilocks::new(5))),
                        (
                            E::new([Goldilocks::new(3), Goldilocks::new(2), Goldilocks::new(1)]),
                            E::from(Goldilocks::new(13)),
                        ),
                    ];
                    state.add_powers(&terms).unwrap();
                    assert_eq!(
                        before,
                        (0..1 << state.num_variables()).map(|i| frozen(i)).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        state.retained_bytes,
                        if retain { 24 << (dimension - first) } else { 0 }
                    );
                    let delta: Vec<_> = (0..1 << state.num_variables())
                        .map(|i| terms.iter().map(|&(p, c)| c * p.exp_u64(i as u64)).sum())
                        .collect();
                    let claim =
                        dense.evals().as_slice().iter().zip(&delta).map(|(&a, &b)| a * b).sum();
                    ResidualSumcheckProver::accumulate_claim(&mut dense, &delta, claim).unwrap();
                    let scale = E::from(Goldilocks::new(31));
                    state.scale_weights_and_claim(scale).unwrap();
                    ResidualSumcheckProver::scale_weights_and_claim(&mut dense, scale).unwrap();
                }
                let coefficients = state.round_coefficients().unwrap();
                assert_eq!(
                    coefficients,
                    ResidualSumcheckProver::round_coefficients(&dense).unwrap()
                );
                let r = E::new([
                    Goldilocks::new(37 + round as u64),
                    Goldilocks::new(17),
                    Goldilocks::new(5),
                ]);
                state.fold_round_with_coefficients(coefficients.0, coefficients.1, r).unwrap();
                ResidualSumcheckProver::fold_round_with_coefficients(
                    &mut dense,
                    coefficients.0,
                    coefficients.1,
                    r,
                )
                .unwrap();
                assert_eq!(state.claimed_sum(), dense.claimed_sum());
            }
            assert_eq!(state.evals().unwrap(), dense.evals());
            assert_eq!(state.weights().unwrap(), dense.weights());
            eprintln!("sourcewise dimension={dimension} first={first} original_reads={} named_final_bytes={}",state.source_reads.load(Ordering::Relaxed),state.named_bytes());
        }
    }
    pub(in crate::c71_matrix) fn native_fixture_original(config:&device::Config,dimension:usize,source:bool)
        ->(NativeOriginal,Vec<Goldilocks>,Arc<AtomicU64>,Arc<Mutex<device::Runtime>>) {
        let owner=Arc::new(Mutex::new(device::Runtime::new(config).unwrap()));
        let scans=Arc::new(AtomicU64::new(0));
        if source {
            let words:Vec<i16>=(0..1<<(dimension-1)).map(|i|((i*97+13)%65535) as i32-32767).map(|x|x as i16).collect();
            let values=words.iter().flat_map(|&x|((i32::from(x)+32768) as u16).to_le_bytes())
                .map(Goldilocks::from_u8).collect();
            let rows=words.len();
            let input=Arc::new(owner.lock().unwrap().upload_signed(&words).unwrap());
            let runtime=owner.clone();let visits=scans.clone();
            let query_input=input.clone();
            let query_window:super::super::replay::NativeByteWindow=Arc::new(move |runtime,first,count| {
                let length=count.max(128).next_power_of_two();
                let window=runtime.byte_window(length)?;
                runtime.scatter_bytes(&query_input,&device::ByteTile {input_first:0,input_stride:1,rows:rows as u64,columns:1,
                    original_first:0,window_first:first as u64,window_length:length as u64,byte_first:0,width:2,signed_width:2,
                    dimension:dimension as u32,suffix:0,bottom:0},&window)?;
                runtime.seal_bytes(window)
            });
            let original=NativeOriginal::Source(super::super::replay::NativeSource {
                runtime:owner.clone(),live:1<<dimension,
                window:query_window,
                scan:Arc::new(move |emit| {
                    visits.fetch_add(1,Ordering::Relaxed);
                    let mut runtime=runtime.lock().map_err(|_|"fixture owner poisoned")?;
                    emit(&mut runtime,&input,device::PcsSourceTile {input_first:0,input_stride:1,
                        rows:rows as u64,columns:1,original_first:0,byte_first:0,width:2,signed_width:2})
                }),
            });
            (original,values,scans,owner)
        } else {
            let live:usize=(1<<dimension)-3;
            let words=Arc::new((0..live).map(|i|(((i*131+17)%65535) as i32-32767) as i16).collect::<Vec<_>>());
            owner.lock().unwrap().install_weights(words.clone(),[47;32]).unwrap();
            let even=live.div_ceil(2);let odd=live/2;
            let mut values:Vec<_>=words.iter().step_by(2).chain(words.iter().skip(1).step_by(2))
                .map(|&x|if x>=0 {Goldilocks::from_u64(x as u64)}else{-Goldilocks::from_u64((-i64::from(x)) as u64)}).collect();
            values.resize(1<<dimension,Goldilocks::ZERO);
            // The ABI requires dyadic tiles even when the live prefix is ragged.
            let mut tiles=Vec::new();let mut first=0;
            for (parity,count) in [(0,even),(1,odd)] {
                let mut offset=0;
                while offset<count {
                    let size=1usize<<(count-offset).ilog2();
                    tiles.push(device::WeightTile {first:first as u64,count:size as u64,
                        packed_first:(parity+2*offset) as u64,packed_stride:2,columns:1});
                    first+=size;offset+=size;
                }
            }
            assert_eq!(first,live);
            let original=NativeOriginal::Weights(super::super::replay::NativeWeights {runtime:owner.clone(),weights:words,layout:[47;32],
                tiles});
            (original,values,scans,owner)
        }
    }

    #[test]
    fn c71_b12_native_residual_state_exact_coefficients_late_retention_and_views() {
        let fixture=device::tests::fixture(512);
        for dimension in [10,12] {for source in [false,true] {
            let (original,values,scans,owner)=native_fixture_original(&fixture.config,dimension,source);
            let original_values=Arc::new(values);
            let get:Getter={let values=original_values.clone();Arc::new(move |i|E::from(values[i]))};
            let point:Vec<_>=(0..dimension).map(|i|match i%3 {0=>E::ZERO,1=>E::ONE,
                _=>E::new([Goldilocks::new(3+i as u64),Goldilocks::new(5),Goldilocks::new(7)])}).collect();
            let target=Poly::new(original_values.as_ref().clone()).eval_base(&Point::new(point.clone()));
            let first=3;
            let mut cpu=State::new(get,None,&point,first,target,source).unwrap();
            let mut native=State::new_native(original,&point,first,target,source).unwrap();
            let initial=native.native_original_stage().unwrap();
            let start=owner.lock().unwrap().stats().unwrap();
            assert_eq!(start.d2h_bytes,(24*(1<<first)+4) as u64);
            let mut current_native=None;let mut current_cpu=None;
            for round in 0..dimension {
                let expected=cpu.round_coefficients().unwrap();
                let actual=native.round_coefficients().unwrap();assert_eq!(actual,expected);
                let r=match round%3 {0=>E::ZERO,1=>E::ONE,_=>E::new([Goldilocks::new(round as u64+11),Goldilocks::new(13),Goldilocks::new(17)])};
                cpu.fold_round_with_coefficients(expected.0,expected.1,r).unwrap();
                native.fold_round_with_coefficients(actual.0,actual.1,r).unwrap();
                assert_eq!(native.claimed_sum(),cpu.claimed_sum());
                if round+1==first {
                    if source {
                        current_native=native.replay_lease().unwrap();current_cpu=cpu.replay_lease().unwrap();
                        assert!(native.add_powers(&[(E::ONE,E::ONE)]).is_err());
                    }
                    let view=native.native_view().unwrap();
                    let ood=E::new([Goldilocks::new(19),Goldilocks::new(23),Goldilocks::new(29)]);
                    let device::ResidualResult::Reduced(before)=view.run(device::ResidualPhase::Ood,device::ResidualCosets::default(),&[],ood).unwrap()
                        else {panic!("native OOD result")};
                    assert_eq!(before[0],cpu.padded_ood(ood,&[]).unwrap());
                    initial.release_initial();
                    let terms=[(E::ZERO,E::ONE),(E::ONE,E::new([Goldilocks::new(31),Goldilocks::new(37),Goldilocks::new(41)]))];
                    cpu.add_powers(&terms).unwrap();native.add_powers(&terms).unwrap();
                    assert_eq!(native.claimed_sum(),cpu.claimed_sum());
                    let device::ResidualResult::Reduced(after)=view.run(device::ResidualPhase::Ood,device::ResidualCosets::default(),&[],ood).unwrap()
                        else {panic!("native OOD result")};
                    assert_eq!(after,before); // the pre-commit view resolves late materialization
                } else if source && round+1>first && (round+1-first)%2==0 && round+1<dimension {
                    let frozen=native.native_view().unwrap();
                    let ood=E::new([Goldilocks::new(43),Goldilocks::new(47),Goldilocks::new(53)]);
                    let expected=cpu.padded_ood(ood,&[]).unwrap();
                    let next_native=native.replay_lease().unwrap();let next_cpu=cpu.replay_lease().unwrap();
                    assert!(native.retained.as_ref().unwrap().promote(&native.prefix).is_err());
                    current_native.take().unwrap().release().unwrap();current_cpu.take().unwrap().release().unwrap();
                    let terms=[(ood,E::ONE)];cpu.add_powers(&terms).unwrap();native.add_powers(&terms).unwrap();
                    current_native=next_native;current_cpu=next_cpu;
                    let device::ResidualResult::Reduced(actual)=frozen.run(device::ResidualPhase::Ood,device::ResidualCosets::default(),&[],ood).unwrap()
                        else {panic!("native OOD result")};
                    assert_eq!(actual[0],expected); // same view, new plane generation
                }
                if native.num_variables()<=6 {
                    let before=owner.lock().unwrap().stats().unwrap().d2h_bytes;
                    assert_eq!(native.evals().unwrap(),cpu.evals().unwrap());
                    let after=owner.lock().unwrap().stats().unwrap().d2h_bytes;
                    assert_eq!(after-before,(24*(1<<native.num_variables())+4) as u64);
                    assert_eq!(native.weights().unwrap(),cpu.weights().unwrap());
                    assert_eq!(native.padded_ood(E::ONE,&[E::ONE,E::ZERO]).unwrap(),cpu.padded_ood(E::ONE,&[E::ONE,E::ZERO]).unwrap());
                }
            }
            if source {
                assert_eq!(scans.load(Ordering::Relaxed),3); // singleton, pre-retention OOD, retention
                current_native.take().unwrap().release().unwrap();current_cpu.take().unwrap().release().unwrap();
                native.native_retained_stage().unwrap().close_native().unwrap();
            }
            initial.close().unwrap();
            let final_stats=owner.lock().unwrap().close().unwrap();
            assert_eq!(final_stats.arena_bytes,0);
            println!("C71_NATIVE_RESIDUAL_STATE_COMPONENT {}",serde_json::json!({"credit":false,"gpu_execution":false,
                "dimension":dimension,"source_bytes":source,"named_final_bytes":native.named_bytes(),
                "source_visits":native.source_reads.load(Ordering::Relaxed),"retained_visits":native.retained_reads.load(Ordering::Relaxed),
                "state_descriptor_bytes":size_of::<State>(),"retained_descriptor_bytes":size_of::<Retained>()+size_of::<RetainedData>(),
                "view_descriptor_bytes":size_of::<NativeView>(),"source_descriptor_bytes":size_of::<NativeOriginalStage>(),
                "native":final_stats}));
        }}
    }


}
