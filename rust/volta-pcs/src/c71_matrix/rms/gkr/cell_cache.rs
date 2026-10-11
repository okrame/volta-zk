//! Bounded tail of the original cell folds, private to one GKR layer.
use super::{fold, Fp3, SourceCellWork};

pub(super) const MAX_BYTES: usize = 16 << 20;

pub(super) struct CellCache {
    depth: usize,
    width: usize,
    programs: usize,
    active: usize,
    prefix: usize,
    ready: bool,
    values: Vec<Fp3>,
    selectors: Vec<Fp3>,
    support: Vec<bool>,
}

impl CellCache {
    pub(super) fn new(depth: usize, width: usize, programs: usize, active: usize,
        prefix: usize, limit: usize) -> Result<Option<Box<Self>>, String> {
        if limit > MAX_BYTES || depth == 0 || depth > 128 || !width.is_power_of_two()
            || width > 1 << 14 || programs == 0 || programs > 421
            || !active.is_power_of_two() || active < 2 || active > 1 << 29 || prefix > 29 {
            return Err("RMS folded cache geometry or budget differs".into());
        }
        let requested = active.checked_mul((width + programs) * core::mem::size_of::<Fp3>() + programs)
            .and_then(|n| n.checked_add(core::mem::size_of::<Self>()))
            .ok_or("RMS folded cache size overflow")?;
        if requested > limit { return Ok(None); }
        let table = Box::new(Self { depth, width, programs, active, prefix, ready: false,
            values: vec![Fp3::ZERO; active * width],
            selectors: vec![Fp3::ZERO; active * programs],
            support: vec![false; active * programs] });
        if table.capacity_bytes() > limit { return Err("RMS folded cache capacity exceeds budget".into()); }
        Ok(Some(table))
    }

    pub(super) fn ready(&self) -> bool { self.ready }

    pub(super) fn finish_capture(&mut self) { self.ready = true; }

    pub(super) fn capacity_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + (self.values.capacity() + self.selectors.capacity()) * core::mem::size_of::<Fp3>()
            + self.support.capacity() * core::mem::size_of::<bool>()
    }

    pub(super) fn validate(&self, depth: usize, width: usize, programs: usize,
        active: usize, prefix: usize) -> Result<(), String> {
        if (self.depth, self.width, self.programs, self.active, self.prefix)
            != (depth, width, programs, active, prefix) {
            return Err("RMS folded cache belongs to a different round".into());
        }
        Ok(())
    }

    pub(super) fn mark_present(&mut self, cell: usize, program: usize) {
        self.support[cell * self.programs + program] = true;
    }

    pub(super) fn store(&mut self, cell: usize, values: &[Fp3], selectors: &[Fp3]) {
        self.values[cell * self.width..(cell + 1) * self.width].copy_from_slice(values);
        self.selectors[cell * self.programs..(cell + 1) * self.programs].copy_from_slice(selectors);
    }

    pub(super) fn row(&self, cell: usize, values: &mut [Fp3], selectors: &mut [Fp3]) {
        values.copy_from_slice(&self.values[cell * self.width..(cell + 1) * self.width]);
        selectors.copy_from_slice(&self.selectors[cell * self.programs..(cell + 1) * self.programs]);
    }

    pub(super) fn pair_support(&self, cell: usize, present: &mut [bool]) {
        assert_eq!(present.len(), self.programs);
        for (p, out) in present.iter_mut().enumerate() {
            *out = self.support[cell * self.programs + p]
                || self.support[(cell + self.active / 2) * self.programs + p];
        }
    }

    pub(super) fn advance(&mut self, challenge: Fp3, work: &mut SourceCellWork) {
        assert!(self.ready && self.active >= 2);
        let count = ((self.values.len() + self.selectors.len()) / 2) as u64;
        fold(&mut self.values, challenge);
        fold(&mut self.selectors, challenge);
        let half = self.support.len() / 2;
        for i in 0..half { self.support[i] |= self.support[i + half]; }
        self.support.truncate(half);
        self.active /= 2;
        self.prefix += 1;
        work.fold_value_multiplications += count;
        work.fold_additions += count;
        work.fold_subtractions += count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Circuit, Gate, Op, Fp, equality_at, signed, source_cell_round, source_cell_round_cached};

    #[test]
    fn c71_rms_folded_cache_budget_geometry_and_capacity() {
        let bytes = core::mem::size_of::<CellCache>() + 8 * ((8 + 3) * 24 + 3);
        assert!(CellCache::new(1,8,3,8,0,bytes-1).unwrap().is_none());
        let mut cache = CellCache::new(1,8,3,8,0,bytes).unwrap().unwrap();
        assert_eq!(cache.capacity_bytes(),bytes);
        assert!(cache.validate(2,8,3,8,0).is_err());
        assert!(cache.validate(1,8,3,4,0).is_err());
        let mut work = SourceCellWork::default();
        cache.finish_capture();
        cache.advance(Fp3::ONE,&mut work);
        cache.validate(1,8,3,4,1).unwrap();
        assert_eq!(cache.capacity_bytes(),bytes); // truncation does not refund capacity
        assert_eq!(work.fold_value_multiplications,44);
        assert_eq!(work.fold_additions,44);
        assert_eq!(work.fold_subtractions,44);
        assert!(CellCache::new(1,8,3,8,0,MAX_BYTES+1).is_err());
        for (width, programs, active) in [(3,3,8),(8,0,8),(8,422,8),(8,3,1),(8,3,7)] {
            assert!(CellCache::new(1,width,programs,active,0,MAX_BYTES).is_err());
        }
    }

    #[test]
    fn c71_rms_folded_cache_exact_zero_one_and_mixed_programs() {
        let programs: Vec<_> = (0..3).map(|p| Circuit {
            ports:8,product_bits:16,valid:0,coefficients:[0;3],arithmetic_bits:1,raw_gates:3,
            levels:vec![vec![Gate{op:Op::And,x:p,y:p+1},
                Gate{op:Op::Xor,x:p+2,y:p+3},Gate{op:Op::Copy,x:p+4,y:p+4}]],
        }).collect();
        let point = [signed(3),Fp3::ONE,Fp3::ZERO,signed(5),signed(7)];
        let row = |cell:usize,out:&mut [Fp3]| {
            assert_ne!(cell%5,0,"padding getter forbidden");
            for (wire,v) in out.iter_mut().enumerate() {
                *v=Fp3::ONE.mul_bool((cell*37+wire*11+wire*cell)%7<3);
            }
            Ok(())
        };
        let selector = |cell:usize| Ok((cell%5!=0).then(|| (cell%3,equality_at(&point,cell))));
        let weights = [signed(11),signed(13),signed(17)];
        let extension = Fp3::new(Fp::new(19),Fp::new(23),Fp::new(29));
        for challenges in [[Fp3::ZERO;5],[Fp3::ONE;5],[Fp3::ZERO,Fp3::ONE,extension,signed(31),extension]] {
            for budget in [0,1,core::mem::size_of::<CellCache>()+2*((8+3)*24+3),
                core::mem::size_of::<CellCache>()+8*((8+3)*24+3),MAX_BYTES] {
                let mut cache=None;
                let mut callbacks=0;
                for round in 0..5 {
                    let prefix=&challenges[..round];
                    let mut reference=SourceCellWork::default();
                    let expected=source_cell_round::<true>(&programs,1,8,32,prefix,&row,&selector,&weights,&mut reference).unwrap();
                    let mut work=SourceCellWork::default();
                    let actual=source_cell_round_cached::<true>(&programs,1,8,32,prefix,&row,&selector,&weights,&mut work,&mut cache,budget).unwrap();
                    assert_eq!(actual.coefficients,expected.coefficients);
                    assert_eq!(actual.terminal,expected.terminal);
                    assert_eq!(work.coefficient_multiplications,reference.coefficient_multiplications);
                    assert_eq!(work.gate_cell_iterations,reference.gate_cell_iterations);
                    assert_eq!(work.unsupported_program_cells,reference.unsupported_program_cells);
                    assert!(work.owned_heap_peak_bytes<=reference.owned_heap_peak_bytes+budget);
                    callbacks+=work.row_source_callbacks;
                    if round<4 { if let Some(table)=cache.as_mut() {table.advance(challenges[round],&mut work);} }
                }
                if budget==MAX_BYTES {assert_eq!(callbacks,25);}
                if budget<=1 {assert_eq!(callbacks,125);}
            }
        }
    }
    #[test]
    fn c71_rms_folded_cache_rejects_partial_capture() {
        let programs = [Circuit { ports:2, product_bits:16, valid:0, coefficients:[0;3],
            arithmetic_bits:1, raw_gates:1,
            levels:vec![vec![Gate{op:Op::Copy,x:0,y:0}]] }];
        let selector=|_:usize| Ok(Some((0,Fp3::ONE)));
        let mut cache=None;
        let failed=|cell:usize,out:&mut [Fp3]| {
            if cell==2 {return Err("injected getter failure".into());}
            out.fill(Fp3::ZERO);Ok(())
        };
        assert!(source_cell_round_cached::<true>(&programs,1,2,4,&[],&failed,&selector,
            &[Fp3::ONE],&mut SourceCellWork::default(),&mut cache,MAX_BYTES).is_err());
        assert!(!cache.as_ref().unwrap().ready());
        let good=|_:usize,out:&mut [Fp3]| {out.fill(Fp3::ZERO);Ok(())};
        let rejected=source_cell_round_cached::<true>(&programs,1,2,4,&[],&good,&selector,
            &[Fp3::ONE],&mut SourceCellWork::default(),&mut cache,MAX_BYTES);
        assert!(rejected.err().unwrap().contains("capture incomplete"));
        cache=None;
        source_cell_round_cached::<true>(&programs,1,2,4,&[],&good,&selector,
            &[Fp3::ONE],&mut SourceCellWork::default(),&mut cache,MAX_BYTES).unwrap();
        assert!(cache.as_ref().unwrap().ready());
        let reduced=source_cell_round_cached::<true>(&programs,1,2,4,&[],&good,&selector,
            &[Fp3::ONE],&mut SourceCellWork::default(),&mut cache,0);
        assert!(reduced.err().unwrap().contains("budget reduced"));
    }

}
