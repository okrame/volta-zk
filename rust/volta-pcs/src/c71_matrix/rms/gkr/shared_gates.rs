//! Exact regrouping by original output index, gate and public program mask.
use super::{accumulate_gate, gates, Circuit, Fp3, Gate, Op, SourceCellWork};
use core::mem::size_of;

const LIMIT: usize = 32 << 20;
type Mask = [u64; 7];

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct Indexed {
    output: u16,
    op: u8,
    x: u16,
    y: u16,
    program: u16,
}

impl Indexed {
    fn gate_key(&self) -> (u16, u8, u16, u16) { (self.output, self.op, self.x, self.y) }
}

#[derive(Clone, Copy)]
struct Weighted {
    weight: Fp3,
    x: u16,
    y: u16,
    op: u8,
}

impl Weighted {
    fn gate(&self) -> Gate {
        Gate { x: self.x as usize, y: self.y as usize,
            op: match self.op { 0 => Op::And, 1 => Op::Xor, 2 => Op::Copy, _ => unreachable!() } }
    }
}

struct Masked { mask: Mask, gate: Weighted }
impl Masked {
    fn key(&self) -> (Mask, u8, u16, u16) { (self.mask, self.gate.op, self.gate.x, self.gate.y) }
}
struct Group { mask: Mask, start: usize, end: usize, products: u64 }

pub(super) struct SharedGates {
    depth: usize,
    width: usize,
    original_products: Vec<u64>,
    groups: Vec<Group>,
    weighted: Vec<Weighted>,
    build_peak: usize,
    weight_additions: u64,
}

fn admit(bytes: usize) -> Result<(), String> {
    if bytes > LIMIT { Err("RMS shared-gate plan exceeds 32 MiB".into()) } else { Ok(()) }
}

impl SharedGates {
    pub(super) fn new(programs: &[Circuit], depth: usize, width: usize, weights: &[Fp3])
        -> Result<Box<Self>, String> {
        if programs.is_empty() || programs.len() > 421 || depth == 0 || depth > 128
            || !width.is_power_of_two() || width > 1 << 14 || weights.len() > 1 << 14 {
            return Err("RMS shared-gate geometry differs".into());
        }
        let mut count = 0usize;
        for program in programs {
            let layer = gates(program, depth);
            if layer.len() > weights.len() || layer.iter().any(|g| g.x >= width || g.y >= width
                || (g.op == Op::Copy && g.x != g.y)) {
                return Err("RMS shared-gate parent or weight differs".into());
            }
            count = count.checked_add(layer.len()).ok_or("RMS shared-gate count overflow")?;
        }
        admit(size_of::<Self>() + programs.len()*size_of::<u64>())?;
        let original_products=programs.iter().map(|p| gates(p,depth).iter()
            .map(|g|if g.op==Op::Copy {2u64} else {6}).sum()).collect::<Vec<_>>();
        let header = size_of::<Self>() + original_products.capacity()*size_of::<u64>();
        admit(header + count * size_of::<Indexed>())?;
        let mut indexed = Vec::with_capacity(count);
        for (p, program) in programs.iter().enumerate() {
            for (i, g) in gates(program, depth).iter().enumerate() {
                indexed.push(Indexed { output: i as u16, program: p as u16,
                    op: match g.op { Op::And=>0, Op::Xor=>1, Op::Copy=>2 },
                    x: g.x.min(g.y) as u16, y: g.x.max(g.y) as u16 });
            }
        }
        indexed.sort_unstable(); // In-place; program is the last key.
        let unique = indexed.iter().enumerate()
            .filter(|&(i, x)| i == 0 || x.gate_key() != indexed[i-1].gate_key()).count();
        let indexed_bytes = indexed.capacity() * size_of::<Indexed>();
        admit(header + indexed_bytes + unique * size_of::<Masked>())?;
        let mut masked = Vec::<Masked>::with_capacity(unique);
        for (i, x) in indexed.iter().enumerate() {
            if i == 0 || x.gate_key() != indexed[i-1].gate_key() {
                masked.push(Masked { mask: [0;7], gate: Weighted {
                    weight: weights[x.output as usize], op: x.op, x: x.x, y: x.y } });
            }
            masked.last_mut().unwrap().mask[x.program as usize / 64] |= 1 << (x.program % 64);
        }
        let mut build_peak = header + indexed_bytes + masked.capacity() * size_of::<Masked>();
        admit(build_peak)?;
        drop(indexed);
        masked.sort_unstable_by_key(Masked::key);
        let group_count = masked.iter().enumerate()
            .filter(|&(i, x)| i == 0 || x.mask != masked[i-1].mask).count();
        let gate_count = masked.iter().enumerate()
            .filter(|&(i, x)| i == 0 || x.key() != masked[i-1].key()).count();
        admit(header + masked.capacity() * size_of::<Masked>()
            + group_count * size_of::<Group>() + gate_count * size_of::<Weighted>())?;
        let mut groups = Vec::<Group>::with_capacity(group_count);
        let mut weighted = Vec::<Weighted>::with_capacity(gate_count);
        let mut weight_additions = 0;
        for (i, x) in masked.iter().enumerate() {
            if i == 0 || x.mask != masked[i-1].mask {
                groups.push(Group { mask: x.mask, start: weighted.len(), end: weighted.len(), products: 0 });
            }
            if i == 0 || x.key() != masked[i-1].key() {
                weighted.push(x.gate);
                groups.last_mut().unwrap().end = weighted.len();
                groups.last_mut().unwrap().products += if x.gate.op==2 {2} else {6};
            } else {
                weighted.last_mut().unwrap().weight += x.gate.weight;
                weight_additions += 1;
            }
        }
        build_peak = build_peak.max(header + masked.capacity() * size_of::<Masked>()
            + groups.capacity() * size_of::<Group>() + weighted.capacity() * size_of::<Weighted>());
        admit(build_peak)?;
        drop(masked);
        Ok(Box::new(Self { depth, width, original_products, groups, weighted,
            build_peak, weight_additions }))
    }

    pub(super) fn validate(&self, depth: usize, width: usize, programs: usize) -> Result<(), String> {
        if (self.depth,self.width,self.original_products.len()) != (depth,width,programs) {
            Err("RMS shared-gate plan belongs to another layer".into())
        } else { Ok(()) }
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        size_of::<Self>() + self.original_products.capacity()*size_of::<u64>()
            + self.groups.capacity()*size_of::<Group>()
            + self.weighted.capacity()*size_of::<Weighted>()
    }
    pub(super) fn build_peak_bytes(&self) -> usize { self.build_peak }
    pub(super) fn weight_additions(&self) -> u64 { self.weight_additions }

    // The choice depends only on public support/geometry, never on field values.
    pub(super) fn use_for(&self, present: &[bool], first_boolean: bool) -> bool {
        assert_eq!(present.len(),self.original_products.len());
        // The Boolean first round already avoids all gate field products.
        if first_boolean {return false;}
        let mut mask=[0u64;7];let mut original=0u64;
        for (p,&live) in present.iter().enumerate() {
            if live { mask[p/64] |= 1<<(p%64); original+=6+if first_boolean {0} else {self.original_products[p]}; }
        }
        if original==0 {return false;}
        let mut shared=0u64;
        for group in &self.groups {
            if group.mask.iter().zip(&mask).any(|(&a,&b)|a&b!=0) {
                shared+=6+if first_boolean {0} else {group.products};
                if shared>=original {return false;}
            }
        }
        true
    }

    pub(super) fn accumulate<const BOOLEAN_ROWS: bool>(&self, lo: &[Fp3], hi: &[Fp3],
        selector_lo: &[Fp3], selector_hi: &[Fp3], present: &[bool], first: bool,
        c: &mut [Fp3;4], work: &mut SourceCellWork) {
        for group in &self.groups {
            let mut a = Fp3::ZERO;
            let mut b = Fp3::ZERO;
            let mut supported = false;
            for (word, &bits) in group.mask.iter().enumerate() {
                let mut remaining = bits;
                while remaining != 0 {
                    let p = 64*word + remaining.trailing_zeros() as usize;
                    remaining &= remaining-1;
                    if present[p] {
                        supported = true;
                        a += selector_lo[p]; b += selector_hi[p];
                        work.coefficient_additions += 2;
                    }
                }
            }
            if !supported { continue; }
            b = b-a;
            let mut u = [Fp3::ZERO;3];
            for g in &self.weighted[group.start..group.end] {
                accumulate_gate::<BOOLEAN_ROWS>(&g.gate(),g.weight,lo,hi,first,&mut u,work);
            }
            for j in 0..3 { c[j] += a*u[j]; c[j+1] += b*u[j]; }
            work.coefficient_multiplications += 6;
            work.coefficient_additions += 6;
            work.coefficient_subtractions += 1;
        }
    }
}

#[cfg(test)]
impl SharedGates {
    pub(super) fn public_groups(&self) -> impl Iterator<Item=(Mask,[u64;3])> + '_ {
        self.groups.iter().map(|g| {
            let mut counts=[0;3];
            for gate in &self.weighted[g.start..g.end] { counts[gate.op as usize]+=1; }
            (g.mask,counts)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Fp, SourceCellWork, equality_at, source_cell_round, source_cell_round_planned};

    fn program(p:usize) -> Circuit {
        Circuit { ports:8, product_bits:16, valid:0, coefficients:[0;3], arithmetic_bits:1,
            raw_gates:5, levels:vec![vec![
                Gate{op:Op::And,x:0,y:1}, Gate{op:Op::And,x:1,y:0},
                Gate{op:if p==1 {Op::And} else {Op::Xor},x:2,y:2},
                Gate{op:Op::Xor,x:3,y:4}, Gate{op:Op::Copy,x:5,y:5}]] }
    }
    fn f(n:u64)->Fp3 {Fp3::new(Fp::new(n),Fp::new(n+3),Fp::new(n*7+1))}

    #[test]
    fn c71_rms_shared_gate_plan_bounds_masks_and_zero_weight() {
        assert!(admit(LIMIT).is_ok());assert!(admit(LIMIT+1).is_err());
        let programs=(0..70).map(|_|program(0)).collect::<Vec<_>>();
        let plan=SharedGates::new(&programs,1,8,&[f(2),-f(2),f(3),f(5),f(7)]).unwrap();
        assert_eq!(plan.groups.len(),1);assert_eq!(plan.weighted.len(),4);
        assert_eq!(plan.weight_additions(),1);
        assert_eq!(plan.groups[0].mask[0],u64::MAX);assert_eq!(plan.groups[0].mask[1],63);
        assert_eq!(plan.weighted.iter().filter(|g|g.weight==Fp3::ZERO).count(),1);
        assert!(plan.use_for(&vec![true;70],false));
        assert!(!plan.use_for(&vec![false;70],false));
        let mut one=vec![false;70];one[69]=true;
        assert!(!plan.use_for(&one,true));
        assert!(plan.capacity_bytes()<=plan.build_peak_bytes());
        assert!(plan.build_peak_bytes()<=LIMIT);
        assert!(plan.validate(2,8,70).is_err());assert!(plan.validate(1,4,70).is_err());
        assert!(SharedGates::new(&[],1,8,&[f(2);5]).is_err());
        assert!(SharedGates::new(&programs,1,8,&[f(2);4]).is_err());
        assert!(SharedGates::new(&programs,1,4,&[f(2);5]).is_err());
        assert!(SharedGates::new(&programs,0,8,&[f(2);5]).is_err());
    }

    #[test]
    fn c71_rms_shared_gate_coefficients_exact_mixed_support_and_challenges() {
        let programs=(0..3).map(program).collect::<Vec<_>>();
        let weights=[f(2),f(3),f(5),f(7),f(11)];
        let plan=SharedGates::new(&programs,1,8,&weights).unwrap();
        for support in 0..8 {
            let point=[Fp3::ZERO,Fp3::ONE,f(17)];
            let selector=|i:usize| Ok((support>>(i%3)&1!=0)
                .then(||(i%3,equality_at(&point,i))));
            for challenges in [[Fp3::ZERO;3],[Fp3::ONE;3],[f(13),Fp3::ZERO,f(19)]] {
                for budget in [0,super::super::cell_cache::MAX_BYTES] {
                    let mut cache=None;
                    for round in 0..3 {
                        let prefix=&challenges[..round];
                        let row=|i:usize,out:&mut[Fp3]| {
                            assert_ne!(support>>(i%3)&1,0);
                            for (j,x) in out.iter_mut().enumerate() {*x=Fp3::ONE.mul_bool((i*13+j*17)%7<3);}
                            Ok(())
                        };
                        let mut baseline=SourceCellWork::default();let mut work=SourceCellWork::default();
                        let expected=source_cell_round::<true>(&programs,1,8,8,prefix,&row,&selector,&weights,&mut baseline).unwrap();
                        let actual=source_cell_round_planned::<true>(&programs,1,8,8,prefix,&row,&selector,&weights,&mut work,
                            &mut cache,budget,Some(&plan)).unwrap();
                        assert_eq!(actual.coefficients,expected.coefficients);
                        assert_eq!(actual.terminal,expected.terminal);
                        assert!(work.coefficient_multiplications<=baseline.coefficient_multiplications);
                        assert_eq!(work.logical_gate_cell_iterations,baseline.logical_gate_cell_iterations);
                        assert_eq!(work.unsupported_program_cells,baseline.unsupported_program_cells);
                        assert!(work.owned_heap_peak_bytes<=baseline.owned_heap_peak_bytes+budget+plan.capacity_bytes());
                        if round<2 {if let Some(c)=cache.as_mut(){c.advance(challenges[round],&mut work);}}
                    }
                }
            }
        }
        // Non-Boolean rows prevent accidental x*x=x or XOR(x,x)=0 rewrites.
        let row=|i:usize,out:&mut[Fp3]| {for (j,x) in out.iter_mut().enumerate(){*x=f((i*17+j*13+3) as u64);}Ok(())};
        let selector=|i:usize| Ok(Some((i%3,f((i+31) as u64))));
        for prefix in [vec![],vec![Fp3::ZERO],vec![Fp3::ONE,f(23)]] {
            let expected=source_cell_round::<false>(&programs,1,8,8,&prefix,&row,&selector,&weights,&mut SourceCellWork::default()).unwrap();
            let actual=source_cell_round_planned::<false>(&programs,1,8,8,&prefix,&row,&selector,&weights,
                &mut SourceCellWork::default(),&mut None,0,Some(&plan)).unwrap();
            assert_eq!(actual.coefficients,expected.coefficients);
        }
    }
}
