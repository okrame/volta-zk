//! Whole-table RNE obligations for i16 sources without a direct P0 endpoint.
//! Original probe and raw-byte MACs both close in the SAME auxiliary PCS.

use super::*;
use crate::c71_matrix::gemma::caller::P0Statement;
use crate::c71_matrix::*;

pub(in crate::c71_matrix) struct Pair {
    pub raw: usize,
    pub output: usize,
    pub shift: i32,
}

pub(in crate::c71_matrix) struct Proof {
    probes: Vec<Fp3>,
    reductions: Vec<rne::Proof>,
}

pub(in crate::c71_matrix) struct Opening<T> {
    pub output_point: Vec<Fp3>,
    pub output: T,
    pub raw_point: Vec<Fp3>,
    pub raw: T,
}

impl Bytes {
    fn quantized_shapes(
        &self,
        plan: &Plan,
        pairs: &[Pair],
    ) -> Result<Vec<([u8; 32], [usize; 2])>, String> {
        if pairs.is_empty() || pairs.len() > 512 || self.scalar.weight_layout != plan.layout_digest
        {
            return Err("RNE table source list or W layout differs".into());
        }
        let mut outputs = std::collections::BTreeSet::new();
        pairs
            .iter()
            .map(|p| {
                let view = self.rne_view(plan, p.raw)?;
                let out = self
                    .scalar
                    .layout
                    .sources
                    .get(p.output)
                    .ok_or("RNE table output source missing")?;
                if self.widths[p.output] != 2
                    || [out.rows, out.cols] != view.1
                    || !outputs.insert(p.output)
                {
                    return Err("RNE table output codec, shape or identity differs".into());
                }
                Ok(view)
            })
            .collect()
    }

    pub fn table_rne_required(&self, plan: &Plan, pairs: &[Pair]) -> Result<usize, String> {
        self.quantized_shapes(plan, pairs)?.iter().zip(pairs).try_fold(
            0,
            |total, ((_, shape), p)| {
                let c = bits(shape[0]) + bits(shape[1]);
                if c > 7 {
                    return Err("RNE table caller exceeds native D7".into());
                }
                Ok(total + 1 + rne::required(c, p.shift))
            },
        )
    }

    fn bind_quantization(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        pairs: &[Pair],
        fs: &mut Fs,
    ) -> Result<(), String> {
        if s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || !s.attempt.valid()
            || s.quantization == [0; 32]
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.auxiliary_layout.layout.layout_digest != self.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != plan.layout_digest
        {
            return Err("RNE table fixed context differs".into());
        }
        let mut bytes = b"C71-source-RNE-B12-v1;whole-table-probe;original-X-and-raw-A\0".to_vec();
        bytes.extend(s.weights.roots()[0]);
        bytes.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            bytes.extend((gamma.len() as u64).to_le_bytes());
            bytes.extend(gamma);
        }
        bytes.extend(plan.layout_digest);
        bytes.extend(self.layout_digest);
        bytes.extend(s.quantization);
        bytes.extend(s.attempt.encode());
        bytes.extend((pairs.len() as u64).to_le_bytes());
        for p in pairs {
            bytes.extend((p.raw as u64).to_le_bytes());
            bytes.extend((p.output as u64).to_le_bytes());
            bytes.extend(p.shift.to_le_bytes());
        }
        fs.set_phase(0xe00);
        fs.record(0xc0, &bytes);
        Ok(())
    }

    pub fn prove_table_rne(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        pairs: &[Pair],
        read: impl Fn(usize, usize, usize, usize) -> u8,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(Proof, Vec<Opening<Auth>>), String> {
        let count = self.table_rne_required(plan, pairs)?;
        if correlations.len() < count {
            return Err("RNE table prover capacity exhausted".into());
        }
        self.bind_quantization(plan, s, pairs, fs)?;
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        let (mut probes, mut reductions, mut pending) = (Vec::new(), Vec::new(), Vec::new());
        for (i, (p, (view, shape))) in
            pairs.iter().zip(self.quantized_shapes(plan, pairs)?).enumerate()
        {
            fs.set_phase(0xe10 + i as u16);
            let output_point: Vec<_> =
                (0..bits(shape[0]) + bits(shape[1])).map(|_| fs.fp3()).collect();
            let columns = shape[1].next_power_of_two();
            let value = eq(&output_point).into_iter().enumerate().fold(Fp3::ZERO, |v, (j, w)| {
                let (r, c) = (j / columns, j % columns);
                if r >= shape[0] || c >= shape[1] {
                    return v;
                }
                let biased = u16::from_le_bytes([read(p.output, r, c, 0), read(p.output, r, c, 1)]);
                v + w * signed(i64::from(biased) - 32768)
            });
            let (wire, original) = range::authenticate([value], &mut rows);
            record_values(fs, 0xc1, &wire);
            let rs = rne::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view,
                attempt: s.attempt,
                output_point: &output_point,
                shape,
                shift: p.shift,
            };
            // RNE indices use independently padded axes, NOT live columns.
            let (proof, raw_point, raw) = rne::prove(
                &rs,
                original[0],
                |j| std::array::from_fn(|b| read(p.raw, j / columns, j % columns, b)),
                fs,
                &mut rows,
            )?;
            probes.push(wire[0]);
            reductions.push(proof);
            pending.push(Opening { output_point, output: original[0], raw_point, raw });
        }
        debug_assert!(rows.next().is_none());
        Ok((Proof { probes, reductions }, pending))
    }

    pub fn verify_table_rne(
        &self,
        plan: &Plan,
        s: &P0Statement<'_>,
        pairs: &[Pair],
        proof: &Proof,
        delta: Fp3,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Key>,
    ) -> Result<Vec<Opening<Key>>, String> {
        let count = self.table_rne_required(plan, pairs)?;
        if correlations.len() < count
            || proof.probes.len() != pairs.len()
            || proof.reductions.len() != pairs.len()
        {
            return Err("RNE table proof shape or capacity differs".into());
        }
        self.bind_quantization(plan, s, pairs, fs)?;
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        let mut pending = Vec::new();
        for (i, (p, (view, shape))) in
            pairs.iter().zip(self.quantized_shapes(plan, pairs)?).enumerate()
        {
            fs.set_phase(0xe10 + i as u16);
            let output_point: Vec<_> =
                (0..bits(shape[0]) + bits(shape[1])).map(|_| fs.fp3()).collect();
            let original = range::correct([proof.probes[i]], delta, &mut rows)[0];
            record_values(fs, 0xc1, &[proof.probes[i]]);
            let rs = rne::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view,
                attempt: s.attempt,
                output_point: &output_point,
                shape,
                shift: p.shift,
            };
            let (raw_point, raw) =
                rne::verify(&rs, original, &proof.reductions[i], delta, fs, &mut rows)?;
            pending.push(Opening { output_point, output: original, raw_point, raw });
        }
        debug_assert!(rows.next().is_none());
        Ok(pending)
    }

    pub fn table_rne_forms<T: Copy>(
        &self,
        plan: &Plan,
        pairs: &[Pair],
        pending: &[Opening<T>],
    ) -> Result<(Vec<Vec<Cube>>, Vec<Fp3>, Vec<T>), String> {
        let shapes = self.quantized_shapes(plan, pairs)?;
        if pairs.len() != pending.len() {
            return Err("RNE table original claims differ".into());
        }
        let (mut forms, mut shifts, mut targets) = (Vec::new(), Vec::new(), Vec::new());
        for ((p, o), (_, shape)) in pairs.iter().zip(pending).zip(shapes) {
            if o.output_point.len() != bits(shape[0]) + bits(shape[1]) {
                return Err("RNE table original point differs".into());
            }
            let (r, c) = o.output_point.split_at(bits(shape[0]));
            let (form, shift) = self.word_form(p.output, r, c, Fp3::ONE)?;
            forms.push(form);
            shifts.push(shift);
            targets.push(o.output);
            forms.push(self.rne_form(plan, p.raw, &o.raw_point)?);
            shifts.push(Fp3::ZERO);
            targets.push(o.raw);
        }
        Ok((forms, shifts, targets))
    }
}
