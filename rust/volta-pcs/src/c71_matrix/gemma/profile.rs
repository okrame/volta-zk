//! One public scale map for the complete integer relation. No independent
//! caller-selected shifts at a producer/consumer boundary, and no witness IO.

use super::*;
use bytes::{affine::Relation, quantize::Pair};
use std::collections::BTreeSet;

pub(in crate::c71_matrix) struct Recipes {
    pub digest: [u8; 32],
    pub matrix: Vec<Pair>,
    pub rms: Vec<[i32; 3]>,
    pub gelu: Vec<[i32; 2]>,
    pub gate_up: Vec<Pair>,
    pub rope: Vec<Pair>,
    pub score: Vec<Pair>,
    pub pv: Vec<Pair>,
    pub affine: Vec<Relation>,
    pub residual: Vec<Pair>,
    pub exp30: Vec<i32>,
    pub softcap: [i32; 2],
}

impl Recipes {
    /// Fresh whole-table probes only for outputs with no original incoming
    /// MAC. The other 410 RNE reductions MUST reuse those original claims.
    pub fn table_pairs(&self, plan: &Plan) -> Result<Vec<Pair>, String> {
        let mut pairs = self
            .matrix
            .iter()
            .filter(|p| {
                matches!(
                    plan.cohorts[p.raw].operation.as_str(),
                    "gate_proj" | "up_proj" | "lm_head"
                )
            })
            .copied()
            .collect::<Vec<_>>();
        if pairs.len() != 121 {
            return Err("Gemma matrix table-probe census differs".into());
        }
        pairs.extend(&self.rope);
        pairs.extend(&self.score);
        pairs.extend(&self.residual);
        if pairs.len() != 482 {
            return Err("Gemma table-probe census differs".into());
        }
        Ok(pairs)
    }

    pub fn original_rne<T: Copy>(
        &self,
        plan: &Plan,
        s: &residual::Sources,
        p0: &caller::PendingP0<T>,
        norms: &rms::caller::Pending<T>,
    ) -> Result<Vec<(bytes::RneRequest<T>, i32)>, String> {
        let a = &s.attention;
        let gu = &a.rope.gate_up;
        let rms = &gu.gelu.rms;
        let bytes = &rms.bytes;
        let mut requests = bytes.rne_requests(plan, p0)?;
        if requests.len() != 240 {
            return Err("Gemma original matrix RNE census differs".into());
        }
        let v = rms.local_v_rne_requests(plan, norms)?;
        if v.len() != 50 {
            return Err("Gemma original V RNE census differs".into());
        }
        requests.extend(v.into_iter().map(|v| bytes::RneRequest {
            consumer: v.norm,
            source: v.source,
            view: v.view,
            shape: v.shape,
            point: v.point,
            original: v.original,
        }));
        let gate = gu.output_rne_requests(plan, p0)?;
        let pv = a.output_rne_requests(plan, p0)?;
        if gate.len() != 60 || pv.len() != 60 {
            return Err("Gemma original product RNE census differs".into());
        }
        requests.extend(gate);
        requests.extend(pv);
        let pairs = self
            .matrix
            .iter()
            .chain(&self.gate_up)
            .chain(&self.pv)
            .map(|p| (p.raw, p))
            .collect::<BTreeMap<_, _>>();
        requests
            .into_iter()
            .map(|r| {
                let p = pairs.get(&r.source).ok_or("original RNE has no fixed public recipe")?;
                let out = &bytes.scalar.layout.sources[p.output];
                if r.shape != [out.rows, out.cols] {
                    return Err("original RNE recipe changes source axes".into());
                }
                let shift = p.shift;
                Ok((r, shift))
            })
            .collect()
    }

    /// Semantic i16 sources only. M and D are EXP30 witnesses, not scales
    /// chosen independently of score; the argmax slack is unsigned distance.
    pub fn exponent_sources(
        s: &residual::Sources,
        o: &output::Output,
        sm: &softmax::Softmax,
    ) -> BTreeSet<usize> {
        let bytes = &s.attention.rope.gate_up.gelu.rms.bytes;
        let excluded = sm
            .layers
            .iter()
            .flat_map(|l| [l.maximum, l.difference])
            .chain([o.slack])
            .collect::<BTreeSet<_>>();
        bytes
            .widths
            .iter()
            .enumerate()
            .filter_map(|(id, &w)| (w == 2 && !excluded.contains(&id)).then_some(id))
            .collect()
    }

    pub fn compile(
        plan: &Plan,
        s: &residual::Sources,
        o: &output::Output,
        sm: &softmax::Softmax,
        weights: &[i32],
        exponents: &BTreeMap<usize, i32>,
    ) -> Result<Self, String> {
        let a = &s.attention;
        let rope = &a.rope;
        let gu = &rope.gate_up;
        let g = &gu.gelu;
        let rms = &g.rms;
        let bytes = &rms.bytes;
        if weights.len() != plan.sources.len()
            || weights.len() != 772
            || weights.iter().any(|e| !(-128..=128).contains(e))
            || exponents.values().any(|e| !(-128..=128).contains(e))
            || exponents.keys().copied().collect::<BTreeSet<_>>()
                != Self::exponent_sources(s, o, sm)
            || bytes.scalar.weight_layout != plan.layout_digest
            || bytes.scalar.layout.sources.len() != 3471
            || a.layers.len() != 60
            || sm.layers.len() != 60
            || ![0, 150, 300].contains(&rope.old)
            || sm.old != rope.old
            || sm.queries != 150
            || sm.heads != 32
        {
            return Err("complete Gemma public scale map or canonical sources differ".into());
        }
        let mut used = BTreeSet::new();
        let mut e = |id| {
            used.insert(id);
            exponents.get(&id).copied().ok_or("Gemma source exponent missing".to_string())
        };
        // The original embedding and tied head use the SAME tensor exponent.
        if e(0)? != weights[plan.cohorts[0].tensor] {
            return Err("embedding source scale differs from its W tensor".into());
        }
        let by_op = plan
            .cohorts
            .iter()
            .enumerate()
            .map(|(i, c)| ((c.layer, c.operation.as_str()), i))
            .collect::<BTreeMap<_, _>>();
        let mut outputs = BTreeMap::new();
        let mut add = |raw, output| -> Result<(), String> {
            if outputs.insert(raw, output).is_some_and(|previous| previous != output) {
                return Err("matrix producer has two distinct output scales/sources".into());
            }
            Ok(())
        };
        for id in 1..plan.cohorts.len() {
            let route = plan.input_route(id)?;
            if let Some(&raw) = by_op.get(&(route.producer.0, route.producer.1.as_str())) {
                if plan.cohorts[raw].kind == Kind::Matrix {
                    add(raw, bytes.scalar.input_sources[id - 1])?;
                }
            }
        }
        for n in &rms.norms {
            if n.cohort.is_none() {
                if let Some(&raw) = by_op.get(&(n.layer, "v_source")) {
                    add(raw, n.input)?;
                }
            }
        }
        for v in &g.gelu {
            add(v.raw_gate, v.input)?;
        }
        for p in &gu.products {
            add(p.up_raw, p.up)?;
        }
        add(o.raw, o.input)?;
        let mut matrix = Vec::new();
        for (raw, c) in plan.cohorts.iter().enumerate().filter(|(_, c)| c.kind == Kind::Matrix) {
            let output = *outputs.get(&raw).ok_or("Gemma matrix quantization missing")?;
            let out = &bytes.scalar.layout.sources[output];
            if [out.rows, out.cols] != [c.rows, c.columns] {
                return Err("matrix quantization changes original output axes".into());
            }
            let shift = e(output)? - e(bytes.scalar.input_sources[raw - 1])? - weights[c.tensor];
            matrix.push(Pair { raw, output, shift: shift.clamp(-15, 48) });
        }
        if outputs.len() != 411 || matrix.len() != 411 {
            return Err("Gemma 411-matrix quantization census differs".into());
        }
        let mut parameters = Vec::new();
        let mut programs = BTreeSet::new();
        for n in &rms.norms {
            let ew = n.cohort.map_or(0, |i| weights[plan.cohorts[i].tensor]);
            let p = [e(n.input)?, ew, e(n.output)?];
            parameters.push(p);
            programs.insert((n.columns, p, n.cohort.is_some()));
        }
        for (d, [ex, ew, ey], weighted) in programs {
            let p = crate::c71_matrix::rms::compile(d, ex, ew, ey, weighted)?;
            if p.levels.len() > 128
                || p.ports > 98
                || p.levels.iter().any(|l| l.len() > 16384)
                || p.levels.iter().map(Vec::len).sum::<usize>() > 2_000_000
            {
                return Err("Gemma RMS profile exceeds the composed public envelope".into());
            }
        }
        let mut gelu = Vec::new();
        let mut gate_up = Vec::new();
        for (v, p) in g.gelu.iter().zip(&gu.products) {
            gelu.push([e(v.input)?, e(v.output)?]);
            let shift = e(p.output)? - e(v.output)? - e(p.up)?;
            gate_up.push(Pair { raw: p.raw, output: p.output, shift: shift.clamp(-15, 48) });
        }
        let mut rotations = Vec::new();
        for r in &rope.rotations {
            let shift = e(r.output)? - e(rms.norms[r.norm].output)? + 30;
            rotations.push(Pair { raw: r.raw, output: r.output, shift: shift.clamp(-15, 48) });
        }
        let (mut score, mut pv, mut exp30) = (Vec::new(), Vec::new(), Vec::new());
        for (l, soft) in a.layers.iter().zip(&sm.layers) {
            if [l.score, l.pi] != [soft.score, soft.pi] || e(l.pi)? != -14 {
                return Err("EXP30 original score/Pi or fixed output exponent differs".into());
            }
            let es = e(l.score)?;
            exp30.push(es);
            // Pinned QSPEC attention scale is exactly one.
            let shift = es - e(l.q)? - e(l.k)?;
            score.push(Pair { raw: l.raw_score, output: l.score, shift: shift.clamp(-15, 48) });
            let shift = e(l.output)? - e(l.pi)? - e(l.v)?;
            pv.push(Pair { raw: l.raw_output, output: l.output, shift: shift.clamp(-15, 48) });
        }
        let softcap = [e(o.input)?, e(o.output)?];
        for op in &s.operations {
            for id in [op.output, op.inputs[0], op.inputs[1]] {
                e(id)?;
            }
        }
        if used != Self::exponent_sources(s, o, sm) {
            return Err("public exponent has no complete-relation consumer".into());
        }
        let (affine, residual) = s.recipes(exponents)?;
        let owners = matrix
            .iter()
            .chain(&gate_up)
            .chain(&rotations)
            .chain(&score)
            .chain(&pv)
            .chain(&residual)
            .map(|p| p.output)
            .chain(rms.norms.iter().map(|n| n.output))
            .chain(g.gelu.iter().map(|v| v.output))
            .chain(sm.layers.iter().map(|l| l.pi))
            .chain([o.output, 0])
            .collect::<Vec<_>>();
        let ownership = owners.iter().copied().collect::<BTreeSet<_>>();
        if owners.len() != 1435 || ownership.len() != owners.len() || ownership != used {
            return Err("Gemma semantic sources lack a unique complete-relation producer".into());
        }
        // This is the scale/recipe identity, NOT a certified-table digest or
        // calibration claim. Absolute RoPE windows and A layouts bind later.
        let mut h = blake3::Hasher::new();
        h.update(b"C71-Gemma-B12-scales-v1;EXP30-v1;RNE;RMS-eps1e-6;GELU-tanh;RoPE-Q30;softcap30;lowest-argmax\0");
        h.update(&plan.layout_digest);
        for (id, exp) in weights.iter().enumerate() {
            h.update(&(id as u64).to_le_bytes());
            h.update(&exp.to_le_bytes());
        }
        for (id, exp) in exponents {
            h.update(&(*id as u64).to_le_bytes());
            h.update(&exp.to_le_bytes());
        }
        Ok(Self {
            digest: *h.finalize().as_bytes(),
            matrix,
            rms: parameters,
            gelu,
            gate_up,
            rope: rotations,
            score,
            pv,
            affine,
            residual,
            exp30,
            softcap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_profile_derives_all_quantization_from_one_scale_map_across_kv() {
        let plan = compile().unwrap();
        let weights = vec![0; 772];
        let mut previous = None;
        for old in [0, 150, 300] {
            let (s, o, sm) = plan.softmax_sources_at(old).unwrap();
            let mut exponents = Recipes::exponent_sources(&s, &o, &sm)
                .into_iter()
                .map(|id| (id, 0))
                .collect::<BTreeMap<_, _>>();
            for l in &sm.layers {
                exponents.insert(l.pi, -14);
            }
            let r = Recipes::compile(&plan, &s, &o, &sm, &weights, &exponents).unwrap();
            if let Some(digest) = previous {
                assert_eq!(digest, r.digest);
            }
            previous = Some(r.digest);
            assert_eq!(
                [
                    r.matrix.len(),
                    r.rms.len(),
                    r.gelu.len(),
                    r.gate_up.len(),
                    r.rope.len(),
                    r.score.len(),
                    r.pv.len(),
                    r.affine.len(),
                    r.residual.len(),
                    r.exp30.len()
                ],
                [411, 421, 60, 60, 120, 60, 60, 181, 181, 60]
            );
            assert_eq!(r.softcap, [0, 0]);
            assert_eq!(r.table_pairs(&plan).unwrap().len(), 482);
            assert_eq!(exponents.len(), 1435); // 1434 activation owners, plus the tied W lookup
            let inputs = (1..plan.cohorts.len())
                .map(|cohort| {
                    let route = plan.input_route(cohort).unwrap();
                    caller::InputOpening {
                        cohort,
                        point: vec![
                            crate::c71_matrix::signed(3);
                            bits(route.selected_rows) + bits(route.columns)
                        ],
                        route,
                        original: cohort,
                    }
                })
                .collect();
            let p0 = caller::PendingP0 {
                cuts: Vec::new(),
                inputs,
                weight_forms: Vec::new(),
                weights: Vec::new(),
            };
            let rms = &s.attention.rope.gate_up.gelu.rms;
            let stats = rms
                .norms
                .iter()
                .enumerate()
                .map(|(i, n)| crate::c71_matrix::rms::statistic::Pending {
                    statistic_point: vec![Fp3::ONE; bits(n.rows)],
                    statistic: 1000 + i,
                    input_point: vec![crate::c71_matrix::signed(4); bits(n.rows) + bits(n.columns)],
                    inputs: [2000 + 3 * i, 2001 + 3 * i, 2002 + 3 * i],
                })
                .collect();
            let norms =
                rms::caller::Pending { statistics: stats, byte_point: Vec::new(), byte: 4000 };
            let demands = r.original_rne(&plan, &s, &p0, &norms).unwrap();
            assert_eq!(demands.len(), 410);
            for (i, (d, _)) in demands.iter().enumerate() {
                let expected = if (240..290).contains(&i) {
                    norms.statistics[d.consumer].inputs[0]
                } else {
                    p0.inputs[d.consumer - 1].original
                };
                assert_eq!(d.original, expected);
                assert_eq!(
                    d.point,
                    vec![
                        crate::c71_matrix::signed(if (240..290).contains(&i) { 4 } else { 3 });
                        d.point.len()
                    ]
                );
            }
            let mut all_rne = demands.iter().map(|(d, _)| d.source).collect::<BTreeSet<_>>();
            for p in r.table_pairs(&plan).unwrap() {
                assert!(all_rne.insert(p.raw));
            }
            assert_eq!(all_rne.len(), 892);
            assert!(r.exp30.iter().all(|&e| e == 0));
            assert!(r.matrix.iter().chain(&r.gate_up).chain(&r.score).all(|p| p.shift == 0));
            assert!(r.rope.iter().all(|p| p.shift == 30));
            assert!(r.pv.iter().all(|p| p.shift == 14));
            let mut changed = exponents.clone();
            changed.insert(sm.layers[0].pi, -13);
            assert!(Recipes::compile(&plan, &s, &o, &sm, &weights, &changed).is_err());
            let mut changed = exponents.clone();
            changed.remove(&o.output);
            assert!(Recipes::compile(&plan, &s, &o, &sm, &weights, &changed).is_err());
            let mut changed = exponents.clone();
            changed.insert(sm.layers[0].difference, 0);
            assert!(Recipes::compile(&plan, &s, &o, &sm, &weights, &changed).is_err());
            let mut changed = weights.clone();
            changed[plan.cohorts[0].tensor] = 1;
            assert!(Recipes::compile(&plan, &s, &o, &sm, &changed, &exponents).is_err());
            // Changing score units MUST also change its input RNE and EXP
            // table parameter, all under a different common profile digest.
            let mut changed = exponents.clone();
            changed.insert(sm.layers[0].score, 1);
            let changed = Recipes::compile(&plan, &s, &o, &sm, &weights, &changed).unwrap();
            assert_ne!(changed.digest, r.digest);
            assert_eq!(changed.score[0].shift, 1);
            assert_eq!(changed.exp30[0], 1);
        }
    }
}
