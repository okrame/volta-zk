//! One public scale map for the complete integer relation. No independent
//! caller-selected shifts at a producer/consumer boundary, and no witness IO.

use super::*;
use bytes::{affine::Relation, quantize::Pair};
use std::collections::BTreeSet;

// The verifier's expected public tables. Cost/shape validation does not
// certify their numerical contents; they are never read from a proof.
#[derive(Clone, Copy)]
pub(in crate::c71_matrix) struct Tables<'a> {
    pub gelu: &'a [crate::c71_matrix::lookup::Table<'a>],
    pub exp30: &'a [crate::c71_matrix::lookup::Table<'a>],
    pub softcap: &'a crate::c71_matrix::lookup::Table<'a>,
    pub rope: &'a [crate::c71_matrix::rope::Table<'a>],
}

pub(in crate::c71_matrix) struct Recipes {
    pub digest: [u8; 32],
    pub matrix: Vec<Pair>,
    pub rms: Vec<[i32; 3]>,
    rms_geometry: Option<rms::caller::RequiredGeometry>,
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
    fn validate_rms(
        programs: BTreeSet<(usize, [i32; 3], bool)>,
    ) -> Result<rms::caller::RequiredGeometry, String> {
        rms::caller::RequiredGeometry::compile(programs)
    }

    /// Complete canonical row reservation, before any live FS or witness IO.
    /// Every operator's actual verifier/prover still must run before acceptance.
    pub fn required(
        &self,
        plan: &Plan,
        s: &residual::Sources,
        output: &output::Output,
        softmax: &softmax::Softmax,
        context: &caller::P0Statement<'_>,
        tables: &Tables<'_>,
    ) -> Result<usize, String> {
        use crate::c71_matrix::{range, Domain};
        let rms = &s.attention.rope.gate_up.gelu.rms;
        let bytes = &rms.bytes;
        let slot = usize::from(context.attempt.slot);
        if plan.sources.len() != 772
            || plan.cohorts.len() != 773
            || bits(plan.live) != 35
            || bits(bytes.live) != 34
            || slot > 2
            || context.tokens.len() != 150
            || s.attention.rope.old != 150 * slot
        {
            return Err("complete Gemma reservation requires the canonical fixed run".into());
        }
        let fresh = self.table_pairs(plan)?;
        let fresh_raws: BTreeSet<_> = fresh.iter().map(|p| p.raw).collect();
        if fresh.len() != 482 || fresh_raws.len() != 482 {
            return Err("complete Gemma table-probe partition differs".into());
        }
        let mut count = bytes.table_rne_required(plan, &fresh)?;
        let mut originals = 0;
        for p in [&self.matrix, &self.gate_up, &self.rope, &self.score, &self.pv, &self.residual]
            .into_iter()
            .flatten()
            .filter(|p| !fresh_raws.contains(&p.raw))
        {
            // Validate the same raw/output shape, then remove the probe row:
            // these 410 predicates MUST consume the caller's original MACs.
            count += bytes.table_rne_required(plan, std::slice::from_ref(p))? - 1;
            originals += 1;
        }
        if originals != 410 {
            return Err("complete Gemma original-RNE partition differs".into());
        }
        let rms_count = match &self.rms_geometry {
            Some(geometry) => rms.rms_required_with_geometry(context, &self.rms, geometry)?,
            // The metadata-only capacity fixture skips compiler admission.
            // It keeps the original public preflight as its explicit oracle.
            #[cfg(test)]
            None => rms.rms_required(context, &self.rms)?,
            #[cfg(not(test))]
            None => return Err("canonical RMS public geometry unavailable".into()),
        };
        count += plan.p0_required() + rms_count;
        count += s.attention.rope.gate_up.gelu.lookup_required(context, tables.gelu)?;
        count += s.attention.rope.gate_up.required(context)?;
        count += s.attention.rope.required(context, tables.rope)?;
        for layer in 0..60 {
            let (qk, pv) = s.attention.required(context, layer)?;
            count += qk + pv;
        }
        count += output.lookup_required(bytes, context, tables.softcap)?;
        count += softmax.required(bytes, context, tables.exp30)?;
        // One ranged W and current A; old A ranges are inherited ONLY from
        // fully accepted history. Each old A adds one fresh KV aggregate/PCS.
        let w = Domain::Flat(35).config()?.num_variables;
        let a = Domain::Flat(34).config()?.num_variables;
        count += range::required(w, 32767) + range::required(a, range::Alphabet::Byte);
        count += (3 * w + 2) + (slot + 1) * (3 * a + 2) + slot;
        // Affine, argmax, causal-mask and D/Z identities use public zero/bias
        // targets already closed by that same current-A PCS, without new rows.
        Ok(count)
    }

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
        #[cfg(test)]
        { Self::compile_inner(plan, s, o, sm, weights, exponents, false) }
        #[cfg(not(test))]
        { Self::compile_inner(plan, s, o, sm, weights, exponents) }
    }

    // Admission already validates these temporary RMS circuits. This fixture
    // shares every retained constructor and cannot be selected in production.
    #[cfg(test)]
    pub(super) fn compile_capacity_only(
        plan: &Plan, s: &residual::Sources, o: &output::Output, sm: &softmax::Softmax,
        weights: &[i32], exponents: &BTreeMap<usize, i32>,
    ) -> Result<Self, String> {
        Self::compile_inner(plan, s, o, sm, weights, exponents, true)
    }

    fn compile_inner(
        plan: &Plan, s: &residual::Sources, o: &output::Output, sm: &softmax::Softmax,
        weights: &[i32], exponents: &BTreeMap<usize, i32>,
        #[cfg(test)] capacity_only: bool,
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
        #[cfg(test)]
        let rms_geometry = if capacity_only { None } else { Some(Self::validate_rms(programs)?) };
        #[cfg(not(test))]
        let rms_geometry = Some(Self::validate_rms(programs)?);
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
            rms_geometry,
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
    fn c71_b12_preflight_norm_and_exp30_counts_without_expanding_canonical_cells() {
        use crate::c71_matrix::{gamma, lookup, AttemptContext, Auth, C61Commitment, Domain, Fs};
        let plan = compile().unwrap();
        let (w, a) = (C61Commitment::new(vec![[1; 32]]), C61Commitment::new(vec![[2; 32]]));
        let wg = gamma(&Domain::Flat(35).config().unwrap());
        let ag = gamma(&Domain::Flat(34).config().unwrap());
        // Exact EXP30 table for e_score=128: every positive D is far past
        // the certified zero shortcut. Synthetic scales, no Gemma witness.
        let mut exponential = vec![0; 65535];
        exponential[0] = 1 << 30;
        let tables: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I32(&exponential),
            })
            .collect();
        // Shape-only placeholders for the other public tables. Their bodies
        // are NOT certified and this cost check grants no proof acceptance.
        let zero_i16 = vec![0; 65535];
        let gelu_tables: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I16(&zero_i16),
            })
            .collect();
        let softcap_table =
            lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&zero_i16) };
        let local_rope = vec![vec![[1 << 30, 0]; 128]; 150];
        let global_rope = vec![vec![[1 << 30, 0]; 64]; 150];
        let mut full_run_rows = 0;
        for (slot, old) in [0, 150, 300].into_iter().enumerate() {
            let (s, o, sm) = plan.softmax_sources_at(old).unwrap();
            let mut exponents: BTreeMap<_, _> =
                Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
            for l in &sm.layers {
                exponents.insert(l.pi, -14);
                exponents.insert(l.score, 128);
            }
            let recipes = Recipes::compile(&plan, &s, &o, &sm, &[0; 772], &exponents).unwrap();
            let rms = &s.attention.rope.gate_up.gelu.rms;
            let bytes = &rms.bytes;
            let context = caller::P0Statement {
                weights: &w,
                auxiliary: &a,
                weight_gamma: &wg,
                auxiliary_gamma: &ag,
                auxiliary_layout: &bytes.scalar,
                quantization: recipes.digest,
                tokens: &[0; 150],
                attempt: AttemptContext {
                    session: [3; 32],
                    capacity: [4; 32],
                    slot: slot as u8,
                    predecessor: if slot == 0 { [0; 32] } else { [5; 32] },
                    nonce: [6; 32],
                },
            };
            let rms_count = rms.rms_required(&context, &recipes.rms).unwrap();
            eprintln!(
                "canonical_RMS_GKR O={old} {}",
                rms.work_census(&context, &recipes.rms).unwrap()
            );
            let exp_count = sm.required(bytes, &context, &tables).unwrap();
            let statistic_count: usize =
                rms.norms.iter().map(|n| 4 * (bits(n.rows) + bits(n.columns)) + 4).sum();
            let joint_upper = 128 * (4 * 29 + 6 * 14 + 3) + 1 + (32 * 33 + 169);
            assert!(rms_count <= 1 + statistic_count + joint_upper);
            assert!(exp_count <= [20_710, 21_348, 21_348][slot]);
            eprintln!("O={old}: RMS={rms_count}, EXP30={exp_count} Fp3; public preflight only");
            let rotations = [
                crate::c71_matrix::rope::Table { position: old, rows: &local_rope },
                crate::c71_matrix::rope::Table { position: old, rows: &global_rope },
            ];
            let public_tables = Tables {
                gelu: &gelu_tables,
                exp30: &tables,
                softcap: &softcap_table,
                rope: &rotations,
            };
            let full = recipes.required(&plan, &s, &o, &sm, &context, &public_tables).unwrap();
            eprintln!("O={old}: complete reservation={full} Fp3; no proof execution");
            full_run_rows += 3 * full;
            let mut fs = Fs::new(b"canonical public preflight, no witness or coins", 0);
            let digest = fs.digest();
            let mut rows = Vec::<Auth>::new().into_iter();
            assert_eq!(
                rms.prove_rms(
                    &context,
                    &recipes.rms,
                    |_, _, _, _| panic!("preflight read RMS witness"),
                    &mut fs,
                    &mut rows,
                )
                .err()
                .unwrap(),
                "RMS dispatcher prover capacity exhausted"
            );
            assert_eq!(
                sm.prove(
                    bytes,
                    &context,
                    &tables,
                    |_, _, _, _| panic!("preflight read EXP30 witness"),
                    &mut fs,
                    &mut rows,
                )
                .err()
                .unwrap(),
                "EXP30 prover capacity exhausted"
            );
            assert_eq!(fs.digest(), digest);
            assert_eq!(fs.requests(), 0);
            assert_eq!(rows.len(), 0);
        }
        assert!(full_run_rows <= 11_466_948);
        eprintln!("complete three-attempt reservation: {full_run_rows} base rows");
    }

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
