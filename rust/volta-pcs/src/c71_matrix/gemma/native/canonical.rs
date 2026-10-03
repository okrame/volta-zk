//! Verifier-owned causal producer schedule over the pinned final A descriptors.
//! Compiles public metadata only; it does not materialize a D34/D35 witness.
use super::*;
use std::collections::{BTreeSet, VecDeque};

#[path = "canonical_calibration.rs"]
mod calibration;
#[path = "canonical_calibration_input.rs"]
pub(in crate::c71_matrix) mod calibration_input;
#[path = "canonical_ordered.rs"]
mod ordered;
#[path = "canonical_prepare.rs"]
mod prepare;
#[path = "canonical_prove.rs"]
mod prove;
#[path = "canonical_state.rs"]
pub(in crate::c71_matrix) mod state;
#[path = "canonical_verify.rs"]
mod verify;
#[cfg(test)]
#[path = "canonical_wire.rs"]
mod wire_tests;

enum Producer {
    Embedding,
    Matrix(usize),
    Norm(usize),
    Rne(Pair),
    Affine(usize),
    Gelu(usize),
    Gate(usize),
    Rope(usize),
    Qk(usize),
    Softmax(usize),
    Pv(usize),
    Softcap,
    Argmax,
}

struct Canonical {
    plan: Plan,
    sources: residual::Sources,
    output: output::Output,
    softmax: softmax::Softmax,
    recipes: profile::Recipes,
    steps: Vec<Producer>,
}

impl Canonical {
    /// The 892 mandatory RNE records alone, without frames, fresh probes,
    /// other operators, header, or any PCS. Metadata only; no witness/PCG.
    fn rne_wire_bytes(&self) -> Result<(usize, usize, usize), String> {
        let (mut bits_sum, mut minimum, mut selected) = (0, 0, 0);
        for step in &self.steps {
            let Producer::Rne(pair) = step else {
                continue;
            };
            let (_, shape) = self.bytes().source_rne_view(pair.raw)?;
            let c = bits(shape[0]) + bits(shape[1]);
            bits_sum += c;
            minimum += kernel::rne::wire_min_bytes(c);
            selected += kernel::rne::wire_bytes(c, pair.shift);
        }
        Ok((bits_sum, minimum, selected))
    }

    fn compile(
        slot: usize,
        weights: &[i32],
        exponents: &BTreeMap<usize, i32>,
    ) -> Result<Self, String> {
        if slot >= 3 {
            return Err("canonical fixed run has only three slots".into());
        }
        let plan = super::super::compile()?;
        let (sources, output, softmax) = plan.softmax_sources_at(150 * slot)?;
        let recipes =
            profile::Recipes::compile(&plan, &sources, &output, &softmax, weights, exponents)?;
        let mut p = Self { plan, sources, output, softmax, recipes, steps: Vec::new() };
        let rms = &p.sources.attention.rope.gate_up.gelu.rms;
        let r = &p.recipes;
        let mut steps = vec![Producer::Embedding];
        steps.extend(
            p.plan
                .cohorts
                .iter()
                .enumerate()
                .filter(|(_, c)| c.kind == Kind::Matrix)
                .map(|(i, _)| Producer::Matrix(i)),
        );
        steps.extend((0..rms.norms.len()).map(Producer::Norm));
        steps.extend(
            [&r.matrix, &r.gate_up, &r.rope, &r.score, &r.pv, &r.residual]
                .into_iter()
                .flatten()
                .copied()
                .map(Producer::Rne),
        );
        steps.extend((0..r.affine.len()).map(Producer::Affine));
        for layer in 0..60 {
            steps.extend([
                Producer::Gelu(layer),
                Producer::Gate(layer),
                Producer::Qk(layer),
                Producer::Softmax(layer),
                Producer::Pv(layer),
            ]);
        }
        steps.extend((0..120).map(Producer::Rope));
        steps.extend([Producer::Softcap, Producer::Argmax]);
        p.steps = p.causal_order(steps)?;
        Ok(p)
    }

    fn bytes(&self) -> &bytes::Bytes {
        &self.sources.attention.rope.gate_up.gelu.rms.bytes
    }

    /// Dependencies are source identities, including the ten pre-norm global
    /// K/V aliases and selected-row consumers. Execution is per causal token:
    /// QK/PV may read only the accepted old tails and current rows <= that token.
    fn ports(&self, step: &Producer) -> (Vec<usize>, Vec<usize>) {
        let a = &self.sources.attention;
        let gu = &a.rope.gate_up;
        let rms = &gu.gelu.rms;
        match step {
            Producer::Embedding => (vec![], vec![0]),
            Producer::Matrix(i) => (vec![self.bytes().scalar.input_sources[i - 1]], vec![*i]),
            Producer::Norm(i) => {
                let n = &rms.norms[*i];
                (vec![n.input], n.cohort.into_iter().chain([n.statistic, n.output]).collect())
            }
            Producer::Rne(p) => (vec![p.raw], vec![p.output]),
            Producer::Affine(i) => {
                let r = &self.recipes.affine[*i];
                (r.inputs.iter().filter(|(_, k)| *k != 0).map(|(id, _)| *id).collect(), vec![r.raw])
            }
            Producer::Gelu(i) => {
                let g = &gu.gelu.gelu[*i];
                (vec![g.input], vec![g.output, g.histogram])
            }
            Producer::Gate(i) => {
                (vec![gu.gelu.gelu[*i].output, gu.products[*i].up], vec![gu.products[*i].raw])
            }
            Producer::Rope(i) => {
                let r = &a.rope.rotations[*i];
                (vec![rms.norms[r.norm].output], vec![r.raw])
            }
            Producer::Qk(i) => {
                let l = &a.layers[*i];
                (vec![l.q, l.k], vec![l.raw_score])
            }
            Producer::Pv(i) => {
                let l = &a.layers[*i];
                (vec![l.pi, l.v], vec![l.raw_output])
            }
            Producer::Softmax(i) => {
                let s = &self.softmax.layers[*i];
                (
                    vec![s.score],
                    vec![s.pi, s.maximum, s.difference, s.exponential, s.denominator, s.histogram],
                )
            }
            Producer::Softcap => {
                (vec![self.output.input], vec![self.output.output, self.output.histogram])
            }
            Producer::Argmax => (vec![self.output.output], vec![self.output.slack]),
        }
    }

    fn causal_order(&self, steps: Vec<Producer>) -> Result<Vec<Producer>, String> {
        let ports: Vec<_> = steps.iter().map(|s| self.ports(s)).collect();
        let mut owner = vec![None; self.bytes().widths.len()];
        for (i, (_, outputs)) in ports.iter().enumerate() {
            for &id in outputs {
                if owner.get_mut(id).ok_or("canonical output outside A")?.replace(i).is_some() {
                    return Err("canonical A source has two producers".into());
                }
            }
        }
        if owner.iter().any(Option::is_none) {
            return Err("canonical A source has no producer".into());
        }
        let mut consumers = vec![Vec::new(); steps.len()];
        let mut degree = vec![0; steps.len()];
        for (i, (inputs, _)) in ports.iter().enumerate() {
            let dependencies = inputs
                .iter()
                .map(|&id| {
                    owner.get(id).copied().flatten().ok_or("canonical input outside produced A")
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            degree[i] = dependencies.len();
            for producer in dependencies {
                consumers[producer].push(i);
            }
        }
        let mut ready: VecDeque<_> =
            degree.iter().enumerate().filter(|(_, n)| **n == 0).map(|(i, _)| i).collect();
        let mut steps: Vec<_> = steps.into_iter().map(Some).collect();
        let mut ordered = Vec::new();
        while let Some(i) = ready.pop_front() {
            ordered.push(steps[i].take().ok_or("canonical producer dispatched twice")?);
            for &c in &consumers[i] {
                degree[c] -= 1;
                if degree[c] == 0 {
                    ready.push_back(c);
                }
            }
        }
        if ordered.len() != steps.len() {
            return Err("canonical producer dependency cycle".into());
        }
        Ok(ordered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_native_affine_rows_cover_all_canonical_relations() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            assert_eq!(p.recipes.affine.len(), 181);
            for r in &p.recipes.affine {
                let columns = p.bytes().scalar.layout.sources[r.raw].cols;
                let x: Vec<_> = (0..columns).map(|i| [-32768, 32767, -1, 0, 1][i % 5]).collect();
                let y: Vec<_> = x.iter().rev().copied().collect();
                for coefficients in [[r.inputs[0].1, r.inputs[1].1], [1 << 30, -(1 << 30)], [0, 0]]
                {
                    let relation = Relation {
                        raw: r.raw,
                        inputs: [
                            (r.inputs[0].0, coefficients[0]),
                            (r.inputs[1].0, coefficients[1]),
                        ],
                    };
                    let raw = p.bytes().prepare_affine_row(&relation, [&x, &y]).unwrap();
                    for ((&value, &x), &y) in raw.iter().zip(&x).zip(&y) {
                        let expected = i128::from(coefficients[0]) * i128::from(x)
                            + i128::from(coefficients[1]) * i128::from(y);
                        assert_eq!(i128::from(value), expected);
                        assert!((-(1i64 << 47)..1i64 << 47).contains(&value));
                    }
                }
                assert!(p.bytes().prepare_affine_row(r, [&x[..columns - 1], &y]).is_err());
                let mut bad = y.clone();
                bad[0] = 32768;
                assert!(p.bytes().prepare_affine_row(r, [&x, &bad]).is_err());
                bad[0] = -32769;
                assert!(p.bytes().prepare_affine_row(r, [&bad, &y]).is_err());
                for coefficient in [i64::MIN, (1 << 30) + 1] {
                    let bad = Relation {
                        raw: r.raw,
                        inputs: [(r.inputs[0].0, coefficient), r.inputs[1]],
                    };
                    assert!(p.bytes().prepare_affine_row(&bad, [&x, &y]).is_err());
                }
                let bad = Relation { raw: r.inputs[0].0, inputs: r.inputs };
                assert!(p.bytes().prepare_affine_row(&bad, [&x, &y]).is_err());
            }
        }
    }

    #[test]
    fn c71_b12_rne_joint_bytes_canonical_geometry() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            let mut view_bits = Vec::new();
            let mut previous = 0;
            let mut previous_rows = 0;
            for step in &p.steps {
                if let Producer::Rne(pair) = step {
                    let (_, shape) = p.bytes().source_rne_view(pair.raw).unwrap();
                    let b = bits(shape[0]) + bits(shape[1]) + 3;
                    view_bits.push(b);
                    previous += kernel::byte_function::wire_bytes(b);
                    previous_rows += kernel::byte_function::required(b);
                }
            }
            assert_eq!(view_bits.len(), 892);
            let exact = kernel::byte_function::batch::unpadded_groups(&view_bits).unwrap();
            let mut ids: Vec<_> = exact.iter().flatten().copied().collect();
            ids.sort_unstable();
            assert_eq!(ids, (0..892).collect::<Vec<_>>());
            let dimensions: Vec<_> = exact
                .iter()
                .map(|group| {
                    let local: Vec<_> = group.iter().map(|&i| view_bits[i]).collect();
                    let (d, _) = kernel::byte_function::batch::geometry(&local).unwrap();
                    assert_eq!(1usize << d, local.iter().map(|&b| 1usize << b).sum::<usize>());
                    d
                })
                .collect();
            let exact_wire: usize =
                dimensions.iter().map(|&d| kernel::byte_function::batch::wire_bytes(d) + 6).sum();
            eprintln!("joint_RNE unpadded slot={slot} dimensions={dimensions:?} wire_with_frames={exact_wire}");
            eprintln!(
                "joint_RNE work slot={slot} separate_byte_cells={} padded_joint_byte_cells={}",
                view_bits.iter().map(|&b| 1u64 << b).sum::<u64>(),
                (1u64 << 34) + (1u64 << 33)
            );
            let groups = kernel::byte_function::batch::groups(&view_bits).unwrap();
            assert_eq!(
                groups.iter().flatten().copied().collect::<Vec<_>>(),
                (0..892).collect::<Vec<_>>()
            );
            let (mut joint, mut joint_rows) = (0, 0);
            let mut dimensions = Vec::new();
            for group in &groups {
                let local: Vec<_> = group.iter().map(|&i| view_bits[i]).collect();
                let (d, offsets) = kernel::byte_function::batch::geometry(&local).unwrap();
                let mut blocks: Vec<_> = offsets
                    .iter()
                    .zip(&local)
                    .map(|(&o, &b)| {
                        assert_eq!(o % (1usize << b), 0);
                        (o, o + (1usize << b))
                    })
                    .collect();
                blocks.sort_unstable();
                assert!(blocks.windows(2).all(|p| p[0].1 == p[1].0));
                assert!(blocks.last().unwrap().1 <= 1usize << d);
                dimensions.push(d);
                // Serialize actual joint Wire types at canonical shapes; synthetic values only.
                use kernel::wire::Wire;
                let mut encoded = Vec::new();
                encoded.extend(8u32.to_le_bytes());
                for i in 0..8 {
                    vec![[Fp3::ZERO; 5]; d + i].write(&mut encoded);
                    [Fp3::ZERO; 8].write(&mut encoded);
                }
                [Fp3::ZERO; 3].write(&mut encoded);
                let mut input = encoded.as_slice();
                let proof = kernel::byte_function::batch::Proof::read(&mut input).unwrap();
                assert!(input.is_empty());
                let mut output = Vec::new();
                proof.write(&mut output);
                assert_eq!(encoded, output);
                assert_eq!(encoded.len(), kernel::byte_function::batch::wire_bytes(d));
                joint += encoded.len();
                joint_rows += kernel::byte_function::batch::required(d);
            }
            let frames = 6 * groups.len();
            let saved = previous - joint - frames;
            let (_, _, old_rne) = p.rne_wire_bytes().unwrap();
            let lower = [47_841_180usize, 54_868_318, 61_797_384][slot] - saved;
            let upper = [65_053_244usize, 78_945_726, 92_723_304][slot] - saved;
            eprintln!("joint_RNE canonical slot={slot} view_bits={dimensions:?} old_functions={previous} joint={joint} extra_frames={frames} saved={saved} selected_RNE={} projected_total_lower={lower} projected_total_upper={upper} saved_fp3_rows={}",
                old_rne - previous + joint, previous_rows - joint_rows);
            assert!(saved > 25_000_000);
            assert!(upper > 35_000_000); // This candidate does not establish the 35 MB target.
        }
    }

    #[test]
    fn c71_b12_native_wire_rne_alone_exceeds_bounded_transport() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            let (sum, minimum, selected) = p.rne_wire_bytes().unwrap();
            assert_eq!(
                (sum, minimum, selected),
                [
                    (18935, 29371448, 30604688),
                    (18995, 29442008, 30675248),
                    (18995, 29442008, 30675248),
                ][slot]
            );
            assert_eq!(minimum, 892 * 7964 + 1176 * sum);
            assert!(selected >= minimum);
            assert!(minimum > kernel::wire::MAX_BYTES);
            eprintln!("slot={slot} RNE cell_bits_sum={sum} universal_wire_lower={minimum} selected_component_wire={selected}");
        }
    }

    #[test]
    fn c71_b12_native_rne_rows_cover_all_canonical_pairs_and_contexts() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        let q_input = s
            .attention
            .rope
            .gate_up
            .gelu
            .rms
            .norms
            .iter()
            .find(|n| n.operation == "q_norm")
            .unwrap()
            .input;
        exponents.insert(q_input, -1); // valid common scale map requiring left-shift RNE
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            assert!(p.recipes.matrix.iter().any(|pair| pair.shift < 0));
            let mut count = 0;
            for step in &p.steps {
                let Producer::Rne(pair) = step else {
                    continue;
                };
                let (raw, rounded) = match pair.shift {
                    i32::MIN..=-15 => (0, 0),
                    -14..=-1 => (1, 1 << -pair.shift),
                    0..=46 => (1 << pair.shift, 1),
                    47 => ((1 << 46) + 1, 1),
                    _ => (1, 0),
                };
                let columns = p.bytes().scalar.layout.sources[pair.raw].cols;
                let mut input: Vec<_> = (0..columns).map(|c| (c as i64 % 3 - 1) * raw).collect();
                let y = p.bytes().prepare_rne_row(&p.plan, pair, &input).unwrap();
                assert_eq!(
                    y,
                    (0..columns).map(|c| (c as i64 % 3 - 1) * rounded).collect::<Vec<_>>()
                );
                assert!(p.bytes().prepare_rne_row(&p.plan, pair, &input[..columns - 1]).is_err());
                input[0] = 1 << 47;
                assert!(p.bytes().prepare_rne_row(&p.plan, pair, &input).is_err());
                let bad = Pair { output: pair.raw, ..*pair };
                assert!(p.bytes().prepare_rne_row(&p.plan, &bad, &input).is_err());
                count += 1;
            }
            assert_eq!(count, 892);
        }
    }

    #[test]
    fn c71_b12_native_norm_rows_use_canonical_heads_and_common_integer_recipes() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        let p = Canonical::compile(0, &[0; 772], &exponents).unwrap();
        let rms = &p.sources.attention.rope.gate_up.gelu.rms;
        let mut checked = (0, 0);
        for (i, n) in rms.norms.iter().enumerate() {
            // A different magnitude/sign in every head catches accidental
            // normalization across heads. No full token/model witness exists.
            let mut input = vec![0; n.heads * n.columns];
            for h in 0..n.heads {
                input[h * n.columns + h % n.columns] =
                    (h as i64 + 1) * if h % 2 == 0 { 1 } else { -1 };
            }
            let weights: Vec<i16> =
                (0..n.columns).map(|c| if c % 2 == 0 { 2 } else { -1 }).collect();
            let w = n.cohort.map(|_| weights.as_slice());
            let (s, product, y) = n.prepare_row(p.recipes.rms[i], &input, w).unwrap();
            assert_eq!((s.len(), product.len(), y.len()), (n.heads, input.len(), input.len()));
            assert_eq!(p.recipes.rms[i], [0; 3]);
            for h in 0..n.heads {
                assert_eq!(s[h], (h as i64 + 1).pow(2));
                for c in 0..n.columns {
                    let index = h * n.columns + c;
                    assert_eq!(product[index], input[index] * w.map_or(1, |w| i64::from(w[c])));
                    assert_eq!(
                        Some(y[index]),
                        kernel::rms::tests::expected(
                            product[index],
                            s[h],
                            n.columns,
                            n.cohort.is_some(),
                            [1_000_000 * n.columns as u128, n.columns as u128, 1_000_000],
                        )
                    );
                }
            }
            assert!(n.prepare_row(p.recipes.rms[i], &input[..input.len() - 1], w).is_err());
            let wrong = if n.cohort.is_some() { None } else { Some(weights.as_slice()) };
            assert!(n.prepare_row(p.recipes.rms[i], &input, wrong).is_err());
            input[0] = -32768;
            assert!(n.prepare_row(p.recipes.rms[i], &input, w).is_err());
            if n.cohort.is_some() {
                checked.0 += 1;
            } else {
                checked.1 += 1;
            }
        }
        assert_eq!(checked, (361, 60));
        // Exact signed half ties use no floating point.
        let integer = kernel::rms::Integer::new(2, 0, 0, 4, true).unwrap();
        for (p, y) in [(1, 62), (3, 188), (-1, -62), (-3, -188), (0, 0)] {
            assert_eq!(integer.round(p, 0).unwrap(), y);
        }
        let small = kernel::rms::Integer::new(2, 0, 0, 11, true).unwrap();
        assert_eq!(small.round(1, 0).unwrap(), 0);
        assert_eq!(small.round(-1, 0).unwrap(), 0);
        assert!(integer.row(&[0, 0], Some(&[i16::MIN, 0])).is_err());
        assert!(integer.row(&[0, 0], Some(&[1])).is_err());
        assert!(integer.round(i64::MIN, 0).is_err());
        assert!(integer.round(32767i64.pow(2), 0).is_err());
        assert!(kernel::rms::Integer::new(5376, 128, 128, -128, true).is_err());
    }

    #[test]
    fn c71_b12_native_canonical_all_sources_have_causal_producers_across_three_contexts() {
        let plan = super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
        }
        for slot in 0..3 {
            let mut p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            let mut produced = BTreeSet::new();
            let mut matrix = 0;
            let mut norms = 0;
            let mut rounding = 0;
            for step in &p.steps {
                let (inputs, outputs) = p.ports(step);
                assert!(inputs.iter().all(|i| produced.contains(i)));
                for id in outputs {
                    assert!(produced.insert(id));
                }
                match step {
                    Producer::Matrix(_) => matrix += 1,
                    Producer::Norm(_) => norms += 1,
                    Producer::Rne(_) => rounding += 1,
                    _ => {}
                }
            }
            assert_eq!((matrix, norms, rounding), (411, 421, 892));
            assert_eq!(p.steps.len(), 2328);
            assert_eq!(produced.len(), 3471);
            assert_eq!(p.plan.cohorts.len(), 773);
            assert_eq!(p.sources.attention.rope.old, 150 * slot);
            assert_eq!(bits(p.bytes().live), 34);
            let rms = &p.sources.attention.rope.gate_up.gelu.rms;
            let mut aliases = 0;
            for n in &rms.norms {
                if n.operation == "v_norm" && n.layer.unwrap() % 6 == 5 {
                    let k = rms
                        .norms
                        .iter()
                        .find(|k| k.layer == n.layer && k.operation == "k_norm")
                        .unwrap();
                    assert_eq!(n.input, k.input);
                    assert_ne!(n.output, k.output);
                    aliases += 1;
                }
            }
            assert_eq!(aliases, 10);
            // A complete list of counts is insufficient: omitted, duplicated or
            // cyclic producers must fail even with a canonical descriptor set.
            let steps = std::mem::take(&mut p.steps);
            let mut missing = p.causal_order(steps).unwrap();
            missing.pop();
            assert!(p.causal_order(missing).is_err());
            let mut p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            let mut duplicated = std::mem::take(&mut p.steps);
            duplicated.push(Producer::Embedding);
            assert!(p.causal_order(duplicated).is_err());
            let mut p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
            let first = &mut p.recipes.matrix[0];
            let raw = first.raw;
            p.sources.attention.rope.gate_up.gelu.rms.bytes.scalar.input_sources[raw - 1] =
                first.output;
            let steps = std::mem::take(&mut p.steps);
            assert!(p.causal_order(steps).is_err());
        }
        assert!(Canonical::compile(3, &[0; 772], &exponents).is_err());
    }
}
