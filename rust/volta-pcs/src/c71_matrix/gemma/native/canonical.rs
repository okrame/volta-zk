//! Verifier-owned causal producer schedule over the pinned final A descriptors.
//! Compiles public metadata only; it does not materialize a D34/D35 witness.
use super::*;
use std::collections::{BTreeSet, VecDeque};

#[path = "canonical_state.rs"]
mod state;
#[path = "canonical_verify.rs"]
mod verify;

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
