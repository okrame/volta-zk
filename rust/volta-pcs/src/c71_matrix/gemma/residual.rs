//! Canonical residual stream and exact public BF16 scalars. Raw identities
//! are one zero form in A; every output RNE also closes its original A MACs.

use super::*;
use bytes::{affine::Relation, quantize::Pair};

pub(in crate::c71_matrix) struct Operation {
    pub name: String,
    pub raw: usize,
    pub output: usize,
    pub inputs: [usize; 2],
    pub scale: Option<(i64, i32)>, // exact public mu * 2^a, None for residual sum
}

pub(in crate::c71_matrix) struct Sources {
    pub attention: attention::Sources,
    pub operations: Vec<Operation>,
}

fn scalar(bits: u16) -> Result<(i64, i32), String> {
    let encoded = (bits >> 7) & 255;
    let power = if encoded == 0 { -133 } else { i32::from(encoded) - 134 };
    let mu = crate::gemma31b_bf16::quantize(bits, power)
        .map_err(|e| format!("public scalar is not a finite BF16 dyadic: {e:?}"))?;
    Ok((i64::from(mu), power))
}

impl Plan {
    pub fn residual_sources(&self) -> Result<Sources, String> {
        self.residual_sources_at(0)
    }

    pub fn residual_sources_at(&self, old: usize) -> Result<Sources, String> {
        let attention = self.attention_sources_at(old)?;
        let rms = &attention.rope.gate_up.gelu.rms;
        let base = rms.bytes.scalar.layout.sources.len();
        let get = |layer: Option<u64>, op: &str| {
            rms.norms
                .iter()
                .find(|n| n.layer == layer && n.operation == op)
                .ok_or("residual original RMS route missing")
        };
        let lookup = self.cohorts.first().ok_or("residual embedding lookup missing")?;
        if lookup.kind != Kind::Lookup || [lookup.rows, lookup.columns] != [150, 5376] {
            return Err("residual stream differs from pinned full hidden shape".into());
        }
        let mut operations = vec![Operation {
            name: "global/embedding_scale".into(),
            raw: 0,
            output: get(Some(0), "input_rms")?.input,
            inputs: [0, 0],
            scale: Some(scalar(0x4293)?),
        }];
        let scalars =
            compile_pinned_gemma31b_frontend().map_err(|e| e.to_string())?.public_layer_scalars;
        for layer in 0..60 {
            let input = get(Some(layer), "input_rms")?.input;
            let post_attention = get(Some(layer), "post_attention_rms")?.output;
            let attention_output = get(Some(layer), "pre_ffw_rms")?.input;
            let post_ffw = get(Some(layer), "post_ffw_rms")?.output;
            let ffw_output = base + layer as usize;
            let output = if layer == 59 {
                get(None, "final_rms")?.input
            } else {
                get(Some(layer + 1), "input_rms")?.input
            };
            if scalars[layer as usize].layer != layer as u8 {
                return Err("residual public scalar layer differs".into());
            }
            operations.extend([
                Operation {
                    name: format!("{layer}/attention_residual_add"),
                    raw: 0,
                    output: attention_output,
                    inputs: [input, post_attention],
                    scale: None,
                },
                Operation {
                    name: format!("{layer}/ffw_residual_add"),
                    raw: 0,
                    output: ffw_output,
                    inputs: [attention_output, post_ffw],
                    scale: None,
                },
                Operation {
                    name: format!("{layer}/layer_scalar_mul"),
                    raw: 0,
                    output,
                    inputs: [ffw_output, ffw_output],
                    scale: Some(scalar(scalars[layer as usize].bf16_bits)?),
                },
            ]);
        }
        let mut extra: Vec<_> =
            (0..60).map(|l| (format!("X/{l}/ffw_residual_add"), 150, 5376, 2)).collect();
        for (i, op) in operations.iter_mut().enumerate() {
            op.raw = base + 60 + i;
            extra.push((format!("R/{}", op.name), 150, 5376, 6));
        }
        let attention = attention.append(extra)?;
        let bytes = &attention.rope.gate_up.gelu.rms.bytes;
        for op in &operations {
            for id in [op.raw, op.output, op.inputs[0], op.inputs[1]] {
                let s = &bytes.scalar.layout.sources[id];
                if [s.rows, s.cols] != [150, 5376] {
                    return Err("residual route changes its full hidden tensor".into());
                }
            }
        }
        Ok(Sources { attention, operations })
    }
}

impl Sources {
    /// Exponents come from the SAME fixed public quantization profile as
    /// P0/RMS/RNE. This method does not calibrate or certify a supplied map.
    pub fn recipes(
        &self,
        exponents: &BTreeMap<usize, i32>,
    ) -> Result<(Vec<Relation>, Vec<Pair>), String> {
        let get = |id| {
            exponents
                .get(&id)
                .copied()
                .filter(|e| (-128..=128).contains(e))
                .ok_or("residual public source exponent missing or exceeds envelope")
        };
        let (mut linear, mut rne) = (Vec::new(), Vec::new());
        for op in &self.operations {
            let e = get(op.output)?;
            let a = get(op.inputs[0])?;
            let (coefficients, shift) = if let Some((mu, power)) = op.scale {
                ([mu, 0], e - a - power)
            } else {
                let b = get(op.inputs[1])?;
                let low = a.min(b);
                if a.max(b) - low > 30 {
                    return Err("residual aligned raw exceeds the public i48 envelope".into());
                }
                ([1i64 << (a - low), 1i64 << (b - low)], e - low)
            };
            linear.push(Relation {
                raw: op.raw,
                inputs: [(op.inputs[0], coefficients[0]), (op.inputs[1], coefficients[1])],
            });
            rne.push(Pair { raw: op.raw, output: op.output, shift: shift.clamp(-15, 48) });
        }
        Ok((linear, rne))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::gemma::caller::P0Statement;
    use crate::c71_matrix::{signed, AttemptContext, C61Commitment, Fs};

    #[test]
    fn c71_b12_gemma_residual_routes_keep_original_stream_and_exact_public_scalars() {
        let plan = compile().unwrap();
        let sources = plan.residual_sources().unwrap();
        let bytes = &sources.attention.rope.gate_up.gelu.rms.bytes;
        assert_eq!(sources.operations.len(), 181);
        assert_eq!(sources.operations[0].scale, Some((147, -1)));
        assert_eq!(bytes.scalar.layout.sources.len(), 3167);
        assert_eq!(bytes.live, 12613738638);
        assert_eq!(bits(bytes.live), 34);
        for layer in 0..60 {
            let [a, f, s] = std::array::from_fn(|i| &sources.operations[1 + 3 * layer + i]);
            assert_eq!(f.inputs[0], a.output);
            assert_eq!(s.inputs, [f.output, f.output]);
            assert_eq!(
                bytes.scalar.layout.sources[s.inputs[0]].name,
                format!("X/{layer}/ffw_residual_add")
            );
            assert_eq!(
                bytes.scalar.layout.sources[s.output].name,
                format!("X/{layer}/layer_scalar_mul")
            );
            if layer < 59 {
                assert_eq!(sources.operations[1 + 3 * (layer + 1)].inputs[0], s.output);
            }
            assert!(s.scale.unwrap().0.abs() <= 255);
        }
        let exponents: BTreeMap<_, _> = sources
            .operations
            .iter()
            .flat_map(|op| [op.output, op.inputs[0], op.inputs[1]])
            .map(|id| (id, 0))
            .collect();
        let (relations, pairs) = sources.recipes(&exponents).unwrap();
        assert_eq!(pairs.len(), 181);
        assert_eq!(pairs[0].shift, 1);
        assert_eq!(relations[0].inputs, [(0, 147), (0, 0)]);
        let root = C61Commitment::new(vec![[1; 32]]);
        let profile = [2; 32];
        let context = P0Statement {
            weights: &root,
            auxiliary: &root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &bytes.scalar,
            quantization: [3; 32],
            tokens: &[0; 150],
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [3; 32],
            },
        };
        let mut fs = Fs::new(b"canonical affine metadata only; no calibrated profile", 10000);
        let (form, _) = bytes.affine_zero_form(&plan, &context, &relations, &mut fs).unwrap();
        assert_eq!(fs.requests(), 28);
        assert_eq!(form.len(), 7956);
        let point = |n| (0..n).map(|i| signed(i as i64 + 3)).collect::<Vec<_>>();
        let pending: Vec<_> = pairs
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let shape = bytes.source_rne_view(p.raw).unwrap().1;
                assert_eq!(shape, [150, 5376]);
                bytes::quantize::Opening {
                    output_point: point(21),
                    output: 2 * i,
                    raw_point: point(24),
                    raw: 2 * i + 1,
                }
            })
            .collect();
        let (forms, _, targets) = bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
        assert_eq!(forms.iter().map(Vec::len).sum::<usize>(), 6516);
        assert_eq!(targets, (0..362).collect::<Vec<_>>());
        assert!(bytes.table_rne_required(&plan, &pairs).is_err()); // full domain is not native D7
        assert_eq!(4189 + 1 + 362, 4552);
        assert_eq!(65067 + 7956 + 6516, 79539);
        assert!(4552 <= super::super::super::linear::MAX_TARGETS);
        assert!(79539 <= super::super::super::linear::MAX_CUBES);
        assert!(sources.recipes(&BTreeMap::new()).is_err());
        let mut invalid = exponents;
        invalid.insert(sources.operations[1].inputs[0], 31);
        assert!(sources.recipes(&invalid).is_err());
        assert!(scalar(0x7f80).is_err());
    }
}
