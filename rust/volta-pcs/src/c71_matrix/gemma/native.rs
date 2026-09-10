//! Bounded native refinement of the composed B12 acceptance machine.
//! The explicit two-token, one-layer profile exercises every producer family.
//! It is not the pinned checkpoint, a new security bound, or a production API.

use super::rms;
use super::*;
use crate::c71_matrix::{self as kernel, *};
use bytes::{affine::Relation, kv, quantize::Pair};

mod prepare;
mod protocol;

const TOKENS: usize = 2;
const DOMAIN_W: Domain = Domain::Flat(10);
const DOMAIN_A: Domain = Domain::Flat(12);
const GELU: [i16; 5] = [0, 0, 0, 1, 2]; // certified (eX,eY)=(0,0), X=-2..2
const SOFTCAP: [i16; 9] = [-4, -3, -2, -1, 0, 1, 2, 3, 4];
const EXP30: [i32; 8] =
    [1073741824, 395007542, 145315154, 53458458, 19666268, 7234816, 2661540, 979126];
// C71-RoPE-Q30-v1, active pair j=0, absolute positions 0..5.
const Q30: [[i32; 2]; 6] = [
    [1073741824, 0],
    [580145183, 903522590],
    [-446834263, 976350678],
    [-1062996349, 151526455],
    [-701844494, -812610492],
    [304579952, -1029637100],
];

enum Step {
    Embedding,
    Matrix(usize),
    Norm(usize),
    Rne(Pair),
    Affine(usize),
    Gelu,
    Gate,
    Rope(usize),
    Qk,
    Softmax,
    Pv,
    Softcap,
    Argmax,
}

struct Profile {
    plan: Plan,
    rms: rms::Sources,
    matrix: Vec<Pair>,
    affine: Vec<Relation>,
    residual: Vec<Pair>,
    rotations: [[usize; 3]; 2], // raw, output, original RMS output
    gate: [usize; 4],           // raw, output, GELU Y, quantized up
    gelu: output::Output,
    output: output::Output,
    softmax: softmax::Softmax,
    attention: [usize; 3], // raw score, raw PV, quantized PV
    steps: Vec<Step>,
    digest: [u8; 32],
    old: usize,
}

impl Profile {
    /// Verifier-owned compiler: no layout, producer, scale or table from a certificate.
    fn small(slot: usize) -> Result<Self, String> {
        if slot >= 3 {
            return Err("fixed run has only three slots".into());
        }
        let mut sources =
            vec![Source { name: "embedding/head".into(), rows: 2, cols: 2, packed_offset: 0 }];
        let definitions = [
            ("embedding_lookup", Kind::Lookup, "token_input"),
            ("input_rms", Kind::Norm, "embedding_scale"),
            ("q_proj", Kind::Matrix, "input_rms"),
            ("q_norm", Kind::Norm, "q_proj"),
            ("k_proj", Kind::Matrix, "input_rms"),
            ("k_norm", Kind::Norm, "k_proj"),
            ("v_source", Kind::Matrix, "input_rms"),
            ("o_proj", Kind::Matrix, "pv_matmul"),
            ("post_attention_rms", Kind::Norm, "o_proj"),
            ("pre_ffw_rms", Kind::Norm, "attention_residual_add"),
            ("gate_proj", Kind::Matrix, "pre_ffw_rms"),
            ("up_proj", Kind::Matrix, "pre_ffw_rms"),
            ("down_proj", Kind::Matrix, "gate_up_mul"),
            ("post_ffw_rms", Kind::Norm, "down_proj"),
            ("final_rms", Kind::Norm, "layer_scalar_mul"),
            ("lm_head", Kind::Matrix, "final_rms"),
        ];
        let mut cohorts = Vec::new();
        let mut h = blake3::Hasher::new();
        h.update(b"C71B12-small-Gemma-v1;1-layer;hidden2;heads1;vocab2;prompt1+generated1;final-KV;embedding-scale1;layer-scale1;RMS-eps1e-6;all-exponents0;Pi=-14\0");
        for (i, (op, kind, producer)) in definitions.into_iter().enumerate() {
            let tensor = if i == 0 || op == "lm_head" {
                0
            } else {
                let last = sources.last().unwrap();
                let offset = last.packed_offset + last.rows * last.cols;
                let id = sources.len();
                sources.push(Source {
                    name: op.into(),
                    rows: if kind == Kind::Norm { 1 } else { 2 },
                    cols: 2,
                    packed_offset: offset,
                });
                id
            };
            let layer = (!matches!(op, "embedding_lookup" | "final_rms" | "lm_head")).then_some(0);
            let producer_layer =
                if matches!(producer, "token_input" | "final_rms") { None } else { Some(0) };
            h.update(&(op.len() as u64).to_le_bytes());
            h.update(op.as_bytes());
            h.update(&(producer.len() as u64).to_le_bytes());
            h.update(producer.as_bytes());
            cohorts.push(Cohort {
                layer,
                operation: op.into(),
                tensor,
                kind,
                rows: if matches!(op, "final_rms" | "lm_head") { 1 } else { 2 },
                columns: 2,
                inner: if kind == Kind::Matrix { 2 } else { 0 },
                heads: 1,
                producer: (producer_layer, producer.into()),
                members: Vec::new(),
                cut_byte_offset: 0,
            });
        }
        for x in GELU.into_iter().chain(SOFTCAP) {
            h.update(&x.to_le_bytes());
        }
        for x in EXP30.into_iter().chain(Q30.into_iter().flatten()) {
            h.update(&x.to_le_bytes());
        }
        let digest = *h.finalize().as_bytes();
        let (tiles, live) = tiles(&sources);
        let plan = Plan { sources, cohorts, tiles, live, layout_digest: digest };
        let rms = plan.rms_sources()?;
        let by_norm = |op: &str| rms.norms.iter().position(|n| n.operation == op).unwrap();
        let ni = [
            "input_rms",
            "q_norm",
            "k_norm",
            "v_norm",
            "post_attention_rms",
            "pre_ffw_rms",
            "post_ffw_rms",
            "final_rms",
        ]
        .map(by_norm);
        let mut extra = Vec::new();
        let base = rms.bytes.widths.len();
        let mut add = |name: &str, rows, cols, width| {
            let id = base + extra.len();
            extra.push((name.into(), rows, cols, width));
            id
        };
        let mut rotations = [[0; 3]; 2];
        for (j, op) in ["Q", "K"].into_iter().enumerate() {
            rotations[j] = [
                add(&format!("R/{op}/RoPE"), 2, 2, 6),
                add(&format!("Y/{op}/RoPE"), 2, 2, 2),
                rms.norms[ni[j + 1]].output,
            ];
        }
        let old = TOKENS * slot;
        let raw_score = add("R/QK", 2, old + 2, 6);
        let score = add("Y/QK", 2, old + 2, 2);
        let pi = add("Pi", 2, old + 2, 2);
        let raw_pv = add("R/PV", 2, 2, 6);
        let pv = rms.bytes.scalar.input_sources[7 - 1];
        let gelu = output::Output {
            raw: 10,
            input: add("X/GELU", 2, 2, 2),
            output: add("Y/GELU", 2, 2, 2),
            histogram: add("M/GELU", 1, GELU.len(), 4),
            slack: 0,
            lower: -2,
            token_offset: 0,
        };
        let up = add("X/up", 2, 2, 2);
        let gate =
            [add("R/gate-up", 2, 2, 6), rms.bytes.scalar.input_sources[12 - 1], gelu.output, up];
        let ffw = add("Y/ffw-add", 2, 2, 2);
        let affine = vec![
            Relation { raw: add("R/embedding-scale", 2, 2, 6), inputs: [(0, 1), (0, 0)] },
            Relation {
                raw: add("R/attention-add", 2, 2, 6),
                inputs: [(rms.norms[ni[0]].input, 1), (rms.norms[ni[4]].output, 1)],
            },
            Relation {
                raw: add("R/ffw-add", 2, 2, 6),
                inputs: [(rms.norms[ni[5]].input, 1), (rms.norms[ni[6]].output, 1)],
            },
            Relation { raw: add("R/layer-scale", 2, 2, 6), inputs: [(ffw, 1), (ffw, 0)] },
        ];
        let residual = affine
            .iter()
            .zip([rms.norms[ni[0]].input, rms.norms[ni[5]].input, ffw, rms.norms[ni[7]].input])
            .map(|(r, output)| Pair { raw: r.raw, output, shift: 0 })
            .collect::<Vec<_>>();
        let output = output::Output {
            raw: 15,
            input: add("X/head", 1, 2, 2),
            output: add("Y/softcap", 1, 2, 2),
            histogram: add("M/softcap", 1, SOFTCAP.len(), 4),
            slack: add("U/argmax", 1, 2, 2),
            lower: -4,
            token_offset: 1,
        };
        let softmax = softmax::Softmax {
            layers: vec![softmax::Layer {
                score,
                pi,
                maximum: add("M/maximum", 2, 1, 2),
                difference: add("D/EXP30", 2, old + 2, 2),
                exponential: add("E/EXP30", 2, old + 2, 4),
                denominator: add("Z/EXP30", 2, 1, 6),
                histogram: add("M/EXP30", 1, EXP30.len(), 4),
            }],
            heads: 1,
            queries: 2,
            old,
        };
        let matrix = [2, 4, 6, 7, 10, 11, 12, 15]
            .into_iter()
            .zip([
                rms.norms[ni[1]].input,
                rms.norms[ni[2]].input,
                rms.norms[ni[3]].input,
                rms.norms[ni[4]].input,
                gelu.input,
                up,
                rms.norms[ni[6]].input,
                output.input,
            ])
            .map(|(raw, output)| Pair { raw, output, shift: 0 })
            .collect::<Vec<_>>();
        let rms = rms.append(extra)?;
        if rms.bytes.live > 1 << 12 {
            return Err("small native A exceeds D12 budget".into());
        }
        let mut steps =
            vec![Step::Embedding, Step::Affine(0), Step::Rne(residual[0]), Step::Norm(ni[0])];
        for (m, n) in [(0, ni[1]), (1, ni[2]), (2, ni[3])] {
            steps.extend([Step::Matrix(matrix[m].raw), Step::Rne(matrix[m]), Step::Norm(n)]);
        }
        for (j, r) in rotations.iter().enumerate() {
            steps.extend([Step::Rope(j), Step::Rne(Pair { raw: r[0], output: r[1], shift: 30 })]);
        }
        steps.extend([
            Step::Qk,
            Step::Rne(Pair { raw: raw_score, output: score, shift: 0 }),
            Step::Softmax,
            Step::Pv,
            Step::Rne(Pair { raw: raw_pv, output: pv, shift: 14 }),
            Step::Matrix(7),
            Step::Rne(matrix[3]),
            Step::Norm(ni[4]),
            Step::Affine(1),
            Step::Rne(residual[1]),
            Step::Norm(ni[5]),
            Step::Matrix(10),
            Step::Rne(matrix[4]),
            Step::Gelu,
            Step::Matrix(11),
            Step::Rne(matrix[5]),
            Step::Gate,
            Step::Rne(Pair { raw: gate[0], output: gate[1], shift: 0 }),
            Step::Matrix(12),
            Step::Rne(matrix[6]),
            Step::Norm(ni[6]),
            Step::Affine(2),
            Step::Rne(residual[2]),
            Step::Affine(3),
            Step::Rne(residual[3]),
            Step::Norm(ni[7]),
            Step::Matrix(15),
            Step::Rne(matrix[7]),
            Step::Softcap,
            Step::Argmax,
        ]);
        let p = Self {
            plan,
            rms,
            matrix,
            affine,
            residual,
            rotations,
            gate,
            gelu,
            output,
            softmax,
            attention: [raw_score, raw_pv, pv],
            steps,
            digest,
            old,
        };
        // Every source has exactly one producer, including histograms and raw cuts.
        let mut owners = vec![0u8; p.bytes().widths.len()];
        for step in &p.steps {
            for id in p.outputs(step) {
                owners[id] += 1;
            }
        }
        if owners.iter().any(|&n| n != 1) {
            return Err(format!("native producer coverage differs: {owners:?}"));
        }
        Ok(p)
    }

    fn bytes(&self) -> &bytes::Bytes {
        &self.rms.bytes
    }
    fn outputs(&self, step: &Step) -> Vec<usize> {
        match step {
            Step::Embedding => vec![0],
            Step::Matrix(i) => vec![*i],
            Step::Norm(i) => {
                let n = &self.rms.norms[*i];
                n.cohort.into_iter().chain([n.statistic, n.output]).collect()
            }
            Step::Rne(p) => vec![p.output],
            Step::Affine(i) => vec![self.affine[*i].raw],
            Step::Gelu => vec![self.gelu.output, self.gelu.histogram],
            Step::Gate => vec![self.gate[0]],
            Step::Rope(i) => vec![self.rotations[*i][0]],
            Step::Qk => vec![self.attention[0]],
            Step::Pv => vec![self.attention[1]],
            Step::Softcap => vec![self.output.output, self.output.histogram],
            Step::Argmax => vec![self.output.slack],
            Step::Softmax => {
                let s = &self.softmax.layers[0];
                vec![s.pi, s.maximum, s.difference, s.exponential, s.denominator, s.histogram]
            }
        }
    }
}
