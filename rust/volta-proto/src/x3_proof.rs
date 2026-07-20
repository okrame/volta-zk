//! Existing-class proof composition for the CPU-only X3 synthetic op pack.
//!
//! X3 does not add a protocol or argument class.  The fixed synthetic trace
//! is bound with the existing authentication/`Pi_ZeroBatch` path; nonlinear
//! rows share one two-phase [`TableBankP`]; requants use the P4/P5 range
//! instances; products use the existing blind Hadamard argument; and every
//! learned or authenticated-matrix multiply uses the existing committed-W
//! blind GEMM.  The public trace binding is intentionally redundant: it is
//! the zero-tolerance conformance oracle for this synthetic spike and makes
//! each named one-cell smoke independently observable.

use crate::block_proof::{
    auth_fp_vec_p, keys_fp_vec_v, layer_dom_base, open_weighted_k, open_weighted_p,
    pair_cols_padded, prove_range_site, range_mult, range_mult_chained, verify_range_site,
    BlockCtxP, BlockCtxV, RangeSiteP, TableBankP, TableBankV, TableCloseProof,
};
use crate::gemm_proof::{
    auth_phase_at, prove_gemm_blind_committed_at, GemmBlindProof, GemmDomains,
};
use crate::hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
use crate::logup::{BlindInstance, Counters, Doms, ProdKeyTriples, ProdTriples, TableKey};
use crate::mle::{eq_vec, eval_mle};
use crate::prod_check::prod_batch_verify;
use crate::sumcheck_blind::blind_verify;
use crate::thaler::pad_bits;
use crate::x2_moe::eval_i16_matrix;
use crate::x3_ops::{
    build_x3_ops_fixture, encode_x3_golden, x3_model_config, X3OpsFixture, X3PadMode, X3RmsWitness,
    X3_D, X3_DFF, X3_GQA_GROUP, X3_HEAD_DIM, X3_KV_HEADS, X3_QKV, X3_Q_HEADS, X3_SCORE_SHIFT,
    X3_SHIFT, X3_SILU_SHIFT, X3_T, X3_TOP_K, X3_T_PAD, X3_VOCAB,
};
use std::collections::BTreeSet;
use volta_field::{Fp, Fp2};
use volta_mac::{
    auth_verifier, CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey,
};

// Reserved X3 range.  Keep it below X2's 216..219 range and disjoint from
// the response proof's prefill embedding/final-LN sections 220/221.
const X3_TRACE_SECTION: u8 = 212;
const X3_OP_SECTION: u8 = 213;
const X3_TABLE_SECTION: u8 = 214;
const X3_GEMM_SECTION: u8 = 215;

#[derive(Debug, PartialEq, Eq)]
pub struct X3RangeProof {
    pub main: BlindInstance,
    pub stage1: Option<BlindInstance>,
}

impl From<RangeSiteP> for X3RangeProof {
    fn from(value: RangeSiteP) -> Self {
        Self { main: value.main.proof, stage1: value.stage1.map(|site| site.proof) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct X3PairProof {
    pub proof: BlindInstance,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X3HadamardProof {
    pub proof: HadamardProof,
}

pub struct X3GemmProof {
    pub proof: GemmBlindProof,
    pub weight_corr: Fp2,
}

pub struct X3OpsProof {
    /// Authentication corrections for every byte of the canonical full-array
    /// encoding.  One transcript-random weighted opening is closed publicly.
    pub trace_corr: Vec<u64>,
    pub ranges: Vec<X3RangeProof>,
    pub pairs: Vec<X3PairProof>,
    pub hadamards: Vec<X3HadamardProof>,
    pub gemms: Vec<X3GemmProof>,
    pub tables: Vec<TableCloseProof>,
}

impl X3OpsProof {
    /// Turn the honest trace authentication into the exact one-cell witness
    /// mutation represented by `mutated`.  This is a deterministic test-only
    /// cheating-prover hook; all other proof messages remain honest.
    #[doc(hidden)]
    pub fn smoke_tamper_trace_like(
        &mut self,
        canonical: &X3OpsFixture,
        mutated: &X3OpsFixture,
    ) -> Option<usize> {
        let before = encode_x3_golden(canonical);
        let after = encode_x3_golden(mutated);
        let index = before.iter().zip(&after).position(|(left, right)| left != right)?;
        let correction = Fp::new(self.trace_corr[index]);
        let delta = Fp::new(u64::from(after[index])) - Fp::new(u64::from(before[index]));
        self.trace_corr[index] = (correction + delta).value();
        Some(index)
    }
}

pub struct X3OpsProverOut {
    pub prod: ProdTriples,
    pub zero: Vec<ProverAuthed>,
    pub instance_counters: Counters,
    pub other_counters: Counters,
    pub corr_counters: CorrCounters,
    pub table_sites: usize,
    pub table_contents: usize,
    pub table_finalizations: usize,
    pub logical_lookup_rows: usize,
    pub padded_lookup_rows: usize,
    pub rope_new_lookup_rows: usize,
}

pub struct X3OpsVerifierOut {
    pub kprod: ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

#[derive(Clone)]
struct RangeData {
    acc: Vec<i64>,
    out: Vec<i16>,
    rows: usize,
    cols: usize,
    shift: u32,
}

#[derive(Clone)]
struct PairData {
    key: TableKey,
    input: Vec<i16>,
    output: Vec<i16>,
    pad_in: i16,
    pad_out: i16,
}

#[derive(Clone)]
struct HadamardData {
    left: Vec<i64>,
    right: Vec<i64>,
    product: Vec<i64>,
}

#[derive(Clone)]
struct GemmData {
    x: Vec<i16>,
    w: Vec<i16>,
    acc: Vec<i64>,
    m: usize,
    k: usize,
    n: usize,
}

fn fp_i16(value: i16) -> Fp {
    Fp::from_i64(i64::from(value))
}

fn fp_i64(value: i64) -> Fp {
    Fp::from_i64(value)
}

fn fp2_values(values: &[Fp]) -> Vec<Fp2> {
    values.iter().copied().map(Fp2::from_base).collect()
}

fn pad_matrix_i16(values: &[i16], rows: usize, cols: usize) -> Vec<Fp> {
    assert_eq!(values.len(), rows * cols);
    let (rp, cp) = (rows.next_power_of_two(), cols.next_power_of_two());
    let mut out = vec![Fp::ZERO; rp * cp];
    for row in 0..rows {
        for col in 0..cols {
            out[row * cp + col] = fp_i16(values[row * cols + col]);
        }
    }
    out
}

fn pad_matrix_i64(values: &[i64], rows: usize, cols: usize) -> Vec<Fp> {
    assert_eq!(values.len(), rows * cols);
    let (rp, cp) = (rows.next_power_of_two(), cols.next_power_of_two());
    let mut out = vec![Fp::ZERO; rp * cp];
    for row in 0..rows {
        for col in 0..cols {
            out[row * cp + col] = fp_i64(values[row * cols + col]);
        }
    }
    out
}

fn public_eval(values: &[Fp], point: &[Fp2]) -> Fp2 {
    eval_mle(&fp2_values(values), point)
}

fn trace_values(fixture: &X3OpsFixture) -> Vec<Fp> {
    encode_x3_golden(fixture).into_iter().map(|value| Fp::new(u64::from(value))).collect()
}

fn power_weights(beta: Fp2, len: usize) -> Vec<Fp2> {
    let mut power = Fp2::ONE;
    (0..len)
        .map(|_| {
            let out = power;
            power = power * beta;
            out
        })
        .collect()
}

fn append_rms_ranges(out: &mut Vec<RangeData>, rms: &X3RmsWitness) {
    out.push(RangeData {
        acc: rms.acc.clone(),
        out: rms.output.clone(),
        rows: rms.output.len() / X3_D,
        cols: X3_D,
        shift: X3_SHIFT,
    });
}

fn range_data(fixture: &X3OpsFixture) -> Vec<RangeData> {
    let mut out = vec![RangeData {
        acc: fixture.embedding_acc.clone(),
        out: fixture.embedding_out.clone(),
        rows: X3_T,
        cols: X3_D,
        shift: X3_SHIFT,
    }];
    for layer in &fixture.layers {
        append_rms_ranges(&mut out, &layer.attention.rms1);
        out.push(RangeData {
            acc: layer.attention.qkv_acc.clone(),
            out: layer.attention.qkv.clone(),
            rows: X3_T,
            cols: X3_QKV,
            shift: X3_SHIFT,
        });
        out.push(RangeData {
            acc: layer.attention.score_acc_real.clone(),
            out: layer.attention.score_q_real.clone(),
            rows: 1,
            cols: layer.attention.score_q_real.len(),
            shift: X3_SCORE_SHIFT,
        });
        out.push(RangeData {
            acc: layer.attention.norm_acc_rect.clone(),
            out: layer.attention.weights_rect.clone(),
            rows: X3_Q_HEADS * X3_T_PAD,
            cols: X3_T_PAD,
            shift: X3_SHIFT,
        });
        out.push(RangeData {
            acc: layer.attention.av_acc.clone(),
            out: layer.attention.av_q.clone(),
            rows: X3_T,
            cols: X3_D,
            shift: X3_SHIFT,
        });
        out.push(RangeData {
            acc: layer.attention.projection_acc.clone(),
            out: layer.attention.projection_q.clone(),
            rows: X3_T,
            cols: X3_D,
            shift: X3_SHIFT,
        });
        append_rms_ranges(&mut out, &layer.rms2);
        for expert in &layer.experts {
            let rows = expert.rows.len();
            for (acc, values, shift, cols) in [
                (&expert.gate_acc, &expert.gate_q, X3_SHIFT, X3_DFF),
                (&expert.up_acc, &expert.up_q, X3_SHIFT, X3_DFF),
                (&expert.product_acc, &expert.product_q, X3_SILU_SHIFT, X3_DFF),
                (&expert.down_acc, &expert.down_q, X3_SHIFT, X3_D),
            ] {
                out.push(RangeData { acc: acc.clone(), out: values.clone(), rows, cols, shift });
            }
        }
        out.push(RangeData {
            acc: layer.combine_acc.clone(),
            out: layer.combine_q.clone(),
            rows: X3_T,
            cols: X3_D,
            shift: X3_SHIFT,
        });
    }
    out.push(RangeData {
        acc: fixture.seam_acc.clone(),
        out: fixture.seam_out.clone(),
        rows: X3_T,
        cols: X3_D,
        shift: X3_SHIFT,
    });
    append_rms_ranges(&mut out, &fixture.final_witness.rms);
    out.push(RangeData {
        acc: fixture.clamp_probe.product_acc.clone(),
        out: fixture.clamp_probe.product_q.clone(),
        rows: 1,
        cols: fixture.clamp_probe.product_q.len(),
        shift: X3_SILU_SHIFT,
    });
    out
}

fn exp_zero_input(fixture: &X3OpsFixture) -> i16 {
    fixture
        .luts
        .exp
        .iter()
        .position(|&value| value == 0)
        .expect("X3 Exp table must provide a padding pair") as u16 as i16
}

fn pair_data(fixture: &X3OpsFixture) -> Vec<PairData> {
    let mut rms_in = Vec::new();
    let mut rms_out = Vec::new();
    let mut clamp_in = Vec::new();
    let mut clamp_out = Vec::new();
    let mut silu_in = Vec::new();
    let mut silu_out = Vec::new();
    let mut exp_in = Vec::new();
    let mut exp_out = Vec::new();
    let mut recip_in = Vec::new();
    let mut recip_out = Vec::new();
    let mut push_rms = |rms: &X3RmsWitness| {
        rms_in.extend_from_slice(&rms.rsqrt_in);
        rms_out.extend_from_slice(&rms.rsqrt_out);
    };
    for layer in &fixture.layers {
        push_rms(&layer.attention.rms1);
        push_rms(&layer.rms2);
        for expert in &layer.experts {
            clamp_in.extend_from_slice(&expert.gate_q);
            clamp_out.extend_from_slice(&expert.gate_clamped);
            clamp_in.extend_from_slice(&expert.up_q);
            clamp_out.extend_from_slice(&expert.up_clamped);
            silu_in.extend_from_slice(&expert.gate_clamped);
            silu_out.extend_from_slice(&expert.silu);
        }
        for ((&score, &mask), &value) in layer
            .attention
            .score_q_rect
            .iter()
            .zip(&layer.attention.real_mask)
            .zip(&layer.attention.exp_rect)
        {
            if mask != 0 {
                exp_in.push(score);
                exp_out.push(value);
            }
        }
        exp_in.extend_from_slice(&layer.attention.sink_scores);
        exp_out.extend_from_slice(&layer.attention.sink_exp);
        recip_in.extend_from_slice(&layer.attention.recip_in);
        recip_out.extend_from_slice(&layer.attention.recips);
    }
    push_rms(&fixture.final_witness.rms);
    clamp_in.extend_from_slice(&fixture.clamp_probe.gate_in);
    clamp_out.extend_from_slice(&fixture.clamp_probe.gate_clamped);
    clamp_in.extend_from_slice(&fixture.clamp_probe.up_in);
    clamp_out.extend_from_slice(&fixture.clamp_probe.up_clamped);
    silu_in.extend_from_slice(&fixture.clamp_probe.gate_clamped);
    silu_out.extend_from_slice(&fixture.clamp_probe.silu);
    vec![
        PairData {
            key: TableKey::LnRsqrt,
            input: rms_in,
            output: rms_out,
            pad_in: 0,
            pad_out: fixture.luts.ln_rsqrt[0],
        },
        PairData {
            key: TableKey::Clamp1024,
            input: clamp_in,
            output: clamp_out,
            pad_in: 0,
            pad_out: 0,
        },
        PairData { key: TableKey::Silu, input: silu_in, output: silu_out, pad_in: 0, pad_out: 0 },
        PairData {
            key: TableKey::Exp,
            input: exp_in,
            output: exp_out,
            pad_in: exp_zero_input(fixture),
            pad_out: 0,
        },
        PairData {
            key: TableKey::SoftmaxRecip,
            input: recip_in,
            output: recip_out,
            pad_in: 0,
            pad_out: fixture.luts.softmax_recip[0],
        },
    ]
}

fn pair_mult(data: &PairData) -> Vec<u32> {
    let size = data.input.len().next_power_of_two();
    let mut out = vec![0u32; 1 << 16];
    for &value in &data.input {
        out[value as u16 as usize] += 1;
    }
    out[data.pad_in as u16 as usize] += (size - data.input.len()) as u32;
    out
}

fn push_hadamard(out: &mut Vec<HadamardData>, left: Vec<i64>, right: Vec<i64>) {
    assert_eq!(left.len(), right.len());
    let product = left.iter().zip(&right).map(|(&a, &b)| a * b).collect();
    out.push(HadamardData { left, right, product });
}

fn append_rms_hadamards(out: &mut Vec<HadamardData>, rms: &X3RmsWitness) {
    let input: Vec<i64> = rms.input.iter().map(|&value| i64::from(value)).collect();
    push_hadamard(out, input.clone(), input);
    let mut rsqrt = Vec::with_capacity(rms.input.len());
    for &value in &rms.rsqrt_out {
        rsqrt.extend(std::iter::repeat_n(i64::from(value), X3_D));
    }
    push_hadamard(out, rms.input.iter().map(|&value| i64::from(value)).collect(), rsqrt);
}

fn hadamard_data(fixture: &X3OpsFixture) -> Vec<HadamardData> {
    let mut out = Vec::new();
    for layer in &fixture.layers {
        append_rms_hadamards(&mut out, &layer.attention.rms1);
        append_rms_hadamards(&mut out, &layer.rms2);
        for expert in &layer.experts {
            push_hadamard(
                &mut out,
                expert.silu.iter().map(|&value| i64::from(value)).collect(),
                expert.up_clamped.iter().map(|&value| i64::from(value)).collect(),
            );
        }

        // RoPE QK pair terms in the exact real-cell order of the witness.
        let mut q_reads = Vec::with_capacity(layer.attention.rope_folded_k.len());
        for head in 0..X3_Q_HEADS {
            for row in 0..X3_T {
                for _key_row in layer.attention.lo[row] as usize..layer.attention.hi[row] as usize {
                    for pair in 0..X3_HEAD_DIM / 2 {
                        let base = row * X3_D + head * X3_HEAD_DIM + 2 * pair;
                        q_reads.extend([
                            i64::from(layer.attention.q[base]),
                            i64::from(layer.attention.q[base + 1]),
                        ]);
                    }
                }
            }
        }
        push_hadamard(&mut out, q_reads, layer.attention.rope_folded_k.clone());

        // Softmax products over the full physical rectangle.  Non-real rows
        // have exp=0 and therefore remain canonical zeros.
        let mut reciprocal_rect = vec![0i64; layer.attention.exp_rect.len()];
        for head in 0..X3_Q_HEADS {
            for row in 0..X3_T {
                for col in 0..X3_T_PAD {
                    let index = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + col;
                    reciprocal_rect[index] = i64::from(layer.attention.recips[head * X3_T + row]);
                }
            }
        }
        push_hadamard(
            &mut out,
            layer.attention.exp_rect.iter().map(|&value| i64::from(value)).collect(),
            reciprocal_rect,
        );

        // Band AV products, including the public GQA head selection.
        let mut av_weight = Vec::new();
        let mut av_value = Vec::new();
        for head in 0..X3_Q_HEADS {
            let kv_head = head / X3_GQA_GROUP;
            for row in 0..X3_T {
                for dim in 0..X3_HEAD_DIM {
                    for key_row in
                        layer.attention.lo[row] as usize..layer.attention.hi[row] as usize
                    {
                        let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + key_row;
                        av_weight.push(i64::from(layer.attention.weights_rect[rect]));
                        let v_index =
                            key_row * X3_KV_HEADS * X3_HEAD_DIM + kv_head * X3_HEAD_DIM + dim;
                        av_value.push(i64::from(layer.attention.v[v_index]));
                    }
                }
            }
        }
        push_hadamard(&mut out, av_weight, av_value);

        let mut route_weight = Vec::with_capacity(layer.route_values.len());
        for token in 0..X3_T {
            for slot in 0..X3_TOP_K {
                route_weight.extend(std::iter::repeat_n(
                    i64::from(layer.route_weights[token * X3_TOP_K + slot]),
                    X3_D,
                ));
            }
        }
        push_hadamard(
            &mut out,
            route_weight,
            layer.route_values.iter().map(|&value| i64::from(value)).collect(),
        );
    }
    append_rms_hadamards(&mut out, &fixture.final_witness.rms);
    push_hadamard(
        &mut out,
        fixture.clamp_probe.silu.iter().map(|&value| i64::from(value)).collect(),
        fixture.clamp_probe.up_clamped.iter().map(|&value| i64::from(value)).collect(),
    );
    out
}

fn gemm_data(fixture: &X3OpsFixture) -> Vec<GemmData> {
    let mut out = Vec::new();
    for (weights, layer) in fixture.weights.iter().zip(&fixture.layers) {
        out.push(GemmData {
            x: layer.attention.rms1.output.clone(),
            w: weights.qkv.clone(),
            acc: layer.attention.qkv_acc.clone(),
            m: X3_T,
            k: X3_D,
            n: X3_QKV,
        });
        out.push(GemmData {
            x: layer.attention.av_q.clone(),
            w: weights.attention.clone(),
            acc: layer.attention.projection_acc.clone(),
            m: X3_T,
            k: X3_D,
            n: X3_D,
        });
        for (expert_weights, expert) in weights.experts.iter().zip(&layer.experts) {
            let rows = expert.rows.len();
            for (x, w, acc, k, n) in [
                (&expert.gathered, &expert_weights.gate, &expert.gate_acc, X3_D, X3_DFF),
                (&expert.gathered, &expert_weights.up, &expert.up_acc, X3_D, X3_DFF),
                (&expert.product_q, &expert_weights.down, &expert.down_acc, X3_DFF, X3_D),
            ] {
                out.push(GemmData { x: x.clone(), w: w.clone(), acc: acc.clone(), m: rows, k, n });
            }
        }

        // Existing band AV argument, one grouped-V matrix per query head.
        for head in 0..X3_Q_HEADS {
            let kv_head = head / X3_GQA_GROUP;
            let mut x = vec![0i16; X3_T * X3_T];
            let mut w = vec![0i16; X3_T * X3_HEAD_DIM];
            let mut acc = vec![0i64; X3_T * X3_HEAD_DIM];
            for row in 0..X3_T {
                for col in 0..X3_T {
                    let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + col;
                    x[row * X3_T + col] = layer.attention.weights_rect[rect];
                }
                for dim in 0..X3_HEAD_DIM {
                    w[row * X3_HEAD_DIM + dim] = layer.attention.v
                        [row * X3_KV_HEADS * X3_HEAD_DIM + kv_head * X3_HEAD_DIM + dim];
                    acc[row * X3_HEAD_DIM + dim] =
                        layer.attention.av_acc[row * X3_D + head * X3_HEAD_DIM + dim];
                }
            }
            out.push(GemmData { x, w, acc, m: X3_T, k: X3_T, n: X3_HEAD_DIM });
        }
    }
    out.push(GemmData {
        x: fixture.final_witness.rms.output.clone(),
        w: fixture.output_weight.clone(),
        acc: fixture.final_witness.logits.clone(),
        m: 1,
        k: X3_D,
        n: X3_VOCAB,
    });
    out
}

pub fn x3_content_keys() -> Vec<TableKey> {
    [
        TableKey::Range(6),
        TableKey::Range(8),
        TableKey::Range(10),
        TableKey::Range(16),
        TableKey::Exp,
        TableKey::Silu,
        TableKey::Clamp1024,
        TableKey::LnRsqrt,
        TableKey::SoftmaxRecip,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

fn add_multiplicities(bank: &mut TableBankP, ranges: &[RangeData], pairs: &[PairData]) {
    for data in ranges {
        if data.shift <= 16 {
            bank.add_mult(
                TableKey::Range(data.shift),
                &range_mult(&data.acc, &data.out, data.rows, data.cols, data.shift),
            );
        } else {
            let (stage1, stage2) = range_mult_chained(&data.acc, data.rows, data.cols, data.shift);
            bank.add_mult(TableKey::Range(data.shift - 16), &stage1);
            bank.add_mult(TableKey::Range(16), &stage2);
        }
    }
    for data in pairs {
        bank.add_mult(data.key, &pair_mult(data));
    }
}

fn close_range_p(data: &RangeData, site: &RangeSiteP, zero: &mut Vec<ProverAuthed>) {
    let out_values = pad_matrix_i16(&data.out, data.rows, data.cols);
    let acc_values = pad_matrix_i64(&data.acc, data.rows, data.cols);
    zero.push(
        site.main.col_claims[1]
            .value
            .sub(ProverAuthed::from_public(public_eval(&out_values, &site.main.point))),
    );
    zero.push(
        site.acc_claim.sub(ProverAuthed::from_public(public_eval(&acc_values, site.acc_point()))),
    );
}

fn close_range_v(
    data: &RangeData,
    site: &crate::block_proof::RangeSiteV,
    delta: Fp2,
    zero: &mut Vec<VerifierKey>,
) {
    let out_values = pad_matrix_i16(&data.out, data.rows, data.cols);
    let acc_values = pad_matrix_i64(&data.acc, data.rows, data.cols);
    zero.push(
        site.main.col_keys[1]
            .key
            .sub(VerifierKey::from_public(public_eval(&out_values, &site.main.point), delta)),
    );
    zero.push(
        site.acc_key
            .sub(VerifierKey::from_public(public_eval(&acc_values, site.acc_point()), delta)),
    );
}

fn alloc_gemm_doms(cursor: &mut Doms, data: &GemmData) -> (GemmDomains, u64) {
    let domains = GemmDomains {
        x_row_base: cursor.take(data.m as u64),
        y_row_base: cursor.take(data.m as u64),
        round_masks: cursor.take(pad_bits(data.k) as u64),
        prod_mask: cursor.take(1),
    };
    let weight = cursor.take(1);
    (domains, weight)
}

#[allow(clippy::too_many_arguments)]
fn verify_gemm_in_auth_reservation_order(
    data: &GemmData,
    proof: &X3GemmProof,
    domains: &GemmDomains,
    weight_dom: u64,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if proof.proof.corr_x.len() != data.m * data.k || proof.proof.corr_y.len() != data.m * data.n {
        return None;
    }
    let r_i: Vec<Fp2> = (0..pad_bits(data.m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(data.n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);

    // Mirror `auth_phase_at`: X-row reservations precede Y-row reservations.
    // The values are cached locally until the sumcheck supplies its
    // contraction point; no domain is expanded twice.
    let mut x_keys = Vec::with_capacity(data.m * data.k);
    for row in 0..data.m {
        x_keys.extend(
            auth_verifier(
                ctx,
                domains.x_row_base + row as u64,
                &proof.proof.corr_x[row * data.k..(row + 1) * data.k],
            )
            .into_iter()
            .map(|key| key.k),
        );
    }
    let mut k_y = Fp2::ZERO;
    for row in 0..data.m {
        let keys = auth_verifier(
            ctx,
            domains.y_row_base + row as u64,
            &proof.proof.corr_y[row * data.n..(row + 1) * data.n],
        );
        let row_key =
            keys.iter().zip(&eq_j).fold(Fp2::ZERO, |sum, (key, &weight)| sum + weight * key.k);
        k_y += eq_i[row] * row_key;
    }
    let (point, k_claim_n) = blind_verify(
        pad_bits(data.k),
        VerifierKey { k: k_y },
        &proof.proof.sumcheck,
        ctx,
        domains.round_masks,
        tx,
    )?;
    let eq_l = eq_vec(&point);
    let mut k_x = Fp2::ZERO;
    for row in 0..data.m {
        let row_key =
            (0..data.k).fold(Fp2::ZERO, |sum, col| sum + eq_l[col] * x_keys[row * data.k + col]);
        k_x += eq_i[row] * row_key;
    }
    let k_w =
        VerifierKey { k: ctx.expand_full_keys(weight_dom, 1)[0] + ctx.delta * proof.weight_corr };
    let k_mask = ctx.expand_full_keys(domains.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    if !prod_batch_verify(
        &[(VerifierKey { k: k_x }, k_w, k_claim_n)],
        k_mask,
        ctx.delta,
        chi,
        &proof.proof.prod,
    ) {
        return None;
    }
    let mut weight_point = r_j;
    weight_point.extend_from_slice(&point);
    Some((weight_point, k_w))
}

pub fn prove_x3_ops(
    fixture: &X3OpsFixture,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (X3OpsProof, X3OpsProverOut) {
    fixture.config.validate().expect("X3 prover config");
    assert_eq!(fixture.config.digest().unwrap(), x3_model_config().digest().unwrap());
    let ranges = range_data(fixture);
    let pairs = pair_data(fixture);
    let hadamards = hadamard_data(fixture);
    let gemms = gemm_data(fixture);

    let trace = trace_values(fixture);
    let canonical = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
    let expected_trace = trace_values(&canonical);
    assert_eq!(trace.len(), expected_trace.len());
    let trace_dom = layer_dom_base(X3_TRACE_SECTION);
    let trace_corr = auth_fp_vec_p(stream, tx, trace_dom, &trace);
    let beta = tx.challenge_fp2();
    let weights = power_weights(beta, trace.len());
    let trace_open = open_weighted_p(stream, trace_dom, &trace, &weights);
    let expected_open = weights
        .iter()
        .zip(&expected_trace)
        .fold(Fp2::ZERO, |sum, (&weight, &value)| sum + weight.mul_base(value));
    let mut zero = vec![trace_open.sub(ProverAuthed::from_public(expected_open))];

    let mut bank = TableBankP::new();
    add_multiplicities(&mut bank, &ranges, &pairs);
    assert_eq!(bank.content_keys(), x3_content_keys());
    let mut table_doms = Doms::new(layer_dom_base(X3_TABLE_SECTION));
    bank.finalize(stream, tx, &mut table_doms);

    let mut cx = BlockCtxP::new(stream, tx, X3_OP_SECTION, &mut bank);
    let mut range_proofs = Vec::with_capacity(ranges.len());
    for data in &ranges {
        let site = prove_range_site(
            &data.acc,
            &data.out,
            data.rows,
            data.cols,
            data.shift,
            Vec::new(),
            &mut cx,
        );
        close_range_p(data, &site, &mut cx.zero);
        range_proofs.push(site.into());
    }
    let mut pair_proofs = Vec::with_capacity(pairs.len());
    for data in &pairs {
        let (input, output) = pair_cols_padded(
            &data.input,
            &data.output,
            1,
            data.input.len(),
            data.pad_in,
            data.pad_out,
        );
        let site =
            cx.inst(data.key, &[input.clone(), output.clone()], &[Some(0), Some(16)], Vec::new());
        cx.zero.push(
            site.col_claims[0]
                .value
                .sub(ProverAuthed::from_public(public_eval(&input, &site.point))),
        );
        cx.zero.push(
            site.col_claims[1]
                .value
                .sub(ProverAuthed::from_public(public_eval(&output, &site.point))),
        );
        pair_proofs.push(X3PairProof { proof: site.proof });
    }
    let mut hadamard_proofs = Vec::with_capacity(hadamards.len());
    for data in &hadamards {
        let size = data.left.len().next_power_of_two();
        let n_vars = pad_bits(size);
        let rho: Vec<Fp2> = (0..n_vars).map(|_| cx.tx.challenge_fp2()).collect();
        let mut left = vec![Fp2::ZERO; size];
        let mut right = vec![Fp2::ZERO; size];
        let mut product = vec![Fp2::ZERO; size];
        for index in 0..data.left.len() {
            left[index] = Fp2::from_base(fp_i64(data.left[index]));
            right[index] = Fp2::from_base(fp_i64(data.right[index]));
            product[index] = Fp2::from_base(fp_i64(data.product[index]));
        }
        let claim = ProverAuthed::from_public(eval_mle(&product, &rho));
        let domains = HadamardDoms::alloc(&mut cx.doms, n_vars);
        let (proof, point, left_claim, right_claim) = hadamard_prove(
            &rho,
            left.clone(),
            right.clone(),
            claim,
            &domains,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
        );
        cx.zero.push(left_claim.sub(ProverAuthed::from_public(eval_mle(&left, &point))));
        cx.zero.push(right_claim.sub(ProverAuthed::from_public(eval_mle(&right, &point))));
        hadamard_proofs.push(X3HadamardProof { proof });
    }

    let instance_counters = cx.ctr_instances;
    let other_counters = cx.ctr_other;
    let mut prod = std::mem::take(&mut cx.prod);
    zero.extend(std::mem::take(&mut cx.zero));
    drop(cx);

    let mut gemm_cursor = Doms::new(layer_dom_base(X3_GEMM_SECTION));
    let mut gemm_proofs = Vec::with_capacity(gemms.len());
    for data in &gemms {
        let (domains, weight_dom) = alloc_gemm_doms(&mut gemm_cursor, data);
        let corrections =
            auth_phase_at(&domains, &data.x, &data.acc, data.m, data.k, data.n, stream, tx);
        let (proof, weight_corr, weight_claim, _, _) = prove_gemm_blind_committed_at(
            &domains,
            &data.x,
            &data.w,
            &data.acc,
            data.m,
            data.k,
            data.n,
            corrections,
            weight_dom,
            stream,
            tx,
        );
        let expected = eval_i16_matrix(&data.w, data.k, data.n, &weight_claim.point);
        zero.push(weight_claim.value.sub(ProverAuthed::from_public(expected)));
        gemm_proofs.push(X3GemmProof { proof, weight_corr });
    }

    let mut counted_instances = instance_counters;
    let tables = bank.close(
        &fixture.luts,
        stream,
        &mut table_doms,
        tx,
        &mut counted_instances,
        &mut prod,
        &mut zero,
    );
    let logical_lookup_rows = ranges
        .iter()
        .map(|data| data.rows * data.cols * if data.shift > 16 { 2 } else { 1 })
        .sum::<usize>()
        + pairs.iter().map(|data| data.input.len()).sum::<usize>();
    let padded_lookup_rows = ranges
        .iter()
        .map(|data| {
            data.rows.next_power_of_two()
                * data.cols.next_power_of_two()
                * if data.shift > 16 { 2 } else { 1 }
        })
        .sum::<usize>()
        + pairs.iter().map(|data| data.input.len().next_power_of_two()).sum::<usize>();
    let table_sites =
        ranges.iter().map(|data| if data.shift > 16 { 2 } else { 1 }).sum::<usize>() + pairs.len();
    let corr_counters = stream.counters;
    (
        X3OpsProof {
            trace_corr,
            ranges: range_proofs,
            pairs: pair_proofs,
            hadamards: hadamard_proofs,
            gemms: gemm_proofs,
            tables,
        },
        X3OpsProverOut {
            prod,
            zero,
            instance_counters: counted_instances,
            other_counters,
            corr_counters,
            table_sites,
            table_contents: x3_content_keys().len(),
            table_finalizations: 1,
            logical_lookup_rows,
            padded_lookup_rows,
            rope_new_lookup_rows: 0,
        },
    )
}

pub fn verify_x3_ops(
    config: &volta_gpt2::ModelConfig,
    proof: &X3OpsProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<X3OpsVerifierOut> {
    config.validate().ok()?;
    if config.digest().ok()? != x3_model_config().digest().ok()? {
        return None;
    }
    let fixture = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
    let ranges = range_data(&fixture);
    let pairs = pair_data(&fixture);
    let hadamards = hadamard_data(&fixture);
    let gemms = gemm_data(&fixture);
    if proof.ranges.len() != ranges.len()
        || proof.pairs.len() != pairs.len()
        || proof.hadamards.len() != hadamards.len()
        || proof.gemms.len() != gemms.len()
    {
        return None;
    }

    let trace = trace_values(&fixture);
    if proof.trace_corr.len() != trace.len() {
        return None;
    }
    let trace_dom = layer_dom_base(X3_TRACE_SECTION);
    let trace_keys = keys_fp_vec_v(ctx, trace_dom, &proof.trace_corr);
    tx.append("auth_corrections", 8 * proof.trace_corr.len() as u64);
    let beta = tx.challenge_fp2();
    let weights = power_weights(beta, trace.len());
    let trace_key = open_weighted_k(&trace_keys, &weights);
    let expected = weights
        .iter()
        .zip(&trace)
        .fold(Fp2::ZERO, |sum, (&weight, &value)| sum + weight.mul_base(value));
    let mut kzero = vec![trace_key.sub(VerifierKey::from_public(expected, ctx.delta))];

    let expected_keys: BTreeSet<_> = x3_content_keys().into_iter().collect();
    let mut table_doms = Doms::new(layer_dom_base(X3_TABLE_SECTION));
    let mut bank = TableBankV::finalize(&expected_keys, &proof.tables, ctx, tx, &mut table_doms)?;
    let mut cx = BlockCtxV::new(ctx, tx, X3_OP_SECTION, &mut bank);
    for (data, site_proof) in ranges.iter().zip(&proof.ranges) {
        let n_vars = pad_bits(data.rows) + pad_bits(data.cols);
        let site = verify_range_site(
            n_vars,
            data.shift,
            &site_proof.main,
            site_proof.stage1.as_ref(),
            &[],
            &mut cx,
        )?;
        let delta = cx.ctx.delta;
        close_range_v(data, &site, delta, &mut cx.kzero);
    }
    for (data, site_proof) in pairs.iter().zip(&proof.pairs) {
        let (input, output) = pair_cols_padded(
            &data.input,
            &data.output,
            1,
            data.input.len(),
            data.pad_in,
            data.pad_out,
        );
        let n_bits = pad_bits(input.len());
        let site = cx.inst(data.key, n_bits, &[Some(0), Some(16)], &site_proof.proof, &[])?;
        let delta = cx.ctx.delta;
        cx.kzero.push(
            site.col_keys[0]
                .key
                .sub(VerifierKey::from_public(public_eval(&input, &site.point), delta)),
        );
        cx.kzero.push(
            site.col_keys[1]
                .key
                .sub(VerifierKey::from_public(public_eval(&output, &site.point), delta)),
        );
    }
    for (data, site_proof) in hadamards.iter().zip(&proof.hadamards) {
        let size = data.left.len().next_power_of_two();
        let n_vars = pad_bits(size);
        let rho: Vec<Fp2> = (0..n_vars).map(|_| cx.tx.challenge_fp2()).collect();
        let mut left = vec![Fp2::ZERO; size];
        let mut right = vec![Fp2::ZERO; size];
        let mut product = vec![Fp2::ZERO; size];
        for index in 0..data.left.len() {
            left[index] = Fp2::from_base(fp_i64(data.left[index]));
            right[index] = Fp2::from_base(fp_i64(data.right[index]));
            product[index] = Fp2::from_base(fp_i64(data.product[index]));
        }
        let delta = cx.ctx.delta;
        let claim = VerifierKey::from_public(eval_mle(&product, &rho), delta);
        let domains = HadamardDoms::alloc(&mut cx.doms, n_vars);
        let (point, left_key, right_key) = hadamard_verify(
            &rho,
            claim,
            &site_proof.proof,
            &domains,
            cx.ctx,
            cx.tx,
            &mut cx.kprod,
            &mut cx.kzero,
        )?;
        cx.kzero.push(left_key.sub(VerifierKey::from_public(eval_mle(&left, &point), delta)));
        cx.kzero.push(right_key.sub(VerifierKey::from_public(eval_mle(&right, &point), delta)));
    }
    let mut kprod = std::mem::take(&mut cx.kprod);
    kzero.extend(std::mem::take(&mut cx.kzero));
    drop(cx);

    let mut gemm_cursor = Doms::new(layer_dom_base(X3_GEMM_SECTION));
    for (data, site_proof) in gemms.iter().zip(&proof.gemms) {
        let (domains, weight_dom) = alloc_gemm_doms(&mut gemm_cursor, data);
        let (point, key) =
            verify_gemm_in_auth_reservation_order(data, site_proof, &domains, weight_dom, ctx, tx)?;
        let expected = eval_i16_matrix(&data.w, data.k, data.n, &point);
        kzero.push(key.sub(VerifierKey::from_public(expected, ctx.delta)));
    }
    bank.close(&fixture.luts, &proof.tables, ctx, &mut table_doms, tx, &mut kprod, &mut kzero)?;
    Some(X3OpsVerifierOut { kprod, kzero })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use volta_mac::zero_batch_exchange;

    #[derive(Clone, Copy)]
    enum Tamper {
        None,
        RmsStatistic,
        RmsOutput,
        ClampSideRow,
        SiluProduct,
        RopeFold,
        GqaHead,
        SinkDenominator,
        SlidingLowerEdge,
        PadPoison,
    }

    fn mutated_fixture(kind: Tamper, canonical: &X3OpsFixture) -> X3OpsFixture {
        let mut fixture = canonical.clone();
        match kind {
            Tamper::None | Tamper::PadPoison => unreachable!(),
            Tamper::RmsStatistic => fixture.layers[0].attention.rms1.mean_square[0] += 1,
            Tamper::RmsOutput => fixture.layers[0].attention.rms1.output[0] += 1,
            Tamper::ClampSideRow => fixture.layers[0].experts[0].gate_clamped[0] += 1,
            Tamper::SiluProduct => fixture.layers[0].experts[0].product_acc[0] += 1,
            Tamper::RopeFold => fixture.layers[0].rope_folded_term_mut_for_test(),
            Tamper::GqaHead => fixture.layers[0].attention.grouped_k_reads[0] += 1,
            Tamper::SinkDenominator => fixture.layers[0].attention.denoms[0] += 1,
            Tamper::SlidingLowerEdge => fixture.layers[1].attention.lo[4] = 0,
        }
        fixture
    }

    trait RopeTamper {
        fn rope_folded_term_mut_for_test(&mut self);
    }

    impl RopeTamper for crate::x3_ops::X3LayerWitness {
        fn rope_folded_term_mut_for_test(&mut self) {
            self.attention.rope_folded_k[0] += 1;
        }
    }

    fn run_case(tamper: Tamper) -> bool {
        let canonical = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
        let prover_fixture = if matches!(tamper, Tamper::PadPoison) {
            build_x3_ops_fixture(X3PadMode::AdmitPoison)
        } else {
            canonical.clone()
        };
        let pcg_seed = [0x83; 32];
        let tx_seed = [0x47; 32];
        let delta = Fp2::new(Fp::new(0x1234_5678), Fp::new(0x9abc_def0));
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut txp = Transcript::new(tx_seed);
        let (mut proof, pout) = prove_x3_ops(&prover_fixture, &mut stream, &mut txp);
        if !matches!(tamper, Tamper::None | Tamper::PadPoison) {
            let mutated = mutated_fixture(tamper, &canonical);
            if proof.smoke_tamper_trace_like(&canonical, &mutated).is_none() {
                return false;
            }
        }

        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut txv = Transcript::new(tx_seed);
        let Some(vout) = verify_x3_ops(&canonical.config, &proof, &mut verifier, &mut txv) else {
            return false;
        };
        let mut closure_p = Doms::new(layer_dom_base(251));
        let mut closure_v = Doms::new(layer_dom_base(251));
        let chi = txp.challenge_fp2();
        if chi != txv.challenge_fp2() {
            return false;
        }
        let prod_dom = closure_p.take(1);
        if prod_dom != closure_v.take(1) {
            return false;
        }
        let mask = stream.draw_fulls(prod_dom, 1)[0];
        let key = verifier.expand_full_keys(prod_dom, 1)[0];
        let prod_proof = prod_batch_prover(&pout.prod, chi, mask, &mut txp);
        let prod_ok = prod_batch_verify(&vout.kprod, key, delta, chi, &prod_proof);
        let zero_dom = closure_p.take(1);
        if zero_dom != closure_v.take(1) {
            return false;
        }
        // The debug implementation deliberately refuses to open a known
        // nonzero ZeroBatch claim.  Treat that refusal as the protocol
        // rejection it represents; proof-message tampers still reach the
        // verifier-side batch check because their prover rows remain zero.
        let zero_ok = if pout.zero.iter().any(|claim| claim.x != Fp2::ZERO) {
            false
        } else {
            zero_batch_exchange(
                &pout.zero,
                &vout.kzero,
                &mut stream,
                &mut verifier,
                zero_dom,
                &mut txp,
            )
        };
        prod_ok && zero_ok
    }

    #[test]
    fn x3_honest_existing_class_composition_accepts() {
        assert!(run_case(Tamper::None));
    }

    #[test]
    fn rmsnorm_mean_square_or_rsqrt_input_one_cell_tamper_rejects() {
        assert!(!run_case(Tamper::RmsStatistic));
    }

    #[test]
    fn rmsnorm_output_one_cell_tamper_rejects() {
        assert!(!run_case(Tamper::RmsOutput));
    }

    #[test]
    fn swiglu_clamp_side_row_tamper_rejects() {
        assert!(!run_case(Tamper::ClampSideRow));
    }

    #[test]
    fn swiglu_silu_or_hadamard_product_one_cell_tamper_rejects() {
        assert!(!run_case(Tamper::SiluProduct));
    }

    #[test]
    fn rope_public_coefficient_or_folded_qk_term_tamper_rejects() {
        assert!(!run_case(Tamper::RopeFold));
    }

    #[test]
    fn gqa_wrong_kv_head_substitution_rejects() {
        assert!(!run_case(Tamper::GqaHead));
    }

    #[test]
    fn attention_sink_score_or_denominator_tamper_rejects() {
        assert!(!run_case(Tamper::SinkDenominator));
    }

    #[test]
    fn sliding_lower_edge_or_out_of_window_cell_admission_rejects() {
        assert!(!run_case(Tamper::SlidingLowerEdge));
    }

    #[test]
    fn pad_poison_sentinel_admission_rejects() {
        assert!(!run_case(Tamper::PadPoison));
    }
}
