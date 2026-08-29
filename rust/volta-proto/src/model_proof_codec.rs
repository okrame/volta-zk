//! Strict canonical disk codec for the retained response proof.
//!
//! C6 historically counted the response transcript but had no parser for
//! [`ModelProof`]. The campaign verifier must reconstruct this object from
//! bytes without retaining prover state, witness material, or keys.

use crate::block_proof::{
    AttnBlockProof, C62SoftmaxRecipProof, FfnBlockProof, LayerProof, LnChainProof, TableCloseProof,
};
use crate::boundary_thinning::EqReductionProof;
use crate::c41_folded_tole::{
    C41DegreeCloseProof, C41ResponseProof, C41_DEGREE12_CLOSE_BYTES, C41_MAX_BRIDGES_PER_RESPONSE,
};
use crate::gemm_proof::ChainedGemmProof;
use crate::hadamard::HadamardProof;
use crate::logup::{
    BlindAuxPart, BlindFracProof, BlindInstance, BlindLayerProof, TableKey, TableSideProof,
};
use crate::model_proof::{
    ChunkProof, EmbedProof, FinalLnProof, LogitsClaimProof, ModelProof, SeamProof, SelectionProof,
};
use crate::private_argmax::{PackedBridgeProof, PrivateArgmaxProof};
use crate::prod_check::ProdProof;
use crate::sumcheck_blind::BlindSumcheckProof;
use std::any::TypeId;
use std::collections::VecDeque;
use std::fmt;
use volta_field::{Fp, Fp2, P};

const MAGIC: &[u8] = b"VC6MRP1\0";
const RETAINED_MAGIC: &[u8] = b"C6RRP1\0\0";
const RETAINED_VERSION: u16 = 1;
const C62_RETAINED_MAGIC: &[u8] = b"C62RRP2\0";
const C62_RETAINED_VERSION: u16 = 2;
const C41_MODEL_MAGIC: &[u8] = b"VC41MP1\0";
const C41_MODEL_VERSION: u16 = 1;
pub const C6_RETAINED_RESPONSE_BYTES: usize = 2_921_744;
/// C6.2 carries the strict C62SRE1 trailer in addition to the historical
/// model-proof grammar. Keep its allocation separate so historical C6/C6.1
/// certificates remain byte-for-byte unchanged.
pub const C62_RETAINED_RESPONSE_BYTES: usize = 4_500_000;
const MAX_COLLECTION_ITEMS: usize = 1_000_000;
const MAX_C62_LOGICAL_SUBFIELD_ITEMS: usize = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelProofCodecError(String);

impl ModelProofCodecError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ModelProofCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ModelProofCodecError {}

type Result<T> = std::result::Result<T, ModelProofCodecError>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct C62SubfieldDigest {
    len: usize,
    digest: [u8; 32],
}

struct Writer {
    bytes: Vec<u8>,
    thin_subfields: bool,
    digest_overrides: VecDeque<C62SubfieldDigest>,
}

impl Writer {
    fn full(bytes: Vec<u8>) -> Self {
        Self { bytes, thin_subfields: false, digest_overrides: VecDeque::new() }
    }

    fn thin(bytes: Vec<u8>, digests: &[C62SubfieldDigest]) -> Self {
        Self { bytes, thin_subfields: true, digest_overrides: digests.iter().cloned().collect() }
    }

    fn finish(self) -> Result<Vec<u8>> {
        if self.digest_overrides.is_empty() {
            Ok(self.bytes)
        } else {
            Err(ModelProofCodecError::new("unused C6.2 subfield digest override"))
        }
    }

    fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn fp2(&mut self, value: Fp2) {
        self.u64(value.c0.value());
        self.u64(value.c1.value());
    }

    fn len(&mut self, len: usize) -> Result<()> {
        self.u32(
            u32::try_from(len)
                .map_err(|_| ModelProofCodecError::new("model-proof collection exceeds u32"))?,
        );
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    thin_subfields: bool,
    subfield_digests: Vec<C62SubfieldDigest>,
    thin_subfield_items: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| ModelProofCodecError::new("model-proof offset overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ModelProofCodecError::new("truncated model-proof encoding"))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed width")))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed width")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed width")))
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(ModelProofCodecError::new("noncanonical Goldilocks element"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn len(&mut self) -> Result<usize> {
        let len = usize::try_from(self.u32()?).expect("u32 fits usize");
        if len > MAX_COLLECTION_ITEMS {
            return Err(ModelProofCodecError::new("model-proof collection exceeds strict cap"));
        }
        Ok(len)
    }

    fn finish(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ModelProofCodecError::new("trailing model-proof bytes"))
        }
    }
}

trait Wire: Sized {
    fn write(&self, out: &mut Writer) -> Result<()>;
    fn read(input: &mut Reader<'_>) -> Result<Self>;
}

impl Wire for u64 {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.u64(*self);
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input.u64()
    }
}

impl Wire for u16 {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.u16(*self);
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input.u16()
    }
}

impl Wire for u8 {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.byte(*self);
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input.byte()
    }
}

impl Wire for Fp2 {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.fp2(*self);
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input.fp2()
    }
}

impl<T: Wire + 'static> Wire for Vec<T> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.len(self.len())?;
        if out.thin_subfields && TypeId::of::<T>() == TypeId::of::<u64>() {
            let digest = match out.digest_overrides.pop_front() {
                Some(entry) => {
                    if entry.len != self.len() {
                        return Err(ModelProofCodecError::new(
                            "C6.2 subfield digest override length differs",
                        ));
                    }
                    entry.digest
                }
                None => {
                    let mut canonical = Writer::full(Vec::with_capacity(self.len() * 8));
                    for value in self {
                        value.write(&mut canonical)?;
                    }
                    *blake3::hash(&canonical.finish()?).as_bytes()
                }
            };
            out.bytes.extend_from_slice(&digest);
            return Ok(());
        }
        for value in self {
            value.write(out)?;
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let len = input.len()?;
        if input.thin_subfields && TypeId::of::<T>() == TypeId::of::<u64>() {
            input.thin_subfield_items = input
                .thin_subfield_items
                .checked_add(len)
                .filter(|items| *items <= MAX_C62_LOGICAL_SUBFIELD_ITEMS)
                .ok_or_else(|| {
                    ModelProofCodecError::new(
                        "C6.2 logical subfield correction census exceeds strict cap",
                    )
                })?;
            let digest: [u8; 32] = input.take(32)?.try_into().expect("fixed digest width");
            if digest == [0; 32] {
                return Err(ModelProofCodecError::new("zero C6.2 subfield digest"));
            }
            input.subfield_digests.push(C62SubfieldDigest { len, digest });
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                let mut zero = Reader {
                    bytes: &[0; 8],
                    offset: 0,
                    thin_subfields: false,
                    subfield_digests: Vec::new(),
                    thin_subfield_items: 0,
                };
                values.push(T::read(&mut zero)?);
            }
            return Ok(values);
        }
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(T::read(input)?);
        }
        Ok(values)
    }
}

impl<T: Wire> Wire for Option<T> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        match self {
            None => out.byte(0),
            Some(value) => {
                out.byte(1);
                value.write(out)?;
            }
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        match input.byte()? {
            0 => Ok(None),
            1 => Ok(Some(T::read(input)?)),
            _ => Err(ModelProofCodecError::new("noncanonical model-proof option tag")),
        }
    }
}

impl<T: Wire, const N: usize> Wire for [T; N] {
    fn write(&self, out: &mut Writer) -> Result<()> {
        for value in self {
            value.write(out)?;
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let mut values = Vec::with_capacity(N);
        for _ in 0..N {
            values.push(T::read(input)?);
        }
        values
            .try_into()
            .map_err(|_| ModelProofCodecError::new("fixed model-proof array has wrong length"))
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    fn write(&self, out: &mut Writer) -> Result<()> {
        self.0.write(out)?;
        self.1.write(out)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok((A::read(input)?, B::read(input)?))
    }
}

macro_rules! wire_struct {
    ($ty:ty { $($field:ident),+ $(,)? }) => {
        impl Wire for $ty {
            fn write(&self, out: &mut Writer) -> Result<()> {
                $(self.$field.write(out)?;)+
                Ok(())
            }
            fn read(input: &mut Reader<'_>) -> Result<Self> {
                Ok(Self { $($field: Wire::read(input)?),+ })
            }
        }
    };
}

macro_rules! wire_struct_with_none {
    ($ty:ty { $($field:ident),+ $(,)? } none $extra:ident) => {
        impl Wire for $ty {
            fn write(&self, out: &mut Writer) -> Result<()> {
                $(self.$field.write(out)?;)+
                Ok(())
            }
            fn read(input: &mut Reader<'_>) -> Result<Self> {
                Ok(Self { $($field: Wire::read(input)?),+, $extra: None })
            }
        }
    };
}

wire_struct!(BlindSumcheckProof { round_corrs });
wire_struct!(ProdProof { m0, m1 });
wire_struct!(ChainedGemmProof { sumcheck, prod });
wire_struct!(HadamardProof { round_corrs, e_corr, r_corr, z_corr });
wire_struct!(C62SoftmaxRecipProof {
    aux_corrs,
    input_low,
    input_high,
    quotient,
    remainder_low,
    remainder_high,
    slack_low,
    slack_high,
    product,
    score_clamp,
});
wire_struct!(BlindLayerProof { round_corrs, split_corrs, z_corrs });
wire_struct!(BlindAuxPart { rounds3, col_corrs });
wire_struct!(BlindFracProof { root_corrs, layers, aux });
wire_struct!(BlindInstance { lookup });
wire_struct!(TableSideProof { table, agg_corrs, cross_corrs });
wire_struct!(EqReductionProof { sumcheck, terminal_corr });
wire_struct!(LnChainProof { inst_ln, inst_ln_stage1, hadamard, inst_rsqrt });
wire_struct!(FfnBlockProof {
    ln_vec_corrs,
    inst_down,
    inst_down_stage1,
    gemm_down,
    gelu_wire_corr,
    w_down_corr,
    inst_gelu,
    inst_up,
    gemm_up,
    ln2_wire_corr,
    w_up_corr,
    ln,
    t1_q_corr,
    t1_abo_reduce,
});
wire_struct_with_none!(AttnBlockProof {
    ln_vec_corrs,
    denoms_corr,
    recip_in_corr,
    recips_corr,
    above_corr,
    row_shift_corr,
    hadamard2,
    ismax_rowsum_corr,
    inst_proj,
    inst_proj_stage1,
    gemm_proj,
    av_wire_corr,
    w_proj_corr,
    inst_av,
    av_split_corrs,
    gemm_wv,
    causal,
    causal_w_corr,
    inst_sn,
    hadamard,
    rowsum_corr,
    inst_exp,
    inst_recip,
    inst_sc,
    sc_split_corrs,
    gemm_qk,
    inst_qkv,
    gemm_cattn,
    ln1_wire_corr,
    w_cattn_corr,
    ln,
    t1_q_corr,
    t1_x_reduce,
} none c62_recip);
wire_struct!(LayerProof { xin_corr, k_corr, v_corr, abo_corr, fbo_corr, ffn, attn });
wire_struct!(SeamProof { inst });
wire_struct!(EmbedProof { out_corr, inst });
wire_struct!(FinalLnProof { out_corr, row_corr, ln_vec_corrs, ln });
wire_struct!(LogitsClaimProof { sc, wte_corr });
wire_struct!(SelectionProof { sc, wte_corr, p_corr, sc_wpe, wpe_corr });
wire_struct!(ChunkProof {
    layers,
    seams,
    embed,
    fin_out_corr,
    fin_ln_vec_corrs,
    fin_ln,
    logits,
    selection,
});
wire_struct!(PackedBridgeProof { claim_corrs, sumchecks, strict_final_corrs, limb_final_corrs });
wire_struct!(PrivateArgmaxProof {
    selected_row_corr,
    phase_claim_corrs,
    phase_strict_corrs,
    phase_hadamards,
    is_max_hadamard,
    packed_bridge,
    limb_instances,
});
wire_struct_with_none!(ModelProof {
    layers,
    seams,
    embed,
    final_ln,
    logits,
    selection,
    chunks,
    tables,
    private_argmax,
} none c41);

impl Wire for C41ResponseProof {
    fn write(&self, out: &mut Writer) -> Result<()> {
        if self.d.is_empty()
            || self.d.len() > 4_000_000
            || self.e.len() != self.d.len().div_ceil(8)
            || (self.d.len() % 8 != 0 && self.e[self.d.len() / 8] >> (self.d.len() % 8) != 0)
            || self.bridge_corrections.is_empty()
            || self.bridge_corrections.len() > C41_MAX_BRIDGES_PER_RESPONSE
        {
            return Err(ModelProofCodecError::new("invalid C4.1 response proof geometry"));
        }
        out.len(self.d.len())?;
        for value in &self.d {
            out.u16(*value);
        }
        out.len(self.e.len())?;
        out.bytes.extend_from_slice(&self.e);
        self.bridge_corrections.write(out)?;
        out.bytes
            .extend_from_slice(&self.close.encode_degree12().map_err(ModelProofCodecError::new)?);
        Ok(())
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let d_len = usize::try_from(input.u32()?).expect("u32 fits usize");
        if d_len == 0 || d_len > 4_000_000 {
            return Err(ModelProofCodecError::new("C4.1 Packed16 cell count exceeds strict cap"));
        }
        let mut d = Vec::with_capacity(d_len);
        for _ in 0..d_len {
            d.push(input.u16()?);
        }
        let e_len = usize::try_from(input.u32()?).expect("u32 fits usize");
        if e_len != d_len.div_ceil(8) {
            return Err(ModelProofCodecError::new("C4.1 correction bitmap length differs"));
        }
        let e = input.take(e_len)?.to_vec();
        if d_len % 8 != 0 && e[d_len / 8] >> (d_len % 8) != 0 {
            return Err(ModelProofCodecError::new("nonzero C4.1 bitmap padding bits"));
        }
        let bridge_corrections = Vec::<Fp2>::read(input)?;
        if bridge_corrections.is_empty() {
            return Err(ModelProofCodecError::new("empty C4.1 bridge correction list"));
        }
        let close = C41DegreeCloseProof::decode_degree12(input.take(C41_DEGREE12_CLOSE_BYTES)?)
            .map_err(ModelProofCodecError::new)?;
        Ok(Self { d, e, bridge_corrections, close })
    }
}

impl Wire for TableKey {
    fn write(&self, out: &mut Writer) -> Result<()> {
        match self {
            Self::Range(shift) => {
                out.byte(0);
                out.u32(*shift);
            }
            Self::Exp => out.byte(1),
            Self::Gelu => out.byte(2),
            Self::Silu => out.byte(3),
            Self::Clamp1024 => out.byte(4),
            Self::LnRsqrt => out.byte(5),
            Self::SoftmaxRecip => out.byte(6),
            Self::ExpGap => out.byte(7),
            Self::ScoreClamp17 => out.byte(8),
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        match input.byte()? {
            0 => Ok(Self::Range(input.u32()?)),
            1 => Ok(Self::Exp),
            2 => Ok(Self::Gelu),
            3 => Ok(Self::Silu),
            4 => Ok(Self::Clamp1024),
            5 => Ok(Self::LnRsqrt),
            6 => Ok(Self::SoftmaxRecip),
            7 => Ok(Self::ExpGap),
            8 => Ok(Self::ScoreClamp17),
            _ => Err(ModelProofCodecError::new("unknown model-proof table key")),
        }
    }
}

wire_struct!(TableCloseProof { key, mult_corr, side });

/// Encode every verifier-consumed model-proof field in one fixed order.
pub fn encode_model_proof_canonical(proof: &ModelProof) -> Result<Vec<u8>> {
    let mut out = Writer::full(MAGIC.to_vec());
    proof.write(&mut out)?;
    out.finish()
}

/// Decode a fresh proof object and reject trailing/noncanonical bytes.
pub fn decode_model_proof_canonical(bytes: &[u8]) -> Result<ModelProof> {
    let mut input = Reader {
        bytes,
        offset: 0,
        thin_subfields: false,
        subfield_digests: Vec::new(),
        thin_subfield_items: 0,
    };
    if input.take(MAGIC.len())? != MAGIC {
        return Err(ModelProofCodecError::new("wrong model-proof codec magic"));
    }
    let proof = ModelProof::read(&mut input)?;
    input.finish()?;
    if encode_model_proof_canonical(&proof)? != bytes {
        return Err(ModelProofCodecError::new("noncanonical model-proof encoding"));
    }
    Ok(proof)
}

/// Strict C4.1 codec: historical model-proof bytes followed by the canonical
/// Packed16 payload and its fixed 201-byte degree-12 close.
pub fn encode_model_proof_c41_canonical(proof: &ModelProof) -> Result<Vec<u8>> {
    let c41 = proof
        .c41
        .as_ref()
        .ok_or_else(|| ModelProofCodecError::new("C4.1 model proof has no C4.1 payload"))?;
    let mut bytes = C41_MODEL_MAGIC.to_vec();
    bytes.extend_from_slice(&C41_MODEL_VERSION.to_le_bytes());
    let mut out = Writer::full(bytes);
    proof.write(&mut out)?;
    c41.write(&mut out)?;
    out.finish()
}

pub fn decode_model_proof_c41_canonical(bytes: &[u8]) -> Result<ModelProof> {
    let mut input = Reader {
        bytes,
        offset: 0,
        thin_subfields: false,
        subfield_digests: Vec::new(),
        thin_subfield_items: 0,
    };
    if input.take(C41_MODEL_MAGIC.len())? != C41_MODEL_MAGIC || input.u16()? != C41_MODEL_VERSION {
        return Err(ModelProofCodecError::new("wrong C4.1 model-proof prefix"));
    }
    let mut proof = ModelProof::read(&mut input)?;
    proof.c41 = Some(C41ResponseProof::read(&mut input)?);
    input.finish()?;
    if encode_model_proof_c41_canonical(&proof)? != bytes {
        return Err(ModelProofCodecError::new("noncanonical C4.1 model-proof encoding"));
    }
    Ok(proof)
}

/// Complete retained non-PCS response proof consumed before C6PA2/C6PIF1.
/// The product challenge and mask domain are transcript-derived and therefore
/// are not duplicated as provider-selected bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct C6RetainedResponseProof {
    pub model: ModelProof,
    pub product: ProdProof,
    c62_subfield_digests: Vec<C62SubfieldDigest>,
}

fn visit_layer_subfield_vecs<'a>(layer: &'a LayerProof, visit: &mut impl FnMut(&'a Vec<u64>)) {
    for values in [&layer.xin_corr, &layer.k_corr, &layer.v_corr, &layer.abo_corr, &layer.fbo_corr]
    {
        visit(values);
    }
    for values in &layer.ffn.ln_vec_corrs {
        visit(values);
    }
    for values in &layer.attn.ln_vec_corrs {
        visit(values);
    }
    for values in [
        &layer.attn.denoms_corr,
        &layer.attn.recip_in_corr,
        &layer.attn.recips_corr,
        &layer.attn.above_corr,
    ] {
        visit(values);
    }
    if let Some(values) = &layer.attn.row_shift_corr {
        visit(values);
    }
}

fn visit_model_subfield_vecs<'a>(model: &'a ModelProof, mut visit: impl FnMut(&'a Vec<u64>)) {
    for layer in &model.layers {
        visit_layer_subfield_vecs(layer, &mut visit);
    }
    visit(&model.embed.out_corr);
    visit(&model.final_ln.out_corr);
    visit(&model.final_ln.row_corr);
    for values in &model.final_ln.ln_vec_corrs {
        visit(values);
    }
    for chunk in &model.chunks {
        for layer in &chunk.layers {
            visit_layer_subfield_vecs(layer, &mut visit);
        }
        visit(&chunk.embed.out_corr);
        visit(&chunk.fin_out_corr);
        for values in &chunk.fin_ln_vec_corrs {
            visit(values);
        }
    }
    for table in &model.tables {
        visit(&table.mult_corr);
    }
    if let Some(argmax) = &model.private_argmax {
        visit(&argmax.selected_row_corr);
    }
}

fn encode_model_proof_c62_compact(
    proof: &ModelProof,
    digests: &[C62SubfieldDigest],
) -> Result<Vec<u8>> {
    let mut out = Writer::thin(MAGIC.to_vec(), digests);
    proof.write(&mut out)?;
    out.finish()
}

fn decode_model_proof_c62_compact(bytes: &[u8]) -> Result<(ModelProof, Vec<C62SubfieldDigest>)> {
    let mut input = Reader {
        bytes,
        offset: 0,
        thin_subfields: true,
        subfield_digests: Vec::new(),
        thin_subfield_items: 0,
    };
    if input.take(MAGIC.len())? != MAGIC {
        return Err(ModelProofCodecError::new("wrong compact model-proof codec magic"));
    }
    let proof = ModelProof::read(&mut input)?;
    input.finish()?;
    let digests = input.subfield_digests;
    if encode_model_proof_c62_compact(&proof, &digests)? != bytes {
        return Err(ModelProofCodecError::new("noncanonical compact model-proof encoding"));
    }
    Ok((proof, digests))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C62RetainedResponseByteCensus {
    /// Historical full grammar, retained only as a diagnostic comparison.
    pub model_bytes: usize,
    /// Actual C6.2 compact model-proof grammar.
    pub compact_model_bytes: usize,
    pub product_bytes: usize,
    pub extension_bytes: Vec<usize>,
    /// Per model layer, including decode chunks: boundary vectors, FFN proof,
    /// and attention proof bytes. Collection prefixes are excluded.
    pub layer_sections: Vec<[usize; 3]>,
    pub non_layer_model_bytes: usize,
    /// Raw canonical payload occupied by element-wise `Fp` corrections. This
    /// excludes the four-byte collection prefixes, which remain structural.
    pub subfield_correction_payload_bytes: usize,
    pub subfield_correction_vector_count: usize,
    /// Exact retained-response size if only those payload bytes were removed.
    /// This is a lower-bound diagnostic, not an admissible codec.
    pub bytes_without_subfield_correction_payload: usize,
    pub bytes_before_padding_and_digest: usize,
}

fn wire_bytes<T: Wire>(value: &T) -> Result<usize> {
    let mut out = Writer::full(Vec::new());
    value.write(&mut out)?;
    Ok(out.finish()?.len())
}

fn c62_layer_byte_sections(layer: &LayerProof) -> Result<[usize; 3]> {
    let boundary = wire_bytes(&layer.xin_corr)?
        + wire_bytes(&layer.k_corr)?
        + wire_bytes(&layer.v_corr)?
        + wire_bytes(&layer.abo_corr)?
        + wire_bytes(&layer.fbo_corr)?;
    Ok([boundary, wire_bytes(&layer.ffn)?, wire_bytes(&layer.attn)?])
}

fn count_u64_vec(values: &[u64], bytes: &mut usize, vectors: &mut usize) -> Result<()> {
    *bytes = bytes
        .checked_add(values.len().checked_mul(8).ok_or_else(|| {
            ModelProofCodecError::new("C6.2 subfield correction byte census overflows")
        })?)
        .ok_or_else(|| {
            ModelProofCodecError::new("C6.2 subfield correction byte census overflows")
        })?;
    *vectors = vectors.checked_add(1).ok_or_else(|| {
        ModelProofCodecError::new("C6.2 subfield correction vector census overflows")
    })?;
    Ok(())
}

fn count_layer_subfield_corrections(
    layer: &LayerProof,
    bytes: &mut usize,
    vectors: &mut usize,
) -> Result<()> {
    for values in [&layer.xin_corr, &layer.k_corr, &layer.v_corr, &layer.abo_corr, &layer.fbo_corr]
    {
        count_u64_vec(values, bytes, vectors)?;
    }
    for values in &layer.ffn.ln_vec_corrs {
        count_u64_vec(values, bytes, vectors)?;
    }
    for values in &layer.attn.ln_vec_corrs {
        count_u64_vec(values, bytes, vectors)?;
    }
    for values in [
        &layer.attn.denoms_corr,
        &layer.attn.recip_in_corr,
        &layer.attn.recips_corr,
        &layer.attn.above_corr,
    ] {
        count_u64_vec(values, bytes, vectors)?;
    }
    if let Some(values) = &layer.attn.row_shift_corr {
        count_u64_vec(values, bytes, vectors)?;
    }
    Ok(())
}

fn c62_subfield_correction_census(model: &ModelProof) -> Result<(usize, usize)> {
    let mut bytes = 0usize;
    let mut vectors = 0usize;
    for layer in
        model.layers.iter().chain(model.chunks.iter().flat_map(|chunk| chunk.layers.iter()))
    {
        count_layer_subfield_corrections(layer, &mut bytes, &mut vectors)?;
    }
    count_u64_vec(&model.embed.out_corr, &mut bytes, &mut vectors)?;
    count_u64_vec(&model.final_ln.out_corr, &mut bytes, &mut vectors)?;
    count_u64_vec(&model.final_ln.row_corr, &mut bytes, &mut vectors)?;
    for values in &model.final_ln.ln_vec_corrs {
        count_u64_vec(values, &mut bytes, &mut vectors)?;
    }
    for chunk in &model.chunks {
        count_u64_vec(&chunk.embed.out_corr, &mut bytes, &mut vectors)?;
        count_u64_vec(&chunk.fin_out_corr, &mut bytes, &mut vectors)?;
        for values in &chunk.fin_ln_vec_corrs {
            count_u64_vec(values, &mut bytes, &mut vectors)?;
        }
    }
    for table in &model.tables {
        count_u64_vec(&table.mult_corr, &mut bytes, &mut vectors)?;
    }
    if let Some(argmax) = &model.private_argmax {
        count_u64_vec(&argmax.selected_row_corr, &mut bytes, &mut vectors)?;
    }
    Ok((bytes, vectors))
}

/// Measure the exact canonical C6.2 retained-response payload without
/// applying its fixed frame. This is intentionally the same writer path used
/// by `encode_c62_parts`, so readiness can reject an oversized proof locally.
pub fn c62_retained_response_byte_census(
    model_proof: &ModelProof,
    product: &ProdProof,
) -> Result<C62RetainedResponseByteCensus> {
    let model = encode_model_proof_canonical(model_proof)?;
    let compact_model = encode_model_proof_c62_compact(model_proof, &[])?;
    let extensions = c62_extensions(model_proof);
    if extensions.is_empty() || extensions.iter().any(|extension| extension.is_none()) {
        return Err(ModelProofCodecError::new(
            "C6.2 retained response lacks a complete C62SRE1 census",
        ));
    }
    let mut product_out = Writer::full(Vec::new());
    product.write(&mut product_out)?;
    let mut extension_bytes = Vec::with_capacity(extensions.len());
    for extension in extensions {
        let mut extension_out = Writer::full(Vec::new());
        extension.write(&mut extension_out)?;
        extension_bytes.push(extension_out.finish()?.len());
    }
    let product_bytes = product_out.finish()?.len();
    let layer_sections = model_proof
        .layers
        .iter()
        .chain(model_proof.chunks.iter().flat_map(|chunk| chunk.layers.iter()))
        .map(c62_layer_byte_sections)
        .collect::<Result<Vec<_>>>()?;
    let layer_payload_bytes = layer_sections.iter().flatten().sum::<usize>();
    let non_layer_model_bytes = model
        .len()
        .checked_sub(layer_payload_bytes)
        .ok_or_else(|| ModelProofCodecError::new("C6.2 layer byte census exceeds model bytes"))?;
    let (subfield_correction_payload_bytes, subfield_correction_vector_count) =
        c62_subfield_correction_census(model_proof)?;
    let fixed_header_bytes = C62_RETAINED_MAGIC.len() + 2 + 2 + 4 + 32;
    let bytes_before_padding_and_digest = fixed_header_bytes
        + compact_model.len()
        + product_bytes
        + 4
        + extension_bytes.iter().sum::<usize>();
    let full_bytes_before_padding_and_digest = fixed_header_bytes
        + model.len()
        + product_bytes
        + 4
        + extension_bytes.iter().sum::<usize>();
    let bytes_without_subfield_correction_payload = full_bytes_before_padding_and_digest
        .checked_sub(subfield_correction_payload_bytes)
        .ok_or_else(|| {
            ModelProofCodecError::new("C6.2 subfield payload exceeds retained response")
        })?;
    Ok(C62RetainedResponseByteCensus {
        model_bytes: model.len(),
        compact_model_bytes: compact_model.len(),
        product_bytes,
        extension_bytes,
        layer_sections,
        non_layer_model_bytes,
        subfield_correction_payload_bytes,
        subfield_correction_vector_count,
        bytes_without_subfield_correction_payload,
        bytes_before_padding_and_digest,
    })
}

impl C6RetainedResponseProof {
    pub fn is_c62_compact(&self) -> bool {
        !self.c62_subfield_digests.is_empty()
    }

    /// Bind every compact digest to the stable decoded placeholder that will
    /// be consumed by the response transcript.
    pub fn c62_subfield_digest_overrides(&self) -> Result<Vec<(*const u64, usize, [u8; 32])>> {
        if self.c62_subfield_digests.is_empty() {
            return Err(ModelProofCodecError::new("C6.2 compact subfield manifest is absent"));
        }
        let mut vectors = Vec::new();
        visit_model_subfield_vecs(&self.model, |values| vectors.push(values));
        if vectors.len() != self.c62_subfield_digests.len() {
            return Err(ModelProofCodecError::new("C6.2 compact subfield census differs"));
        }
        vectors
            .into_iter()
            .zip(&self.c62_subfield_digests)
            .filter(|(values, _)| !values.is_empty())
            .map(|(values, entry)| {
                if values.len() != entry.len || values.iter().any(|value| *value != 0) {
                    return Err(ModelProofCodecError::new(
                        "C6.2 compact subfield placeholder differs",
                    ));
                }
                Ok((values.as_ptr(), values.len(), entry.digest))
            })
            .collect()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Self::encode_parts(&self.model, &self.product)
    }

    pub fn encode_parts(model_proof: &ModelProof, product: &ProdProof) -> Result<Vec<u8>> {
        if c62_extension_count(model_proof) != 0 {
            return Err(ModelProofCodecError::new(
                "C62SRE1 extensions require the C6.2 retained-response codec",
            ));
        }
        let model = encode_model_proof_canonical(model_proof)?;
        let model_len = u32::try_from(model.len())
            .map_err(|_| ModelProofCodecError::new("retained model proof exceeds u32"))?;
        let mut out = Writer::full(RETAINED_MAGIC.to_vec());
        out.u16(RETAINED_VERSION);
        out.u16(0);
        out.u32(model_len);
        out.bytes.extend_from_slice(blake3::hash(&model).as_bytes());
        out.bytes.extend_from_slice(&model);
        product.write(&mut out)?;
        let padding = C6_RETAINED_RESPONSE_BYTES
            .checked_sub(out.bytes.len())
            .and_then(|remaining| remaining.checked_sub(32))
            .ok_or_else(|| {
                ModelProofCodecError::new("retained response exceeds its frozen allocation")
            })?;
        out.bytes.resize(out.bytes.len() + padding, 0);
        let digest = blake3::hash(&out.bytes);
        out.bytes.extend_from_slice(digest.as_bytes());
        out.finish()
    }

    /// Encode the C6.2 response with a distinct frame and a strict C62SRE1
    /// trailer. The base model-proof bytes retain their historical grammar.
    pub fn encode_c62(&self) -> Result<Vec<u8>> {
        Self::encode_c62_parts_with_digests(&self.model, &self.product, &self.c62_subfield_digests)
    }

    pub fn encode_c62_parts(model_proof: &ModelProof, product: &ProdProof) -> Result<Vec<u8>> {
        Self::encode_c62_parts_with_digests(model_proof, product, &[])
    }

    fn encode_c62_parts_with_digests(
        model_proof: &ModelProof,
        product: &ProdProof,
        digests: &[C62SubfieldDigest],
    ) -> Result<Vec<u8>> {
        let model = encode_model_proof_c62_compact(model_proof, digests)?;
        let model_len = u32::try_from(model.len())
            .map_err(|_| ModelProofCodecError::new("C6.2 retained model proof exceeds u32"))?;
        let extensions = c62_extensions(model_proof);
        if extensions.is_empty() || extensions.iter().any(|extension| extension.is_none()) {
            return Err(ModelProofCodecError::new(
                "C6.2 retained response lacks a complete C62SRE1 census",
            ));
        }
        let mut out = Writer::full(C62_RETAINED_MAGIC.to_vec());
        out.u16(C62_RETAINED_VERSION);
        out.u16(0);
        out.u32(model_len);
        out.bytes.extend_from_slice(blake3::hash(&model).as_bytes());
        out.bytes.extend_from_slice(&model);
        product.write(&mut out)?;
        out.u32(
            u32::try_from(extensions.len())
                .map_err(|_| ModelProofCodecError::new("C62SRE1 census exceeds u32"))?,
        );
        for extension in extensions {
            extension.write(&mut out)?;
        }
        let padding = C62_RETAINED_RESPONSE_BYTES
            .checked_sub(out.bytes.len())
            .and_then(|remaining| remaining.checked_sub(32))
            .ok_or_else(|| {
                ModelProofCodecError::new(format!(
                    "C6.2 retained response requires {} bytes before padding and digest; allocation is {} bytes",
                    out.bytes.len(),
                    C62_RETAINED_RESPONSE_BYTES,
                ))
            })?;
        out.bytes.resize(out.bytes.len() + padding, 0);
        let digest = blake3::hash(&out.bytes);
        out.bytes.extend_from_slice(digest.as_bytes());
        out.finish()
    }

    pub fn decode_c62(bytes: &[u8]) -> Result<Self> {
        let frame = bytes
            .get(..C62_RETAINED_RESPONSE_BYTES)
            .ok_or_else(|| ModelProofCodecError::new("truncated C6.2 retained response"))?;
        if bytes.len() != C62_RETAINED_RESPONSE_BYTES {
            return Err(ModelProofCodecError::new("trailing C6.2 retained-response bytes"));
        }
        let mut input = Reader {
            bytes: frame,
            offset: 0,
            thin_subfields: false,
            subfield_digests: Vec::new(),
            thin_subfield_items: 0,
        };
        if input.take(C62_RETAINED_MAGIC.len())? != C62_RETAINED_MAGIC
            || input.u16()? != C62_RETAINED_VERSION
            || input.u16()? != 0
        {
            return Err(ModelProofCodecError::new(
                "C6.2 retained-response header, version, or reserved field differs",
            ));
        }
        let model_len = usize::try_from(input.u32()?).expect("u32 fits usize");
        let expected_model_digest: [u8; 32] =
            input.take(32)?.try_into().expect("fixed model digest width");
        let model_bytes = input.take(model_len)?;
        if *blake3::hash(model_bytes).as_bytes() != expected_model_digest {
            return Err(ModelProofCodecError::new("C6.2 retained model-proof digest mismatch"));
        }
        let (mut model, c62_subfield_digests) = decode_model_proof_c62_compact(model_bytes)?;
        let product = ProdProof::read(&mut input)?;
        let count = usize::try_from(input.u32()?).expect("u32 fits usize");
        let expected_count = c62_layer_count(&model);
        if count == 0 || count != expected_count {
            return Err(ModelProofCodecError::new("C62SRE1 extension census differs"));
        }
        let mut extensions = Vec::with_capacity(count);
        for _ in 0..count {
            let extension = Option::<C62SoftmaxRecipProof>::read(&mut input)?;
            if extension.is_none() {
                return Err(ModelProofCodecError::new("C62SRE1 extension is absent"));
            }
            extensions.push(extension);
        }
        install_c62_extensions(&mut model, extensions)?;
        let padding_len = C62_RETAINED_RESPONSE_BYTES
            .checked_sub(input.offset)
            .and_then(|remaining| remaining.checked_sub(32))
            .ok_or_else(|| ModelProofCodecError::new("C6.2 retained framing overflows"))?;
        if input.take(padding_len)?.iter().any(|byte| *byte != 0) {
            return Err(ModelProofCodecError::new("nonzero C6.2 retained-response padding"));
        }
        let body_end = input.offset;
        let expected_digest: [u8; 32] =
            input.take(32)?.try_into().expect("fixed retained digest width");
        if *blake3::hash(&frame[..body_end]).as_bytes() != expected_digest {
            return Err(ModelProofCodecError::new("C6.2 retained-response digest mismatch"));
        }
        input.finish()?;
        let proof = Self { model, product, c62_subfield_digests };
        if proof.encode_c62()? != frame {
            return Err(ModelProofCodecError::new("noncanonical C6.2 retained response"));
        }
        Ok(proof)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (proof, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(ModelProofCodecError::new("trailing retained-response bytes"));
        }
        Ok(proof)
    }

    /// Decode one self-framed retained response at the start of a larger
    /// certificate payload and return its exact canonical prefix length.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize)> {
        let frame = bytes
            .get(..C6_RETAINED_RESPONSE_BYTES)
            .ok_or_else(|| ModelProofCodecError::new("truncated retained-response allocation"))?;
        let mut input = Reader {
            bytes: frame,
            offset: 0,
            thin_subfields: false,
            subfield_digests: Vec::new(),
            thin_subfield_items: 0,
        };
        if input.take(RETAINED_MAGIC.len())? != RETAINED_MAGIC
            || input.u16()? != RETAINED_VERSION
            || input.u16()? != 0
        {
            return Err(ModelProofCodecError::new(
                "retained-response header/version/reserved mismatch",
            ));
        }
        let model_len = usize::try_from(input.u32()?).expect("u32 fits usize");
        let expected_model_digest: [u8; 32] =
            input.take(32)?.try_into().expect("fixed retained model digest width");
        let model_bytes = input.take(model_len)?;
        if *blake3::hash(model_bytes).as_bytes() != expected_model_digest {
            return Err(ModelProofCodecError::new("retained model-proof digest mismatch"));
        }
        let model = decode_model_proof_canonical(model_bytes)?;
        let product = ProdProof::read(&mut input)?;
        let padding_len = C6_RETAINED_RESPONSE_BYTES
            .checked_sub(input.offset)
            .and_then(|remaining| remaining.checked_sub(32))
            .ok_or_else(|| ModelProofCodecError::new("retained-response framing overflows"))?;
        if input.take(padding_len)?.iter().any(|byte| *byte != 0) {
            return Err(ModelProofCodecError::new("nonzero retained-response padding"));
        }
        let body_end = input.offset;
        let expected_digest: [u8; 32] =
            input.take(32)?.try_into().expect("fixed retained-response digest width");
        if *blake3::hash(&frame[..body_end]).as_bytes() != expected_digest {
            return Err(ModelProofCodecError::new("retained-response digest mismatch"));
        }
        let proof = Self { model, product, c62_subfield_digests: Vec::new() };
        let consumed = input.offset;
        if proof.encode()? != frame[..consumed] {
            return Err(ModelProofCodecError::new("noncanonical retained-response encoding"));
        }
        Ok((proof, consumed))
    }
}

fn c62_layer_count(model: &ModelProof) -> usize {
    model.layers.len() + model.chunks.iter().map(|chunk| chunk.layers.len()).sum::<usize>()
}

fn c62_extensions(model: &ModelProof) -> Vec<&Option<C62SoftmaxRecipProof>> {
    model
        .layers
        .iter()
        .chain(model.chunks.iter().flat_map(|chunk| chunk.layers.iter()))
        .map(|layer| &layer.attn.c62_recip)
        .collect()
}

fn c62_extension_count(model: &ModelProof) -> usize {
    c62_extensions(model).into_iter().filter(|extension| extension.is_some()).count()
}

fn install_c62_extensions(
    model: &mut ModelProof,
    extensions: Vec<Option<C62SoftmaxRecipProof>>,
) -> Result<()> {
    if extensions.len() != c62_layer_count(model) {
        return Err(ModelProofCodecError::new("C62SRE1 install census differs"));
    }
    let mut extensions = extensions.into_iter();
    for layer in &mut model.layers {
        layer.attn.c62_recip = extensions.next().expect("checked C62SRE1 census");
    }
    for chunk in &mut model.chunks {
        for layer in &mut chunk.layers {
            layer.attn.c62_recip = extensions.next().expect("checked C62SRE1 census");
        }
    }
    debug_assert!(extensions.next().is_none());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sumcheck() -> BlindSumcheckProof {
        BlindSumcheckProof { round_corrs: vec![[Fp2::ONE, Fp2::ZERO]] }
    }

    fn frac() -> BlindFracProof {
        BlindFracProof {
            root_corrs: [Fp2::ONE, Fp2::ZERO],
            layers: vec![BlindLayerProof {
                round_corrs: vec![[Fp2::ZERO, Fp2::ONE]],
                split_corrs: [Fp2::ZERO; 4],
                z_corrs: [Fp2::ONE; 3],
            }],
            aux: Some(BlindAuxPart {
                rounds3: vec![[Fp2::ZERO, Fp2::ONE, Fp2::ZERO]],
                col_corrs: vec![[Fp2::ONE, Fp2::ZERO]],
            }),
        }
    }

    fn instance() -> BlindInstance {
        BlindInstance { lookup: frac() }
    }

    fn hadamard() -> HadamardProof {
        HadamardProof {
            round_corrs: vec![[Fp2::ZERO, Fp2::ONE, Fp2::ZERO]],
            e_corr: Fp2::ONE,
            r_corr: Fp2::ZERO,
            z_corr: Fp2::ONE,
        }
    }

    pub(super) fn c62_recip() -> C62SoftmaxRecipProof {
        C62SoftmaxRecipProof {
            aux_corrs: [Fp2::ONE; 7],
            input_low: instance(),
            input_high: instance(),
            quotient: instance(),
            remainder_low: instance(),
            remainder_high: instance(),
            slack_low: instance(),
            slack_high: instance(),
            product: hadamard(),
            score_clamp: Some(instance()),
        }
    }

    fn gemm() -> ChainedGemmProof {
        ChainedGemmProof { sumcheck: sumcheck(), prod: ProdProof { m0: Fp2::ZERO, m1: Fp2::ONE } }
    }

    fn ln() -> LnChainProof {
        LnChainProof {
            inst_ln: instance(),
            inst_ln_stage1: Some(instance()),
            hadamard: hadamard(),
            inst_rsqrt: instance(),
        }
    }

    fn reduction() -> EqReductionProof {
        EqReductionProof { sumcheck: sumcheck(), terminal_corr: Fp2::ONE }
    }

    fn layer() -> LayerProof {
        LayerProof {
            xin_corr: vec![1],
            k_corr: vec![2],
            v_corr: vec![3],
            abo_corr: vec![4],
            fbo_corr: vec![5],
            ffn: FfnBlockProof {
                ln_vec_corrs: [vec![6], vec![7], vec![8], vec![9]],
                inst_down: instance(),
                inst_down_stage1: Some(instance()),
                gemm_down: gemm(),
                gelu_wire_corr: Fp2::ONE,
                w_down_corr: Fp2::ZERO,
                inst_gelu: instance(),
                inst_up: instance(),
                gemm_up: gemm(),
                ln2_wire_corr: Fp2::ONE,
                w_up_corr: Fp2::ZERO,
                ln: ln(),
                t1_q_corr: Some(Fp2::ONE),
                t1_abo_reduce: Some(reduction()),
            },
            attn: AttnBlockProof {
                ln_vec_corrs: [vec![10], vec![11], vec![12], vec![13]],
                denoms_corr: vec![14],
                recip_in_corr: vec![15],
                recips_corr: vec![16],
                above_corr: vec![17],
                row_shift_corr: Some(vec![18]),
                hadamard2: Some(hadamard()),
                ismax_rowsum_corr: Some(Fp2::ONE),
                inst_proj: instance(),
                inst_proj_stage1: Some(instance()),
                gemm_proj: gemm(),
                av_wire_corr: Fp2::ONE,
                w_proj_corr: Fp2::ZERO,
                inst_av: instance(),
                av_split_corrs: [Fp2::ONE; 12],
                gemm_wv: vec![(gemm(), Fp2::ONE)],
                causal: sumcheck(),
                causal_w_corr: Fp2::ZERO,
                inst_sn: instance(),
                hadamard: hadamard(),
                rowsum_corr: Fp2::ONE,
                inst_exp: instance(),
                inst_recip: instance(),
                c62_recip: None,
                inst_sc: instance(),
                sc_split_corrs: [Fp2::ZERO; 12],
                gemm_qk: vec![(gemm(), Fp2::ZERO)],
                inst_qkv: instance(),
                gemm_cattn: gemm(),
                ln1_wire_corr: Fp2::ONE,
                w_cattn_corr: Fp2::ZERO,
                ln: ln(),
                t1_q_corr: Some(Fp2::ZERO),
                t1_x_reduce: Some(reduction()),
            },
        }
    }

    fn selection() -> SelectionProof {
        SelectionProof {
            sc: sumcheck(),
            wte_corr: Fp2::ONE,
            p_corr: Fp2::ZERO,
            sc_wpe: sumcheck(),
            wpe_corr: Fp2::ONE,
        }
    }

    pub(super) fn proof() -> ModelProof {
        ModelProof {
            layers: vec![layer()],
            seams: vec![Some(SeamProof { inst: instance() })],
            embed: EmbedProof { out_corr: vec![19], inst: instance() },
            final_ln: FinalLnProof {
                out_corr: vec![20],
                row_corr: vec![21],
                ln_vec_corrs: [vec![22], vec![23], vec![24], vec![25]],
                ln: ln(),
            },
            logits: LogitsClaimProof { sc: sumcheck(), wte_corr: Fp2::ONE },
            selection: selection(),
            chunks: vec![ChunkProof {
                layers: vec![layer()],
                seams: vec![None],
                embed: EmbedProof { out_corr: vec![26], inst: instance() },
                fin_out_corr: vec![27],
                fin_ln_vec_corrs: [vec![28], vec![29], vec![30], vec![31]],
                fin_ln: ln(),
                logits: LogitsClaimProof { sc: sumcheck(), wte_corr: Fp2::ZERO },
                selection: selection(),
            }],
            tables: vec![TableCloseProof {
                key: TableKey::Range(16),
                mult_corr: vec![32],
                side: TableSideProof {
                    table: frac(),
                    agg_corrs: vec![[Fp2::ZERO; 3]],
                    cross_corrs: [Fp2::ONE; 4],
                },
            }],
            private_argmax: Some(PrivateArgmaxProof {
                selected_row_corr: vec![33],
                phase_claim_corrs: vec![Fp2::ONE],
                phase_strict_corrs: vec![Fp2::ZERO],
                phase_hadamards: vec![hadamard()],
                is_max_hadamard: hadamard(),
                packed_bridge: PackedBridgeProof {
                    claim_corrs: [Fp2::ZERO; 2],
                    sumchecks: vec![sumcheck()],
                    strict_final_corrs: [Fp2::ONE; 2],
                    limb_final_corrs: [Fp2::ZERO; 6],
                },
                limb_instances: vec![instance()],
            }),
            c41: None,
        }
    }

    #[test]
    fn complete_model_proof_round_trips_and_decoder_is_strict() {
        let proof = proof();
        let bytes = encode_model_proof_canonical(&proof).unwrap();
        assert_eq!(decode_model_proof_canonical(&bytes).unwrap(), proof);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_model_proof_canonical(&trailing).is_err());
        assert!(decode_model_proof_canonical(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_model_proof_canonical(b"wrong").is_err());

        let mut noncanonical = [0u8; 16];
        noncanonical[..8].copy_from_slice(&P.to_le_bytes());
        let mut field = Reader {
            bytes: &noncanonical,
            offset: 0,
            thin_subfields: false,
            subfield_digests: Vec::new(),
            thin_subfield_items: 0,
        };
        assert!(field.fp2().is_err());

        let mut compact_vec = Vec::from(1u32.to_le_bytes());
        compact_vec.extend_from_slice(&[1; 32]);
        let mut capped = Reader {
            bytes: &compact_vec,
            offset: 0,
            thin_subfields: true,
            subfield_digests: Vec::new(),
            thin_subfield_items: MAX_C62_LOGICAL_SUBFIELD_ITEMS,
        };
        assert!(Vec::<u64>::read(&mut capped).is_err());
    }

    #[test]
    fn c41_model_proof_round_trips_and_rejects_bitmap_padding() {
        let mut proof = proof();
        proof.c41 = Some(C41ResponseProof {
            d: vec![1, 2, 3],
            e: vec![0b0000_0101],
            bridge_corrections: vec![Fp2::ONE],
            close: C41DegreeCloseProof { degree: 12, coefficients: vec![Fp2::ZERO; 12] },
        });
        let bytes = encode_model_proof_c41_canonical(&proof).unwrap();
        assert_eq!(decode_model_proof_c41_canonical(&bytes).unwrap(), proof);

        proof.c41.as_mut().unwrap().e[0] |= 0x80;
        assert!(encode_model_proof_c41_canonical(&proof).is_err());

        let c41 = proof.c41.as_mut().unwrap();
        c41.e[0] &= 0x07;
        c41.bridge_corrections = vec![Fp2::ZERO; C41_MAX_BRIDGES_PER_RESPONSE + 1];
        assert!(encode_model_proof_c41_canonical(&proof).is_err());
    }

    #[test]
    fn retained_response_codec_is_strict_and_prefix_decodable() {
        let retained = C6RetainedResponseProof {
            model: proof(),
            product: ProdProof { m0: Fp2::ONE, m1: Fp2::ZERO },
            c62_subfield_digests: Vec::new(),
        };
        let bytes = retained.encode().unwrap();
        assert_eq!(C6RetainedResponseProof::decode(&bytes).unwrap(), retained);

        let mut followed = bytes.clone();
        followed.extend_from_slice(b"C6PA2");
        let (decoded, consumed) = C6RetainedResponseProof::decode_prefix(&followed).unwrap();
        assert_eq!(decoded, retained);
        assert_eq!(consumed, bytes.len());
        assert!(C6RetainedResponseProof::decode(&followed).is_err());

        let mut mutation = bytes.clone();
        let model_start = RETAINED_MAGIC.len() + 2 + 2 + 4 + 32;
        mutation[model_start] ^= 1;
        assert!(C6RetainedResponseProof::decode(&mutation).is_err());
        let model_len = usize::try_from(u32::from_le_bytes(
            bytes[12..16].try_into().expect("fixed retained model length"),
        ))
        .unwrap();
        let padding_start = model_start + model_len + 32;
        let mut nonzero_padding = bytes.clone();
        nonzero_padding[padding_start] = 1;
        assert!(C6RetainedResponseProof::decode(&nonzero_padding).is_err());
        assert!(C6RetainedResponseProof::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(C6RetainedResponseProof::decode(b"wrong").is_err());
    }

    #[test]
    fn c62_byte_census_uses_the_canonical_writer() {
        let mut model = proof();
        for layer in &mut model.layers {
            layer.attn.c62_recip = Some(c62_recip());
        }
        for chunk in &mut model.chunks {
            for layer in &mut chunk.layers {
                layer.attn.c62_recip = Some(c62_recip());
            }
        }
        let product = ProdProof { m0: Fp2::ONE, m1: Fp2::ZERO };
        let census = c62_retained_response_byte_census(&model, &product).unwrap();
        assert_eq!(census.model_bytes, encode_model_proof_canonical(&model).unwrap().len());
        assert_eq!(census.extension_bytes.len(), 2);
        assert_eq!(
            census.layer_sections.iter().flatten().sum::<usize>() + census.non_layer_model_bytes,
            census.model_bytes,
        );
        assert_ne!(census.compact_model_bytes, census.model_bytes);
        assert!(census.bytes_before_padding_and_digest + 32 <= C62_RETAINED_RESPONSE_BYTES);
        let bytes = C6RetainedResponseProof::encode_c62_parts(&model, &product).unwrap();
        let decoded = C6RetainedResponseProof::decode_c62(&bytes).unwrap();
        assert!(decoded.is_c62_compact());
        assert!(!decoded.c62_subfield_digest_overrides().unwrap().is_empty());
        assert_eq!(decoded.encode_c62().unwrap(), bytes);
        let mut mutation = bytes;
        mutation[C62_RETAINED_MAGIC.len() + 2 + 2 + 4 + 32 + MAGIC.len() + 4] ^= 1;
        assert!(C6RetainedResponseProof::decode_c62(&mutation).is_err());
    }
}

#[cfg(test)]
pub(crate) fn retained_response_c62_test_bytes() -> Vec<u8> {
    let mut model = tests::proof();
    for layer in &mut model.layers {
        layer.attn.c62_recip = Some(tests::c62_recip());
    }
    for chunk in &mut model.chunks {
        for layer in &mut chunk.layers {
            layer.attn.c62_recip = Some(tests::c62_recip());
        }
    }
    C6RetainedResponseProof {
        model,
        product: ProdProof { m0: Fp2::ONE, m1: Fp2::ZERO },
        c62_subfield_digests: Vec::new(),
    }
    .encode_c62()
    .unwrap()
}

#[cfg(test)]
pub(crate) fn retained_response_test_bytes() -> Vec<u8> {
    C6RetainedResponseProof {
        model: tests::proof(),
        product: ProdProof { m0: Fp2::ONE, m1: Fp2::ZERO },
        c62_subfield_digests: Vec::new(),
    }
    .encode()
    .unwrap()
}
