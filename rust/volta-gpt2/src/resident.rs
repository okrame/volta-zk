//! Internal P7 resident-witness seam.
//!
//! The frozen CPU witness remains the specification.  This module packs the
//! same wires into context-owned typed CUDA buffers and exposes borrowed
//! regions to the prover without revealing a raw device pointer.  Lookup
//! traces are intentionally absent: the prover already recomputes their
//! columns and multiplicities from the witness wires.

use volta_accel::{AccelError, Backend, BackendKind, DeviceBuffer, DeviceSlice};

use crate::layer::{D, DFF, DH, H};
use crate::model::{Gpt2Model, P5Params, L, NPOS, VOCAB};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Region {
    offset: usize,
    len: usize,
}

fn take(cursor: &mut usize, len: usize) -> Region {
    let region = Region { offset: *cursor, len };
    *cursor = cursor.checked_add(len).expect("resident witness layout overflow");
    region
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum LayerI16Field {
    XIn = 0,
    K,
    V,
    AttnBlockOut,
    FfnBlockOut,
    Ln1RsqrtOut,
    Ln1Out,
    Q,
    ScoresQ,
    RowShift,
    ExpOut,
    Recips,
    SoftmaxW,
    AvQ,
    AttnProjQ,
    Ln2RsqrtOut,
    Ln2Out,
    FfnUpQ,
    GeluOut,
    FfnDownQ,
}

impl LayerI16Field {
    pub const ALL: [Self; 20] = [
        Self::XIn,
        Self::K,
        Self::V,
        Self::AttnBlockOut,
        Self::FfnBlockOut,
        Self::Ln1RsqrtOut,
        Self::Ln1Out,
        Self::Q,
        Self::ScoresQ,
        Self::RowShift,
        Self::ExpOut,
        Self::Recips,
        Self::SoftmaxW,
        Self::AvQ,
        Self::AttnProjQ,
        Self::Ln2RsqrtOut,
        Self::Ln2Out,
        Self::FfnUpQ,
        Self::GeluOut,
        Self::FfnDownQ,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum LayerI64Field {
    Ln1Mean = 0,
    Ln1Var,
    Ln1RsqrtIn,
    QkvAcc,
    ScoresAcc,
    Denoms,
    AvAcc,
    ProjAcc,
    Ln2Mean,
    Ln2Var,
    Ln2RsqrtIn,
    FfnUpAcc,
    FfnDownAcc,
}

impl LayerI64Field {
    pub const ALL: [Self; 13] = [
        Self::Ln1Mean,
        Self::Ln1Var,
        Self::Ln1RsqrtIn,
        Self::QkvAcc,
        Self::ScoresAcc,
        Self::Denoms,
        Self::AvAcc,
        Self::ProjAcc,
        Self::Ln2Mean,
        Self::Ln2Var,
        Self::Ln2RsqrtIn,
        Self::FfnUpAcc,
        Self::FfnDownAcc,
    ];
}

#[derive(Debug)]
struct LayerLayout {
    i16: [Region; 20],
    i64: [Region; 13],
    i16_len: usize,
    i64_len: usize,
    score_entries: usize,
}

impl LayerLayout {
    fn new(t: usize) -> LayerLayout {
        let td = t.checked_mul(D).expect("layer witness shape overflow");
        let tdff = t.checked_mul(DFF).expect("layer witness shape overflow");
        let caus = t.checked_mul(t + 1).expect("layer witness shape overflow") / 2;
        let scores = H.checked_mul(caus).expect("layer witness shape overflow");
        let rows = H.checked_mul(t).expect("layer witness shape overflow");

        let mut p16 = 0;
        let i16 = [
            take(&mut p16, td),     // x_in
            take(&mut p16, td),     // k
            take(&mut p16, td),     // v
            take(&mut p16, td),     // attn_block_out
            take(&mut p16, td),     // ffn_block_out
            take(&mut p16, t),      // ln1_rsqrt_out
            take(&mut p16, td),     // ln1_out
            take(&mut p16, td),     // q
            take(&mut p16, scores), // scores_q
            take(&mut p16, rows),   // row_shift
            take(&mut p16, scores), // exp_out
            take(&mut p16, rows),   // recips
            take(&mut p16, scores), // softmax_w
            take(&mut p16, td),     // av_q
            take(&mut p16, td),     // attn_proj_q
            take(&mut p16, t),      // ln2_rsqrt_out
            take(&mut p16, td),     // ln2_out
            take(&mut p16, tdff),   // ffn_up_q
            take(&mut p16, tdff),   // gelu_out
            take(&mut p16, td),     // ffn_down_q
        ];

        let mut p64 = 0;
        let i64 = [
            take(&mut p64, t),      // ln1_mean
            take(&mut p64, t),      // ln1_var
            take(&mut p64, t),      // ln1_rsqrt_in
            take(&mut p64, 3 * td), // qkv_acc
            take(&mut p64, scores), // scores_acc
            take(&mut p64, rows),   // denoms
            take(&mut p64, td),     // av_acc
            take(&mut p64, td),     // proj_acc
            take(&mut p64, t),      // ln2_mean
            take(&mut p64, t),      // ln2_var
            take(&mut p64, t),      // ln2_rsqrt_in
            take(&mut p64, tdff),   // ffn_up_acc
            take(&mut p64, td),     // ffn_down_acc
        ];
        LayerLayout { i16, i64, i16_len: p16, i64_len: p64, score_entries: scores }
    }
}

/// Every proof-relevant wire of one layer, packed by scalar type.  The field
/// enums are stable only inside the workspace; this is not a public model API.
#[derive(Debug)]
pub struct ResidentLayerWitness {
    t: usize,
    layout: LayerLayout,
    i16_values: DeviceBuffer<i16>,
    i64_values: DeviceBuffer<i64>,
}

impl ResidentLayerWitness {
    pub fn t(&self) -> usize {
        self.t
    }

    pub fn score_entries(&self) -> usize {
        self.layout.score_entries
    }

    pub fn i16(&self, field: LayerI16Field) -> DeviceSlice<'_, i16> {
        let r = self.layout.i16[field as usize];
        DeviceSlice::new(&self.i16_values, r.offset, r.len).expect("valid layer i16 layout")
    }

    pub fn i64(&self, field: LayerI64Field) -> DeviceSlice<'_, i64> {
        let r = self.layout.i64[field as usize];
        DeviceSlice::new(&self.i64_values, r.offset, r.len).expect("valid layer i64 layout")
    }

    fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let first = backend.free_device(self.i64_values).err();
        let second = backend.free_device(self.i16_values).err();
        first.or(second).map_or(Ok(()), Err)
    }
}

#[derive(Clone, Copy, Debug)]
struct LayerWeightLayout {
    c_attn: Region,
    c_attn_bias: Region,
    attn_proj: Region,
    attn_proj_bias: Region,
    ffn_up: Region,
    ffn_up_bias: Region,
    ffn_down: Region,
    ffn_down_bias: Region,
    ln1_gain: Region,
    ln1_bias: Region,
    ln2_gain: Region,
    ln2_bias: Region,
}

#[derive(Debug)]
struct ModelWeightLayout {
    layers: [LayerWeightLayout; L],
    wte: Region,
    wpe: Region,
    lnf_gain: Region,
    lnf_bias: Region,
    exp: Region,
    gelu: Region,
    ln_rsqrt: Region,
    softmax_recip: Region,
    len: usize,
}

impl ModelWeightLayout {
    fn new() -> ModelWeightLayout {
        let mut p = 0;
        let layers = std::array::from_fn(|_| LayerWeightLayout {
            c_attn: take(&mut p, D * 3 * D),
            c_attn_bias: take(&mut p, 3 * D),
            attn_proj: take(&mut p, D * D),
            attn_proj_bias: take(&mut p, D),
            ffn_up: take(&mut p, D * DFF),
            ffn_up_bias: take(&mut p, DFF),
            ffn_down: take(&mut p, DFF * D),
            ffn_down_bias: take(&mut p, D),
            ln1_gain: take(&mut p, D),
            ln1_bias: take(&mut p, D),
            ln2_gain: take(&mut p, D),
            ln2_bias: take(&mut p, D),
        });
        let wte = take(&mut p, VOCAB * D);
        let wpe = take(&mut p, NPOS * D);
        let lnf_gain = take(&mut p, D);
        let lnf_bias = take(&mut p, D);
        let exp = take(&mut p, 1 << 16);
        let gelu = take(&mut p, 1 << 16);
        let ln_rsqrt = take(&mut p, 1 << 16);
        let softmax_recip = take(&mut p, 1 << 16);
        ModelWeightLayout {
            layers,
            wte,
            wpe,
            lnf_gain,
            lnf_bias,
            exp,
            gelu,
            ln_rsqrt,
            softmax_recip,
            len: p,
        }
    }
}

/// Persistent public weights/LUTs for resident forward execution.
#[derive(Debug)]
pub struct ResidentGpt2Model {
    params: P5Params,
    values: DeviceBuffer<i16>,
    layout: ModelWeightLayout,
}

impl ResidentGpt2Model {
    fn slice(&self, region: Region) -> DeviceSlice<'_, i16> {
        DeviceSlice::new(&self.values, region.offset, region.len).expect("valid weight layout")
    }

    pub fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        backend.free_device(self.values)
    }
}

fn upload_region(
    backend: &mut Backend,
    buffer: &DeviceBuffer<i16>,
    region: Region,
    values: &[i16],
) -> Result<(), AccelError> {
    if region.len != values.len() {
        return Err(AccelError::InvalidInput("resident model weight layout mismatch"));
    }
    backend.upload_device(buffer, region.offset, values)
}

/// Upload the frozen public model once.  Call this outside the online
/// measurement when setup/commitment costs are reported separately.
pub fn upload_resident_model(
    model: &Gpt2Model,
    backend: &mut Backend,
) -> Result<ResidentGpt2Model, AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident model upload requires the cuda-resident backend",
        ));
    }
    if model.layers.len() != L {
        return Err(AccelError::InvalidInput("frozen GPT-2 layer count mismatch"));
    }
    let layout = ModelWeightLayout::new();
    let values = backend.alloc_device(layout.len)?;
    let result = (|| {
        for (index, ((weights, biases), region)) in
            model.layers.iter().zip(layout.layers.iter()).enumerate()
        {
            let _ = index;
            upload_region(backend, &values, region.c_attn, &weights.c_attn)?;
            upload_region(backend, &values, region.c_attn_bias, &biases.c_attn)?;
            upload_region(backend, &values, region.attn_proj, &weights.attn_proj)?;
            upload_region(backend, &values, region.attn_proj_bias, &biases.attn_proj)?;
            upload_region(backend, &values, region.ffn_up, &weights.ffn_up)?;
            upload_region(backend, &values, region.ffn_up_bias, &biases.ffn_up)?;
            upload_region(backend, &values, region.ffn_down, &weights.ffn_down)?;
            upload_region(backend, &values, region.ffn_down_bias, &biases.ffn_down)?;
            upload_region(backend, &values, region.ln1_gain, &weights.ln1_gain)?;
            upload_region(backend, &values, region.ln1_bias, &weights.ln1_bias)?;
            upload_region(backend, &values, region.ln2_gain, &weights.ln2_gain)?;
            upload_region(backend, &values, region.ln2_bias, &weights.ln2_bias)?;
        }
        upload_region(backend, &values, layout.wte, &model.wte)?;
        upload_region(backend, &values, layout.wpe, &model.wpe)?;
        upload_region(backend, &values, layout.lnf_gain, &model.lnf_gain)?;
        upload_region(backend, &values, layout.lnf_bias, &model.lnf_bias)?;
        upload_region(backend, &values, layout.exp, &model.luts.exp)?;
        upload_region(backend, &values, layout.gelu, &model.luts.gelu)?;
        upload_region(backend, &values, layout.ln_rsqrt, &model.luts.ln_rsqrt)?;
        upload_region(backend, &values, layout.softmax_recip, &model.luts.softmax_recip)
    })();
    if let Err(error) = result {
        let _ = backend.free_device(values);
        return Err(error);
    }
    Ok(ResidentGpt2Model { params: model.p.clone(), values, layout })
}

/// Device-resident full-forward witness.  Only the final logits are public;
/// downloading any other field is a differential-test action, not part of
/// the resident execution path.
#[derive(Debug)]
pub struct ResidentModelWitness {
    pub t: usize,
    embed_out: DeviceBuffer<i16>,
    embed_acc: DeviceBuffer<i64>,
    pub layers: Vec<ResidentLayerWitness>,
    final_i16: DeviceBuffer<i16>, // [rsqrt_out | out[D]]
    final_i64: DeviceBuffer<i64>, // [mean | var | rsqrt_in]
    logits: DeviceBuffer<i64>,
}

impl ResidentModelWitness {
    pub fn embed_out(&self) -> DeviceSlice<'_, i16> {
        DeviceSlice::new(&self.embed_out, 0, self.t * D).expect("valid embed layout")
    }

    pub fn embed_acc(&self) -> DeviceSlice<'_, i64> {
        DeviceSlice::new(&self.embed_acc, 0, self.t * D).expect("valid embed layout")
    }

    pub fn final_mean(&self) -> DeviceSlice<'_, i64> {
        DeviceSlice::new(&self.final_i64, 0, 1).expect("valid final-LN layout")
    }

    pub fn final_var(&self) -> DeviceSlice<'_, i64> {
        DeviceSlice::new(&self.final_i64, 1, 1).expect("valid final-LN layout")
    }

    pub fn final_rsqrt_in(&self) -> DeviceSlice<'_, i64> {
        DeviceSlice::new(&self.final_i64, 2, 1).expect("valid final-LN layout")
    }

    pub fn final_rsqrt_out(&self) -> DeviceSlice<'_, i16> {
        DeviceSlice::new(&self.final_i16, 0, 1).expect("valid final-LN layout")
    }

    pub fn final_out(&self) -> DeviceSlice<'_, i16> {
        DeviceSlice::new(&self.final_i16, 1, D).expect("valid final-LN layout")
    }

    pub fn logits(&self) -> DeviceSlice<'_, i64> {
        DeviceSlice::new(&self.logits, 0, VOCAB).expect("valid logits layout")
    }

    pub fn free(self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        for layer in self.layers {
            remember_error(&mut first, layer.free(backend));
        }
        remember_error(&mut first, backend.free_device(self.logits));
        remember_error(&mut first, backend.free_device(self.final_i64));
        remember_error(&mut first, backend.free_device(self.final_i16));
        remember_error(&mut first, backend.free_device(self.embed_acc));
        remember_error(&mut first, backend.free_device(self.embed_out));
        first.map_or(Ok(()), Err)
    }
}

fn remember_error(first: &mut Option<AccelError>, result: Result<(), AccelError>) {
    if first.is_none() {
        *first = result.err();
    }
}

#[derive(Default)]
struct PendingForward {
    tokens: Option<DeviceBuffer<u32>>,
    error: Option<DeviceBuffer<u32>>,
    embed_out: Option<DeviceBuffer<i16>>,
    embed_acc: Option<DeviceBuffer<i64>>,
    layers: Vec<ResidentLayerWitness>,
    temporary_i16: Option<DeviceBuffer<i16>>,
    final_i16: Option<DeviceBuffer<i16>>,
    final_i64: Option<DeviceBuffer<i64>>,
    logits: Option<DeviceBuffer<i64>>,
}

impl PendingForward {
    fn cleanup(mut self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        if let Some(buffer) = self.temporary_i16.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.logits.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.final_i64.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.final_i16.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        for layer in self.layers.drain(..) {
            remember_error(&mut first, layer.free(backend));
        }
        if let Some(buffer) = self.embed_acc.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.embed_out.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.error.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        if let Some(buffer) = self.tokens.take() {
            remember_error(&mut first, backend.free_device(buffer));
        }
        first.map_or(Ok(()), Err)
    }

    fn finish(mut self, t: usize) -> ResidentModelWitness {
        ResidentModelWitness {
            t,
            embed_out: self.embed_out.take().expect("built embed output"),
            embed_acc: self.embed_acc.take().expect("built embed accumulator"),
            layers: std::mem::take(&mut self.layers),
            final_i16: self.final_i16.take().expect("built final i16 witness"),
            final_i64: self.final_i64.take().expect("built final i64 witness"),
            logits: self.logits.take().expect("built logits"),
        }
    }
}

fn layer_slice16(layer: &ResidentLayerWitness, field: LayerI16Field) -> DeviceSlice<'_, i16> {
    layer.i16(field)
}

fn layer_slice64(layer: &ResidentLayerWitness, field: LayerI64Field) -> DeviceSlice<'_, i64> {
    layer.i64(field)
}

/// Execute the full causal forward while retaining every proof wire on the
/// GPU.  The only online D2H transfer is a four-byte sticky error flag; proof
/// messages are produced later by the resident prover.
pub fn forward_model_tokens_resident(
    model: &ResidentGpt2Model,
    tokens: &[u32],
    backend: &mut Backend,
) -> Result<ResidentModelWitness, AccelError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "resident forward requires the cuda-resident backend",
        ));
    }
    let t = tokens.len();
    if t == 0 || t > NPOS || tokens.iter().any(|&token| token as usize >= VOCAB) {
        return Err(AccelError::InvalidInput("invalid resident token sequence"));
    }
    let td = t.checked_mul(D).ok_or(AccelError::InvalidInput("shape overflow"))?;
    let mut pending = PendingForward { layers: Vec::with_capacity(L), ..Default::default() };
    if let Err(error) = build_resident_forward(model, tokens, t, td, backend, &mut pending) {
        let _ = pending.cleanup(backend);
        return Err(error);
    }

    let error_buffer = pending.error.take().expect("built error flag");
    let error_value = match backend.download_device(&error_buffer, 0, 1) {
        Ok(value) => value[0],
        Err(error) => {
            let _ = backend.free_device(error_buffer);
            let _ = pending.cleanup(backend);
            return Err(error);
        }
    };
    if let Err(error) = backend.free_device(error_buffer) {
        let _ = pending.cleanup(backend);
        return Err(error);
    }
    let token_buffer = pending.tokens.take().expect("built token buffer");
    if let Err(error) = backend.free_device(token_buffer) {
        let _ = pending.cleanup(backend);
        return Err(error);
    }
    if error_value != 0 {
        let _ = pending.cleanup(backend);
        return Err(AccelError::Cuda(
            "resident fixed-point forward violated a no-clamp/domain invariant".to_owned(),
        ));
    }
    Ok(pending.finish(t))
}

fn pending_error(pending: &PendingForward) -> DeviceSlice<'_, u32> {
    DeviceSlice::new(pending.error.as_ref().expect("allocated error flag"), 0, 1)
        .expect("valid error flag")
}

fn build_resident_forward(
    model: &ResidentGpt2Model,
    tokens: &[u32],
    t: usize,
    td: usize,
    backend: &mut Backend,
    pending: &mut PendingForward,
) -> Result<(), AccelError> {
    pending.tokens = Some(backend.upload_new_device(tokens)?);
    pending.error = Some(backend.upload_new_device(&[0u32])?);
    pending.embed_out = Some(backend.alloc_device(td)?);
    pending.embed_acc = Some(backend.alloc_device(td)?);
    backend.fixed_embed_device(
        DeviceSlice::new(pending.tokens.as_ref().expect("tokens"), 0, t)?,
        model.slice(model.layout.wte),
        model.slice(model.layout.wpe),
        DeviceSlice::new(pending.embed_acc.as_ref().expect("embed acc"), 0, td)?,
        DeviceSlice::new(pending.embed_out.as_ref().expect("embed out"), 0, td)?,
        pending_error(pending),
        t,
        D,
        VOCAB,
        NPOS,
        0,
        model.params.shift_embed,
    )?;

    for layer_index in 0..L {
        let layout = LayerLayout::new(t);
        pending.temporary_i16 = Some(backend.alloc_device(layout.i16_len)?);
        let i64_values = backend.alloc_device(layout.i64_len)?;
        let i16_values = pending.temporary_i16.take().expect("pending layer i16 allocation");
        let layer = ResidentLayerWitness { t, layout, i16_values, i64_values };
        pending.layers.push(layer);

        let (source, seam_shift) = if layer_index == 0 {
            (DeviceSlice::new(pending.embed_out.as_ref().expect("embed out"), 0, td)?, 0)
        } else {
            (
                layer_slice16(&pending.layers[layer_index - 1], LayerI16Field::FfnBlockOut),
                model.params.seam_shifts[layer_index - 1],
            )
        };
        backend.fixed_requant_i16_device(
            source,
            layer_slice16(&pending.layers[layer_index], LayerI16Field::XIn),
            pending_error(pending),
            seam_shift,
        )?;

        let weights = model.layout.layers[layer_index];
        let mut params = model.params.lut;
        params.shift_attn_proj = model.params.shift_attn_proj[layer_index];
        params.shift_ffn_down = model.params.shift_ffn_down[layer_index];

        backend.fixed_layer_norm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::XIn),
            model.slice(weights.ln1_gain),
            model.slice(weights.ln1_bias),
            model.slice(model.layout.ln_rsqrt),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln1Mean),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln1Var),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln1RsqrtIn),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln1RsqrtOut),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln1Out),
            pending_error(pending),
            t,
            D,
            params.ln_var_shift,
            params.shift_ln_norm,
        )?;

        let qkv_len = 3 * td;
        pending.temporary_i16 = Some(backend.alloc_device(qkv_len)?);
        backend.fixed_gemm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln1Out),
            model.slice(weights.c_attn),
            Some(model.slice(weights.c_attn_bias)),
            None,
            layer_slice64(&pending.layers[layer_index], LayerI64Field::QkvAcc),
            DeviceSlice::new(pending.temporary_i16.as_ref().expect("qkv temporary"), 0, qkv_len)?,
            None,
            pending_error(pending),
            t,
            D,
            3 * D,
            params.shift_qkv,
        )?;
        backend.fixed_qkv_split_device(
            DeviceSlice::new(pending.temporary_i16.as_ref().expect("qkv temporary"), 0, qkv_len)?,
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Q),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::K),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::V),
            t,
            D,
        )?;
        backend.free_device(pending.temporary_i16.take().expect("qkv temporary"))?;

        backend.fixed_attention_scores_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Q),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::K),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::ScoresAcc),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::ScoresQ),
            pending_error(pending),
            t,
            t,
            0,
            H,
            DH,
            params.shift_scores,
        )?;
        backend.fixed_softmax_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::ScoresQ),
            model.slice(model.layout.exp),
            model.slice(model.layout.softmax_recip),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::RowShift),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::ExpOut),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Denoms),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Recips),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::SoftmaxW),
            pending_error(pending),
            t,
            t,
            0,
            H,
            params.recip_den_shift,
            params.shift_softmax_norm,
            params.softmax_row_shift,
        )?;
        backend.fixed_av_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::SoftmaxW),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::V),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::AvAcc),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::AvQ),
            pending_error(pending),
            t,
            t,
            0,
            D,
            H,
            params.shift_av,
        )?;
        backend.fixed_gemm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::AvQ),
            model.slice(weights.attn_proj),
            Some(model.slice(weights.attn_proj_bias)),
            Some(layer_slice16(&pending.layers[layer_index], LayerI16Field::XIn)),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::ProjAcc),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::AttnProjQ),
            Some(layer_slice16(&pending.layers[layer_index], LayerI16Field::AttnBlockOut)),
            pending_error(pending),
            t,
            D,
            D,
            params.shift_attn_proj,
        )?;

        backend.fixed_layer_norm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::AttnBlockOut),
            model.slice(weights.ln2_gain),
            model.slice(weights.ln2_bias),
            model.slice(model.layout.ln_rsqrt),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln2Mean),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln2Var),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::Ln2RsqrtIn),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln2RsqrtOut),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln2Out),
            pending_error(pending),
            t,
            D,
            params.ln_var_shift,
            params.shift_ln_norm,
        )?;
        backend.fixed_gemm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::Ln2Out),
            model.slice(weights.ffn_up),
            Some(model.slice(weights.ffn_up_bias)),
            None,
            layer_slice64(&pending.layers[layer_index], LayerI64Field::FfnUpAcc),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::FfnUpQ),
            None,
            pending_error(pending),
            t,
            D,
            DFF,
            params.shift_ffn_up,
        )?;
        backend.fixed_lookup_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::FfnUpQ),
            model.slice(model.layout.gelu),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::GeluOut),
        )?;
        backend.fixed_gemm_device(
            layer_slice16(&pending.layers[layer_index], LayerI16Field::GeluOut),
            model.slice(weights.ffn_down),
            Some(model.slice(weights.ffn_down_bias)),
            Some(layer_slice16(&pending.layers[layer_index], LayerI16Field::AttnBlockOut)),
            layer_slice64(&pending.layers[layer_index], LayerI64Field::FfnDownAcc),
            layer_slice16(&pending.layers[layer_index], LayerI16Field::FfnDownQ),
            Some(layer_slice16(&pending.layers[layer_index], LayerI16Field::FfnBlockOut)),
            pending_error(pending),
            t,
            DFF,
            D,
            params.shift_ffn_down,
        )?;
    }

    pending.final_i16 = Some(backend.alloc_device(D + 1)?);
    pending.final_i64 = Some(backend.alloc_device(3)?);
    let last =
        layer_slice16(pending.layers.last().expect("non-empty model"), LayerI16Field::FfnBlockOut);
    let last_row = DeviceSlice::new(last.buffer(), last.offset() + (t - 1) * D, D)?;
    backend.fixed_layer_norm_device(
        last_row,
        model.slice(model.layout.lnf_gain),
        model.slice(model.layout.lnf_bias),
        model.slice(model.layout.ln_rsqrt),
        DeviceSlice::new(pending.final_i64.as_ref().expect("final i64"), 0, 1)?,
        DeviceSlice::new(pending.final_i64.as_ref().expect("final i64"), 1, 1)?,
        DeviceSlice::new(pending.final_i64.as_ref().expect("final i64"), 2, 1)?,
        DeviceSlice::new(pending.final_i16.as_ref().expect("final i16"), 0, 1)?,
        DeviceSlice::new(pending.final_i16.as_ref().expect("final i16"), 1, D)?,
        pending_error(pending),
        1,
        D,
        model.params.lut.ln_var_shift,
        model.params.lut.shift_ln_norm,
    )?;
    pending.logits = Some(backend.alloc_device(VOCAB)?);
    backend.fixed_logits_device(
        DeviceSlice::new(pending.final_i16.as_ref().expect("final i16"), 1, D)?,
        model.slice(model.layout.wte),
        DeviceSlice::new(pending.logits.as_ref().expect("logits"), 0, VOCAB)?,
        1,
        D,
        VOCAB,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "cuda"))]
mod tests {
    use super::*;
    use crate::model::{forward_model_tokens, load_model};
    use std::path::Path;

    fn weights_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    fn required_gpu() -> Option<Backend> {
        match Backend::cuda_resident() {
            Ok(gpu) => Some(gpu),
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident forward differential: {error}");
                None
            }
            Err(error) => panic!("CUDA required: {error}"),
        }
    }

    fn download16(backend: &mut Backend, slice: DeviceSlice<'_, i16>) -> Vec<i16> {
        backend.download_device(slice.buffer(), slice.offset(), slice.len()).unwrap()
    }

    fn download64(backend: &mut Backend, slice: DeviceSlice<'_, i64>) -> Vec<i64> {
        backend.download_device(slice.buffer(), slice.offset(), slice.len()).unwrap()
    }

    fn compare_witness(
        backend: &mut Backend,
        got: &ResidentModelWitness,
        expected: &crate::model::ModelWitness,
    ) {
        assert_eq!(got.t, expected.t);
        assert_eq!(download64(backend, got.embed_acc()), expected.embed.acc);
        assert_eq!(download16(backend, got.embed_out()), expected.embed.out);
        assert_eq!(got.layers.len(), expected.layers.len());
        for (index, (got, expected)) in got.layers.iter().zip(&expected.layers).enumerate() {
            macro_rules! eq16 {
                ($field:ident, $expected:ident) => {
                    assert_eq!(
                        download16(backend, got.i16(LayerI16Field::$field)),
                        expected.$expected,
                        "layer {index} {}",
                        stringify!($expected),
                    );
                };
            }
            macro_rules! eq64 {
                ($field:ident, $expected:ident) => {
                    assert_eq!(
                        download64(backend, got.i64(LayerI64Field::$field)),
                        expected.$expected,
                        "layer {index} {}",
                        stringify!($expected),
                    );
                };
            }
            eq16!(XIn, x_in);
            eq16!(K, k);
            eq16!(V, v);
            eq16!(AttnBlockOut, attn_block_out);
            eq16!(FfnBlockOut, ffn_block_out);
            eq64!(Ln1Mean, ln1_mean);
            eq64!(Ln1Var, ln1_var);
            eq64!(Ln1RsqrtIn, ln1_rsqrt_in);
            eq16!(Ln1RsqrtOut, ln1_rsqrt_out);
            eq16!(Ln1Out, ln1_out);
            eq64!(QkvAcc, qkv_acc);
            eq16!(Q, q);
            eq64!(ScoresAcc, scores_acc);
            eq16!(ScoresQ, scores_q);
            eq16!(RowShift, row_shift);
            eq16!(ExpOut, exp_out);
            eq64!(Denoms, denoms);
            eq16!(Recips, recips);
            eq16!(SoftmaxW, softmax_w);
            eq64!(AvAcc, av_acc);
            eq16!(AvQ, av_q);
            eq64!(ProjAcc, proj_acc);
            eq16!(AttnProjQ, attn_proj_q);
            eq64!(Ln2Mean, ln2_mean);
            eq64!(Ln2Var, ln2_var);
            eq64!(Ln2RsqrtIn, ln2_rsqrt_in);
            eq16!(Ln2RsqrtOut, ln2_rsqrt_out);
            eq16!(Ln2Out, ln2_out);
            eq64!(FfnUpAcc, ffn_up_acc);
            eq16!(FfnUpQ, ffn_up_q);
            eq16!(GeluOut, gelu_out);
            eq64!(FfnDownAcc, ffn_down_acc);
            eq16!(FfnDownQ, ffn_down_q);
        }
        assert_eq!(download64(backend, got.final_mean()), vec![expected.final_ln.mean]);
        assert_eq!(download64(backend, got.final_var()), vec![expected.final_ln.var]);
        assert_eq!(download64(backend, got.final_rsqrt_in()), vec![expected.final_ln.rsqrt_in]);
        assert_eq!(download16(backend, got.final_rsqrt_out()), vec![expected.final_ln.rsqrt_out]);
        assert_eq!(download16(backend, got.final_out()), expected.final_ln.out);
        assert_eq!(download64(backend, got.logits()), expected.logits);
    }

    #[test]
    fn cuda_resident_full_witness_is_bit_exact_and_reusable() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping resident forward differential: frozen artifact absent");
            return;
        }
        let Some(mut gpu) = required_gpu() else { return };
        let host = load_model(&dir).unwrap();
        let tokens = host.p.tokens[..3].to_vec();
        let expected = forward_model_tokens(&host, &tokens);
        let mut resident_model = upload_resident_model(&host, &mut gpu).unwrap();
        let setup_live = gpu.stats().unwrap().live_device_bytes;

        for _ in 0..2 {
            gpu.begin_measurement().unwrap();
            let got = forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
            let stats = gpu.finish_measurement().unwrap();
            assert_eq!(stats.h2d_bytes, (tokens.len() * 4 + 4) as u64);
            assert_eq!(stats.d2h_bytes, 4);
            assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
            assert!(stats.operation(volta_accel::Operation::Gemm).calls >= 147);
            compare_witness(&mut gpu, &got, &expected);
            got.free(&mut gpu).unwrap();
            assert_eq!(
                gpu.stats().unwrap().live_device_bytes,
                setup_live,
                "resident forward leaked across context reuse"
            );
        }
        let original_embed_shift = resident_model.params.shift_embed;
        resident_model.params.shift_embed = -30;
        assert!(matches!(
            forward_model_tokens_resident(&resident_model, &tokens, &mut gpu),
            Err(AccelError::Cuda(_))
        ));
        assert_eq!(
            gpu.stats().unwrap().live_device_bytes,
            setup_live,
            "failed resident forward did not roll back every allocation"
        );
        resident_model.params.shift_embed = original_embed_shift;
        let recovered = forward_model_tokens_resident(&resident_model, &tokens, &mut gpu).unwrap();
        compare_witness(&mut gpu, &recovered, &expected);
        recovered.free(&mut gpu).unwrap();
        assert_eq!(gpu.stats().unwrap().live_device_bytes, setup_live);
        resident_model.free(&mut gpu).unwrap();
    }
}
