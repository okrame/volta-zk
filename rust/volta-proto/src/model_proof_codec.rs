//! Strict canonical disk codec for the retained response proof.
//!
//! C6 historically counted the response transcript but had no parser for
//! [`ModelProof`]. The campaign verifier must reconstruct this object from
//! bytes without retaining prover state, witness material, or keys.

use crate::block_proof::{
    AttnBlockProof, FfnBlockProof, LayerProof, LnChainProof, TableCloseProof,
};
use crate::boundary_thinning::EqReductionProof;
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
use std::fmt;
use volta_field::{Fp, Fp2, P};

const MAGIC: &[u8] = b"VC6MRP1\0";
const MAX_COLLECTION_ITEMS: usize = 1_000_000;

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

struct Writer(Vec<u8>);

impl Writer {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
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

    fn finish(self) -> Result<()> {
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

impl Wire for Fp2 {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.fp2(*self);
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input.fp2()
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.len(self.len())?;
        for value in self {
            value.write(out)?;
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let len = input.len()?;
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

wire_struct!(BlindSumcheckProof { round_corrs });
wire_struct!(ProdProof { m0, m1 });
wire_struct!(ChainedGemmProof { sumcheck, prod });
wire_struct!(HadamardProof { round_corrs, e_corr, r_corr, z_corr });
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
wire_struct!(AttnBlockProof {
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
});
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
wire_struct!(ModelProof {
    layers,
    seams,
    embed,
    final_ln,
    logits,
    selection,
    chunks,
    tables,
    private_argmax,
});

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
            _ => Err(ModelProofCodecError::new("unknown model-proof table key")),
        }
    }
}

wire_struct!(TableCloseProof { key, mult_corr, side });

/// Encode every verifier-consumed model-proof field in one fixed order.
pub fn encode_model_proof_canonical(proof: &ModelProof) -> Result<Vec<u8>> {
    let mut out = Writer(MAGIC.to_vec());
    proof.write(&mut out)?;
    Ok(out.0)
}

/// Decode a fresh proof object and reject trailing/noncanonical bytes.
pub fn decode_model_proof_canonical(bytes: &[u8]) -> Result<ModelProof> {
    let mut input = Reader { bytes, offset: 0 };
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

    fn proof() -> ModelProof {
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
        let mut field = Reader { bytes: &noncanonical, offset: 0 };
        assert!(field.fp2().is_err());
    }
}
