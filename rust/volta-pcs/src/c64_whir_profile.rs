//! Structural-only D23/D20 WHIR screen for C6.4.

use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir_c61::pcs::zk::ZkParameters;

use crate::c61_whir_reference::C61WhirStructuralBudget;
use crate::c63_preencoded_whir::{
    c63_projected_whir_structural_bytes_for_config, c63_whir_structural_budget_for_config,
    C63WhirConfig, C63_WHIR_SECURITY_BITS,
};

pub const C64_INPUT_VARIABLES: usize = 23;
pub const C64_SKETCH_VARIABLES: usize = 20;
pub const C64_BASE_LIMBS: usize = 4;

fn c64_profile(num_variables: usize) -> Result<(usize, Vec<usize>, Vec<usize>), String> {
    match num_variables {
        // Keep the C6.3 round count. One additional variable remains in the
        // small final base case; adding a whole query round costs more bytes.
        C64_INPUT_VARIABLES => {
            Ok((19, vec![1, 2, 3, 3, 4, 5, 6, 7], vec![1, 2, 2, 2, 2, 2, 2, 2, 2]))
        }
        C64_SKETCH_VARIABLES => Ok((18, vec![1, 2, 3, 4, 5, 6], vec![1, 2, 2, 2, 2, 2, 3])),
        _ => Err("C6.4 WHIR admits only D23 or D20".to_owned()),
    }
}

pub fn c64_whir_config(num_variables: usize) -> Result<C63WhirConfig, String> {
    let (pow_bits, rates, folding) = c64_profile(num_variables)?;
    C63WhirConfig::new_with_query_security_level(
        num_variables,
        ProtocolParameters {
            security_level: C63_WHIR_SECURITY_BITS,
            pow_bits,
            round_log_inv_rates: rates,
            folding_factor: FoldingFactor::PerRound(folding),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        ZkParameters { ell_zk: 16, mask_log_inv_rate: 1 },
        C63_WHIR_SECURITY_BITS,
    )
    .map_err(|error| format!("C6.4 WHIR configuration failed: {error}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C64WhirStructuralScreen {
    pub input: C61WhirStructuralBudget,
    pub sketch: C61WhirStructuralBudget,
    pub sketch_with_transition_openings_bytes: usize,
    pub eight_body_bytes: usize,
    pub four_transition_opening_bytes: usize,
}

pub fn c64_whir_structural_screen() -> Result<C64WhirStructuralScreen, String> {
    let input_config = c64_whir_config(C64_INPUT_VARIABLES)?;
    let sketch_config = c64_whir_config(C64_SKETCH_VARIABLES)?;
    let input = c63_whir_structural_budget_for_config(&input_config)?;
    let sketch = c63_whir_structural_budget_for_config(&sketch_config)?;
    let sketch_with_transition_openings_bytes =
        c63_projected_whir_structural_bytes_for_config(&sketch_config)?;
    let eight_body_bytes = C64_BASE_LIMBS
        .checked_mul(
            input
                .strict_chain_bytes
                .checked_add(sketch.strict_chain_bytes)
                .ok_or_else(|| "C6.4 WHIR body byte count overflows".to_owned())?,
        )
        .ok_or_else(|| "C6.4 eight-body byte count overflows".to_owned())?;
    let four_transition_opening_bytes = C64_BASE_LIMBS
        .checked_mul(
            sketch_with_transition_openings_bytes
                .checked_sub(sketch.strict_chain_bytes)
                .ok_or_else(|| "C6.4 transition opening byte count underflows".to_owned())?,
        )
        .ok_or_else(|| "C6.4 transition opening byte count overflows".to_owned())?;
    Ok(C64WhirStructuralScreen {
        input,
        sketch,
        sketch_with_transition_openings_bytes,
        eight_body_bytes,
        four_transition_opening_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d23_d20_profiles_keep_the_c63_query_security() {
        let input = c64_whir_config(C64_INPUT_VARIABLES).unwrap();
        let sketch = c64_whir_config(C64_SKETCH_VARIABLES).unwrap();
        assert_eq!(
            input.round_parameters.iter().map(|round| round.num_queries).collect::<Vec<_>>(),
            vec![245, 245, 113, 74, 74, 55, 44, 36]
        );
        assert_eq!(input.final_queries, 31);
        assert_eq!(input.mask_queries, 257);
        assert_eq!(
            sketch.round_parameters.iter().map(|round| round.num_queries).collect::<Vec<_>>(),
            vec![245, 245, 113, 74, 55, 44]
        );
        assert_eq!(sketch.final_queries, 36);
        assert_eq!(sketch.mask_queries, 254);
        let screen = c64_whir_structural_screen().unwrap();
        assert_eq!(screen.input.strict_chain_bytes, 1_319_928);
        assert_eq!(screen.sketch.strict_chain_bytes, 1_010_584);
        assert_eq!(screen.sketch_with_transition_openings_bytes, 1_324_917);
        assert_eq!(screen.eight_body_bytes, 9_322_048);
        assert_eq!(screen.four_transition_opening_bytes, 1_257_332);
    }
}
