//! Exact provider-side cache owners for the first C6 T1 response.
//!
//! The adapter consumes the K/V slabs emitted by the canonical GPT-2
//! witness generator.  It does not recompute the forward pass and it does
//! not accept a provider-authored cache table.

use volta_field::{Fp, Fp2};
use volta_gpt2::{BandModelWitness, ModelWitness};
use volta_pcs::{
    C6CacheCell, C6CacheSlotKind, C6PersistentCacheLayout, C6PersistentCacheStateWitness,
};

pub struct C6CacheLayerSlabs<'a> {
    pub prefill_k: &'a [i16],
    pub prefill_v: &'a [i16],
    pub decode_k: &'a [i16],
    pub decode_v: &'a [i16],
}

/// Materialize genesis and successor cache states from one ordered response
/// slab census.  This geometry-parametric form exists so the exact index map
/// can be tested without allocating the production D24 cohorts.
pub fn materialize_c6_genesis_cache_states(
    layout: C6PersistentCacheLayout,
    prefill_len: u16,
    decode_len: u16,
    layers: &[C6CacheLayerSlabs<'_>],
) -> Result<(C6PersistentCacheStateWitness, C6PersistentCacheStateWitness), String> {
    layout.validate().map_err(|error| error.to_string())?;
    let new_len = prefill_len
        .checked_add(decode_len)
        .ok_or_else(|| "C6 T1 cache length overflows".to_owned())?;
    if new_len > layout.capacity_tokens || layers.len() != usize::from(layout.layers) {
        return Err("C6 T1 cache response geometry mismatch".to_owned());
    }
    let width = usize::from(layout.width);
    let prefill_entries = usize::from(prefill_len)
        .checked_mul(width)
        .ok_or_else(|| "C6 T1 prefill cache slab length overflows".to_owned())?;
    let decode_entries = usize::from(decode_len)
        .checked_mul(width)
        .ok_or_else(|| "C6 T1 decode cache slab length overflows".to_owned())?;
    if layers.iter().any(|layer| {
        layer.prefill_k.len() != prefill_entries
            || layer.prefill_v.len() != prefill_entries
            || layer.decode_k.len() != decode_entries
            || layer.decode_v.len() != decode_entries
    }) {
        return Err("C6 T1 cache K/V slab census mismatch".to_owned());
    }

    let predecessor =
        C6PersistentCacheStateWitness::zero(layout).map_err(|error| error.to_string())?;
    let mut successor =
        C6PersistentCacheStateWitness::zero(layout).map_err(|error| error.to_string())?;
    for (layer, slabs) in layers.iter().enumerate() {
        let layer = u16::try_from(layer).map_err(|_| "C6 T1 layer index overflows".to_owned())?;
        for (kind, prefill, decode) in [
            (C6CacheSlotKind::Key, slabs.prefill_k, slabs.decode_k),
            (C6CacheSlotKind::Value, slabs.prefill_v, slabs.decode_v),
        ] {
            for position in 0..new_len {
                let (source, source_position) = if position < prefill_len {
                    (prefill, position)
                } else {
                    (decode, position - prefill_len)
                };
                for channel in 0..layout.width {
                    let source_index = usize::from(source_position) * width + usize::from(channel);
                    successor
                        .set(
                            layout,
                            C6CacheCell { kind, layer, position, channel },
                            Fp2::from_base(Fp::from_i64(i64::from(source[source_index]))),
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
        }
    }
    predecessor.validate_canonical(layout, 0).map_err(|error| error.to_string())?;
    successor.validate_canonical(layout, new_len).map_err(|error| error.to_string())?;
    Ok((predecessor, successor))
}

/// Capture the exact production cache owners emitted by the frozen first
/// `100+50` T1 response witness.
pub fn materialize_c6_t1_genesis_cache_states(
    prefill: &ModelWitness,
    decode: &BandModelWitness,
) -> Result<(C6PersistentCacheStateWitness, C6PersistentCacheStateWitness), String> {
    let layout = C6PersistentCacheLayout::production();
    if prefill.t != 100 || decode.t0 != prefill.t || decode.q != 50 {
        return Err("C6 T1 requires the frozen genesis 100+50 response".to_owned());
    }
    if prefill.layers.len() != decode.layers.len() {
        return Err("C6 T1 prefill/decode layer census mismatch".to_owned());
    }
    let layers = prefill
        .layers
        .iter()
        .zip(&decode.layers)
        .map(|(prefill, decode)| C6CacheLayerSlabs {
            prefill_k: &prefill.k,
            prefill_v: &prefill.v,
            decode_k: &decode.k,
            decode_v: &decode.v,
        })
        .collect::<Vec<_>>();
    materialize_c6_genesis_cache_states(layout, 100, 50, &layers)
}

/// Materialize the predecessor and successor cache states for one C6.2
/// continuation. The full witness contains the accepted prefix and exactly
/// 50 new rows.
pub fn materialize_c62_continuation_cache_states(
    full: &ModelWitness,
    old_len: u16,
) -> Result<(C6PersistentCacheStateWitness, C6PersistentCacheStateWitness), String> {
    let layout = C6PersistentCacheLayout::production();
    let new_len = old_len
        .checked_add(50)
        .ok_or_else(|| "C6.2 continuation cache length overflows".to_owned())?;
    if old_len < 150
        || old_len > 900
        || old_len % 50 != 0
        || full.t != usize::from(new_len)
        || full.layers.len() != usize::from(layout.layers)
    {
        return Err("C6.2 continuation cache witness geometry differs".to_owned());
    }
    let width = usize::from(layout.width);
    let expected_entries = usize::from(new_len)
        .checked_mul(width)
        .ok_or_else(|| "C6.2 continuation cache slab length overflows".to_owned())?;
    if full.layers.iter().any(|layer| {
        layer.k.len() != expected_entries || layer.v.len() != expected_entries
    }) {
        return Err("C6.2 continuation K/V slab census differs".to_owned());
    }

    let mut predecessor =
        C6PersistentCacheStateWitness::zero(layout).map_err(|error| error.to_string())?;
    let mut successor =
        C6PersistentCacheStateWitness::zero(layout).map_err(|error| error.to_string())?;
    for (layer_index, layer) in full.layers.iter().enumerate() {
        let layer_index = u16::try_from(layer_index)
            .map_err(|_| "C6.2 continuation layer index overflows".to_owned())?;
        for (kind, values) in
            [(C6CacheSlotKind::Key, &layer.k), (C6CacheSlotKind::Value, &layer.v)]
        {
            for position in 0..new_len {
                for channel in 0..layout.width {
                    let source_index = usize::from(position) * width + usize::from(channel);
                    let value = Fp2::from_base(Fp::from_i64(i64::from(values[source_index])));
                    let cell = C6CacheCell {
                        kind,
                        layer: layer_index,
                        position,
                        channel,
                    };
                    successor.set(layout, cell, value).map_err(|error| error.to_string())?;
                    if position < old_len {
                        predecessor
                            .set(layout, cell, value)
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
        }
    }
    predecessor
        .validate_canonical(layout, old_len)
        .map_err(|error| error.to_string())?;
    successor
        .validate_canonical(layout, new_len)
        .map_err(|error| error.to_string())?;
    Ok((predecessor, successor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scaled_layout() -> C6PersistentCacheLayout {
        C6PersistentCacheLayout {
            layers: 2,
            capacity_tokens: 4,
            width: 3,
            padded_layers: 2,
            padded_width: 4,
        }
    }

    #[test]
    fn cache_states_are_exactly_the_ordered_response_kv_slabs() {
        let layout = scaled_layout();
        let layer0 = C6CacheLayerSlabs {
            prefill_k: &[1, -2, 3, 4, 5, 6],
            prefill_v: &[11, 12, 13, 14, 15, 16],
            decode_k: &[7, 8, 9],
            decode_v: &[-17, 18, 19],
        };
        let layer1 = C6CacheLayerSlabs {
            prefill_k: &[21, 22, 23, 24, 25, 26],
            prefill_v: &[31, 32, 33, 34, 35, 36],
            decode_k: &[27, 28, 29],
            decode_v: &[37, 38, 39],
        };
        let (predecessor, successor) =
            materialize_c6_genesis_cache_states(layout, 2, 1, &[layer0, layer1]).unwrap();

        predecessor.validate_canonical(layout, 0).unwrap();
        successor.validate_canonical(layout, 3).unwrap();
        assert_eq!(
            successor
                .value(
                    layout,
                    C6CacheCell { kind: C6CacheSlotKind::Key, layer: 0, position: 1, channel: 2 },
                )
                .unwrap(),
            Fp2::from_base(Fp::from_i64(6)),
        );
        assert_eq!(
            successor
                .value(
                    layout,
                    C6CacheCell { kind: C6CacheSlotKind::Value, layer: 0, position: 2, channel: 0 },
                )
                .unwrap(),
            Fp2::from_base(Fp::from_i64(-17)),
        );
        assert_eq!(
            successor
                .value(
                    layout,
                    C6CacheCell { kind: C6CacheSlotKind::Key, layer: 1, position: 2, channel: 2 },
                )
                .unwrap(),
            Fp2::from_base(Fp::from_i64(29)),
        );
        assert!(materialize_c6_genesis_cache_states(
            layout,
            2,
            1,
            &[C6CacheLayerSlabs {
                prefill_k: &[0; 5],
                prefill_v: &[0; 6],
                decode_k: &[0; 3],
                decode_v: &[0; 3],
            }],
        )
        .is_err());
    }
}
