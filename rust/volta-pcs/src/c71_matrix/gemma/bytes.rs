//! Biased byte encoding of the canonical P0 C/X sources. Every scalar MAC
//! pulls back affinely to this SAME byte root, without fresh authentication.

use super::{
    caller::{Auxiliary, PendingP0},
    *,
};

struct ByteTile {
    scalar: usize,
    first: usize,
    width: usize,
    offset: usize,
}

pub(in crate::c71_matrix) struct Bytes {
    pub scalar: Auxiliary,
    tiles: Vec<ByteTile>,
    by_scalar: Vec<Vec<usize>>,
    widths: Vec<usize>,
    packed_offsets: Vec<usize>,
    pub live: usize,
    pub layout_digest: [u8; 32],
}

impl Plan {
    pub fn auxiliary_bytes(&self) -> Result<Bytes, String> {
        let scalar = self.auxiliary_layout()?;
        let widths: Vec<_> = scalar
            .layout
            .sources
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if i >= self.cohorts.len() {
                    return 2;
                }
                match self.cohorts[i].kind {
                    Kind::Matrix => 6,
                    Kind::Norm => 4,
                    Kind::Lookup => 2,
                }
            })
            .collect();
        let mut packed_offsets = Vec::new();
        let mut live = 0;
        for (source, &bytes) in scalar.layout.sources.iter().zip(&widths) {
            packed_offsets.push(live);
            live += source.rows * source.cols * bytes;
        }
        let mut tiles = Vec::new();
        for (index, tile) in scalar.layout.tiles.iter().enumerate() {
            for (first, width) in intervals(widths[tile.tensor]) {
                tiles.push(ByteTile { scalar: index, first, width, offset: 0 });
            }
        }
        tiles.sort_by_key(|b| {
            let t = &scalar.layout.tiles[b.scalar];
            (std::cmp::Reverse(t.rows * t.cols * b.width), t.tensor, t.row, t.col, b.first)
        });
        let mut offset = 0;
        let mut by_scalar = vec![Vec::new(); scalar.layout.tiles.len()];
        for (i, tile) in tiles.iter_mut().enumerate() {
            let original = &scalar.layout.tiles[tile.scalar];
            let size = original.rows * original.cols * tile.width;
            assert_eq!(offset % size, 0);
            tile.offset = offset;
            offset += size;
            by_scalar[tile.scalar].push(i);
        }
        assert_eq!(live, offset);
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-P0-byte-A-v1;biased-i48-i32-i16;byte-fastest;dyadic-MSB\0");
        digest.update(&scalar.layout.layout_digest);
        for (&width, &offset) in widths.iter().zip(&packed_offsets) {
            digest.update(&(width as u64).to_le_bytes());
            digest.update(&(offset as u64).to_le_bytes());
        }
        for tile in &tiles {
            for word in [tile.scalar, tile.first, tile.width, tile.offset] {
                digest.update(&(word as u64).to_le_bytes());
            }
        }
        Ok(Bytes {
            scalar,
            tiles,
            by_scalar,
            widths,
            packed_offsets,
            live,
            layout_digest: *digest.finalize().as_bytes(),
        })
    }
}

impl Bytes {
    /// Extra source encoding identity to bind alongside the actual PCS Gamma
    /// before P0's output points. The scalar source identities also remain bound.
    pub fn profile(&self, gamma: &[u8]) -> Vec<u8> {
        let mut result = b"C71-P0-byte-A-profile-v1\0".to_vec();
        result.extend((gamma.len() as u64).to_le_bytes());
        result.extend(gamma);
        result.extend(self.layout_digest);
        result
    }

    /// (Packed two's-complement byte address, XOR mask). No physical copy;
    /// XOR 128 applies only to the top byte of each signed scalar.
    pub fn virtual_to_packed(&self, index: usize) -> Result<Option<(usize, u8)>, String> {
        if index >= self.live.next_power_of_two() {
            return Err("P0 byte index exceeds root domain".into());
        }
        if index >= self.live {
            return Ok(None);
        }
        let tile = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let scalar = &self.scalar.layout.tiles[tile.scalar];
        let source = &self.scalar.layout.sources[scalar.tensor];
        let local = index - tile.offset;
        let byte = tile.first + local % tile.width;
        let cell = local / tile.width;
        let scalar_index =
            (scalar.row + cell / scalar.cols) * source.cols + scalar.col + cell % scalar.cols;
        let address =
            self.packed_offsets[scalar.tensor] + scalar_index * self.widths[scalar.tensor] + byte;
        Ok(Some((address, if byte + 1 == self.widths[scalar.tensor] { 128 } else { 0 })))
    }

    /// Forms and PUBLIC additive shifts: open (original MAC + shift) in the
    /// byte root. With native k=m+Delta*x, update k by Delta*shift, m unchanged.
    pub fn forms<T>(
        &self,
        plan: &Plan,
        pending: &PendingP0<T>,
    ) -> Result<(Vec<Vec<Cube>>, Vec<Fp3>), String> {
        let scalar_forms = self.scalar.forms(plan, pending)?;
        let mut forms = Vec::new();
        let mut shifts = Vec::new();
        for scalar_form in scalar_forms {
            let mut form = Vec::new();
            let mut shift = Fp3::ZERO;
            for cube in scalar_form {
                let index = self
                    .scalar
                    .layout
                    .tiles
                    .binary_search_by_key(&cube.offset, |t| t.offset)
                    .map_err(|_| "P0 scalar cube does not start at a source tile")?;
                let scalar = &self.scalar.layout.tiles[index];
                if 1usize << cube.point.len() != scalar.rows * scalar.cols {
                    return Err("P0 scalar cube changes its source tile domain".into());
                }
                // Each scalar tile is entirely live; sum EQ over its local
                // Boolean domain is one, including fixed/degenerate coordinates.
                shift += cube.coefficient
                    * super::super::signed(1i64 << (8 * self.widths[scalar.tensor] - 1));
                for &b in &self.by_scalar[index] {
                    let tile = &self.tiles[b];
                    let mut point = cube.point.clone();
                    let mut coefficient =
                        cube.coefficient * super::super::signed(1i64 << (8 * tile.first));
                    for bit in (0..bits(tile.width)).rev() {
                        let beta = super::super::signed(1i64 << (8 * (1 << bit)));
                        coefficient = coefficient * (Fp3::ONE + beta);
                        point.push(beta * (Fp3::ONE + beta).inv());
                    }
                    form.push(Cube { offset: tile.offset, point, coefficient });
                }
            }
            forms.push(form);
            shifts.push(shift);
        }
        Ok((forms, shifts))
    }
}

#[cfg(test)]
mod tests {
    use super::super::caller::{CutOpening, InputOpening};
    use super::*;
    use crate::c71_matrix::{
        from_p3, gamma, linear, matrix_config, range, record_values, signed, AttemptContext, Auth,
        Fs, Key, MatrixRng, Model, E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_b12_gemma_biased_bytes_open_original_i48_i32_i16_macs() {
        let sources = vec![
            Source { name: "embedding".into(), rows: 5, cols: 3, packed_offset: 0 },
            Source { name: "projection".into(), rows: 3, cols: 3, packed_offset: 15 },
            Source { name: "norm".into(), rows: 1, cols: 3, packed_offset: 24 },
        ];
        let (tiles, live) = super::super::tiles(&sources);
        let cohort = |op: &str, tensor, kind, rows, columns, inner, producer: &str| Cohort {
            layer: None,
            operation: op.into(),
            tensor,
            kind,
            rows,
            columns,
            inner,
            heads: 1,
            producer: (None, producer.into()),
            members: Vec::new(),
            cut_byte_offset: 0,
        };
        let plan = Plan {
            sources,
            tiles,
            live,
            layout_digest: [16; 32],
            cohorts: vec![
                cohort("embedding_lookup", 0, Kind::Lookup, 3, 3, 0, "token_input"),
                cohort("q_proj", 1, Kind::Matrix, 3, 3, 3, "embedding_lookup"),
                cohort("q_norm", 2, Kind::Norm, 3, 3, 0, "q_proj"),
                cohort("final_rms", 2, Kind::Norm, 2, 3, 0, "q_proj"),
                cohort("lm_head", 0, Kind::Matrix, 1, 5, 3, "last_row_select"),
            ],
        };
        let bytes = plan.auxiliary_bytes().unwrap();
        assert_eq!(bytes.live, 210);
        let mut scalar_values = Vec::new();
        let mut packed = Vec::<u8>::new();
        for (source, &width) in bytes.scalar.layout.sources.iter().zip(&bytes.widths) {
            let bound = 1i64 << (8 * width - 1);
            let cases = [-bound, -32767, -1, 0, 1, 32767, bound - 1];
            let values: Vec<_> =
                (0..source.rows * source.cols).map(|i| cases[i % cases.len()]).collect();
            for value in &values {
                packed.extend(&value.to_le_bytes()[..width]);
            }
            scalar_values.push(values);
        }
        assert_eq!(packed.len(), bytes.live);
        let mut virtual_bytes = vec![0; 1024];
        let mut addresses = Vec::new();
        for (i, value) in virtual_bytes.iter_mut().enumerate().take(bytes.live) {
            let (address, xor) = bytes.virtual_to_packed(i).unwrap().unwrap();
            *value = i16::from(packed[address] ^ xor);
            addresses.push(address);
        }
        addresses.sort_unstable();
        assert_eq!(addresses, (0..bytes.live).collect::<Vec<_>>());
        assert_eq!(bytes.virtual_to_packed(255).unwrap(), None);
        assert!(bytes.virtual_to_packed(256).is_err());
        let model = Model::new(32, virtual_bytes).unwrap();
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(19);
        let target_count = 9;
        let count = target_count + range::required(10, range::Alphabet::Byte) + 32;
        assert_eq!(count, 551);
        let mut rng = MatrixRng::from_seed([125; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let mut statement = bytes.profile(&gamma(&matrix_config(32).unwrap()));
        statement.extend(model.root.roots()[0]);
        statement.extend(attempt.encode());
        let start = || Fs::new(&statement, 100_000);
        let mut fs = start();
        let mut rows = rows.into_iter();
        let mut pending = PendingP0 {
            cuts: Vec::new(),
            inputs: Vec::new(),
            weights: Vec::new(),
            weight_forms: Vec::new(),
        };
        let mut wire = Vec::new();
        let evaluate = |source: usize, r: &[Fp3], s: &[Fp3], offset: usize, count: usize| {
            let columns = bytes.scalar.layout.sources[source].cols;
            (0..count).fold(Fp3::ZERO, |z, row| {
                z + (0..columns).fold(Fp3::ZERO, |z, col| {
                    z + eq_index(r, row)
                        * eq_index(s, col)
                        * signed(scalar_values[source][(offset + row) * columns + col])
                })
            })
        };
        for (ordinal, c) in plan.cohorts.iter().enumerate() {
            let r = vec![signed(2); bits(c.rows)];
            let s = vec![signed(3); bits(c.columns)];
            let (correction, target) =
                range::authenticate([evaluate(ordinal, &r, &s, 0, c.rows)], &mut rows);
            wire.extend(correction);
            let mut point = r;
            point.extend(s);
            pending.cuts.push(CutOpening { cohort: ordinal, point, original: target[0] });
        }
        for ordinal in 1..plan.cohorts.len() {
            let route = plan.input_route(ordinal).unwrap();
            let source = bytes
                .scalar
                .layout
                .sources
                .iter()
                .position(|s| s.name == format!("X/global/{}", route.producer.1))
                .unwrap();
            let r = vec![signed(4); bits(route.selected_rows)];
            let s = vec![signed(5); bits(route.columns)];
            let (correction, target) = range::authenticate(
                [evaluate(source, &r, &s, route.row_offset, route.selected_rows)],
                &mut rows,
            );
            wire.extend(correction);
            let mut point = r;
            point.extend(s);
            pending.inputs.push(InputOpening {
                cohort: ordinal,
                route,
                point,
                original: target[0],
            });
        }
        record_values(&mut fs, 0x63, &wire);
        let (range_proof, range_forms, range_targets) = range::prove(
            &model,
            attempt,
            bytes.layout_digest,
            bytes.live,
            range::Alphabet::Byte,
            &mut fs,
            &mut rows,
        )
        .unwrap();
        let (mut forms, shifts) = bytes.forms(&plan, &pending).unwrap();
        let mut targets: Vec<_> = pending
            .cuts
            .iter()
            .map(|c| c.original)
            .chain(pending.inputs.iter().map(|c| c.original))
            .zip(&shifts)
            .map(|(a, &bias)| Auth::new(a.x + bias, a.m))
            .collect();
        forms.extend(range_forms);
        targets.extend(range_targets);
        let (pcs, digest) = linear::prove(
            &model,
            attempt,
            bytes.layout_digest,
            &forms,
            &targets,
            &mut fs,
            &mut rows,
        )
        .unwrap();
        assert!(rows.next().is_none());
        let check = |wrong_bias: bool| -> Result<_, String> {
            let mut fs = start();
            let mut rows = keys.clone().into_iter();
            let original: Vec<_> =
                wire.iter().map(|&c| range::correct([c], delta, &mut rows)[0]).collect();
            record_values(&mut fs, 0x63, &wire);
            let (range_forms, range_targets) = range::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut rows,
            )?;
            let verifier_pending = PendingP0 {
                cuts: pending
                    .cuts
                    .iter()
                    .zip(&original)
                    .map(|(c, &key)| CutOpening {
                        cohort: c.cohort,
                        point: c.point.clone(),
                        original: key,
                    })
                    .collect(),
                inputs: pending
                    .inputs
                    .iter()
                    .zip(&original[pending.cuts.len()..])
                    .map(|(c, &key)| InputOpening {
                        cohort: c.cohort,
                        route: c.route.clone(),
                        point: c.point.clone(),
                        original: key,
                    })
                    .collect(),
                weights: Vec::new(),
                weight_forms: Vec::new(),
            };
            let (mut forms, shifts) = bytes.forms(&plan, &verifier_pending)?;
            let mut targets: Vec<_> = original
                .iter()
                .zip(&shifts)
                .map(|(key, &bias)| Key::new(key.k + delta * bias))
                .collect();
            if wrong_bias {
                targets[0].k = targets[0].k - delta * shifts[0] * signed(2);
            }
            forms.extend(range_forms);
            targets.extend(range_targets);
            let digest = linear::verify(
                32,
                &model.root,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut rows,
            )?;
            assert!(rows.next().is_none());
            Ok(digest)
        };
        assert_eq!(check(false).unwrap(), digest);
        assert!(check(true).is_err());
    }
}
