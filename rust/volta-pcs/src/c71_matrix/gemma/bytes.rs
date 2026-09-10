//! Biased byte encoding of the canonical P0 C/X sources. Every scalar MAC
//! pulls back affinely to this SAME byte root, without fresh authentication.

use super::{
    caller::{Auxiliary, PendingP0},
    *,
};

pub(super) mod quantize;
pub(super) mod affine;

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

pub(in crate::c71_matrix) struct RneRequest<T> {
    pub consumer: usize,
    pub source: usize,
    pub view: [u8; 32],
    pub shape: [usize; 2],
    pub point: Vec<Fp3>,
    pub original: T,
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
        Bytes::new(scalar, widths)
    }
}

impl Bytes {
    /// Extend the SAME source statement while retaining all original IDs.
    /// Used before committing A; every packed offset and form is recompiled.
    pub(super) fn append(self, extra: Vec<(String, usize, usize, usize)>) -> Result<Self, String> {
        let Self { mut scalar, mut widths, .. } = self;
        let mut names: std::collections::BTreeSet<_> =
            scalar.layout.sources.iter().map(|s| s.name.clone()).collect();
        let mut offset =
            scalar.layout.sources.last().map_or(0, |s| s.packed_offset + s.rows * s.cols);
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-A-extension-v1;preserved-source-identities\0");
        digest.update(&scalar.layout.layout_digest);
        digest.update(&(extra.len() as u64).to_le_bytes());
        for (name, rows, cols, width) in extra {
            if rows == 0 || cols == 0 || ![2, 4, 6].contains(&width) || !names.insert(name.clone())
            {
                return Err("A extension repeats or changes a source".into());
            }
            let next = rows
                .checked_mul(cols)
                .and_then(|n| offset.checked_add(n))
                .ok_or("A extension overflows")?;
            digest.update(&(name.len() as u64).to_le_bytes());
            digest.update(name.as_bytes());
            for v in [rows, cols, width, offset] {
                digest.update(&(v as u64).to_le_bytes());
            }
            scalar.layout.sources.push(Source { name, rows, cols, packed_offset: offset });
            widths.push(width);
            offset = next;
        }
        (scalar.layout.tiles, scalar.layout.live) = tiles(&scalar.layout.sources);
        scalar.layout.layout_digest = *digest.finalize().as_bytes();
        Self::new(scalar, widths)
    }

    // Reuse the same canonical byte packing for extensions of A. Every
    // source width and the extended scalar identity enter the byte digest.
    pub(super) fn new(scalar: Auxiliary, widths: Vec<usize>) -> Result<Self, String> {
        if widths.len() != scalar.layout.sources.len()
            || widths.iter().any(|w| ![2, 4, 6].contains(w))
        {
            return Err("P0 byte source widths differ".into());
        }
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
    /// Direct P0 consumers of raw matrix producers. Shift values still come
    /// from the fixed PUBLIC quantization profile; these are original MAC
    /// obligations, not new outputs or an inferred calibrated profile.
    pub fn rne_requests<T: Copy>(
        &self,
        plan: &Plan,
        pending: &PendingP0<T>,
    ) -> Result<Vec<RneRequest<T>>, String> {
        if self.scalar.weight_layout != plan.layout_digest
            || pending.inputs.len() + 1 != plan.cohorts.len()
        {
            return Err("RNE input obligations differ from P0 layout".into());
        }
        let mut producers = BTreeMap::new();
        for (i, c) in plan.cohorts.iter().enumerate() {
            if producers.insert((c.layer, c.operation.as_str()), i).is_some() {
                return Err("RNE producer identity repeated".into());
            }
        }
        let mut result = Vec::new();
        for (i, input) in pending.inputs.iter().enumerate() {
            let consumer = i + 1;
            let route = plan.input_route(consumer)?; // never trust a copied route/selector
            if input.cohort != consumer
                || input.point.len() != bits(route.selected_rows) + bits(route.columns)
            {
                return Err("RNE original consumer point differs".into());
            }
            let Some(&source) = producers.get(&(route.producer.0, route.producer.1.as_str()))
            else {
                continue;
            };
            if plan.cohorts[source].kind != Kind::Matrix {
                continue;
            }
            let (view, shape) = self.rne_view(plan, source)?;
            if route.row_offset != 0
                || route.selected_rows != shape[0]
                || [route.rows, route.columns] != shape
            {
                return Err("RNE matrix consumer needs an explicit selected-row form".into());
            }
            // A norm's token/head row bits followed by lane bits already
            // equal the matrix's token row bits followed by full channels.
            result.push(RneRequest {
                consumer,
                source,
                view,
                shape,
                point: input.point.clone(),
                original: input.original,
            });
        }
        Ok(result)
    }

    /// Canonical padded row/column/six-byte view of a raw matrix P0 cut.
    /// The 8-lane RNE view adds two public zero lanes, never source cells.
    pub fn rne_view(&self, plan: &Plan, cohort: usize) -> Result<([u8; 32], [usize; 2]), String> {
        let c = plan.cohorts.get(cohort).ok_or("RNE cohort missing")?;
        if self.scalar.weight_layout != plan.layout_digest || c.kind != Kind::Matrix {
            return Err("RNE view is not a raw matrix cut of this W layout".into());
        }
        self.raw_view(cohort, b"C71-RNE-view-v1;raw-C;row-col-byte-MSB;6-of-8-lanes\0")
    }

    /// Non-matrix raw sources retain the same six-byte codec. The caller
    /// must derive their identity from the canonical producer graph.
    pub fn source_rne_view(&self, source: usize) -> Result<([u8; 32], [usize; 2]), String> {
        self.raw_view(source, b"C71-RNE-source-view-v1;raw-A;row-col-byte-MSB;6-of-8-lanes\0")
    }

    fn raw_view(&self, id: usize, domain: &[u8]) -> Result<([u8; 32], [usize; 2]), String> {
        let source = self.scalar.layout.sources.get(id).ok_or("RNE raw source missing")?;
        if self.widths[id] != 6 {
            return Err("RNE raw source is not biased-i48".into());
        }
        let mut digest = blake3::Hasher::new();
        digest.update(domain);
        digest.update(&self.layout_digest);
        digest.update(&(id as u64).to_le_bytes());
        for word in [source.rows, source.cols] {
            digest.update(&(word as u64).to_le_bytes());
        }
        Ok((*digest.finalize().as_bytes(), [source.rows, source.cols]))
    }

    /// Pull the ORIGINAL P/S byte MAC into the same A root. No affine bias:
    /// the endpoint is already a biased byte, including the explicit zero lanes.
    pub fn rne_form(&self, plan: &Plan, cohort: usize, point: &[Fp3]) -> Result<Vec<Cube>, String> {
        self.rne_view(plan, cohort)?;
        self.source_rne_form(cohort, point)
    }

    pub fn source_rne_form(&self, source: usize, point: &[Fp3]) -> Result<Vec<Cube>, String> {
        let (_, shape) = self.source_rne_view(source)?;
        let (rb, cb) = (bits(shape[0]), bits(shape[1]));
        if point.len() != rb + cb + 3 {
            return Err("RNE source point axes differ".into());
        }
        self.view_form(source, &point[..rb], &point[rb..rb + cb], &point[rb + cb..], 0, Fp3::ONE)
    }

    /// A word's bytes in a public lane interval. Splitting respects BOTH
    /// the source-byte tile and view-lane alignment (e.g. S48 at lane 2).
    /// Unused lanes have no source term; this never authenticates a value.
    pub fn view_form(
        &self,
        source: usize,
        row: &[Fp3],
        column: &[Fp3],
        lane: &[Fp3],
        first_lane: usize,
        coefficient: Fp3,
    ) -> Result<Vec<Cube>, String> {
        let width = *self.widths.get(source).ok_or("Byte view source missing")?;
        if lane.len() > 4 || first_lane.checked_add(width).is_none_or(|n| n > 1 << lane.len()) {
            return Err("Byte view lane interval differs".into());
        }
        let mut result = Vec::new();
        for cube in self.scalar.layout.project(source, row, column, coefficient)? {
            let index =
                self.scalar.layout.tiles.binary_search_by_key(&cube.offset, |t| t.offset).unwrap();
            for &b in &self.by_scalar[index] {
                let tile = &self.tiles[b];
                let mut start = 0;
                while start < tile.width {
                    let mut size = (tile.width - start).next_power_of_two();
                    while start % size != 0 || (first_lane + tile.first + start) % size != 0 {
                        size /= 2;
                    }
                    let low = bits(size);
                    let coefficient = cube.coefficient
                        * eq_index(
                            &lane[..lane.len() - low],
                            (first_lane + tile.first + start) / size,
                        );
                    if coefficient != Fp3::ZERO {
                        let mut point = cube.point.clone();
                        for bit in (low..bits(tile.width)).rev() {
                            point.push(if start >> bit & 1 == 1 { Fp3::ONE } else { Fp3::ZERO });
                        }
                        point.extend(&lane[lane.len() - low..]);
                        result.push(Cube { offset: tile.offset, point, coefficient });
                    }
                    start += size;
                }
            }
        }
        Ok(result)
    }

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
            let (form, shift) = self.pullback(scalar_form)?;
            forms.push(form);
            shifts.push(shift);
        }
        Ok((forms, shifts))
    }

    pub fn word_form(
        &self,
        source: usize,
        row: &[Fp3],
        column: &[Fp3],
        coefficient: Fp3,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        self.pullback(self.scalar.layout.project(source, row, column, coefficient)?)
    }

    fn pullback(&self, scalar_form: Vec<Cube>) -> Result<(Vec<Cube>, Fp3), String> {
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
        Ok((form, shift))
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
    fn c71_b12_gemma_p0_rne_uses_same_ragged_raw_cut_and_quantized_input_macs() {
        p0_rne_graph(false);
    }

    #[test]
    fn c71_b12_gemma_table_rne_probes_share_original_raw_and_consumer_sources() {
        p0_rne_graph(true);
    }

    fn p0_rne_graph(table_probe: bool) {
        use super::super::caller::{Compact, P0Statement};
        use crate::c71_matrix::{eq, rne};
        enum QuantizedProof {
            Direct(rne::Proof),
            Table(quantize::Proof),
        }
        let sources = vec![
            Source { name: "embedding".into(), rows: 4, cols: 3, packed_offset: 0 },
            Source { name: "projection".into(), rows: 3, cols: 3, packed_offset: 12 },
            Source { name: "norm".into(), rows: 1, cols: 3, packed_offset: 21 },
        ];
        let (tiles, live) = super::super::tiles(&sources);
        let cohort = |operation: &str, tensor, kind, inner, producer: &str| Cohort {
            layer: None,
            operation: operation.into(),
            tensor,
            kind,
            rows: 3,
            columns: 3,
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
            layout_digest: [22; 32],
            cohorts: vec![
                cohort("embedding_lookup", 0, Kind::Lookup, 0, "token_input"),
                cohort("q_proj", 1, Kind::Matrix, 3, "embedding_lookup"),
                cohort("q_norm", 2, Kind::Norm, 0, "q_proj"),
            ],
        };
        let bytes = plan.auxiliary_bytes().unwrap();
        assert_eq!(bytes.live, 144);
        let (view, shape) = bytes.rne_view(&plan, 1).unwrap();
        assert_eq!(shape, [3, 3]);
        assert!(bytes.rne_view(&plan, 0).is_err());
        assert!(bytes.rne_view(&plan, 2).is_err());
        assert!(bytes.rne_form(&plan, 1, &[]).is_err());
        let packed =
            [1i64, -2, 3, 2, 1, -1, -2, 3, 1, 1, 1, 1, 2, -1, 1, -1, 2, 1, 1, 1, -2, 2, -1, 3];
        let lookup = packed[..9].to_vec();
        let mut raw = vec![0i64; 9];
        for row in 0..3 {
            for col in 0..3 {
                raw[3 * row + col] =
                    (0..3).map(|k| lookup[3 * row + k] * packed[12 + 3 * col + k]).sum();
            }
        }
        let rounded = |v: i64| {
            let (q, r) = (v.div_euclid(4), v.rem_euclid(4));
            q + i64::from(r > 2 || (r == 2 && q & 1 == 1))
        };
        let biased =
            |value: i64| -> [u8; 6] { (value + (1 << 47)).to_le_bytes()[..6].try_into().unwrap() };
        let mut w_values = vec![0i16; 1024];
        for (i, v) in w_values.iter_mut().enumerate().take(plan.live) {
            *v = packed[plan.virtual_to_packed(i).unwrap().unwrap()] as i16;
        }
        let w_model = Model::new(32, w_values).unwrap();
        let gamma = gamma(&matrix_config(32).unwrap());
        let profile = bytes.profile(&gamma);
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = signed(31);
        let count = plan.p0_required()
            + rne::required(4, 2)
            + range::required(10, 7)
            + range::required(10, range::Alphabet::Byte)
            + 64
            + usize::from(table_probe);
        assert_eq!(count, 1355 + usize::from(table_probe));
        let pairs = [quantize::Pair { raw: 1, output: bytes.scalar.input_sources[1], shift: 2 }];
        assert_eq!(bytes.table_rne_required(&plan, &pairs).unwrap(), 1 + rne::required(4, 2));
        let mut rng = MatrixRng::from_seed([128; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        for fault in 0..3 {
            let mut quant: Vec<_> = raw.iter().map(|&v| rounded(v)).collect();
            if fault == 1 {
                quant[0] += 1;
            }
            let cuts = [
                lookup.clone(),
                raw.clone(),
                quant.iter().enumerate().map(|(i, &v)| v * packed[21 + i % 3]).collect(),
            ];
            let inputs = [&lookup, &quant];
            let values = [&cuts[0], &cuts[1], &cuts[2], &lookup, &quant];
            let mut physical = Vec::<u8>::new();
            for ((source, &width), values) in
                bytes.scalar.layout.sources.iter().zip(&bytes.widths).zip(values)
            {
                assert_eq!(source.rows * source.cols, values.len());
                for &v in values {
                    physical.extend(&v.to_le_bytes()[..width]);
                }
            }
            let mut a_values = vec![0i16; 1024];
            for (i, v) in a_values.iter_mut().enumerate().take(bytes.live) {
                let (address, xor) = bytes.virtual_to_packed(i).unwrap().unwrap();
                *v = i16::from(physical[address] ^ xor);
            }
            let a_model = Model::new(32, a_values).unwrap();
            let statement = P0Statement {
                weights: &w_model.root,
                auxiliary: &a_model.root,
                weight_gamma: &gamma,
                auxiliary_gamma: &profile,
                auxiliary_layout: &bytes.scalar,
                quantization: [23; 32],
                attempt,
                tokens: &[0, 1, 2],
            };
            let start = || Fs::new(b"canonical same-W P0 and RNE ragged sources", 100_000);
            if table_probe && fault == 0 {
                let needed = bytes.table_rne_required(&plan, &pairs).unwrap();
                let mut exhausted = vec![Auth::ZERO; needed - 1].into_iter();
                assert!(bytes
                    .prove_table_rne(
                        &plan,
                        &statement,
                        &pairs,
                        |_, _, _, _| panic!("exhausted RNE read source"),
                        &mut start(),
                        &mut exhausted
                    )
                    .is_err());
                assert_eq!(exhausted.len(), needed - 1);
                assert!(bytes
                    .table_rne_required(&plan, &[quantize::Pair { raw: 1, output: 1, shift: 2 }])
                    .is_err());
                assert!(bytes
                    .table_rne_required(
                        &plan,
                        &[quantize::Pair { raw: 0, output: pairs[0].output, shift: 2 }]
                    )
                    .is_err());
            }
            let mut fs = start();
            let mut prows = rows.clone().into_iter();
            let (p0, pending) = plan
                .prove_p0(
                    &statement,
                    |points| {
                        Ok(plan
                            .cohorts
                            .iter()
                            .enumerate()
                            .map(|(ordinal, c)| {
                                let (r, s) = points[ordinal].split_at(2);
                                let output = cuts[ordinal].iter().enumerate().fold(
                                    Fp3::ZERO,
                                    |v, (i, &x)| {
                                        v + eq_index(r, i / 3) * eq_index(s, i % 3) * signed(x)
                                    },
                                );
                                if c.kind == Kind::Lookup {
                                    return Compact { output, x: Vec::new(), w: Vec::new() };
                                }
                                let mut x = vec![Fp3::ZERO; 4];
                                let mut w = x.clone();
                                for k in 0..3 {
                                    for row in 0..3 {
                                        x[k] += eq_index(r, row)
                                            * signed(inputs[ordinal - 1][3 * row + k]);
                                    }
                                    let source = &plan.sources[c.tensor];
                                    for j in 0..source.rows {
                                        let coefficient = if c.kind == Kind::Norm {
                                            Fp3::ONE
                                        } else {
                                            eq_index(s, j)
                                        };
                                        w[k] += coefficient
                                            * signed(packed[source.packed_offset + 3 * j + k]);
                                    }
                                }
                                Compact { output, x, w }
                            })
                            .collect::<Vec<_>>())
                    },
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
            let requests = bytes.rne_requests(&plan, &pending).unwrap();
            assert_eq!(requests.len(), 1);
            let output = &requests[0];
            assert_eq!((output.consumer, output.source), (2, 1));
            assert_eq!((output.view, output.shape), (view, shape));
            let rq = rne::Statement {
                root: &a_model.root,
                profile: &profile,
                view,
                attempt,
                output_point: &output.point,
                shape,
                shift: 2,
            };
            let mut used = raw.clone();
            if fault == 2 {
                used[0] = [raw[0] - 1, raw[0] + 1]
                    .into_iter()
                    .find(|&v| rounded(v) == rounded(raw[0]))
                    .unwrap();
            }
            let (quantized, byte_point, byte, quant_forms, quant_targets) = if table_probe {
                let read = |source: usize, row: usize, col: usize, b: usize| {
                    let columns = bytes.scalar.layout.sources[source].cols;
                    let v = if source == 1 {
                        used[row * columns + col]
                    } else {
                        values[source][row * columns + col]
                    };
                    let word = (v + (1i64 << (8 * bytes.widths[source] - 1))) as u64;
                    (word >> (8 * b)) as u8
                };
                let (proof, pending) = bytes
                    .prove_table_rne(&plan, &statement, &pairs, read, &mut fs, &mut prows)
                    .unwrap();
                let (forms, shifts, targets) =
                    bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
                let targets = targets
                    .into_iter()
                    .zip(shifts)
                    .map(|(a, s)| Auth::new(a.x + s, a.m))
                    .collect::<Vec<_>>();
                (
                    QuantizedProof::Table(proof),
                    pending[0].raw_point.clone(),
                    pending[0].raw,
                    forms,
                    targets,
                )
            } else {
                let (proof, point, byte) = rne::prove(
                    &rq,
                    output.original,
                    |i| biased(used[(i / 4) * 3 + i % 4]),
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                let form = bytes.rne_form(&plan, output.source, &point).unwrap();
                (QuantizedProof::Direct(proof), point, byte, vec![form], vec![byte])
            };
            let byte_form = quant_forms.last().unwrap();
            if fault == 0 {
                let expected = (0..3).flat_map(|row| (0..3).map(move |col| (row, col))).fold(
                    Fp3::ZERO,
                    |v, (row, col)| {
                        v + eq_index(&byte_point[..2], row)
                            * eq_index(&byte_point[2..4], col)
                            * biased(raw[3 * row + col]).iter().enumerate().fold(
                                Fp3::ZERO,
                                |v, (lane, &b)| {
                                    v + eq_index(&byte_point[4..], lane) * signed(i64::from(b))
                                },
                            )
                    },
                );
                assert_eq!(byte.x, expected);
                let opened = byte_form.iter().fold(Fp3::ZERO, |v, cube| {
                    v + cube.coefficient
                        * eq(&cube.point).iter().enumerate().fold(Fp3::ZERO, |v, (i, &r)| {
                            v + r * signed(i64::from(a_model.weights[cube.offset + i]))
                        })
                });
                assert_eq!(opened, expected);
            }
            let (wr, wf, wt) = range::prove(
                &w_model,
                attempt,
                plan.layout_digest,
                plan.live,
                7,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (ar, af, at) = range::prove(
                &a_model,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let mut weight_forms = pending.weight_forms.clone();
            weight_forms.extend(wf);
            let mut weight_targets = pending.weights.clone();
            weight_targets.extend(wt);
            let (mut aux_forms, shifts) = bytes.forms(&plan, &pending).unwrap();
            aux_forms.extend(af);
            aux_forms.extend(quant_forms);
            let mut aux_targets: Vec<_> = pending
                .cuts
                .iter()
                .map(|c| c.original)
                .chain(pending.inputs.iter().map(|c| c.original))
                .zip(&shifts)
                .map(|(a, &bias)| Auth::new(a.x + bias, a.m))
                .collect();
            aux_targets.extend(at);
            aux_targets.extend(quant_targets);
            let (wp, _) = linear::prove(
                &w_model,
                attempt,
                plan.layout_digest,
                &weight_forms,
                &weight_targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (ap, digest) = linear::prove(
                &a_model,
                attempt,
                bytes.layout_digest,
                &aux_forms,
                &aux_targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let check = || -> Result<blake3::Hash, String> {
                let mut fs = start();
                let mut vrows = keys.clone().into_iter();
                let pending = plan.verify_p0(&statement, &p0, delta, &mut fs, &mut vrows)?;
                let requests = bytes.rne_requests(&plan, &pending)?;
                let output = &requests[0];
                let rq = rne::Statement {
                    root: &a_model.root,
                    profile: &profile,
                    view,
                    attempt,
                    output_point: &output.point,
                    shape,
                    shift: 2,
                };
                let (quant_forms, quant_targets) = match &quantized {
                    QuantizedProof::Direct(proof) => {
                        let (point, byte) =
                            rne::verify(&rq, output.original, proof, delta, &mut fs, &mut vrows)?;
                        (vec![bytes.rne_form(&plan, output.source, &point)?], vec![byte])
                    }
                    QuantizedProof::Table(proof) => {
                        let pending = bytes.verify_table_rne(
                            &plan, &statement, &pairs, proof, delta, &mut fs, &mut vrows,
                        )?;
                        let (forms, shifts, targets) =
                            bytes.table_rne_forms(&plan, &pairs, &pending)?;
                        (
                            forms,
                            targets
                                .into_iter()
                                .zip(shifts)
                                .map(|(k, s)| Key::new(k.k + delta * s))
                                .collect(),
                        )
                    }
                };
                let (wf, wt) = range::verify(
                    32,
                    &w_model.root,
                    attempt,
                    plan.layout_digest,
                    plan.live,
                    7,
                    &wr,
                    delta,
                    &mut fs,
                    &mut vrows,
                )?;
                let (af, at) = range::verify(
                    32,
                    &a_model.root,
                    attempt,
                    bytes.layout_digest,
                    bytes.live,
                    range::Alphabet::Byte,
                    &ar,
                    delta,
                    &mut fs,
                    &mut vrows,
                )?;
                let mut weight_forms = pending.weight_forms.clone();
                weight_forms.extend(wf);
                let mut weight_targets = pending.weights.clone();
                weight_targets.extend(wt);
                let (mut aux_forms, shifts) = bytes.forms(&plan, &pending)?;
                aux_forms.extend(af);
                aux_forms.extend(quant_forms);
                let mut aux_targets: Vec<_> = pending
                    .cuts
                    .iter()
                    .map(|c| c.original)
                    .chain(pending.inputs.iter().map(|c| c.original))
                    .zip(shifts)
                    .map(|(a, bias)| Key::new(a.k + delta * bias))
                    .collect();
                aux_targets.extend(at);
                aux_targets.extend(quant_targets);
                linear::verify(
                    32,
                    &w_model.root,
                    attempt,
                    plan.layout_digest,
                    &weight_forms,
                    &weight_targets,
                    &wp,
                    delta,
                    &mut fs,
                    &mut vrows,
                )?;
                let checked = linear::verify(
                    32,
                    &a_model.root,
                    attempt,
                    bytes.layout_digest,
                    &aux_forms,
                    &aux_targets,
                    &ap,
                    delta,
                    &mut fs,
                    &mut vrows,
                )?;
                assert!(vrows.next().is_none());
                Ok(checked)
            };
            match fault {
                0 => assert_eq!(check().unwrap(), digest),
                1 => assert_eq!(check().unwrap_err(), "B12 RNE sumcheck MAC rejected"),
                _ => assert_eq!(check().unwrap_err(), "C71 matrix sumcheck MAC rejected"),
            }
        }
    }

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
