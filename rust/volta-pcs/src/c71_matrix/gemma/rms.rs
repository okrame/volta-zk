//! Canonical RMS sources in the SAME auxiliary root as P0. Metadata only;
//! no full witness allocation or calibrated profile is inferred here.

use super::{bytes::Bytes, *};

pub(super) mod caller;

pub(in crate::c71_matrix) struct Norm {
    pub cohort: Option<usize>, // None for the parameter-free v_norm
    pub layer: Option<u64>,
    pub operation: String,
    pub rows: usize,
    pub columns: usize,
    pub heads: usize,
    pub input: usize,
    pub product: usize,
    pub statistic: usize,
    pub output: usize,
}

pub(in crate::c71_matrix) struct Sources {
    pub bytes: Bytes,
    pub norms: Vec<Norm>,
    pub cells: usize,
    pub view: [u8; 32],
    tiles: Vec<Tile>,
}

fn name(layer: Option<u64>, operation: &str) -> String {
    format!("X/{}/{operation}", layer.map_or_else(|| "global".into(), |l| l.to_string()))
}

fn add(
    sources: &mut Vec<Source>,
    widths: &mut Vec<usize>,
    names: &mut BTreeMap<String, usize>,
    name: String,
    rows: usize,
    cols: usize,
    bytes: usize,
) -> Result<usize, String> {
    if let Some(&index) = names.get(&name) {
        let s = &sources[index];
        if [s.rows, s.cols, widths[index]] != [rows, cols, bytes] {
            return Err("RMS shared source changes shape or width".into());
        }
        return Ok(index);
    }
    let packed_offset = sources.last().map_or(0, |s| s.packed_offset + s.rows * s.cols);
    let index = sources.len();
    sources.push(Source { name: name.clone(), rows, cols, packed_offset });
    widths.push(bytes);
    names.insert(name, index);
    Ok(index)
}

impl Plan {
    pub fn rms_sources(&self) -> Result<Sources, String> {
        let mut scalar = self.auxiliary_layout()?;
        let mut widths: Vec<_> = scalar
            .layout
            .sources
            .iter()
            .enumerate()
            .map(|(i, _)| {
                self.cohorts.get(i).map_or(2, |c| match c.kind {
                    Kind::Matrix => 6,
                    Kind::Norm => 4,
                    Kind::Lookup => 2,
                })
            })
            .collect();
        let mut names: BTreeMap<_, _> =
            scalar.layout.sources.iter().enumerate().map(|(i, s)| (s.name.clone(), i)).collect();
        if names.len() != scalar.layout.sources.len() {
            return Err("RMS original sources repeat".into());
        }
        let mut norms = Vec::new();
        for (i, c) in self.cohorts.iter().enumerate().filter(|(_, c)| c.kind == Kind::Norm) {
            let route = self.input_route(i)?;
            if route.row_offset != 0 {
                return Err("RMS needs an explicit shifted input view".into());
            }
            for weighted in [true, false] {
                if !weighted && c.operation != "k_norm" {
                    continue;
                }
                let operation = if weighted { c.operation.as_str() } else { "v_norm" };
                let input = if weighted {
                    scalar.input_sources[i - 1]
                } else {
                    let layer = c.layer.ok_or("RMS V alias needs a layer")?;
                    let v = self
                        .cohorts
                        .iter()
                        .find(|v| v.layer == c.layer && v.operation == "v_source");
                    if (layer % 6 == 5) != v.is_none() {
                        return Err("RMS local V/global K alias differs from pinned DAG".into());
                    }
                    if let Some(v) = v {
                        if v.kind != Kind::Matrix
                            || [v.rows, v.columns] != [route.rows, route.columns]
                        {
                            return Err("RMS V projection geometry differs".into());
                        }
                        add(
                            &mut scalar.layout.sources,
                            &mut widths,
                            &mut names,
                            name(c.layer, "v_source"),
                            route.rows,
                            route.columns,
                            2,
                        )?
                    } else {
                        if route.producer != (c.layer, "k_proj".into()) {
                            return Err("RMS global V must alias K before normalization".into());
                        }
                        scalar.input_sources[i - 1]
                    }
                };
                let statistic = add(
                    &mut scalar.layout.sources,
                    &mut widths,
                    &mut names,
                    format!("S/{}", norms.len()),
                    c.rows,
                    1,
                    6,
                )?;
                let output = add(
                    &mut scalar.layout.sources,
                    &mut widths,
                    &mut names,
                    name(c.layer, operation),
                    c.rows / c.heads,
                    c.columns * c.heads,
                    2,
                )?;
                norms.push(Norm {
                    cohort: weighted.then_some(i),
                    layer: c.layer,
                    operation: operation.into(),
                    rows: c.rows,
                    columns: c.columns,
                    heads: c.heads,
                    input,
                    product: if weighted { i } else { input },
                    statistic,
                    output,
                });
            }
        }
        if norms.is_empty() {
            return Err("RMS source plan has no norms".into());
        }
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-P0-RMS-A-v1;original-C-X;shared-S-Y;dyadic-MSB\0");
        digest.update(&scalar.layout.layout_digest);
        for (source, &width) in scalar.layout.sources.iter().zip(&widths) {
            digest.update(&(source.name.len() as u64).to_le_bytes());
            digest.update(source.name.as_bytes());
            for v in [source.rows, source.cols, source.packed_offset, width] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        (scalar.layout.tiles, scalar.layout.live) = tiles(&scalar.layout.sources);
        scalar.layout.layout_digest = *digest.finalize().as_bytes();
        let bytes = Bytes::new(scalar, widths)?;
        let cell_sources: Vec<_> = norms
            .iter()
            .enumerate()
            .map(|(i, n)| Source {
                name: format!("RMS/{i}"),
                rows: n.rows,
                cols: n.columns,
                packed_offset: 0,
            })
            .collect();
        let (tiles, cells) = tiles(&cell_sources);
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-RMS-view-v1;tile-cell-lane-MSB;biased-P-S-Y;16-lanes\0");
        digest.update(&bytes.layout_digest);
        for n in &norms {
            digest.update(&(n.operation.len() as u64).to_le_bytes());
            digest.update(n.operation.as_bytes());
            digest.update(&n.layer.unwrap_or(u64::MAX).to_le_bytes());
            for v in [
                n.cohort.unwrap_or(usize::MAX),
                n.rows,
                n.columns,
                n.heads,
                n.input,
                n.product,
                n.statistic,
                n.output,
            ] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        for t in &tiles {
            for v in [t.tensor, t.row, t.col, t.rows, t.cols, t.offset] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        Ok(Sources { bytes, norms, cells, view: *digest.finalize().as_bytes(), tiles })
    }
}

fn prefix(first: usize, size: usize, total: usize, low: &[Fp3]) -> Vec<Fp3> {
    let mut result: Vec<_> = (bits(size)..bits(total))
        .rev()
        .map(|b| if first >> b & 1 == 1 { Fp3::ONE } else { Fp3::ZERO })
        .collect();
    result.extend(low);
    result
}

impl Sources {
    // Reinterpret token||head||lane without moving cells. A shorter selected
    // row domain gains only fixed leading zero bits in the full producer.
    fn coordinates(
        &self,
        source: usize,
        row: &[Fp3],
        column: &[Fp3],
    ) -> Result<(Vec<Fp3>, Vec<Fp3>), String> {
        let s = self.bytes.scalar.layout.sources.get(source).ok_or("RMS word source missing")?;
        let total = bits(s.rows) + bits(s.cols);
        if total < row.len() + column.len() {
            return Err("RMS reshape loses coordinates".into());
        }
        let mut point = vec![Fp3::ZERO; total - row.len() - column.len()];
        point.extend(row);
        point.extend(column);
        let column = point.split_off(bits(s.rows));
        Ok((point, column))
    }

    /// Canonical one-byte endpoint of the JOINT RMS view, including S
    /// broadcast and parameter-free V. Dummy cells/lane 12..15 are zero.
    pub fn form(&self, point: &[Fp3]) -> Result<Vec<Cube>, String> {
        let cb = bits(self.cells);
        if point.len() != cb + 4 {
            return Err("RMS joint byte point differs".into());
        }
        let lane = &point[cb..];
        let mut result = Vec::new();
        for t in &self.tiles {
            let n = &self.norms[t.tensor];
            let local = bits(t.rows) + bits(t.cols);
            let coefficient = eq_index(&point[..cb - local], t.offset / (t.rows * t.cols));
            if coefficient == Fp3::ZERO {
                continue;
            }
            let rp = prefix(t.row, t.rows, n.rows, &point[cb - local..cb - bits(t.cols)]);
            let cp = prefix(t.col, t.cols, n.columns, &point[cb - bits(t.cols)..cb]);
            let pbytes = if n.cohort.is_some() { 4 } else { 2 };
            for (source, first) in [(n.product, 0), (n.output, pbytes + 6)] {
                let (r, c) = self.coordinates(source, &rp, &cp)?;
                result.extend(self.bytes.view_form(source, &r, &c, lane, first, coefficient)?);
            }
            // Summing the local column EQ gives one. Repeated column tiles
            // retain their different GLOBAL prefix coefficients above.
            result.extend(self.bytes.view_form(
                n.statistic,
                &rp,
                &[],
                lane,
                pbytes,
                coefficient,
            )?);
        }
        Ok(result)
    }

    /// ORIGINAL statistic-kernel X MAC, with exact selected-row/column
    /// support. The final norm must not accidentally include producer row 149.
    pub fn input_form(&self, norm: usize, point: &[Fp3]) -> Result<(Vec<Cube>, Fp3), String> {
        let n = self.norms.get(norm).ok_or("RMS norm missing")?;
        let (rb, cb) = (bits(n.rows), bits(n.columns));
        if point.len() != rb + cb {
            return Err("RMS statistic X point differs".into());
        }
        let (mut result, mut shift) = (Vec::new(), Fp3::ZERO);
        for (row, rows) in intervals(n.rows) {
            for (col, cols) in intervals(n.columns) {
                let coefficient = eq_index(&point[..rb - bits(rows)], row / rows)
                    * eq_index(&point[rb..rb + cb - bits(cols)], col / cols);
                if coefficient == Fp3::ZERO {
                    continue;
                }
                let rp = prefix(row, rows, n.rows, &point[rb - bits(rows)..rb]);
                let cp = prefix(col, cols, n.columns, &point[rb + cb - bits(cols)..]);
                let (r, c) = self.coordinates(n.input, &rp, &cp)?;
                let (form, bias) = self.bytes.word_form(n.input, &r, &c, coefficient)?;
                result.extend(form);
                shift += bias;
            }
        }
        Ok((result, shift))
    }

    pub fn statistic_form(&self, norm: usize, point: &[Fp3]) -> Result<(Vec<Cube>, Fp3), String> {
        let n = self.norms.get(norm).ok_or("RMS norm missing")?;
        self.bytes.word_form(n.statistic, point, &[], Fp3::ONE)
    }

    /// (norm ordinal, selected row, channel), without expanding the domain.
    pub fn cell(&self, index: usize) -> Result<Option<(usize, usize, usize)>, String> {
        if index >= self.cells.next_power_of_two() {
            return Err("RMS cell exceeds padded domain".into());
        }
        if index >= self.cells {
            return Ok(None);
        }
        let t = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let local = index - t.offset;
        Ok(Some((t.tensor, t.row + local / t.cols, t.col + local % t.cols)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{eq, signed};

    fn evaluate(form: &[Cube], source: &[u8]) -> Fp3 {
        form.iter().fold(Fp3::ZERO, |v, c| {
            v + c.coefficient
                * source[c.offset..c.offset + (1 << c.point.len())]
                    .iter()
                    .zip(eq(&c.point))
                    .fold(Fp3::ZERO, |s, (&b, r)| s + signed(i64::from(b)) * r)
        })
    }

    fn value(source: usize, row: usize, col: usize) -> i64 {
        17 * (source as i64 + 1) + 7 * row as i64 - col as i64
    }
    fn word(value: i64, bytes: usize) -> Vec<u8> {
        let biased = (value + (1 << (8 * bytes - 1))) as u64;
        (0..bytes).map(|b| (biased >> (8 * b)) as u8).collect()
    }

    pub(in crate::c71_matrix::gemma) fn toy_plan(tokens: usize, head_rows: usize) -> Plan {
        let sources = vec![
            Source { name: "embedding".into(), rows: 4, cols: 4, packed_offset: 0 },
            Source { name: "projection".into(), rows: 4, cols: 4, packed_offset: 16 },
            Source { name: "norm2".into(), rows: 1, cols: 2, packed_offset: 32 },
            Source { name: "norm4".into(), rows: 1, cols: 4, packed_offset: 34 },
        ];
        let (tiles, live) = super::super::tiles(&sources);
        let cohort = |layer,
                      operation: &str,
                      tensor,
                      kind,
                      rows,
                      columns,
                      heads,
                      producer: (Option<u64>, &str)| Cohort {
            layer,
            operation: operation.into(),
            tensor,
            kind,
            rows,
            columns,
            heads,
            inner: if kind == Kind::Matrix { 4 } else { 0 },
            producer: (producer.0, producer.1.into()),
            members: Vec::new(),
            cut_byte_offset: 0,
        };
        Plan {
            sources,
            tiles,
            live,
            layout_digest: [61; 32],
            cohorts: vec![
                cohort(
                    None,
                    "embedding_lookup",
                    0,
                    Kind::Lookup,
                    tokens,
                    4,
                    1,
                    (None, "token_input"),
                ),
                cohort(None, "q_proj", 1, Kind::Matrix, tokens, 4, 1, (None, "embedding_lookup")),
                cohort(None, "q_norm", 2, Kind::Norm, 2 * tokens, 2, 2, (None, "q_proj")),
                cohort(None, "final_rms", 3, Kind::Norm, tokens - 1, 4, 1, (None, "q_norm")),
                cohort(None, "lm_head", 0, Kind::Matrix, head_rows, 4, 1, (None, "final_rms")),
                cohort(
                    Some(0),
                    "k_proj",
                    1,
                    Kind::Matrix,
                    tokens,
                    4,
                    1,
                    (None, "embedding_lookup"),
                ),
                cohort(
                    Some(0),
                    "v_source",
                    1,
                    Kind::Matrix,
                    tokens,
                    4,
                    1,
                    (None, "embedding_lookup"),
                ),
                cohort(Some(0), "k_norm", 2, Kind::Norm, 2 * tokens, 2, 2, (Some(0), "k_proj")),
            ],
        }
    }

    #[test]
    fn c71_b12_gemma_rms_views_share_canonical_sources_and_preserve_selected_rows_and_head_axes() {
        let plan = toy_plan(4, 2);
        let rms = plan.rms_sources().unwrap();
        assert_eq!((rms.norms.len(), rms.cells, rms.bytes.live), (4, 60, 954));
        assert_eq!(rms.norms[0].output, rms.norms[1].input);
        assert_eq!(rms.norms[1].output, rms.bytes.scalar.input_sources[3]);
        assert_ne!(rms.norms[2].input, rms.norms[3].input);
        let scalar = &rms.bytes.scalar.layout;
        let mut packed = Vec::new();
        for (i, s) in scalar.sources.iter().enumerate() {
            let bytes = if i < plan.cohorts.len() {
                match plan.cohorts[i].kind {
                    Kind::Matrix => 6,
                    Kind::Norm => 4,
                    Kind::Lookup => 2,
                }
            } else if s.name.starts_with("S/") {
                6
            } else {
                2
            };
            for row in 0..s.rows {
                for col in 0..s.cols {
                    let v = value(i, row, col) as u64;
                    packed.extend((0..bytes).map(|b| (v >> (8 * b)) as u8));
                }
            }
        }
        let mut actual = vec![0; rms.bytes.live.next_power_of_two()];
        for (i, b) in actual.iter_mut().enumerate() {
            if let Some((address, xor)) = rms.bytes.virtual_to_packed(i).unwrap() {
                *b = packed[address] ^ xor;
            }
        }
        let point: Vec<_> = (0..10).map(|i| signed(2 * i + 3)).collect();
        let form = rms.form(&point).unwrap();
        let literal = eq(&point).iter().enumerate().fold(Fp3::ZERO, |v, (i, &r)| {
            let Some((ordinal, row, col)) = rms.cell(i / 16).unwrap() else {
                return v;
            };
            let n = &rms.norms[ordinal];
            let pbytes = if n.cohort.is_some() { 4 } else { 2 };
            let source_word = |source: usize, bytes: usize| {
                let cols = scalar.sources[source].cols;
                let index = row * n.columns + col;
                word(value(source, index / cols, index % cols), bytes)
            };
            let frame: Vec<_> = source_word(n.product, pbytes)
                .into_iter()
                .chain(word(value(n.statistic, row, 0), 6))
                .chain(source_word(n.output, 2))
                .collect();
            v + r * signed(i64::from(frame.get(i % 16).copied().unwrap_or(0)))
        });
        assert_eq!(evaluate(&form, &actual), literal);
        for (i, n) in rms.norms.iter().enumerate() {
            let point: Vec<_> =
                (0..bits(n.rows) + bits(n.columns)).map(|b| signed(5 + 2 * b as i64)).collect();
            let (form, shift) = rms.input_form(i, &point).unwrap();
            let cols = scalar.sources[n.input].cols;
            let expected = eq(&point).iter().enumerate().fold(Fp3::ZERO, |v, (j, &r)| {
                let (row, col) = (j >> bits(n.columns), j % n.columns.next_power_of_two());
                if row >= n.rows || col >= n.columns {
                    return v;
                }
                let index = row * n.columns + col;
                v + r * signed(value(n.input, index / cols, index % cols))
            });
            assert_eq!(evaluate(&form, &actual) - shift, expected);
            let rp = &point[..bits(n.rows)];
            let (form, shift) = rms.statistic_form(i, rp).unwrap();
            let expected = eq(rp)
                .iter()
                .take(n.rows)
                .enumerate()
                .fold(Fp3::ZERO, |v, (row, &r)| v + r * signed(value(n.statistic, row, 0)));
            assert_eq!(evaluate(&form, &actual) - shift, expected);
        }
        assert!(rms.form(&[]).is_err());
        assert!(rms.input_form(4, &[]).is_err());
        assert!(rms.cell(rms.cells.next_power_of_two()).is_err());

        // Full pinned geometry, without any full source bodies or GKR trace.
        let plan = super::super::compile().unwrap();
        let rms = plan.rms_sources().unwrap();
        assert_eq!(rms.norms.len(), 421);
        assert_eq!(rms.norms.iter().filter(|n| n.cohort.is_some()).count(), 361);
        assert_eq!(rms.cells, 347_937_024);
        let mut aliases = 0;
        for n in rms.norms.iter().filter(|n| n.operation == "v_norm") {
            let k =
                rms.norms.iter().find(|k| k.layer == n.layer && k.operation == "k_norm").unwrap();
            assert_eq!(n.input == k.input, n.layer.unwrap() % 6 == 5);
            aliases += usize::from(n.input == k.input);
            assert_eq!(n.product, n.input);
        }
        assert_eq!(aliases, 10);
        let point: Vec<_> = (0..bits(rms.cells) + 4).map(|i| signed(3 + 2 * i as i64)).collect();
        let forms = rms.form(&point).unwrap();
        let mut input_forms = 0;
        let mut stat_forms = 0;
        for (i, n) in rms.norms.iter().enumerate() {
            let p: Vec<_> =
                (0..bits(n.rows) + bits(n.columns)).map(|j| signed(7 + 2 * j as i64)).collect();
            input_forms += rms.input_form(i, &p).unwrap().0.len();
            stat_forms += rms.statistic_form(i, &p[..bits(n.rows)]).unwrap().0.len();
        }
        assert_eq!(rms.bytes.scalar.layout.sources.len(), 2146);
        assert_eq!(rms.bytes.live, 7_091_219_838);
        assert_eq!((forms.len(), input_forms, stat_forms), (14688, 3612, 3368));
        assert_eq!(18472 + 3840 + forms.len() + 2 * input_forms + stat_forms + 34, 47626);
        assert!(47626 <= crate::c71_matrix::linear::MAX_CUBES);
        // Public original-claim routing only: the D29 dispatcher is NOT
        // executed by this metadata check. Local V preserves its S-kernel X.
        let statistics = rms
            .norms
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let input_point: Vec<_> =
                    (0..bits(n.rows) + bits(n.columns)).map(|b| signed((b + 3) as i64)).collect();
                crate::c71_matrix::rms::statistic::Pending {
                    statistic_point: input_point[..bits(n.rows)].to_vec(),
                    statistic: i,
                    input_point,
                    inputs: [3 * i, 3 * i + 1, 3 * i + 2],
                }
            })
            .collect();
        let pending = caller::Pending { statistics, byte_point: point, byte: usize::MAX };
        let requests = rms.local_v_rne_requests(&plan, &pending).unwrap();
        assert_eq!(requests.len(), 50);
        let mut extra_cubes = 0;
        for r in requests {
            assert_eq!(r.original, pending.statistics[r.norm].inputs[0]);
            assert_eq!(r.point, pending.statistics[r.norm].input_point);
            assert_eq!(plan.cohorts[r.source].operation, "v_source");
            assert_eq!(r.shape, [150, 4096]);
            assert_eq!((r.view, r.shape), rms.bytes.rne_view(&plan, r.source).unwrap());
            let p: Vec<_> = (0..23).map(|i| signed((i + 7) as i64)).collect();
            extra_cubes += rms.bytes.rne_form(&plan, r.source, &p).unwrap().len();
        }
        assert_eq!(extra_cubes, 400);
        assert!(47626 + extra_cubes <= crate::c71_matrix::linear::MAX_CUBES);
        assert!(rms.bytes.live <= 1usize << 33);
    }
}
