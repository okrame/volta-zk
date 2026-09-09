//! Pinned native W layout/P0 routes. Reuse the validated frontend and DAG;
//! do not inherit their historical protocol or runtime-admission flags.

use super::{linear::Cube, Fp3};
use crate::{
    c7_gemma_frontend::compile_pinned_gemma31b_frontend,
    gemma31b_qspec_dag::declared_gemma31b_qspec_dag,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(super) struct Source {
    pub name: String,
    pub rows: usize,
    pub cols: usize,
    pub packed_offset: usize, // i16 cells in the EXISTING terminal-order file
}

#[derive(Clone, Debug)]
struct Tile {
    tensor: usize,
    row: usize,
    col: usize,
    rows: usize,
    cols: usize,
    offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Kind {
    Matrix,
    Norm,
    Lookup,
}

#[derive(Clone, Debug)]
pub(super) struct Cohort {
    pub layer: Option<u64>,
    pub operation: String,
    pub tensor: usize,
    pub kind: Kind,
    pub rows: usize,
    pub columns: usize,
    pub inner: usize,
    pub heads: usize,
    pub producer: (Option<u64>, String),
    pub members: Vec<(u64, usize, usize)>, // DAG node, first aggregate row, row count
    pub cut_byte_offset: usize,
}

pub(super) struct Plan {
    pub sources: Vec<Source>, // canonical metadata key order
    tiles: Vec<Tile>,
    pub cohorts: Vec<Cohort>,
    pub live: usize,
    pub layout_digest: [u8; 32], // layout/flow identity; NOT a calibrated quant profile
}

fn intervals(mut length: usize) -> Vec<(usize, usize)> {
    let (mut start, mut result) = (0, Vec::new());
    while length != 0 {
        let width = 1usize << length.ilog2();
        result.push((start, width));
        start += width;
        length -= width;
    }
    result
}

fn tiles(sources: &[Source]) -> (Vec<Tile>, usize) {
    let mut result = Vec::new();
    for (tensor, source) in sources.iter().enumerate() {
        for (row, rows) in intervals(source.rows) {
            for (col, cols) in intervals(source.cols) {
                result.push(Tile { tensor, row, col, rows, cols, offset: 0 });
            }
        }
    }
    result.sort_by_key(|t| (std::cmp::Reverse(t.rows * t.cols), t.tensor, t.row, t.col));
    let mut live = 0;
    for tile in &mut result {
        assert_eq!(live % (tile.rows * tile.cols), 0);
        tile.offset = live;
        live += tile.rows * tile.cols;
    }
    (result, live)
}

pub(super) fn compile() -> Result<Plan, String> {
    let frontend = compile_pinned_gemma31b_frontend().map_err(|e| e.to_string())?;
    let dag = declared_gemma31b_qspec_dag().map_err(|e| e.to_string())?;
    let mut packed = 0usize;
    let mut by_name = BTreeMap::new();
    for relation in &frontend.weight_relations {
        for source in &relation.private_sources {
            let shape = source
                .shape
                .iter()
                .map(|&n| {
                    usize::try_from(n)
                        .map_err(|_| "Gemma shape exceeds native address space".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (rows, cols) = match shape.as_slice() {
                &[cols] => (1, cols),
                &[rows, cols] => (rows, cols),
                _ => return Err("Gemma W source is not a vector or matrix".into()),
            };
            let next = packed
                .checked_add(rows.checked_mul(cols).ok_or("Gemma source size overflow")?)
                .ok_or("Gemma packed offset overflow")?;
            if by_name
                .insert(
                    source.name.clone(),
                    Source { name: source.name.clone(), rows, cols, packed_offset: packed },
                )
                .is_some()
            {
                return Err("Gemma source duplicated in packed order".into());
            }
            packed = next;
        }
    }
    let sources: Vec<_> = by_name.into_values().collect();
    let index: BTreeMap<_, _> =
        sources.iter().enumerate().map(|(i, s)| (s.name.clone(), i)).collect();
    let owners: BTreeMap<_, _> = frontend.weight_relations.iter().map(|r| (&r.owner, r)).collect();
    let (mut cohorts, mut cohort_index) = (Vec::<Cohort>::new(), BTreeMap::new());
    for node in &dag.nodes {
        let Some(owner) = &node.weight_terminal else {
            continue;
        };
        let relation = owners.get(owner).ok_or("Gemma DAG weight owner missing from metadata")?;
        let source = if relation.private_sources.len() == 1 {
            &relation.private_sources[0]
        } else {
            let suffix = match node.operation.as_str() {
                "input_rms" => "input_layernorm.weight",
                "q_norm" => "self_attn.q_norm.weight",
                "k_norm" => "self_attn.k_norm.weight",
                "post_attention_rms" => "post_attention_layernorm.weight",
                "pre_ffw_rms" => "pre_feedforward_layernorm.weight",
                "post_ffw_rms" => "post_feedforward_layernorm.weight",
                _ => return Err("Gemma norm bundle used by an unknown operator".into()),
            };
            let key = format!(
                "model.language_model.layers.{}.{}",
                node.layer.ok_or("Gemma layer missing")?,
                suffix
            );
            relation
                .private_sources
                .iter()
                .find(|s| s.name == key)
                .ok_or("Gemma norm source missing")?
        };
        let tensor = index[&source.name];
        let kind = if node.operation == "embedding_lookup" {
            Kind::Lookup
        } else if source.shape.len() == 1 {
            Kind::Norm
        } else {
            Kind::Matrix
        };
        let heads = if matches!(node.operation.as_str(), "q_norm" | "k_norm") {
            let role = if node.operation == "q_norm" { "q" } else { "k" };
            let projection = format!(
                "model.language_model.layers.{}.self_attn.{}_proj.weight",
                node.layer.unwrap(),
                role
            );
            let height =
                sources[*index.get(&projection).ok_or("Gemma norm projection missing")?].rows;
            if height % sources[tensor].cols != 0 {
                return Err("Gemma norm head geometry differs".into());
            }
            height / sources[tensor].cols
        } else {
            1
        };
        let [dependency] = node.dependencies.as_slice() else {
            return Err("Gemma P0 input arity differs".into());
        };
        let producer = dag.nodes.get(*dependency as usize).ok_or("Gemma P0 producer missing")?;
        let producer = (producer.layer, producer.operation.clone());
        let key = (node.layer, node.operation.clone());
        let c = *cohort_index.entry(key.clone()).or_insert_with(|| {
            let c = cohorts.len();
            cohorts.push(Cohort {
                layer: node.layer,
                operation: node.operation.clone(),
                tensor,
                kind,
                rows: 0,
                columns: if kind == Kind::Matrix {
                    sources[tensor].rows
                } else {
                    sources[tensor].cols
                },
                inner: if kind == Kind::Matrix { sources[tensor].cols } else { 0 },
                heads,
                producer: producer.clone(),
                members: Vec::new(),
                cut_byte_offset: 0,
            });
            c
        });
        let c = &mut cohorts[c];
        if c.tensor != tensor || c.kind != kind || c.heads != heads || c.producer != producer {
            return Err("Gemma P0 cohort changes source or producer across executions".into());
        }
        let rows = heads * if node.operation == "lm_head" || node.execution != 0 { 1 } else { 100 };
        c.members.push((node.id, c.rows, rows));
        c.rows += rows;
    }
    let mut cut = 0;
    for c in &mut cohorts {
        c.cut_byte_offset = cut;
        cut += c.rows
            * c.columns
            * match c.kind {
                Kind::Matrix => 6,
                Kind::Norm => 4,
                Kind::Lookup => 2,
            };
    }
    let (tiles, live) = tiles(&sources);
    if sources.len() != 772
        || cohorts.len() != 773
        || live != 30_697_345_280
        || packed != live
        || cohorts.iter().map(|c| c.members.len()).sum::<usize>() != 39_421
    {
        return Err("Gemma native P0/source census differs".into());
    }
    let mut digest = blake3::Hasher::new();
    digest.update(b"C71-W-layout-v1;terminal-packed;dyadic-key-sorted;MSB;P0-DAG-rows\0");
    digest.update(frontend.source_metadata_blake3.as_bytes());
    digest.update(&dag.manifest_blake3);
    for source in &sources {
        digest.update(&(source.name.len() as u64).to_le_bytes());
        digest.update(source.name.as_bytes());
        for word in [source.rows, source.cols, source.packed_offset] {
            digest.update(&(word as u64).to_le_bytes());
        }
    }
    for tile in &tiles {
        for word in [tile.tensor, tile.row, tile.col, tile.rows, tile.cols, tile.offset] {
            digest.update(&(word as u64).to_le_bytes());
        }
    }
    for c in &cohorts {
        digest.update(&(c.operation.len() as u64).to_le_bytes());
        digest.update(c.operation.as_bytes());
        for word in [
            c.layer.map_or(u64::MAX, |x| x),
            c.tensor as u64,
            c.kind as u64,
            c.rows as u64,
            c.columns as u64,
            c.inner as u64,
            c.heads as u64,
            c.cut_byte_offset as u64,
        ] {
            digest.update(&word.to_le_bytes());
        }
        digest.update(&(c.members.len() as u64).to_le_bytes());
        for &(node, first, count) in &c.members {
            for word in [node, first as u64, count as u64] {
                digest.update(&word.to_le_bytes());
            }
        }
    }
    Ok(Plan { sources, tiles, cohorts, live, layout_digest: *digest.finalize().as_bytes() })
}

fn bits(n: usize) -> usize {
    (n - 1).checked_ilog2().map_or(0, |b| b as usize + 1)
}

fn eq_index(point: &[Fp3], index: usize) -> Fp3 {
    point.iter().enumerate().fold(Fp3::ONE, |s, (i, &r)| {
        s * if index >> (point.len() - 1 - i) & 1 == 1 { r } else { Fp3::ONE - r }
    })
}

impl Plan {
    /// Canonical scalar address in the existing packed file; None is ONLY
    /// the root's public zero suffix, not an out-of-domain access.
    pub fn virtual_to_packed(&self, index: usize) -> Result<Option<usize>, String> {
        if index >= self.live.next_power_of_two() {
            return Err("W virtual index exceeds root domain".into());
        }
        if index >= self.live {
            return Ok(None);
        }
        let tile = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let local = index - tile.offset;
        let source = &self.sources[tile.tensor];
        Ok(Some(
            source.packed_offset
                + (tile.row + local / tile.cols) * source.cols
                + tile.col
                + local % tile.cols,
        ))
    }

    pub fn tensor_to_virtual(
        &self,
        tensor: usize,
        row: usize,
        col: usize,
    ) -> Result<usize, String> {
        let source = self.sources.get(tensor).ok_or("W tensor index missing")?;
        if row >= source.rows || col >= source.cols {
            return Err("W tensor coordinates out of bounds".into());
        }
        let tile = self
            .tiles
            .iter()
            .find(|t| {
                t.tensor == tensor
                    && (t.row..t.row + t.rows).contains(&row)
                    && (t.col..t.col + t.cols).contains(&col)
            })
            .ok_or("W tensor tile missing")?;
        Ok(tile.offset + (row - tile.row) * tile.cols + col - tile.col)
    }

    fn project(
        &self,
        tensor: usize,
        r: &[Fp3],
        s: &[Fp3],
        coefficient: Fp3,
    ) -> Result<Vec<Cube>, String> {
        let source = &self.sources[tensor];
        if r.len() != bits(source.rows) || s.len() != bits(source.cols) {
            return Err("W tensor point axes differ".into());
        }
        let mut result = Vec::new();
        for tile in self.tiles.iter().filter(|t| t.tensor == tensor) {
            let (rb, cb) = (bits(tile.rows), bits(tile.cols));
            let scale = coefficient
                * eq_index(&r[..r.len() - rb], tile.row / tile.rows)
                * eq_index(&s[..s.len() - cb], tile.col / tile.cols);
            if scale == Fp3::ZERO {
                continue;
            }
            let mut point = r[r.len() - rb..].to_vec();
            point.extend(&s[s.len() - cb..]);
            result.push(Cube { offset: tile.offset, point, coefficient: scale });
        }
        Ok(result)
    }

    /// Ordered P0 endpoint points, derived by its verifier, NOT prover-chosen
    /// forms. Matrix points are (output-column, inner); norm points ([], s).
    pub fn weight_forms(
        &self,
        points: &[(Vec<Fp3>, Vec<Fp3>)],
        tokens: &[u32],
    ) -> Result<Vec<Vec<Cube>>, String> {
        if points.len() != self.cohorts.len() || tokens.len() != 150 {
            return Err("Gemma W endpoint/token count differs".into());
        }
        let mut forms = Vec::new();
        for (c, (r, s)) in self.cohorts.iter().zip(points) {
            if c.kind != Kind::Lookup {
                forms.push(self.project(c.tensor, r, s, Fp3::ONE)?);
                continue;
            }
            if r.len() != bits(tokens.len()) {
                return Err("Gemma lookup token axis differs".into());
            }
            let source = &self.sources[c.tensor];
            let mut form = Vec::new();
            for (i, &token) in tokens.iter().enumerate() {
                if token as usize >= source.rows {
                    return Err("Gemma public token is outside vocabulary".into());
                }
                let point: Vec<_> = (0..bits(source.rows))
                    .rev()
                    .map(|j| if token as usize >> j & 1 == 1 { Fp3::ONE } else { Fp3::ZERO })
                    .collect();
                form.extend(self.project(c.tensor, &point, s, eq_index(r, i))?);
            }
            forms.push(form);
        }
        Ok(forms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{eq, signed};

    #[test]
    fn c71_b12_gemma_layout_matches_packed_addresses_and_physical_tensor_mles() {
        // Key order differs from terminal-packed order, and every axis is ragged.
        let sources = vec![
            Source { name: "embedding".into(), rows: 5, cols: 3, packed_offset: 18 },
            Source { name: "matrix".into(), rows: 3, cols: 5, packed_offset: 0 },
            Source { name: "norm".into(), rows: 1, cols: 3, packed_offset: 15 },
        ];
        let (tiles, live) = tiles(&sources);
        let plan = Plan { sources, tiles, live, cohorts: Vec::new(), layout_digest: [0; 32] };
        assert_eq!(live, 33);
        let value = |i| signed((13 * i as i64 + 7) % 31 - 15);
        let virtual_w: Vec<_> =
            (0..64).map(|i| plan.virtual_to_packed(i).unwrap().map_or(Fp3::ZERO, value)).collect();
        let mut addresses: Vec<_> =
            (0..live).map(|i| plan.virtual_to_packed(i).unwrap().unwrap()).collect();
        addresses.sort_unstable();
        assert_eq!(addresses, (0..live).collect::<Vec<_>>());
        assert!(plan.virtual_to_packed(64).is_err());
        assert_eq!(plan.virtual_to_packed(63).unwrap(), None);
        for (i, source) in plan.sources.iter().enumerate() {
            let r: Vec<_> = (0..bits(source.rows)).map(|j| signed(2 + j as i64)).collect();
            let s: Vec<_> = (0..bits(source.cols)).map(|j| signed(5 + j as i64)).collect();
            let expected = (0..source.rows).fold(Fp3::ZERO, |total, row| {
                total
                    + (0..source.cols).fold(Fp3::ZERO, |sum, col| {
                        let packed = source.packed_offset + row * source.cols + col;
                        let virtual_index = plan.tensor_to_virtual(i, row, col).unwrap();
                        assert_eq!(plan.virtual_to_packed(virtual_index).unwrap(), Some(packed));
                        sum + eq_index(&r, row) * eq_index(&s, col) * value(packed)
                    })
            });
            let forms = plan.project(i, &r, &s, Fp3::ONE).unwrap();
            let got = forms.iter().fold(Fp3::ZERO, |total, cube| {
                total
                    + cube.coefficient
                        * eq(&cube.point)
                            .iter()
                            .enumerate()
                            .fold(Fp3::ZERO, |sum, (j, &c)| sum + c * virtual_w[cube.offset + j])
            });
            assert_eq!(got, expected);
            assert!(plan.tensor_to_virtual(i, source.rows, 0).is_err());
            assert!(plan.project(i, &[Fp3::ONE; 9], &s, Fp3::ONE).is_err());
        }
    }

    #[test]
    fn c71_b12_gemma_pinned_dag_compiles_all_original_p0_weight_forms() {
        let plan = compile().unwrap();
        assert_eq!(plan.sources.len(), 772);
        assert_eq!(plan.cohorts.len(), 773);
        assert_eq!(plan.tiles.len(), 3156);
        assert_eq!(plan.live, 30_697_345_280);
        let counts = [Kind::Matrix, Kind::Norm, Kind::Lookup]
            .map(|kind| plan.cohorts.iter().filter(|c| c.kind == kind).count());
        assert_eq!(counts, [411, 361, 1]);
        assert_eq!(plan.cohorts[0].tensor, plan.cohorts.last().unwrap().tensor);
        assert_eq!(plan.cohorts[0].rows, 150);
        assert_eq!(plan.cohorts[771].rows, 149);
        assert_eq!(plan.cohorts[772].rows, 50);
        assert_eq!(plan.cohorts.iter().map(|c| c.members.len()).sum::<usize>(), 39421);
        for c in &plan.cohorts {
            let mut cursor = 0;
            for &(_, first, count) in &c.members {
                assert_eq!(first, cursor);
                cursor += count;
            }
            assert_eq!(cursor, c.rows);
            if c.layer.is_some_and(|l| l % 6 == 5) {
                assert_ne!(c.operation, "v_source");
            }
        }
        for (i, source) in plan.sources.iter().enumerate() {
            for row in [0, source.rows - 1] {
                for col in [0, source.cols - 1] {
                    let v = plan.tensor_to_virtual(i, row, col).unwrap();
                    assert_eq!(
                        plan.virtual_to_packed(v).unwrap(),
                        Some(source.packed_offset + row * source.cols + col)
                    );
                }
            }
        }
        let points: Vec<_> = plan
            .cohorts
            .iter()
            .map(|c| {
                let source = &plan.sources[c.tensor];
                (
                    vec![signed(2); bits(if c.kind == Kind::Lookup { 150 } else { source.rows })],
                    vec![signed(3); bits(source.cols)],
                )
            })
            .collect();
        let tokens: Vec<_> = (0..150).collect();
        let forms = plan.weight_forms(&points, &tokens).unwrap();
        assert_eq!(forms.len(), 773);
        assert_eq!(forms.iter().map(Vec::len).sum::<usize>(), 3606);
        assert_eq!(forms[0].len(), 450);
        assert!(plan.weight_forms(&points[..772], &tokens).is_err());
        let mut bad = tokens;
        bad[0] = 262144;
        assert!(plan.weight_forms(&points, &bad).is_err());
        assert_ne!(plan.layout_digest, [0; 32]);
    }
}
