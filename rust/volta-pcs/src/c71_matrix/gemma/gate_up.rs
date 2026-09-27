//! Gate-up uses the SAME GELU Y, quantized up input, raw product and
//! original down-P0 input. Reuse the cubic P0 kernel; no product PCS.

use super::caller::{P0Statement, PendingP0};

component_wire!(Proof { raw, reduction, product });
use super::rms::prefix as point;
use super::*;
use crate::c71_matrix::{
    p0, range, record_values, signed, AttemptContext, Auth, C61Commitment, Fs, Key,
};

pub(in crate::c71_matrix) struct Product {
    pub up_raw: usize,
    pub up: usize,
    pub raw: usize,
    pub output: usize,
    pub down: usize,
}

pub(in crate::c71_matrix) struct Sources {
    pub gelu: gelu::Sources,
    pub products: Vec<Product>, // SAME order as gelu.gelu
    pub cells: usize,
    pub view: [u8; 32],
    tiles: Vec<Tile>,
}

impl Plan {
    pub fn gate_up_sources(&self) -> Result<Sources, String> {
        let gelu = self.gelu_sources()?;
        let base = gelu.rms.bytes.scalar.layout.sources.len();
        let mut extra = Vec::new();
        let mut products = Vec::new();
        for (i, g) in gelu.gelu.iter().enumerate() {
            let find = |operation: &str| -> Result<usize, String> {
                let mut matching = self.cohorts.iter().enumerate().filter(|(_, c)| {
                    c.layer == Some(u64::from(g.layer)) && c.operation == operation
                });
                let (id, c) = matching.next().ok_or("gate-up matrix producer missing")?;
                if matching.next().is_some() || c.kind != Kind::Matrix {
                    return Err("gate-up matrix producer differs".into());
                }
                Ok(id)
            };
            let up_raw = find("up_proj")?;
            let down = find("down_proj")?;
            let u = &self.cohorts[up_raw];
            let route = self.input_route(down)?;
            if [u.rows, u.columns] != [g.rows, g.columns]
                || route.producer != (Some(u64::from(g.layer)), "gate_up_mul".into())
                || [route.rows, route.columns] != [g.rows, g.columns]
                || route.row_offset != 0
                || route.selected_rows != g.rows
            {
                return Err("gate-up source shape or down consumer differs".into());
            }
            products.push(Product {
                up_raw,
                up: base + i,
                raw: base + gelu.gelu.len() + i,
                output: gelu.rms.bytes.scalar.input_sources[down - 1],
                down,
            });
            extra.push((format!("X/{}/up_proj", g.layer), g.rows, g.columns, 2));
        }
        for g in &gelu.gelu {
            extra.push((format!("R/{}/gate_up_mul", g.layer), g.rows, g.columns, 6));
        }
        let gelu = gelu.append(extra)?;
        let words: Vec<_> = gelu
            .gelu
            .iter()
            .map(|g| Source {
                name: format!("gate-up/{}", g.layer),
                rows: g.rows,
                cols: g.columns,
                packed_offset: 0,
            })
            .collect();
        let (tiles, cells) = tiles(&words);
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-gate-up-source-v1;original-G-U-R-down-X;dyadic-MSB\0");
        digest.update(&gelu.view);
        for (g, p) in gelu.gelu.iter().zip(&products) {
            for v in [
                g.layer as usize,
                g.output,
                p.up_raw,
                p.up,
                p.raw,
                p.output,
                p.down,
                g.rows,
                g.columns,
            ] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        for t in &tiles {
            for v in [t.tensor, t.row, t.col, t.rows, t.cols, t.offset] {
                digest.update(&(v as u64).to_le_bytes());
            }
        }
        Ok(Sources { gelu, products, cells, view: *digest.finalize().as_bytes(), tiles })
    }
}

impl Sources {
    pub(super) fn append(
        mut self,
        extra: Vec<(String, usize, usize, usize)>,
    ) -> Result<Self, String> {
        self.gelu = self.gelu.append(extra)?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-gate-up-view-A-extension-v1\0");
        digest.update(&self.view);
        digest.update(&self.gelu.view);
        self.view = *digest.finalize().as_bytes();
        Ok(self)
    }

    pub fn up_rne_pairs(&self, shifts: &[i32]) -> Result<Vec<bytes::quantize::Pair>, String> {
        if shifts.len() != self.products.len() {
            return Err("gate-up projection shifts differ".into());
        }
        Ok(self
            .products
            .iter()
            .zip(shifts)
            .map(|(p, &shift)| bytes::quantize::Pair { raw: p.up_raw, output: p.up, shift })
            .collect())
    }

    pub fn output_rne_requests<T: Copy>(
        &self,
        plan: &Plan,
        pending: &PendingP0<T>,
    ) -> Result<Vec<bytes::RneRequest<T>>, String> {
        if self.gelu.rms.bytes.scalar.weight_layout != plan.layout_digest
            || pending.inputs.len() + 1 != plan.cohorts.len()
        {
            return Err("gate-up original P0 inputs differ".into());
        }
        self.products
            .iter()
            .zip(&self.gelu.gelu)
            .map(|(p, g)| {
                let input = &pending.inputs[p.down - 1];
                let route = plan.input_route(p.down)?;
                if input.cohort != p.down
                    || route.producer != (Some(g.layer as u64), "gate_up_mul".into())
                    || route.row_offset != 0
                    || route.selected_rows != g.rows
                    || [route.rows, route.columns] != [g.rows, g.columns]
                    || input.point.len() != bits(g.rows) + bits(g.columns)
                {
                    return Err("gate-up original down point or route differs".into());
                }
                let (view, shape) = self.gelu.rms.bytes.source_rne_view(p.raw)?;
                Ok(bytes::RneRequest {
                    consumer: p.down,
                    source: p.raw,
                    view,
                    shape,
                    point: input.point.clone(),
                    original: input.original,
                })
            })
            .collect()
    }

    pub fn cell(&self, index: usize) -> Result<Option<(usize, usize, usize)>, String> {
        if index >= self.cells.next_power_of_two() {
            return Err("gate-up cell exceeds padded domain".into());
        }
        if index >= self.cells {
            return Ok(None);
        }
        let t = &self.tiles[self.tiles.partition_point(|t| t.offset <= index) - 1];
        let local = index - t.offset;
        Ok(Some((t.tensor, t.row + local / t.cols, t.col + local % t.cols)))
    }

    /// Raw R at its fresh probe; original G/U at the cubic endpoint.
    pub fn forms(&self, raw: &[Fp3], inputs: &[Fp3]) -> Result<([Vec<Cube>; 3], [Fp3; 3]), String> {
        let c = bits(self.cells);
        if raw.len() != c || inputs.len() != c {
            return Err("gate-up original source points differ".into());
        }
        let mut forms: [Vec<Cube>; 3] = std::array::from_fn(|_| Vec::new());
        let mut shifts = [Fp3::ZERO; 3];
        for t in &self.tiles {
            let p = &self.products[t.tensor];
            let g = &self.gelu.gelu[t.tensor];
            let low = bits(t.rows) + bits(t.cols);
            for (i, source, q) in [(0, p.raw, raw), (1, g.output, inputs), (2, p.up, inputs)] {
                let coefficient = eq_index(&q[..c - low], t.offset / (t.rows * t.cols));
                let rp = point(t.row, t.rows, g.rows, &q[c - low..c - bits(t.cols)]);
                let cp = point(t.col, t.cols, g.columns, &q[c - bits(t.cols)..]);
                let (form, shift) = self.gelu.rms.bytes.word_form(source, &rp, &cp, coefficient)?;
                forms[i].extend(form);
                shifts[i] += shift;
            }
        }
        Ok((forms, shifts))
    }

    fn prepare<'a>(&self, s: &'a P0Statement<'_>) -> Result<(Statement<'a>, Vec<u8>), String> {
        if s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.auxiliary_layout.layout.layout_digest
                != self.gelu.rms.bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != self.gelu.rms.bytes.scalar.weight_layout
        {
            return Err("gate-up fixed source context differs".into());
        }
        let mut bytes = b"C71-canonical-gate-up-B12-v1\0".to_vec();
        bytes.extend(s.weights.roots()[0]);
        bytes.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            bytes.extend((gamma.len() as u64).to_le_bytes());
            bytes.extend(gamma);
        }
        bytes.extend(s.quantization);
        bytes.extend(s.attempt.encode());
        bytes.extend(self.view);
        Ok((
            Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view: self.view,
                attempt: s.attempt,
                cells: self.cells,
            },
            bytes,
        ))
    }

    pub fn required(&self, s: &P0Statement<'_>) -> Result<usize, String> {
        self.prepare(s)?.0.required()
    }

    pub fn statement<'a>(
        &'a self,
        s: &'a P0Statement<'_>,
        fs: &mut Fs,
    ) -> Result<Statement<'a>, String> {
        let (statement, frame) = self.prepare(s)?;
        fs.set_phase(0x1000);
        fs.record(0xd1, &frame);
        Ok(statement)
    }
}

pub(in crate::c71_matrix) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub cells: usize,
}

pub(in crate::c71_matrix) struct Proof {
    raw: Fp3,
    reduction: p0::Proof,
    product: [Fp3; 2],
}

pub(in crate::c71_matrix) struct Pending<T> {
    pub raw_point: Vec<Fp3>,
    pub input_point: Vec<Fp3>,
    pub originals: [T; 3], // R, G, U; all still need the SAME ranged A PCS
}

impl Statement<'_> {
    pub fn required(&self) -> Result<usize, String> {
        if self.cells == 0
            || self.cells > 1 << 29
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("gate-up product exceeds D29 or fixed context differs".into());
        }
        Ok(2 + p0::required(bits(self.cells), true))
    }

    fn bind(&self, fs: &mut Fs) -> Vec<Fp3> {
        let mut bytes = b"C71-gate-up-product-B12-v1;raw-probe;original-G-U-R;tail-zero\0".to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        bytes.extend((self.cells as u64).to_le_bytes());
        fs.set_phase(0x1010);
        fs.record(0xd2, &bytes);
        (0..bits(self.cells)).map(|_| fs.fp3()).collect()
    }
}

pub(in crate::c71_matrix) fn prove(
    s: &Statement<'_>,
    read: impl Fn(usize) -> (i16, i16, [u8; 6]),
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("gate-up prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let raw_point = s.bind(fs);
    let mut g = vec![Fp3::ZERO; s.cells.next_power_of_two()];
    let mut u = g.clone();
    let mut value = Fp3::ZERO;
    for (i, a) in crate::c71_matrix::eq(&raw_point).into_iter().take(s.cells).enumerate() {
        let (gv, uv, raw) = read(i);
        g[i] = signed(i64::from(gv));
        u[i] = signed(i64::from(uv));
        let raw = raw.iter().enumerate().fold(0i64, |v, (b, &x)| v + (i64::from(x) << (8 * b)));
        value += a * signed(raw - (1 << 47));
    }
    let (wire, raw) = range::authenticate([value], &mut rows);
    record_values(fs, 0xd3, &wire);
    let (reduction, input_point, inputs) =
        p0::prove(g, u, raw[0], Some(&raw_point), fs, &mut rows)?;
    let product = range::prove_products(&[inputs], rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    Ok((
        Proof { raw: wire[0], reduction, product },
        Pending { raw_point, input_point, originals: [raw[0], inputs[0], inputs[1]] },
    ))
}

pub(in crate::c71_matrix) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<Pending<Key>, String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("gate-up verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let raw_point = s.bind(fs);
    let raw = range::correct([proof.raw], delta, &mut rows)[0];
    record_values(fs, 0xd3, &[proof.raw]);
    let (input_point, inputs) =
        p0::verify(bits(s.cells), raw, Some(&raw_point), &proof.reduction, delta, fs, &mut rows)?;
    range::verify_products(&[inputs], rows.next().unwrap(), proof.product, delta, fs)?;
    debug_assert!(rows.next().is_none());
    Ok(Pending { raw_point, input_point, originals: [raw, inputs[0], inputs[1]] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{eq, from_p3, gamma, linear, matrix_config, rne, MatrixRng, Model, E};
    use rand_010::{RngExt, SeedableRng};

    fn evaluate(forms: &[Cube], source: &[i16]) -> Fp3 {
        forms.iter().fold(Fp3::ZERO, |v, c| {
            v + c.coefficient
                * source[c.offset..]
                    .iter()
                    .zip(eq(&c.point))
                    .fold(Fp3::ZERO, |v, (&x, w)| v + signed(i64::from(x)) * w)
        })
    }

    #[test]
    fn c71_b12_gemma_gate_up_product_and_both_rne_keep_original_macs_in_one_ranged_source() {
        let layout = [73; 32];
        let sources: Vec<_> = [("R", 6), ("G", 2), ("U", 2), ("Y", 2), ("up_raw", 6)]
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| Source {
                name: name.into(),
                rows: 1,
                cols: 3,
                packed_offset: 3 * i,
            })
            .collect();
        let (tiles, live) = tiles(&sources);
        let bytes = bytes::Bytes::new(
            caller::Auxiliary {
                layout: Plan { sources, tiles, live, cohorts: Vec::new(), layout_digest: layout },
                weight_layout: layout,
                input_sources: Vec::new(),
            },
            vec![6, 2, 2, 2, 6],
        )
        .unwrap();
        assert!(bytes.source_rne_view(1).is_err());
        assert_eq!(bytes.source_rne_view(0).unwrap().1, [1, 3]);
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let profile = gamma(&matrix_config(32).unwrap());
        let delta = signed(37);
        for fault in 0..3 {
            let g = [2i16, -3, 0];
            let u = [-4i16, 5, 7];
            let mut raw = [-8i64, -15, 0];
            if fault == 1 {
                raw[0] += 1;
            }
            let output = [-2i64, -4, 0];
            let values =
                [raw, g.map(i64::from), u.map(i64::from), output, u.map(|x| 4 * i64::from(x))];
            let packed: Vec<u8> = values
                .iter()
                .zip([6, 2, 2, 2, 6])
                .flat_map(|(words, width)| {
                    words
                        .iter()
                        .flat_map(move |&v| (0..width).map(move |b| ((v as u64) >> (8 * b)) as u8))
                })
                .collect();
            let source: Vec<_> = (0..1024)
                .map(|i| {
                    if i >= bytes.live.next_power_of_two() {
                        return 0;
                    }
                    bytes.virtual_to_packed(i).unwrap().map_or(0, |(a, x)| i16::from(packed[a] ^ x))
                })
                .collect();
            let model = Model::new(32, source.clone()).unwrap();
            let s = Statement {
                root: &model.root,
                profile: &profile,
                view: bytes.layout_digest,
                attempt,
                cells: 3,
            };
            let count = s.required().unwrap() + 1 + 2 * rne::required(2, 2) + 510 + 32;
            assert_eq!(count, 1372);
            let mut rng = MatrixRng::from_seed([157; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"gate-up original ranged byte source", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (proof, p) = prove(
                &s,
                |i| {
                    let (gv, uv) = if fault == 2 { (u[i], g[i]) } else { (g[i], u[i]) };
                    let raw = (raw[i] + (1 << 47)) as u64;
                    (gv, uv, std::array::from_fn(|b| (raw >> (8 * b)) as u8))
                },
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(fs.requests(), 5);
            // A tiny output probe stands in for the original down-P0
            // endpoint. The full canonical route preserves that P0 MAC.
            let output_point: Vec<_> = (0..2).map(|_| fs.fp3()).collect();
            let value = output
                .into_iter()
                .zip(eq(&output_point))
                .fold(Fp3::ZERO, |v, (x, w)| v + signed(x) * w);
            let (output_wire, output_mac) = range::authenticate([value], &mut prows);
            record_values(&mut fs, 0xd4, &output_wire);
            let statements = [
                rne::Statement {
                    root: &model.root,
                    profile: &profile,
                    view: bytes.source_rne_view(0).unwrap().0,
                    attempt,
                    output_point: &output_point,
                    shape: [1, 3],
                    shift: 2,
                },
                rne::Statement {
                    root: &model.root,
                    profile: &profile,
                    view: bytes.source_rne_view(4).unwrap().0,
                    attempt,
                    output_point: &p.input_point,
                    shape: [1, 3],
                    shift: 2,
                },
            ];
            let mut rne_proofs = Vec::new();
            let mut rne_originals = Vec::new();
            for (i, rs) in statements.iter().enumerate() {
                let (proof, point, original) = rne::prove(
                    rs,
                    if i == 0 { output_mac[0] } else { p.originals[2] },
                    |j| {
                        let v = if i == 0 {
                            raw[j]
                        } else {
                            4 * i64::from(if fault == 2 { g[j] } else { u[j] })
                        };
                        std::array::from_fn(|b| (((v + (1 << 47)) as u64) >> (8 * b)) as u8)
                    },
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                rne_proofs.push(proof);
                rne_originals.push((point, original));
            }
            let forms = |p: &Pending<_>| {
                let mut result = Vec::new();
                let mut shifts = Vec::new();
                for (id, point) in [(0, &p.raw_point), (1, &p.input_point), (2, &p.input_point)] {
                    let (form, shift) = bytes.word_form(id, &[], point, Fp3::ONE).unwrap();
                    result.push(form);
                    shifts.push(shift);
                }
                (result, shifts)
            };
            let (mut extra, mut shifts) = forms(&p);
            if fault == 0 {
                for i in 0..3 {
                    assert_eq!(evaluate(&extra[i], &source), p.originals[i].x + shifts[i]);
                }
                let q: Vec<_> = (0..5).map(|i| signed(i + 3)).collect();
                let form = bytes.source_rne_form(0, &q).unwrap();
                let expected = eq(&q).into_iter().enumerate().fold(Fp3::ZERO, |v, (j, w)| {
                    let (cell, b) = (j / 8, j % 8);
                    if cell >= 3 || b >= 6 {
                        return v;
                    }
                    v + w * signed((((raw[cell] + (1 << 47)) as u64 >> (8 * b)) as u8) as i64)
                });
                assert_eq!(evaluate(&form, &source), expected);
            }
            let (form, shift) = bytes.word_form(3, &[], &output_point, Fp3::ONE).unwrap();
            extra.push(form);
            shifts.push(shift);
            let mut original_targets = p.originals.to_vec();
            original_targets.push(output_mac[0]);
            for ((point, original), id) in rne_originals.iter().zip([0, 4]) {
                extra.push(bytes.source_rne_form(id, point).unwrap());
                shifts.push(Fp3::ZERO);
                original_targets.push(*original);
            }
            let (range_proof, ranged, targets) = range::prove(
                &model,
                attempt,
                layout,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let all_forms: Vec<_> = ranged.into_iter().chain(extra).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(
                    original_targets.into_iter().zip(shifts).map(|(a, s)| Auth::new(a.x + s, a.m)),
                )
                .collect();
            let (pcs, digest) =
                linear::prove(&model, attempt, layout, &all_forms, &targets, &mut fs, &mut prows)
                    .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let result = verify(&s, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 {
                assert!(result.is_err(), "incorrect product passed GKR");
                continue;
            }
            let v = result.unwrap();
            assert_eq!(fs.requests(), 5);
            let verifier_output_point: Vec<_> = (0..2).map(|_| fs.fp3()).collect();
            assert_eq!(verifier_output_point, output_point);
            let output_key = range::correct(output_wire, delta, &mut vrows)[0];
            record_values(&mut fs, 0xd4, &output_wire);
            let mut rne_keys = Vec::new();
            for (i, rs) in statements.iter().enumerate() {
                let output_point = if i == 0 { &verifier_output_point } else { &v.input_point };
                let statement = rne::Statement { output_point, ..*rs };
                rne_keys.push(
                    rne::verify(
                        &statement,
                        if i == 0 { output_key } else { v.originals[2] },
                        &rne_proofs[i],
                        delta,
                        &mut fs,
                        &mut vrows,
                    )
                    .unwrap(),
                );
            }
            let (ranged, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                bytes.live,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            // Point identity is verifier-derived; only the MAC type changes.
            let vp = Pending {
                raw_point: v.raw_point,
                input_point: v.input_point,
                originals: p.originals,
            };
            let (mut extra, mut shifts) = forms(&vp);
            let (form, shift) = bytes.word_form(3, &[], &verifier_output_point, Fp3::ONE).unwrap();
            extra.push(form);
            shifts.push(shift);
            let mut original_targets = v.originals.to_vec();
            original_targets.push(output_key);
            for ((point, original), id) in rne_keys.iter().zip([0, 4]) {
                extra.push(bytes.source_rne_form(id, point).unwrap());
                shifts.push(Fp3::ZERO);
                original_targets.push(*original);
            }
            let all_forms: Vec<_> = ranged.into_iter().chain(extra).collect();
            let targets: Vec<_> = targets
                .into_iter()
                .chain(
                    original_targets
                        .into_iter()
                        .zip(shifts)
                        .map(|(k, s)| Key::new(k.k + delta * s)),
                )
                .collect();
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                layout,
                &all_forms,
                &targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert!(result.is_err(), "swapped operands with equal product detached from A");
                assert!(vrows.len() > 0);
            } else {
                assert_eq!(result.unwrap(), digest);
                assert!(vrows.next().is_none());
            }
            let mut exhausted = vec![Auth::ZERO; s.required().unwrap() - 1].into_iter();
            let before = exhausted.len();
            assert!(prove(&s, |_| panic!("exhaustion read witness"), &mut start(), &mut exhausted)
                .is_err());
            assert_eq!(exhausted.len(), before);
        }
    }

    #[test]
    fn c71_b12_gemma_gate_up_sources_reuse_gelu_and_original_down_rne_and_recount_d34() {
        let mut small = rms::tests::toy_plan(3, 2);
        for op in ["gate_proj", "up_proj", "down_proj"] {
            let mut c = small.cohorts[1].clone();
            c.layer = Some(0);
            c.operation = op.into();
            c.producer = if op == "down_proj" {
                (Some(0), "gate_up_mul".into())
            } else {
                (None, "q_norm".into())
            };
            small.cohorts.push(c);
        }
        let source = small.gate_up_sources().unwrap();
        let g = &source.gelu.gelu[0];
        let p = &source.products[0];
        let value = |id, r, c| {
            let gv = 1 + r as i64 - c as i64;
            let uv = 2 - r as i64 + c as i64;
            if id == g.output {
                gv
            } else if id == p.up {
                uv
            } else if id == p.raw {
                gv * uv
            } else {
                0
            }
        };
        let mut packed = Vec::new();
        for (i, s) in source.gelu.rms.bytes.scalar.layout.sources.iter().enumerate() {
            let width = if i < small.cohorts.len() {
                match small.cohorts[i].kind {
                    Kind::Matrix => 6,
                    Kind::Norm => 4,
                    Kind::Lookup => 2,
                }
            } else if s.name.starts_with("S/") || s.name.starts_with("R/") {
                6
            } else if s.name.starts_with("M/") {
                4
            } else {
                2
            };
            for r in 0..s.rows {
                for c in 0..s.cols {
                    let word = value(i, r, c) as u64;
                    packed.extend((0..width).map(|b| (word >> (8 * b)) as u8));
                }
            }
        }
        let literal: Vec<_> = (0..source.gelu.rms.bytes.live.next_power_of_two())
            .map(|i| {
                source
                    .gelu
                    .rms
                    .bytes
                    .virtual_to_packed(i)
                    .unwrap()
                    .map_or(0, |(a, x)| i16::from(packed[a] ^ x))
            })
            .collect();
        let root = C61Commitment::new(vec![[1; 32]]);
        let wroot = C61Commitment::new(vec![[2; 32]]);
        let profile = [7; 32];
        let context = P0Statement {
            weights: &wroot,
            auxiliary: &root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &source.gelu.rms.bytes.scalar,
            quantization: [8; 32],
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [3; 32],
            },
            tokens: &[0, 1, 2],
        };
        let delta = signed(37);
        let mut rng = MatrixRng::from_seed([159; 32]);
        let rows: Vec<_> = (0..21)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        let start = || Fs::new(b"canonical gate-up literal source view; no PCS acceptance", 10000);
        let mut fs = start();
        let mut prows = rows.into_iter();
        let s = source.statement(&context, &mut fs).unwrap();
        assert_eq!(s.required().unwrap(), 21);
        let (proof, pending) = prove(
            &s,
            |i| {
                let (index, r, c) = source.cell(i).unwrap().unwrap();
                assert_eq!(index, 0);
                let raw = (value(p.raw, r, c) + (1 << 47)) as u64;
                (
                    value(g.output, r, c) as i16,
                    value(p.up, r, c) as i16,
                    std::array::from_fn(|b| (raw >> (8 * b)) as u8),
                )
            },
            &mut fs,
            &mut prows,
        )
        .unwrap();
        assert!(prows.next().is_none());
        let mut fs = start();
        let mut vrows = keys.into_iter();
        let s = source.statement(&context, &mut fs).unwrap();
        let verified = verify(&s, &proof, delta, &mut fs, &mut vrows).unwrap();
        assert!(vrows.next().is_none());
        let (forms, shifts) = source.forms(&verified.raw_point, &verified.input_point).unwrap();
        for i in 0..3 {
            let a = pending.originals[i];
            assert_eq!(a.m + delta * a.x, verified.originals[i].k);
            assert_eq!(evaluate(&forms[i], &literal), a.x + shifts[i]);
        }
        // Placeholder roots above check canonical routing only. The other
        // 1,372-row test closes a real small ranged source PCS.
        let plan = compile().unwrap();
        let before = plan.gelu_sources().unwrap();
        let source = plan.gate_up_sources().unwrap();
        assert_eq!(source.products.len(), 60);
        assert_eq!(source.cells, 193536000);
        assert_eq!(source.tiles.len(), 720);
        assert_eq!(source.gelu.rms.bytes.live, 9429380238);
        assert_eq!(bits(source.gelu.rms.bytes.live), 34);
        assert_eq!(source.gelu.rms.bytes.scalar.layout.sources.len(), 2446);
        assert_ne!(source.gelu.view, before.view);
        assert_ne!(source.gelu.rms.view, before.rms.view);
        for (old, new) in before.gelu.iter().zip(&source.gelu.gelu) {
            assert_eq!(
                [old.raw_gate, old.input, old.output, old.histogram],
                [new.raw_gate, new.input, new.output, new.histogram]
            );
        }
        let q: Vec<_> = (0..28).map(|i| signed(i + 3)).collect();
        let (forms, _) = source.forms(&q, &q).unwrap();
        assert_eq!(forms.each_ref().map(Vec::len), [1440, 720, 720]);
        for t in &source.tiles {
            assert_eq!(source.cell(t.offset).unwrap(), Some((t.tensor, t.row, t.col)));
            assert_eq!(
                source.cell(t.offset + t.rows * t.cols - 1).unwrap(),
                Some((t.tensor, t.row + t.rows - 1, t.col + t.cols - 1))
            );
        }
        assert_eq!(source.cell(source.cells).unwrap(), None);
        let pairs = source.up_rne_pairs(&vec![0; 60]).unwrap();
        assert!(source.up_rne_pairs(&[]).is_err());
        let pending = caller::PendingP0 {
            cuts: Vec::new(),
            weights: Vec::new(),
            weight_forms: Vec::new(),
            inputs: (1..plan.cohorts.len())
                .map(|i| {
                    let route = plan.input_route(i).unwrap();
                    caller::InputOpening {
                        cohort: i,
                        point: (0..bits(route.selected_rows) + bits(route.columns))
                            .map(|j| signed(j as i64 + 3))
                            .collect(),
                        route,
                        original: i,
                    }
                })
                .collect(),
        };
        let requests = source.output_rne_requests(&plan, &pending).unwrap();
        let mut count = 0;
        for (((p, g), pair), request) in
            source.products.iter().zip(&source.gelu.gelu).zip(&pairs).zip(&requests)
        {
            assert_eq!(plan.cohorts[p.up_raw].layer, Some(g.layer as u64));
            assert_eq!(plan.cohorts[p.up_raw].operation, "up_proj");
            assert_eq!((pair.raw, pair.output), (p.up_raw, p.up));
            assert_eq!(request.consumer, p.down);
            assert_eq!(request.original, pending.inputs[p.down - 1].original);
            assert_eq!(request.point, pending.inputs[p.down - 1].point);
            assert_eq!(request.source, p.raw);
            assert_eq!(request.shape, [150, 21504]);
            assert_eq!(
                source.gelu.rms.bytes.scalar.layout.sources[p.output].name,
                format!("X/{}/gate_up_mul", g.layer)
            );
            let q: Vec<_> = (0..26).map(|j| signed(j + 5)).collect();
            count += source.gelu.rms.bytes.source_rne_form(p.raw, &q).unwrap().len();
        }
        assert_eq!(count, 1440);
        let openings: Vec<_> = (0..60)
            .map(|i| bytes::quantize::Opening {
                output_point: (0..23).map(|j| signed(j + 3)).collect(),
                output: 2 * i,
                raw_point: (0..26).map(|j| signed(j + 5)).collect(),
                raw: 2 * i + 1,
            })
            .collect();
        let (forms, _, targets) =
            source.gelu.rms.bytes.table_rne_forms(&plan, &pairs, &openings).unwrap();
        assert_eq!(forms.iter().map(Vec::len).sum::<usize>(), 2160);
        assert_eq!(targets, (0..120).collect::<Vec<_>>());
        // Public preflight only; no full-domain execution.
        assert!(source.gelu.rms.bytes.table_rne_required(&plan, &pairs).is_ok());
        // Every old form must be recompiled at D34; no stored old-offset form is reused.
        assert_eq!(source.gelu.forms(&q).unwrap().0.each_ref().map(Vec::len), [720, 720, 960]);
        let mut wrong = pending;
        wrong.inputs[source.products[0].down - 1].cohort += 1;
        assert!(source.output_rne_requests(&plan, &wrong).is_err());
    }
}
