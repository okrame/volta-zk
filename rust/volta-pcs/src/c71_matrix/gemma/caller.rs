//! The pinned P0 caller owns challenge generation and original-MAC routing.
//! Success returns pending source openings, not a complete Gemma proof.

use super::*;

component_wire!(Proof { cohorts, products });
use crate::c71_matrix::{p0, range, record_values, AttemptContext, Auth, C61Commitment, Fs, Key};

pub(in crate::c71_matrix) struct P0Statement<'a> {
    pub weights: &'a C61Commitment,
    pub auxiliary: &'a C61Commitment,
    pub weight_gamma: &'a [u8],
    pub auxiliary_gamma: &'a [u8],
    pub auxiliary_layout: &'a Auxiliary,
    pub quantization: [u8; 32],
    pub attempt: AttemptContext,
    pub tokens: &'a [u32],
}

pub(in crate::c71_matrix) struct Compact {
    pub output: Fp3,
    pub x: Vec<Fp3>,
    pub w: Vec<Fp3>,
}

pub(in crate::c71_matrix) struct Proof {
    cohorts: Vec<(Fp3, Option<p0::Proof>)>,
    products: [Fp3; 2],
}

#[derive(Clone, Debug)]
pub(in crate::c71_matrix) struct InputRoute {
    pub producer: (Option<u64>, String),
    pub rows: usize,
    pub columns: usize,
    pub selected_rows: usize,
    pub row_offset: usize,
}

pub(in crate::c71_matrix) struct CutOpening<T> {
    pub cohort: usize,
    pub point: Vec<Fp3>, // token/head row, then output column, MSB first
    pub original: T,
}

pub(in crate::c71_matrix) struct InputOpening<T> {
    pub cohort: usize,
    pub route: InputRoute,
    pub point: Vec<Fp3>, // selected token row, then full producer channel
    pub original: T,
}

pub(in crate::c71_matrix) struct PendingP0<T> {
    pub cuts: Vec<CutOpening<T>>,
    pub inputs: Vec<InputOpening<T>>,
    pub weight_forms: Vec<Vec<Cube>>,
    pub weights: Vec<T>,
}

/// Public field-cell layout for the RAW P0 statement. Materializing all of
/// these sources is NOT the selected four-read/6-GiB physical schedule.
pub(in crate::c71_matrix) struct Auxiliary {
    pub layout: Plan,
    pub(super) weight_layout: [u8; 32],
    pub(super) input_sources: Vec<usize>, // non-lookup cohort order; same producer shares one source
}

impl Auxiliary {
    pub fn forms<T>(&self, plan: &Plan, pending: &PendingP0<T>) -> Result<Vec<Vec<Cube>>, String> {
        if self.weight_layout != plan.layout_digest
            || pending.cuts.len() != plan.cohorts.len()
            || pending.inputs.len() != self.input_sources.len()
        {
            return Err("Gemma auxiliary source/claim census differs".into());
        }
        let mut forms = Vec::new();
        for (ordinal, claim) in pending.cuts.iter().enumerate() {
            let c = &plan.cohorts[ordinal];
            if claim.cohort != ordinal || claim.point.len() != bits(c.rows) + bits(c.columns) {
                return Err("Gemma original cut point differs".into());
            }
            let (r, s) = claim.point.split_at(bits(c.rows));
            forms.push(self.layout.project(ordinal, r, s, Fp3::ONE)?);
        }
        for (index, claim) in pending.inputs.iter().enumerate() {
            if claim.cohort != index + 1 {
                return Err("Gemma original input order differs".into());
            }
            // Re-derive the route; no caller-selected producer or row selector.
            let route = plan.input_route(claim.cohort)?;
            let rb = bits(route.selected_rows);
            if claim.point.len() != rb + bits(route.columns) {
                return Err("Gemma original input point differs".into());
            }
            let (r, s) = claim.point.split_at(rb);
            let source = self.input_sources[index];
            if route.row_offset == 0 && route.selected_rows == route.rows {
                forms.push(self.layout.project(source, r, s, Fp3::ONE)?);
                continue;
            }
            let mut form = Vec::new();
            let mut row = 0;
            while row < route.selected_rows {
                let mut width = 1usize << (route.selected_rows - row).ilog2();
                while row % width != 0 || (route.row_offset + row) % width != 0 {
                    width /= 2;
                }
                let low = bits(width);
                let high = bits(route.rows) - low;
                let prefix = (route.row_offset + row) / width;
                let mut point: Vec<_> = (0..high)
                    .rev()
                    .map(|b| if prefix >> b & 1 == 1 { Fp3::ONE } else { Fp3::ZERO })
                    .collect();
                point.extend(&r[r.len() - low..]);
                form.extend(self.layout.project(
                    source,
                    &point,
                    s,
                    eq_index(&r[..r.len() - low], row / width),
                )?);
                row += width;
            }
            forms.push(form);
        }
        Ok(forms)
    }
}

// The same four-state carry/borrow DP as the existing Python input selector,
// with MSB-first points. No row-sized table or inverse at the verifier.
fn shifted_eq(input: &[Fp3], source: &[Fp3], offset: usize, count: usize) -> Fp3 {
    let mut state = [[Fp3::ZERO; 2]; 2];
    state[0][0] = Fp3::ONE;
    for i in 0..=source.len() {
        let mut next = [[Fp3::ZERO; 2]; 2];
        for carry in 0..2 {
            for borrow in 0..2 {
                for bit in 0..=usize::from(i < input.len()) {
                    let added = bit + ((offset >> i) & 1) + carry;
                    let source_bit = added & 1;
                    let a = if i < input.len() {
                        let r = input[input.len() - 1 - i];
                        if bit == 1 {
                            r
                        } else {
                            Fp3::ONE - r
                        }
                    } else {
                        Fp3::ONE
                    };
                    let b = if i < source.len() {
                        let r = source[source.len() - 1 - i];
                        if source_bit == 1 {
                            r
                        } else {
                            Fp3::ONE - r
                        }
                    } else if source_bit == 0 {
                        Fp3::ONE
                    } else {
                        Fp3::ZERO
                    };
                    let borrowed = usize::from(bit < ((count >> i) & 1) + borrow);
                    next[added >> 1][borrowed] += state[carry][borrow] * a * b;
                }
            }
        }
        state = next;
    }
    state[0][1]
}

impl<T> InputOpening<T> {
    /// Coefficient MLE for the ORIGINAL input claim at a producer point.
    /// The producer must still prove its i16 relation and this linear claim.
    pub fn form_at(&self, source_point: &[Fp3]) -> Result<Fp3, String> {
        let route = &self.route;
        let (rb, cb) = (bits(route.selected_rows), bits(route.columns));
        if self.point.len() != rb + cb || source_point.len() != bits(route.rows) + cb {
            return Err("Gemma P0 input/producer point axes differ".into());
        }
        let (r, s) = self.point.split_at(rb);
        let (u, v) = source_point.split_at(bits(route.rows));
        Ok(shifted_eq(r, u, route.row_offset, route.selected_rows)
            * shifted_eq(s, v, 0, route.columns))
    }
}

impl Plan {
    pub fn auxiliary_layout(&self) -> Result<Auxiliary, String> {
        let mut sources = Vec::new();
        let mut packed = 0usize;
        let mut add = |name, rows, cols| {
            sources.push(Source { name, rows, cols, packed_offset: packed });
            packed += rows * cols;
        };
        for (ordinal, c) in self.cohorts.iter().enumerate() {
            add(format!("C/{ordinal}"), c.rows, c.columns);
        }
        let routes: Vec<_> =
            (1..self.cohorts.len()).map(|i| self.input_route(i)).collect::<Result<_, _>>()?;
        let mut producers = BTreeMap::new();
        for route in &routes {
            let shape = (route.rows, route.columns);
            if *producers.entry(route.producer.clone()).or_insert(shape) != shape {
                return Err("Gemma auxiliary producer shape changes".into());
            }
        }
        let mut producer_index = BTreeMap::new();
        for ((layer, operation), (rows, cols)) in producers {
            let index = producer_index.len() + self.cohorts.len();
            add(
                format!(
                    "X/{}/{operation}",
                    layer.map_or_else(|| "global".into(), |l| l.to_string())
                ),
                rows,
                cols,
            );
            producer_index.insert((layer, operation), index);
        }
        let input_sources = routes.iter().map(|r| producer_index[&r.producer]).collect();
        let (tiles, live) = super::tiles(&sources);
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-P0-A-v1;raw-C;producer-output-X;field-cells;dyadic-MSB\0");
        digest.update(&self.layout_digest);
        for source in &sources {
            digest.update(&(source.name.len() as u64).to_le_bytes());
            digest.update(source.name.as_bytes());
            for value in [source.rows, source.cols, source.packed_offset] {
                digest.update(&(value as u64).to_le_bytes());
            }
        }
        Ok(Auxiliary {
            layout: Plan {
                sources,
                tiles,
                live,
                cohorts: Vec::new(),
                layout_digest: *digest.finalize().as_bytes(),
            },
            weight_layout: self.layout_digest,
            input_sources,
        })
    }

    pub fn input_route(&self, ordinal: usize) -> Result<InputRoute, String> {
        let c = self.cohorts.get(ordinal).ok_or("Gemma P0 cohort missing")?;
        let tokens = self.cohorts.first().ok_or("Gemma lookup cohort missing")?.rows;
        if c.kind == Kind::Lookup || !c.heads.is_power_of_two() || c.rows % c.heads != 0 {
            return Err("Gemma P0 input route is not a weighted producer".into());
        }
        if c.heads > 1 && !c.columns.is_power_of_two() {
            return Err("Gemma head reshape is not aligned".into());
        }
        let mut route = InputRoute {
            producer: c.producer.clone(),
            rows: tokens,
            columns: if c.kind == Kind::Matrix { c.inner } else { c.columns * c.heads },
            selected_rows: c.rows / c.heads,
            row_offset: 0,
        };
        if c.operation == "lm_head" {
            let final_norm = self
                .cohorts
                .iter()
                .find(|n| n.operation == "final_rms")
                .ok_or("Gemma final norm producer missing")?;
            route.producer = (final_norm.layer, final_norm.operation.clone());
            route.rows = final_norm.rows;
            route.row_offset =
                route.rows.checked_sub(c.rows).ok_or("Gemma head selects too many decisions")?;
        }
        if route.selected_rows == 0
            || route.row_offset + route.selected_rows > route.rows
            || bits(route.selected_rows) + bits(route.columns)
                != bits(c.rows) + bits(if c.kind == Kind::Matrix { c.inner } else { c.columns })
        {
            return Err("Gemma P0 input selection changes its padded domain".into());
        }
        Ok(route)
    }

    pub fn p0_required(&self) -> usize {
        1 + self
            .cohorts
            .iter()
            .map(|c| {
                1 + match c.kind {
                    Kind::Lookup => 0,
                    Kind::Matrix => p0::required(bits(c.inner), false),
                    Kind::Norm => p0::required(bits(c.columns), true),
                }
            })
            .sum::<usize>()
    }

    fn begin(&self, statement: &P0Statement<'_>, fs: &mut Fs) -> Result<Vec<Vec<Fp3>>, String> {
        if self.layout_digest == [0; 32]
            || statement.auxiliary_layout.weight_layout != self.layout_digest
            || statement.quantization == [0; 32]
            || !statement.attempt.valid()
            || statement.weights.num_roots() != 1
            || statement.auxiliary.num_roots() != 1
            || statement.weight_gamma.is_empty()
            || statement.auxiliary_gamma.is_empty()
            || self
                .cohorts
                .first()
                .is_none_or(|c| c.kind != Kind::Lookup || c.rows != statement.tokens.len())
        {
            return Err("Gemma P0 fixed source context differs".into());
        }
        let vocabulary = self.sources[self.cohorts[0].tensor].rows;
        if statement.tokens.iter().any(|&t| t as usize >= vocabulary) {
            return Err("Gemma P0 public token is outside vocabulary".into());
        }
        let mut wire =
            b"C71-Gemma-P0-v1;all-output-points-before-corrections;original-MACs".to_vec();
        for bytes in [statement.weight_gamma, statement.auxiliary_gamma] {
            wire.extend((bytes.len() as u64).to_le_bytes());
            wire.extend(bytes);
        }
        wire.extend(statement.weights.roots()[0]);
        wire.extend(statement.auxiliary.roots()[0]);
        wire.extend(self.layout_digest);
        wire.extend(statement.auxiliary_layout.layout.layout_digest);
        wire.extend(statement.quantization);
        wire.extend(statement.attempt.encode());
        wire.extend((statement.tokens.len() as u64).to_le_bytes());
        for t in statement.tokens {
            wire.extend(t.to_le_bytes());
        }
        fs.set_phase(0x800);
        fs.record(0x60, &wire);
        // One continuous FS block; root/layout/quantization and ALL tokens are
        // already fixed. This permits a common W pass for compact preparation.
        Ok(self
            .cohorts
            .iter()
            .map(|c| (0..bits(c.rows) + bits(c.columns)).map(|_| fs.fp3()).collect())
            .collect())
    }

    fn cohort_prefix(ordinal: usize, fs: &mut Fs) {
        fs.set_phase(0x801);
        fs.record(0x61, &(ordinal as u64).to_le_bytes());
    }

    /// `prepare` sees all output points together. Its values are untrusted:
    /// every C/X/W result must close at the returned original source MAC.
    /// ZK requires the honest preparer's NoPeek contract: use only the fixed
    /// source bodies and public points, never unused correlation rows.
    pub fn prove_p0<I: IntoIterator<Item = Compact>>(
        &self,
        statement: &P0Statement<'_>,
        prepare: impl FnOnce(&[Vec<Fp3>]) -> Result<I, String>,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(Proof, PendingP0<Auth>), String> {
        if correlations.len() < self.p0_required() {
            return Err("Gemma P0 prover capacity exhausted".into());
        }
        let points = self.begin(statement, fs)?;
        let mut compact = prepare(&points)?.into_iter();
        let (mut cuts, mut inputs, mut weights, mut weight_points, mut products, mut proofs) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (ordinal, (c, point)) in self.cohorts.iter().zip(points).enumerate() {
            let Compact { output, x, w } =
                compact.next().ok_or("Gemma P0 compact cohort missing")?;
            Self::cohort_prefix(ordinal, fs);
            let (wire, target) = range::authenticate([output], correlations);
            record_values(fs, 0x62, &wire);
            let (r, s) = point.split_at(bits(c.rows));
            if c.kind == Kind::Lookup {
                if !x.is_empty() || !w.is_empty() {
                    return Err("Gemma lookup has no private product vectors".into());
                }
                weight_points.push((r.to_vec(), s.to_vec()));
                weights.push(target[0]);
                proofs.push((wire[0], None));
            } else {
                let norm = c.kind == Kind::Norm;
                let width = 1 << bits(if norm { c.columns } else { c.inner });
                if x.len() != width || w.len() != width {
                    return Err("Gemma P0 compact source disagrees with the pinned cohort".into());
                }
                let (proof, inner, original) =
                    p0::prove(x, w, target[0], norm.then_some(s), fs, correlations)?;
                let mut input_point = r.to_vec();
                input_point.extend(&inner);
                inputs.push(InputOpening {
                    cohort: ordinal,
                    route: self.input_route(ordinal)?,
                    point: input_point,
                    original: original[0],
                });
                weight_points.push((if norm { Vec::new() } else { s.to_vec() }, inner));
                weights.push(original[1]);
                products.push(original);
                proofs.push((wire[0], Some(proof)));
            }
            cuts.push(CutOpening { cohort: ordinal, point, original: target[0] });
        }
        if compact.next().is_some() {
            return Err("Gemma P0 extra compact cohort".into());
        }
        let products = range::prove_products(&products, correlations.next().unwrap(), fs);
        let weight_forms = self.weight_forms(&weight_points, statement.tokens)?;
        Ok((Proof { cohorts: proofs, products }, PendingP0 { cuts, inputs, weight_forms, weights }))
    }

    pub fn verify_p0(
        &self,
        statement: &P0Statement<'_>,
        proof: &Proof,
        delta: Fp3,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Key>,
    ) -> Result<PendingP0<Key>, String> {
        if correlations.len() < self.p0_required()
            || proof.cohorts.len() != self.cohorts.len()
            || self
                .cohorts
                .iter()
                .zip(&proof.cohorts)
                .any(|(c, (_, p))| (c.kind == Kind::Lookup) != p.is_none())
        {
            return Err("Gemma P0 verifier capacity or cohort proof shape differs".into());
        }
        let points = self.begin(statement, fs)?;
        let (mut cuts, mut inputs, mut weights, mut weight_points, mut products) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (ordinal, ((c, point), (wire, proof))) in
            self.cohorts.iter().zip(points).zip(&proof.cohorts).enumerate()
        {
            Self::cohort_prefix(ordinal, fs);
            let target = range::correct([*wire], delta, correlations)[0];
            record_values(fs, 0x62, &[*wire]);
            let (r, s) = point.split_at(bits(c.rows));
            if let Some(proof) = proof {
                let norm = c.kind == Kind::Norm;
                let (inner, original) = p0::verify(
                    bits(if norm { c.columns } else { c.inner }),
                    target,
                    norm.then_some(s),
                    proof,
                    delta,
                    fs,
                    correlations,
                )?;
                let mut input_point = r.to_vec();
                input_point.extend(&inner);
                inputs.push(InputOpening {
                    cohort: ordinal,
                    route: self.input_route(ordinal)?,
                    point: input_point,
                    original: original[0],
                });
                weight_points.push((if norm { Vec::new() } else { s.to_vec() }, inner));
                weights.push(original[1]);
                products.push(original);
            } else {
                weight_points.push((r.to_vec(), s.to_vec()));
                weights.push(target);
            }
            cuts.push(CutOpening { cohort: ordinal, point, original: target });
        }
        range::verify_products(&products, correlations.next().unwrap(), proof.products, delta, fs)?;
        let weight_forms = self.weight_forms(&weight_points, statement.tokens)?;
        Ok(PendingP0 { cuts, inputs, weight_forms, weights })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{from_p3, gamma, linear, matrix_config, signed, MatrixRng, Model, E};
    use rand_010::{RngExt, SeedableRng};

    fn attempt() -> AttemptContext {
        AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        }
    }

    fn rows(count: usize, delta: Fp3) -> (Vec<Auth>, Vec<Key>) {
        let mut rng = MatrixRng::from_seed([121; 32]);
        let rows: Vec<_> = (0..count)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect();
        let keys = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
        (rows, keys)
    }

    #[test]
    fn c71_b12_gemma_caller_routes_all_pinned_cohorts_and_rejects_misassigned_proofs() {
        let plan = compile().unwrap();
        let roots = C61Commitment::new(vec![[17; 32]]);
        let tokens: Vec<_> = (0..150).collect();
        let auxiliary = plan.auxiliary_layout().unwrap();
        // Geometry/compact-reduction check only: these stand-in roots are
        // never accepted by a PCS, and no full Gemma witness is executed.
        let statement = P0Statement {
            weights: &roots,
            auxiliary: &roots,
            weight_gamma: b"D35 geometry only",
            auxiliary_gamma: b"pending auxiliary profile",
            auxiliary_layout: &auxiliary,
            quantization: [6; 32],
            attempt: attempt(),
            tokens: &tokens,
        };
        let delta = signed(31);
        assert_eq!(plan.p0_required(), 35_961);
        let (rows, keys) = rows(plan.p0_required(), delta);
        let mut rows = rows.into_iter();
        let start = || Fs::new(b"all pinned P0 compact kernels; no full Gemma execution", 25_893);
        let mut fs = start();
        let (mut proof, claims) = plan
            .prove_p0(
                &statement,
                |points| {
                    assert_eq!(points.len(), 773);
                    assert_eq!(points.iter().map(Vec::len).sum::<usize>(), 16_306);
                    Ok(plan.cohorts.iter().map(|c| {
                        let size = match c.kind {
                            Kind::Lookup => 0,
                            Kind::Matrix => 1 << bits(c.inner),
                            Kind::Norm => 1 << bits(c.columns),
                        };
                        Compact {
                            output: Fp3::ZERO,
                            x: vec![Fp3::ZERO; size],
                            w: vec![Fp3::ZERO; size],
                        }
                    }))
                },
                &mut fs,
                &mut rows,
            )
            .unwrap();
        assert!(rows.next().is_none());
        assert_eq!(fs.requests(), 25_893);
        let mut vf = start();
        let mut verifier_rows = keys.clone().into_iter();
        let checked =
            plan.verify_p0(&statement, &proof, delta, &mut vf, &mut verifier_rows).unwrap();
        assert!(verifier_rows.next().is_none());
        assert_eq!(fs.digest(), vf.digest());
        assert_eq!(
            (checked.cuts.len(), checked.inputs.len(), checked.weights.len()),
            (773, 772, 773)
        );
        assert_eq!(checked.weight_forms.iter().map(Vec::len).sum::<usize>(), 3606);
        assert_eq!(auxiliary.layout.sources.len(), 1375);
        assert_eq!(auxiliary.layout.live, 1_653_698_048);
        let aux_forms = auxiliary.forms(&plan, &checked).unwrap();
        assert_eq!(aux_forms.len(), 1545);
        assert_eq!(aux_forms.iter().map(Vec::len).sum::<usize>(), 14909);
        let bytes = plan.auxiliary_bytes().unwrap();
        assert_eq!(bytes.live, 6_525_586_944);
        let (byte_forms, shifts) = bytes.forms(&plan, &checked).unwrap();
        assert_eq!((byte_forms.len(), shifts.len()), (1545, 1545));
        assert_eq!(byte_forms.iter().map(Vec::len).sum::<usize>(), 18472);
        let mut rne_views = 0;
        let mut rne_cubes = 0;
        let mut largest = 0;
        for (ordinal, c) in plan.cohorts.iter().enumerate() {
            if c.kind != Kind::Matrix {
                continue;
            }
            let (_, shape) = bytes.rne_view(&plan, ordinal).unwrap();
            assert_eq!(shape, [c.rows, c.columns]);
            let b = bits(c.rows) + bits(c.columns);
            largest = largest.max(b);
            let point = vec![signed(2); b + 3];
            rne_cubes += bytes.rne_form(&plan, ordinal, &point).unwrap().len();
            rne_views += 1;
        }
        assert_eq!(rne_views, 411);
        assert_eq!((rne_cubes, largest), (7126, 24));
        assert!(18472 + rne_cubes + 34 < 32768);
        let requests = bytes.rne_requests(&plan, &checked).unwrap();
        assert_eq!(requests.len(), 240);
        let mut requested_cubes = 0;
        let mut requested_bits = 0;
        let mut counts = BTreeMap::new();
        for request in &requests {
            let c = &plan.cohorts[request.source];
            *counts.entry(c.operation.as_str()).or_insert(0) += 1;
            assert_eq!(request.original, checked.inputs[request.consumer - 1].original);
            assert_eq!(request.point, checked.inputs[request.consumer - 1].point);
            let b = bits(c.rows) + bits(c.columns);
            requested_bits += b;
            requested_cubes +=
                bytes.rne_form(&plan, request.source, &vec![signed(2); b + 3]).unwrap().len();
        }
        assert_eq!(
            counts,
            BTreeMap::from([("q_proj", 60), ("k_proj", 60), ("o_proj", 60), ("down_proj", 60)])
        );
        assert_eq!((requested_cubes, requested_bits), (3840, 4980));
        let mut producers = std::collections::BTreeSet::new();
        for (p, v) in claims.inputs.iter().zip(&checked.inputs) {
            assert_eq!(p.cohort, v.cohort);
            assert_eq!(p.point, v.point);
            assert_eq!(p.original.m + delta * p.original.x, v.original.k);
            producers.insert(v.route.producer.clone());
            let c = &plan.cohorts[v.cohort];
            if c.operation == "q_norm" && c.layer == Some(5) {
                assert_eq!(
                    (v.route.rows, v.route.columns, v.route.selected_rows),
                    (150, 16_384, 150)
                );
            }
        }
        assert_eq!(producers.len(), 602);
        let final_norm = &checked.inputs[770];
        assert_eq!(
            (final_norm.route.rows, final_norm.route.selected_rows, final_norm.route.row_offset),
            (150, 149, 0)
        );
        let head = checked.inputs.last().unwrap();
        assert_eq!(
            (head.route.rows, head.route.selected_rows, head.route.row_offset),
            (149, 50, 99)
        );
        assert_eq!(head.route.producer, (None, "final_rms".into()));
        // Same-shape matrix proofs cannot be interchanged under original rows.
        let a = plan.cohorts.iter().position(|c| c.operation == "gate_proj").unwrap();
        let b = plan.cohorts.iter().position(|c| c.operation == "up_proj").unwrap();
        proof.cohorts.swap(a, b);
        assert!(plan
            .verify_p0(&statement, &proof, delta, &mut start(), &mut keys.clone().into_iter())
            .is_err());
        proof.cohorts.swap(a, b);
        proof.cohorts[0].1 = proof.cohorts[a].1.take();
        let mut malformed_rows = keys.into_iter();
        assert!(plan
            .verify_p0(&statement, &proof, delta, &mut start(), &mut malformed_rows)
            .is_err());
        assert_eq!(malformed_rows.len(), plan.p0_required());
    }

    fn virtual_model(plan: &Plan, packed: &[i16]) -> Model {
        let mut values = vec![0; 1024];
        for (i, v) in values.iter_mut().enumerate().take(plan.live) {
            *v = packed[plan.virtual_to_packed(i).unwrap().unwrap()];
        }
        Model::new(32, values).unwrap()
    }

    fn physical_point(row: usize, rows: usize) -> Vec<Fp3> {
        (0..bits(rows))
            .rev()
            .map(|b| if row >> b & 1 == 1 { Fp3::ONE } else { Fp3::ZERO })
            .collect()
    }

    fn literal_auxiliary_forms<T>(
        plan: &Plan,
        auxiliary: &Auxiliary,
        pending: &PendingP0<T>,
    ) -> Vec<Vec<Cube>> {
        let mut forms: Vec<_> = pending
            .cuts
            .iter()
            .map(|c| {
                let (r, s) = c.point.split_at(bits(plan.cohorts[c.cohort].rows));
                auxiliary.layout.project(c.cohort, r, s, Fp3::ONE).unwrap()
            })
            .collect();
        for (index, claim) in pending.inputs.iter().enumerate() {
            let source = auxiliary.input_sources[index];
            let (r, s) = claim.point.split_at(bits(claim.route.selected_rows));
            let mut form = Vec::new();
            for row in 0..claim.route.selected_rows {
                form.extend(
                    auxiliary
                        .layout
                        .project(
                            source,
                            &physical_point(row + claim.route.row_offset, claim.route.rows),
                            s,
                            eq_index(r, row),
                        )
                        .unwrap(),
                );
            }
            // Compare the succinct selector at a non-Boolean source point
            // with the literal selected physical rows/columns.
            let u = vec![signed(2); bits(claim.route.rows)];
            let v = vec![signed(3); bits(claim.route.columns)];
            let expected = (0..claim.route.selected_rows).fold(Fp3::ZERO, |z, row| {
                z + eq_index(r, row) * eq_index(&u, row + claim.route.row_offset)
            }) * (0..claim.route.columns)
                .fold(Fp3::ZERO, |z, col| z + eq_index(s, col) * eq_index(&v, col));
            let mut point = u;
            point.extend(v);
            assert_eq!(claim.form_at(&point).unwrap(), expected);
            assert!(claim.form_at(&[]).is_err());
            forms.push(form);
        }
        forms
    }

    #[test]
    fn c71_b12_gemma_caller_closes_selected_inputs_and_tied_head_in_one_ranged_w() {
        let sources = vec![
            Source { name: "embedding".into(), rows: 4, cols: 2, packed_offset: 0 },
            Source { name: "projection".into(), rows: 4, cols: 2, packed_offset: 8 },
            Source { name: "q_norm".into(), rows: 1, cols: 2, packed_offset: 16 },
            Source { name: "final_norm".into(), rows: 1, cols: 2, packed_offset: 18 },
        ];
        let (tiles, live) = super::tiles(&sources);
        let cohort =
            |operation: &str, tensor, kind, rows, columns, inner, heads, producer: &str| Cohort {
                layer: None,
                operation: operation.into(),
                tensor,
                kind,
                rows,
                columns,
                inner,
                heads,
                producer: (None, producer.into()),
                members: Vec::new(),
                cut_byte_offset: 0,
            };
        let plan = Plan {
            sources,
            tiles,
            live,
            layout_digest: [11; 32],
            cohorts: vec![
                cohort("embedding_lookup", 0, Kind::Lookup, 6, 2, 0, 1, "token_input"),
                cohort("q_proj", 1, Kind::Matrix, 6, 4, 2, 1, "embedding_lookup"),
                cohort("q_norm", 2, Kind::Norm, 12, 2, 0, 2, "q_proj"),
                cohort("final_rms", 3, Kind::Norm, 5, 2, 0, 1, "embedding_lookup"),
                cohort("lm_head", 0, Kind::Matrix, 2, 4, 2, 1, "last_row_select"),
            ],
        };
        let packed = vec![1, -2, 3, 1, -1, 2, 2, -3, 2, 1, 1, -2, -1, 1, 2, -1, 2, -1, 3, 2];
        let tokens = [0, 1, 2, 3, 1, 2];
        // A real tiny RAW producer graph; these products are not full RMS.
        let lookup: Vec<i16> = tokens
            .iter()
            .flat_map(|&t| packed[2 * t as usize..2 * t as usize + 2].iter().copied())
            .collect();
        let mut projection = vec![0; 24];
        for row in 0..6 {
            for col in 0..4 {
                projection[row * 4 + col] =
                    (0..2).map(|k| lookup[row * 2 + k] * packed[8 + col * 2 + k]).sum();
            }
        }
        let norm: Vec<_> =
            projection.iter().enumerate().map(|(i, &x)| x * packed[16 + i % 2]).collect();
        let final_norm: Vec<_> =
            lookup[..10].iter().enumerate().map(|(i, &x)| x * packed[18 + i % 2]).collect();
        let mut head = vec![0; 8];
        for row in 0..2 {
            for col in 0..4 {
                head[row * 4 + col] =
                    (0..2).map(|k| final_norm[(3 + row) * 2 + k] * packed[col * 2 + k]).sum();
            }
        }
        let cuts = [lookup, projection, norm, final_norm, head];
        let auxiliary = plan.auxiliary_layout().unwrap();
        let mut auxiliary_packed = vec![0; auxiliary.layout.live];
        for (c, values) in auxiliary.layout.sources.iter().zip(&cuts) {
            auxiliary_packed[c.packed_offset..c.packed_offset + values.len()]
                .copy_from_slice(values);
        }
        for (index, &source) in auxiliary.input_sources.iter().enumerate() {
            let route = plan.input_route(index + 1).unwrap();
            let producer = plan
                .cohorts
                .iter()
                .position(|c| (c.layer, c.operation.clone()) == route.producer)
                .unwrap();
            let values = &cuts[producer];
            let offset = auxiliary.layout.sources[source].packed_offset;
            auxiliary_packed[offset..offset + values.len()].copy_from_slice(values);
        }
        let w_model = virtual_model(&plan, &packed);
        let a_model = virtual_model(&auxiliary.layout, &auxiliary_packed);
        let profile = gamma(&matrix_config(32).unwrap());
        let statement = P0Statement {
            weights: &w_model.root,
            auxiliary: &a_model.root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &auxiliary,
            quantization: [13; 32],
            attempt: attempt(),
            tokens: &tokens,
        };
        let start = || Fs::new(b"tiny original-source DAG with tied embedding/head", 100_000);
        let delta = signed(31);
        let count = range::required(10, 7) + plan.p0_required() + 64;
        assert_eq!(count, 365);
        let (rows, keys) = rows(count, delta);
        let mut rows = rows.into_iter();
        let mut fs = start();
        let (proof, pending) = plan
            .prove_p0(
                &statement,
                |points| {
                    Ok(plan
                        .cohorts
                        .iter()
                        .enumerate()
                        .map(|(ordinal, c)| {
                            let (r, s) = points[ordinal].split_at(bits(c.rows));
                            let output =
                                cuts[ordinal].iter().enumerate().fold(Fp3::ZERO, |z, (i, &v)| {
                                    z + eq_index(r, i / c.columns)
                                        * eq_index(s, i % c.columns)
                                        * signed(i64::from(v))
                                });
                            if c.kind == Kind::Lookup {
                                return Compact { output, x: Vec::new(), w: Vec::new() };
                            }
                            let route = plan.input_route(ordinal).unwrap();
                            let source = plan
                                .cohorts
                                .iter()
                                .position(|c| (c.layer, c.operation.clone()) == route.producer)
                                .unwrap();
                            let inner = if c.kind == Kind::Matrix { c.inner } else { c.columns };
                            let mut x = vec![Fp3::ZERO; inner.next_power_of_two()];
                            let mut w = x.clone();
                            for k in 0..inner {
                                for row in 0..c.rows {
                                    x[k] += eq_index(r, row)
                                        * signed(i64::from(
                                            cuts[source][route.row_offset * route.columns
                                                + row * inner
                                                + k],
                                        ));
                                }
                                let source = &plan.sources[c.tensor];
                                for j in 0..source.rows {
                                    let coefficient = if c.kind == Kind::Norm {
                                        Fp3::ONE
                                    } else {
                                        eq_index(s, j)
                                    };
                                    w[k] += coefficient
                                        * signed(i64::from(
                                            packed[source.packed_offset + j * source.cols + k],
                                        ));
                                }
                            }
                            Compact { output, x, w }
                        })
                        .collect::<Vec<_>>())
                },
                &mut fs,
                &mut rows,
            )
            .unwrap();
        let (range_proof, range_forms, range_targets) =
            range::prove(&w_model, attempt(), plan.layout_digest, plan.live, 7, &mut fs, &mut rows)
                .unwrap();
        let mut wf = pending.weight_forms.clone();
        wf.extend(range_forms);
        let mut wt = pending.weights.clone();
        wt.extend(range_targets);
        let af = auxiliary.forms(&plan, &pending).unwrap();
        let literal = literal_auxiliary_forms(&plan, &auxiliary, &pending);
        let expand = |form: &[Cube]| {
            let mut values = vec![Fp3::ZERO; 1024];
            for cube in form {
                for (i, w) in crate::c71_matrix::eq(&cube.point).into_iter().enumerate() {
                    values[cube.offset + i] += cube.coefficient * w;
                }
            }
            values
        };
        for (a, b) in af.iter().zip(literal) {
            assert_eq!(expand(a), expand(&b));
        }
        let at: Vec<_> = pending
            .cuts
            .iter()
            .map(|c| c.original)
            .chain(pending.inputs.iter().map(|c| c.original))
            .collect();
        let (w_proof, _) =
            linear::prove(&w_model, attempt(), plan.layout_digest, &wf, &wt, &mut fs, &mut rows)
                .unwrap();
        let (a_proof, digest) = linear::prove(
            &a_model,
            attempt(),
            auxiliary.layout.layout_digest,
            &af,
            &at,
            &mut fs,
            &mut rows,
        )
        .unwrap();
        assert!(rows.next().is_none());
        let verify = |wrong_head_rows: bool| -> Result<_, String> {
            let mut fs = start();
            let mut rows = keys.clone().into_iter();
            let mut pending = plan.verify_p0(&statement, &proof, delta, &mut fs, &mut rows)?;
            let (forms, targets) = range::verify(
                32,
                &w_model.root,
                attempt(),
                plan.layout_digest,
                plan.live,
                7,
                &range_proof,
                delta,
                &mut fs,
                &mut rows,
            )?;
            pending.weight_forms.extend(forms);
            pending.weights.extend(targets);
            linear::verify(
                32,
                &w_model.root,
                attempt(),
                plan.layout_digest,
                &pending.weight_forms,
                &pending.weights,
                &w_proof,
                delta,
                &mut fs,
                &mut rows,
            )?;
            if wrong_head_rows {
                pending.inputs.last_mut().unwrap().route.row_offset = 0;
            }
            let canonical = auxiliary.forms(&plan, &pending)?;
            for (a, b) in canonical.iter().zip(&af) {
                assert_eq!(expand(a), expand(b));
            }
            let forms = if wrong_head_rows {
                literal_auxiliary_forms(&plan, &auxiliary, &pending)
            } else {
                canonical
            };
            let targets: Vec<_> = pending
                .cuts
                .iter()
                .map(|c| c.original)
                .chain(pending.inputs.iter().map(|c| c.original))
                .collect();
            let digest = linear::verify(
                32,
                &a_model.root,
                attempt(),
                auxiliary.layout.layout_digest,
                &forms,
                &targets,
                &a_proof,
                delta,
                &mut fs,
                &mut rows,
            )?;
            assert!(rows.next().is_none());
            Ok(digest)
        };
        assert_eq!(verify(false).unwrap(), digest);
        assert!(verify(true).is_err());
        // Context changes move ALL output challenges, before any correction.
        let mut changed = P0Statement { quantization: [14; 32], ..statement };
        assert!(plan
            .verify_p0(&changed, &proof, delta, &mut start(), &mut keys.clone().into_iter())
            .is_err());
        changed.quantization = [0; 32];
        let mut unopened = keys.into_iter();
        assert!(plan.verify_p0(&changed, &proof, delta, &mut start(), &mut unopened).is_err());
        assert_eq!(unopened.len(), count);
        // Boundary identities include the empty selection and complete domain,
        // with arbitrary non-Boolean/degenerate coordinates.
        for count in 0..=4 {
            for offset in 0..=8 - count {
                let r = [Fp3::ZERO, signed(2)];
                let s = [Fp3::ONE, signed(3), signed(4)];
                let exact = (0..count)
                    .fold(Fp3::ZERO, |z, i| z + eq_index(&r, i) * eq_index(&s, offset + i));
                assert_eq!(shifted_eq(&r, &s, offset, count), exact);
            }
        }
    }
}
