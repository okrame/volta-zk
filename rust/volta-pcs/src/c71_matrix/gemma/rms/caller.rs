//! Bounded canonical RMS/statistic dispatcher. Public parameters are the
//! verifier's fixed profile, not prover-chosen calibration. Original source
//! obligations still join P0/RNE in ONE auxiliary PCS.

use super::*;

component_wire!(Proof { statistics, products, joint });
use crate::c71_matrix::gemma::caller::P0Statement;
use crate::c71_matrix::rms::{self as kernel, gkr, statistic};
use crate::c71_matrix::*;

pub(in crate::c71_matrix) struct Proof {
    statistics: Vec<statistic::Proof>,
    products: [Fp3; 2],
    joint: gkr::Proof,
}

pub(in crate::c71_matrix) struct Pending<T> {
    pub statistics: Vec<statistic::Pending<T>>,
    pub byte_point: Vec<Fp3>,
    pub byte: T,
}

pub(in crate::c71_matrix) struct VRequest<T> {
    pub norm: usize,
    pub source: usize,
    pub view: [u8; 32],
    pub shape: [usize; 2],
    pub point: Vec<Fp3>,
    pub original: T,
}

/// Original RMS endpoint bytes retained only through the joint RMS proof.
/// Products and outputs are cell-major; each statistic is stored once per
/// selected row rather than broadcast over that row's columns.
struct CompactFrames<'a> {
    sources: &'a Sources,
    payload: Vec<u8>,
    norms: Vec<CompactNorm>,
    source_byte_reads: u64,
}

#[derive(Clone, Copy)]
struct CompactNorm {
    product: usize,
    statistic: usize,
    output: usize,
    cells: usize,
    pbytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactFrameWorkspace {
    payload_len: usize,
    payload_capacity: usize,
    metadata_len: usize,
    metadata_capacity: usize,
    retained_capacity_bytes: usize,
    build_peak_owned_bytes: usize,
    source_byte_reads: u64,
}

impl<'a> CompactFrames<'a> {
    fn build(
        sources: &'a Sources,
        mut read: impl FnMut(usize, usize, usize, usize) -> Result<u8, String>,
    ) -> Result<Self, String> {
        let mut payload_len = 0usize;
        for norm in &sources.norms {
            let pbytes = if norm.cohort.is_some() { 4 } else { 2 };
            payload_len = payload_len
                .checked_add(
                    norm.rows
                        .checked_mul(norm.columns)
                        .ok_or("RMS frame size overflow")?
                        .checked_mul(pbytes + 2)
                        .ok_or("RMS frame size overflow")?,
                )
                .and_then(|n| n.checked_add(norm.rows.checked_mul(6)?))
                .ok_or("RMS frame size overflow")?;
        }
        let metadata = sources
            .norms
            .len()
            .checked_mul(core::mem::size_of::<CompactNorm>())
            .ok_or("RMS frame metadata overflow")?;
        if payload_len.checked_add(metadata).filter(|&n| n <= 2usize << 30).is_none() {
            return Err("RMS compact frames exceed reused 2 GiB slot".into());
        }
        let mut payload = Vec::with_capacity(payload_len);
        let mut norms = Vec::with_capacity(sources.norms.len());
        for norm in &sources.norms {
            let pbytes = if norm.cohort.is_some() { 4 } else { 2 };
            let cells = norm.rows.checked_mul(norm.columns).ok_or("RMS frame size overflow")?;
            let product = payload.len();
            for row in 0..norm.rows {
                for col in 0..norm.columns {
                    let (r, c) = sources.position(norm.product, norm, row, col);
                    for byte in 0..pbytes {
                        payload.push(read(norm.product, r, c, byte)?);
                    }
                }
            }
            let statistic = payload.len();
            for row in 0..norm.rows {
                for byte in 0..6 {
                    payload.push(read(norm.statistic, row, 0, byte)?);
                }
            }
            let output = payload.len();
            for row in 0..norm.rows {
                for col in 0..norm.columns {
                    let (r, c) = sources.position(norm.output, norm, row, col);
                    for byte in 0..2 {
                        payload.push(read(norm.output, r, c, byte)?);
                    }
                }
            }
            norms.push(CompactNorm { product, statistic, output, cells, pbytes });
        }
        if payload.len() != payload_len {
            return Err("RMS compact frame payload differs".into());
        }
        Ok(Self { sources, source_byte_reads: payload_len as u64, payload, norms })
    }

    /// Uses the canonical tile lookup in `Sources::cell`; padded cells remain
    /// the all-zero frame and no N-entry assignment/index table is retained.
    fn frame(&self, cell: usize) -> Result<[u8; 12], String> {
        let sources = self.sources;
        let mut frame = [0u8; 12];
        let Some((ordinal, row, col)) = sources.cell(cell)? else {
            return Ok(frame);
        };
        let norm = sources.norms.get(ordinal).ok_or("RMS compact norm missing")?;
        let compact = self.norms.get(ordinal).ok_or("RMS compact frame layout missing")?;
        let local = row
            .checked_mul(norm.columns)
            .and_then(|v| v.checked_add(col))
            .filter(|&v| v < compact.cells)
            .ok_or("RMS compact frame coordinate differs")?;
        let p = compact.product + local * compact.pbytes;
        frame[..compact.pbytes].copy_from_slice(&self.payload[p..p + compact.pbytes]);
        let s = compact.statistic + row * 6;
        frame[compact.pbytes..compact.pbytes + 6].copy_from_slice(&self.payload[s..s + 6]);
        let y = compact.output + local * 2;
        frame[compact.pbytes + 6..compact.pbytes + 8].copy_from_slice(&self.payload[y..y + 2]);
        Ok(frame)
    }

    fn workspace(&self) -> CompactFrameWorkspace {
        let metadata_len = self.norms.len() * core::mem::size_of::<CompactNorm>();
        let metadata_capacity = self.norms.capacity() * core::mem::size_of::<CompactNorm>();
        let retained_capacity_bytes = self.payload.capacity() + metadata_capacity;
        CompactFrameWorkspace {
            payload_len: self.payload.len(),
            payload_capacity: self.payload.capacity(),
            metadata_len,
            metadata_capacity,
            retained_capacity_bytes,
            // Construction has no second heap payload or N-entry index. This
            // excludes Vec allocator headers/rounding and the caller's reader.
            build_peak_owned_bytes: retained_capacity_bytes,
            source_byte_reads: self.source_byte_reads,
        }
    }
}

impl Sources {
    fn statistic_statement<'a>(
        &'a self,
        s: &'a P0Statement<'a>,
        ordinal: usize,
    ) -> statistic::Statement<'a> {
        let n = &self.norms[ordinal];
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-RMS-statistic-view-v1\0");
        digest.update(&self.view);
        digest.update(&(ordinal as u64).to_le_bytes());
        statistic::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: *digest.finalize().as_bytes(),
            attempt: s.attempt,
            shape: [n.rows, n.columns],
        }
    }

    fn prepare(
        &self,
        s: &P0Statement<'_>,
        parameters: &[[i32; 3]],
    ) -> Result<(Vec<kernel::Circuit>, Vec<usize>, usize), String> {
        if self.cells == 0
            || self.cells > 1 << 29
            || self.norms.is_empty()
            || self.norms.len() > 421
            || parameters.len() != self.norms.len()
            || s.auxiliary_layout.layout.layout_digest != self.bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != self.bytes.scalar.weight_layout
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.quantization == [0; 32]
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || !s.attempt.valid()
        {
            return Err("RMS dispatcher fixed context or D29 cell envelope differs".into());
        }
        let mut indices = BTreeMap::new();
        let mut keys = Vec::new();
        let mut profile = Vec::new();
        for (n, &[x, w, y]) in self.norms.iter().zip(parameters) {
            let key = (n.columns, x, w, y, n.cohort.is_some());
            let next = indices.len();
            let index = *indices.entry(key).or_insert(next);
            if index == keys.len() {
                keys.push(key);
            }
            profile.push(index);
        }
        let programs = keys
            .into_iter()
            .map(|(d, x, w, y, weighted)| kernel::compile(d, x, w, y, weighted))
            .collect::<Result<Vec<_>, _>>()?;
        let mut count = gkr::required(&programs, bits(self.cells))? + 1;
        for n in 0..self.norms.len() {
            count += self.statistic_statement(s, n).required()?;
        }
        Ok((programs, profile, count))
    }

    /// Public metadata only. Counts the current source-level algorithm before
    /// compiler simplification; these are neither instruction nor time lowers.
    #[cfg(test)]
    pub(in crate::c71_matrix) fn work_census(
        &self,
        s: &P0Statement<'_>,
        parameters: &[[i32; 3]],
    ) -> Result<serde_json::Value, String> {
        let (programs, profiles, _) = self.prepare(s, parameters)?;
        let mut assigned = vec![0u64; programs.len()];
        for (norm, &profile) in self.norms.iter().zip(&profiles) {
            assigned[profile] += (norm.rows * norm.columns) as u64;
        }
        assert_eq!(assigned.iter().sum::<u64>(), self.cells as u64);
        // Check the original tile mapping at each boundary, without N entries.
        for tile in &self.tiles {
            for i in [tile.offset, tile.offset + tile.rows * tile.cols - 1] {
                let (norm, _, _) = self.cell(i)?.ok_or("missing live RMS cell")?;
                assert_eq!(profiles[norm], profiles[tile.tensor]);
            }
        }
        let mut report = gkr::work_census(&programs, &assigned, bits(self.cells))?;
        report["profile_digest"] = serde_json::json!(s.quantization);
        report["RMS_view"] = serde_json::json!(self.view);
        let support: Vec<Vec<usize>> = (0..bits(self.cells))
            .map(|round| {
                let half = self.cells.next_power_of_two() >> (round + 1);
                let mut intervals = vec![Vec::<(usize, usize)>::new(); programs.len()];
                for tile in &self.tiles {
                    let p = profiles[tile.tensor];
                    let size = tile.rows * tile.cols;
                    let begin = tile.offset % half;
                    if size >= half {
                        intervals[p].push((0, half));
                    } else if begin + size <= half {
                        intervals[p].push((begin, begin + size));
                    } else {
                        intervals[p].push((begin, half));
                        intervals[p].push((0, begin + size - half));
                    }
                }
                intervals
                    .into_iter()
                    .map(|mut spans| {
                        spans.sort_unstable();
                        let (mut end, mut count) = (0, 0);
                        for (a, b) in spans {
                            if b > end {
                                count += b - a.max(end);
                                end = b;
                            }
                        }
                        count
                    })
                    .collect()
            })
            .collect();
        report["public_supported_pairs_by_round_and_profile"] = serde_json::json!(support);
        let statistics: usize = self.norms.iter().map(|norm| norm.rows * 6).sum();
        let products: usize = self
            .norms
            .iter()
            .map(|norm| norm.rows * norm.columns * if norm.cohort.is_some() { 4 } else { 2 })
            .sum();
        let checkpoint = products + 2 * self.cells + statistics;
        report["compact_original_PYS_candidate"] = serde_json::json!({
            "product_bytes":products, "output_bytes":2*self.cells,
            "shared_statistic_s48_bytes":statistics, "payload_bytes":checkpoint,
            "metadata_bytes":self.norms.len()*core::mem::size_of::<CompactNorm>(),
            "payload_and_metadata_bytes":checkpoint+self.norms.len()*core::mem::size_of::<CompactNorm>(),
            "range_slot_bytes":2usize<<30,
            "payload_fits_reused_range_slot":checkpoint <= 2usize<<30,
            "construction_before_RMS_after_A_root_is_proof_only":true,
            "release_after_original_byte_endpoint_before_RNE_and_range":true,
            "physical_peak_complete":false,
        });
        Ok(report)
    }

    pub fn rms_required(
        &self,
        s: &P0Statement<'_>,
        parameters: &[[i32; 3]],
    ) -> Result<usize, String> {
        self.prepare(s, parameters).map(|(_, _, count)| count)
    }

    fn bind(&self, s: &P0Statement<'_>, parameters: &[[i32; 3]], fs: &mut Fs) {
        let mut bytes=b"C71-canonical-RMS-B12-v1;all-statistics;shared-product-batch;joint-predicate;original-A\0".to_vec();
        bytes.extend(s.weights.roots()[0]);
        bytes.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            bytes.extend((gamma.len() as u64).to_le_bytes());
            bytes.extend(gamma);
        }
        bytes.extend(self.bytes.layout_digest);
        bytes.extend(self.view);
        bytes.extend(s.quantization);
        bytes.extend(s.attempt.encode());
        bytes.extend((parameters.len() as u64).to_le_bytes());
        for p in parameters {
            for e in p {
                bytes.extend(e.to_le_bytes());
            }
        }
        fs.set_phase(0xc00);
        fs.record(0xa0, &bytes);
    }

    fn position(&self, source: usize, n: &Norm, row: usize, col: usize) -> (usize, usize) {
        let columns = self.bytes.scalar.layout.sources[source].cols;
        let index = row * n.columns + col;
        (index / columns, index % columns)
    }

    /// Reads biased bytes from the SAME source IDs/coordinates as the PCS
    /// view. This bounded in-memory seam is not a full Gemma file reader.
    pub fn frame(
        &self,
        cell: usize,
        read: impl Fn(usize, usize, usize, usize) -> u8,
    ) -> Result<[u8; 12], String> {
        let mut frame = [0; 12];
        let Some((ordinal, row, col)) = self.cell(cell)? else {
            return Ok(frame);
        };
        let n = &self.norms[ordinal];
        let pbytes = if n.cohort.is_some() { 4 } else { 2 };
        for (source, first, width) in
            [(n.product, 0, pbytes), (n.statistic, pbytes, 6), (n.output, pbytes + 6, 2)]
        {
            let (r, c) =
                if source == n.statistic { (row, 0) } else { self.position(source, n, row, col) };
            for b in 0..width {
                frame[first + b] = read(source, r, c, b);
            }
        }
        Ok(frame)
    }

    pub fn prove_rms(
        &self,
        s: &P0Statement<'_>,
        parameters: &[[i32; 3]],
        read: impl Fn(usize, usize, usize, usize) -> u8,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(Proof, Pending<Auth>), String> {
        let (programs, profiles, count) = self.prepare(s, parameters)?;
        if correlations.len() < count {
            return Err("RMS dispatcher prover capacity exhausted".into());
        }
        let assignment = |cell| {
            self.cell(cell)
                .expect("validated RMS padded cell domain")
                .map(|(norm, _, _)| profiles[norm])
        };
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        self.bind(s, parameters, fs);
        let (mut statistics, mut pending, mut triples) = (Vec::new(), Vec::new(), Vec::new());
        for (ordinal, n) in self.norms.iter().enumerate() {
            let (proof, original) = statistic::prove(
                &self.statistic_statement(s, ordinal),
                |row, col| {
                    let (r, c) = self.position(n.input, n, row, col);
                    let biased =
                        u16::from_le_bytes([read(n.input, r, c, 0), read(n.input, r, c, 1)]);
                    (i32::from(biased) - 32768) as i16
                },
                |row| std::array::from_fn(|b| read(n.statistic, row, 0, b)),
                fs,
                &mut rows,
            )?;
            triples.push(original.inputs);
            pending.push(original);
            statistics.push(proof);
        }
        let products = range::prove_products(&triples, rows.next().unwrap(), fs);
        // Materialize each original P/Y cell byte once and each row statistic
        // once. Joint GKR replays this bounded checkpoint; it never re-reads
        // the numeric producer or expands padding into N frame rows.
        let frames = CompactFrames::build(self, |source, row, col, byte| {
            Ok(read(source, row, col, byte))
        })?;
        let gs = gkr::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.view,
            attempt: s.attempt,
            programs: &programs,
            assignments: gkr::Assignments::new(self.cells.next_power_of_two(), &assignment),
        };
        let (joint, byte_point, byte) =
            gkr::prove(&gs, |i| frames.frame(i).unwrap(), fs, &mut rows)?;
        debug_assert!(rows.next().is_none());
        Ok((
            Proof { statistics, products, joint },
            Pending { statistics: pending, byte_point, byte },
        ))
    }

    pub fn verify_rms(
        &self,
        s: &P0Statement<'_>,
        parameters: &[[i32; 3]],
        proof: &Proof,
        delta: Fp3,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Key>,
    ) -> Result<Pending<Key>, String> {
        let (programs, profiles, count) = self.prepare(s, parameters)?;
        if correlations.len() < count || proof.statistics.len() != self.norms.len() {
            return Err("RMS dispatcher verifier shape or capacity differs".into());
        }
        let assignment = |cell| {
            self.cell(cell)
                .expect("validated RMS padded cell domain")
                .map(|(norm, _, _)| profiles[norm])
        };
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        self.bind(s, parameters, fs);
        let (mut pending, mut triples) = (Vec::new(), Vec::new());
        for (ordinal, proof) in proof.statistics.iter().enumerate() {
            let original = statistic::verify(
                &self.statistic_statement(s, ordinal),
                proof,
                delta,
                fs,
                &mut rows,
            )?;
            triples.push(original.inputs);
            pending.push(original);
        }
        range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
        let gs = gkr::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.view,
            attempt: s.attempt,
            programs: &programs,
            assignments: gkr::Assignments::new(self.cells.next_power_of_two(), &assignment),
        };
        let (byte_point, byte) = gkr::verify(&gs, &proof.joint, delta, fs, &mut rows)?;
        debug_assert!(rows.next().is_none());
        Ok(Pending { statistics: pending, byte_point, byte })
    }

    pub fn rms_forms<T: Copy>(
        &self,
        pending: &Pending<T>,
    ) -> Result<(Vec<Vec<Cube>>, Vec<Fp3>, Vec<T>), String> {
        if pending.statistics.len() != self.norms.len() {
            return Err("RMS original statistic count differs".into());
        }
        let (mut forms, mut shifts, mut targets) = (Vec::new(), Vec::new(), Vec::new());
        for (i, p) in pending.statistics.iter().enumerate() {
            let (form, shift) = self.statistic_form(i, &p.statistic_point)?;
            forms.push(form);
            shifts.push(shift);
            targets.push(p.statistic);
            for x in &p.inputs[..2] {
                let (form, shift) = self.input_form(i, &p.input_point)?;
                forms.push(form);
                shifts.push(shift);
                targets.push(*x);
            }
        }
        forms.push(self.form(&pending.byte_point)?);
        shifts.push(Fp3::ZERO);
        targets.push(pending.byte);
        Ok((forms, shifts, targets))
    }

    /// Local V has no weighted P0 consumer. Its statistic's ORIGINAL X
    /// endpoint supplies the missing RNE demand; global V already aliases K.
    pub fn local_v_rne_requests<T: Copy>(
        &self,
        plan: &Plan,
        pending: &Pending<T>,
    ) -> Result<Vec<VRequest<T>>, String> {
        if self.bytes.scalar.weight_layout != plan.layout_digest
            || pending.statistics.len() != self.norms.len()
        {
            return Err("RMS local V original obligations differ".into());
        }
        let mut result = Vec::new();
        for (i, n) in self.norms.iter().enumerate().filter(|(_, n)| n.cohort.is_none()) {
            if n.layer.ok_or("RMS V layer missing")? % 6 == 5 {
                continue;
            }
            let source = plan
                .cohorts
                .iter()
                .position(|c| c.layer == n.layer && c.operation == "v_source")
                .ok_or("RMS V raw producer missing")?;
            let (view, shape) = self.bytes.rne_view(plan, source)?;
            let p = &pending.statistics[i];
            let x = &self.bytes.scalar.layout.sources[n.input];
            if shape != [x.rows, x.cols] || p.input_point.len() != bits(shape[0]) + bits(shape[1]) {
                return Err("RMS V RNE source shape differs".into());
            }
            result.push(VRequest {
                norm: i,
                source,
                view,
                shape,
                point: p.input_point.clone(),
                original: p.inputs[0],
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::gemma::caller::{Compact, PendingP0};
    use rand_010::{RngExt, SeedableRng};

    fn width(plan: &Plan, sources: &Sources, i: usize) -> usize {
        if let Some(c) = plan.cohorts.get(i) {
            match c.kind {
                Kind::Matrix => 6,
                Kind::Norm => 4,
                Kind::Lookup => 2,
            }
        } else if sources.bytes.scalar.layout.sources[i].name.starts_with("S/") {
            6
        } else {
            2
        }
    }

    fn values(plan: &Plan, sources: &Sources, w: &[i64], fault: usize) -> Vec<Vec<i64>> {
        let mut values: Vec<_> =
            sources.bytes.scalar.layout.sources.iter().map(|s| vec![0; s.rows * s.cols]).collect();
        let finish_norm = |values: &mut Vec<Vec<i64>>, n: &Norm| {
            let program = kernel::compile(n.columns, 0, 0, 0, n.cohort.is_some()).unwrap();
            for row in 0..n.rows {
                let sum =
                    (0..n.columns).map(|col| values[n.input][row * n.columns + col].pow(2)).sum();
                values[n.statistic][row] = sum;
                for col in 0..n.columns {
                    let p = values[n.product][row * n.columns + col];
                    values[n.output][row * n.columns + col] = kernel::tests::expected(
                        p,
                        sum,
                        n.columns,
                        n.cohort.is_some(),
                        program.coefficients,
                    )
                    .unwrap();
                }
            }
        };
        for (i, c) in plan.cohorts.iter().enumerate() {
            let source = &plan.sources[c.tensor];
            if c.kind == Kind::Lookup {
                for row in 0..c.rows {
                    for col in 0..c.columns {
                        values[i][row * c.columns + col] =
                            w[source.packed_offset + row * source.cols + col];
                    }
                }
            } else {
                let input = sources.bytes.scalar.input_sources[i - 1];
                let route = plan.input_route(i).unwrap();
                for row in 0..c.rows {
                    for col in 0..c.columns {
                        values[i][row * c.columns + col] = if c.kind == Kind::Norm {
                            values[input][row * c.columns + col] * w[source.packed_offset + col]
                        } else {
                            (0..c.inner)
                                .map(|k| {
                                    values[input][(route.row_offset + row) * c.inner + k]
                                        * w[source.packed_offset + col * c.inner + k]
                                })
                                .sum()
                        };
                    }
                }
            }
            if c.kind == Kind::Norm {
                let n = sources.norms.iter().find(|n| n.cohort == Some(i)).unwrap();
                finish_norm(&mut values, n);
            } else if let Some(output) = sources
                .bytes
                .scalar
                .layout
                .sources
                .iter()
                .position(|s| s.name == name(c.layer, &c.operation))
            {
                values[output] = values[i]
                    .iter()
                    .map(|&v| {
                        if c.kind == Kind::Lookup {
                            v
                        } else {
                            let (q, r) = (v.div_euclid(2), v.rem_euclid(2));
                            q + i64::from(r == 1 && q & 1 == 1)
                        }
                    })
                    .collect();
            }
        }
        for n in sources.norms.iter().filter(|n| n.cohort.is_none()) {
            if fault == 1 {
                values[n.input][0] += 1;
            }
            finish_norm(&mut values, n);
        }
        values
    }

    #[test]
    fn compact_frames_match_original_rms_frame_without_broadcast_statistic_storage() {
        let plan = super::super::tests::toy_plan(3, 2);
        let sources = plan.rms_sources().unwrap();
        let mut weights = vec![1i64; plan.live];
        for (i, value) in weights.iter_mut().enumerate() {
            *value = i as i64 % 5 - 2;
        }
        let values = values(&plan, &sources, &weights, 0);
        let read = |source: usize, row: usize, col: usize, byte: usize| {
            let shape = &sources.bytes.scalar.layout.sources[source];
            let width = width(&plan, &sources, source);
            let word = (values[source][row * shape.cols + col] + (1 << (8 * width - 1))) as u64;
            (word >> (8 * byte)) as u8
        };
        let cache = CompactFrames::build(&sources, |s, r, c, b| Ok(read(s, r, c, b))).unwrap();
        assert!(CompactFrames::build(&sources, |_, _, _, _| Err("source failure".into()))
            .err()
            .unwrap()
            .contains("source failure"));
        assert!(cache.frame(sources.cells.next_power_of_two()).is_err());
        let expected_payload: usize = sources
            .norms
            .iter()
            .map(|norm| {
                let pbytes = if norm.cohort.is_some() { 4 } else { 2 };
                norm.rows * norm.columns * (pbytes + 2) + norm.rows * 6
            })
            .sum();
        let workspace = cache.workspace();
        assert_eq!(workspace.payload_len, expected_payload);
        assert!(workspace.payload_capacity >= expected_payload);
        assert_eq!(workspace.source_byte_reads, expected_payload as u64);
        assert_eq!(workspace.build_peak_owned_bytes, workspace.retained_capacity_bytes);
        for cell in 0..sources.cells.next_power_of_two() {
            assert_eq!(cache.frame(cell).unwrap(), sources.frame(cell, read).unwrap());
        }

        // A row statistic occupies six retained bytes once, yet both columns
        // reconstruct exactly the broadcast S bytes in the original frame.
        let first = cache.frame(0).unwrap();
        let second = cache.frame(1).unwrap();
        let pbytes = if sources.norms[0].cohort.is_some() { 4 } else { 2 };
        assert_eq!(&first[pbytes..pbytes + 6], &second[pbytes..pbytes + 6]);
    }

    fn compact(
        plan: &Plan,
        sources: &Sources,
        values: &[Vec<i64>],
        w: &[i64],
        points: &[Vec<Fp3>],
    ) -> Vec<Compact> {
        plan.cohorts
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let (r, s) = points[i].split_at(bits(c.rows));
                let output = values[i].iter().enumerate().fold(Fp3::ZERO, |v, (j, &x)| {
                    v + eq_index(r, j / c.columns) * eq_index(s, j % c.columns) * signed(x)
                });
                if c.kind == Kind::Lookup {
                    return Compact { output, x: Vec::new(), w: Vec::new() };
                }
                let input = sources.bytes.scalar.input_sources[i - 1];
                let route = plan.input_route(i).unwrap();
                let inner = if c.kind == Kind::Norm { c.columns } else { c.inner };
                let mut x = vec![Fp3::ZERO; inner.next_power_of_two()];
                let mut weights = x.clone();
                let source = &plan.sources[c.tensor];
                for k in 0..inner {
                    for row in 0..c.rows {
                        let index = if c.kind == Kind::Norm {
                            row * c.columns + k
                        } else {
                            (route.row_offset + row) * c.inner + k
                        };
                        x[k] += eq_index(r, row) * signed(values[input][index]);
                    }
                    if c.kind == Kind::Norm {
                        weights[k] = signed(w[source.packed_offset + k]);
                    } else {
                        for col in 0..c.columns {
                            weights[k] += eq_index(s, col)
                                * signed(w[source.packed_offset + col * c.inner + k]);
                        }
                    }
                }
                Compact { output, x, w: weights }
            })
            .collect()
    }

    fn demands<T: Copy>(
        sources: &Sources,
        plan: &Plan,
        p: &PendingP0<T>,
        r: &Pending<T>,
    ) -> Vec<(usize, [u8; 32], [usize; 2], Vec<Fp3>, T)> {
        let mut result: Vec<_> = sources
            .bytes
            .rne_requests(plan, p)
            .unwrap()
            .into_iter()
            .map(|v| (v.source, v.view, v.shape, v.point, v.original))
            .collect();
        let extra = sources.local_v_rne_requests(plan, r).unwrap();
        assert_eq!(extra.len(), 1);
        result.extend(extra.into_iter().map(|v| (v.source, v.view, v.shape, v.point, v.original)));
        assert_eq!(result.len(), 3);
        result
    }

    fn auxiliary_forms<T: Copy>(
        sources: &Sources,
        plan: &Plan,
        p: &PendingP0<T>,
        r: &Pending<T>,
        rne: &[(usize, Vec<Fp3>, T)],
    ) -> (Vec<Vec<Cube>>, Vec<(T, Fp3)>) {
        let (mut forms, shifts) = sources.bytes.forms(plan, p).unwrap();
        let mut originals: Vec<_> = p
            .cuts
            .iter()
            .map(|c| c.original)
            .chain(p.inputs.iter().map(|c| c.original))
            .zip(shifts)
            .collect();
        let (more, shifts, targets) = sources.rms_forms(r).unwrap();
        forms.extend(more);
        originals.extend(targets.into_iter().zip(shifts));
        for (source, point, original) in rne {
            forms.push(sources.bytes.rne_form(plan, *source, point).unwrap());
            originals.push((*original, Fp3::ZERO));
        }
        (forms, originals)
    }

    fn lookup_inputs<T: Copy>(
        plan: &Plan,
        p: &PendingP0<T>,
        tokens: &[u32],
    ) -> (Vec<Vec<Cube>>, Vec<T>) {
        let mut forms = Vec::new();
        let mut targets = Vec::new();
        for input in &p.inputs {
            let route = plan.input_route(input.cohort).unwrap();
            if route.producer == (None, "embedding_lookup".into()) {
                let (r, c) = input.point.split_at(bits(tokens.len()));
                forms.push(plan.lookup_form(r, c, tokens).unwrap());
                targets.push(input.original);
            }
        }
        assert_eq!(forms.len(), 3);
        (forms, targets)
    }

    #[test]
    fn c71_b12_gemma_rms_dispatch_joins_p0_local_v_rne_and_both_original_roots() {
        let plan = super::super::tests::toy_plan(2, 1);
        let sources = plan.rms_sources().unwrap();
        assert_eq!((sources.cells, sources.bytes.live), (28, 462));
        let mut fixed_w = vec![0i64; plan.live];
        fixed_w[..16].copy_from_slice(&[1, 2, -1, 3, -2, 1, 0, 2, 2, -1, 1, 0, 1, 1, -2, 1]);
        for i in 0..4 {
            fixed_w[16 + 5 * i] = 2;
        }
        fixed_w[32..].fill(1);
        let gamma = gamma(&matrix_config(32).unwrap());
        let profile = sources.bytes.profile(&gamma);
        let parameters = vec![[0, 0, 0]; sources.norms.len()];
        let tokens = [0, 1];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        for fault in 0..3 {
            // Independent component instances, each with fresh salted roots.
            let mut w_values = vec![0; 1024];
            for i in 0..plan.live {
                w_values[i] = fixed_w[plan.virtual_to_packed(i).unwrap().unwrap()] as i16;
            }
            let w_model = Model::new(32, w_values).unwrap();
            let mut used_w = fixed_w.clone();
            if fault == 2 {
                used_w[32] = 2;
            }
            let values = values(&plan, &sources, &used_w, fault);
            let read = |source: usize, row: usize, col: usize, byte: usize| {
                let s = &sources.bytes.scalar.layout.sources[source];
                let word = (values[source][row * s.cols + col]
                    + (1 << (8 * width(&plan, &sources, source) - 1)))
                    as u64;
                (word >> (8 * byte)) as u8
            };
            let mut packed = Vec::new();
            for (i, values) in values.iter().enumerate() {
                for v in values {
                    packed.extend_from_slice(&v.to_le_bytes()[..width(&plan, &sources, i)]);
                }
            }
            let mut a_values = vec![0; 1024];
            for i in 0..sources.bytes.live {
                let (address, xor) = sources.bytes.virtual_to_packed(i).unwrap().unwrap();
                a_values[i] = i16::from(packed[address] ^ xor);
            }
            let a_model = Model::new(32, a_values).unwrap();
            let statement = P0Statement {
                weights: &w_model.root,
                auxiliary: &a_model.root,
                weight_gamma: &gamma,
                auxiliary_gamma: &profile,
                auxiliary_layout: &sources.bytes.scalar,
                quantization: [63; 32],
                attempt,
                tokens: &tokens,
            };
            let count = plan.p0_required()
                + sources.rms_required(&statement, &parameters).unwrap()
                + 3 * rne::required(3, 1)
                + 269
                + 510
                + 64;
            assert_eq!(plan.p0_required(), 70);
            assert_eq!(sources.rms_required(&statement, &parameters).unwrap(), 7746);
            assert_eq!(rne::required(3, 1), 448);
            assert_eq!(count, 10003);
            let mut rng = MatrixRng::from_seed([139; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || {
                Fs::new(
                    b"canonical toy RMS flow; public RMS exponents 0 and projection shifts 1",
                    100_000,
                )
            };
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (p0_proof, p0) = plan
                .prove_p0(
                    &statement,
                    |points| Ok(compact(&plan, &sources, &values, &used_w, points)),
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
            let (rms_proof, rms) =
                sources.prove_rms(&statement, &parameters, read, &mut fs, &mut prows).unwrap();
            let mut rne_proofs = Vec::new();
            let mut rne_targets = Vec::new();
            for (source, view, shape, point, original) in demands(&sources, &plan, &p0, &rms) {
                let s = rne::Statement {
                    root: &a_model.root,
                    profile: &profile,
                    view,
                    attempt,
                    output_point: &point,
                    shape,
                    shift: 1,
                };
                let (proof, point, original) = rne::prove(
                    &s,
                    original,
                    |i| std::array::from_fn(|b| read(source, i / shape[1], i % shape[1], b)),
                    &mut fs,
                    &mut prows,
                )
                .unwrap();
                rne_proofs.push(proof);
                rne_targets.push((source, point, original));
            }
            let (wrange, wforms, wtargets) = range::prove(
                &w_model,
                attempt,
                plan.layout_digest,
                plan.live,
                7,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let mut wforms = Vec::from(wforms);
            let mut wtargets = Vec::from(wtargets);
            let (extra, targets) = lookup_inputs(&plan, &p0, &tokens);
            wforms.extend(extra);
            wtargets.extend(targets);
            wforms.extend(p0.weight_forms.clone());
            wtargets.extend(&p0.weights);
            let (wpcs, wdigest) = linear::prove(
                &w_model,
                attempt,
                plan.layout_digest,
                &wforms,
                &wtargets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (arange, aforms, atargets) = range::prove(
                &a_model,
                attempt,
                sources.bytes.layout_digest,
                sources.bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let mut aforms = Vec::from(aforms);
            let mut atargets = Vec::from(atargets);
            let (extra, targets) = auxiliary_forms(&sources, &plan, &p0, &rms, &rne_targets);
            aforms.extend(extra);
            atargets.extend(targets.into_iter().map(|(a, s)| Auth::new(a.x + s, a.m)));
            let (apcs, adigest) = linear::prove(
                &a_model,
                attempt,
                sources.bytes.layout_digest,
                &aforms,
                &atargets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let p0 = plan.verify_p0(&statement, &p0_proof, delta, &mut fs, &mut vrows).unwrap();
            let rms = sources
                .verify_rms(&statement, &parameters, &rms_proof, delta, &mut fs, &mut vrows)
                .unwrap();
            let mut rne_targets = Vec::new();
            let mut rejected = false;
            for ((source, view, shape, point, original), proof) in
                demands(&sources, &plan, &p0, &rms).into_iter().zip(&rne_proofs)
            {
                let s = rne::Statement {
                    root: &a_model.root,
                    profile: &profile,
                    view,
                    attempt,
                    output_point: &point,
                    shape,
                    shift: 1,
                };
                let checked = rne::verify(&s, original, proof, delta, &mut fs, &mut vrows);
                if fault == 1 && plan.cohorts[source].operation == "v_source" {
                    assert_eq!(checked.unwrap_err(), "B12 RNE sumcheck MAC rejected");
                    rejected = true;
                    break;
                }
                let (point, original) = checked.unwrap();
                rne_targets.push((source, point, original));
            }
            if fault == 1 {
                assert!(rejected);
                continue;
            }
            let (wforms, wtargets) = range::verify(
                32,
                &w_model.root,
                attempt,
                plan.layout_digest,
                plan.live,
                7,
                &wrange,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut wforms = Vec::from(wforms);
            let mut wtargets = Vec::from(wtargets);
            let (extra, targets) = lookup_inputs(&plan, &p0, &tokens);
            wforms.extend(extra);
            wtargets.extend(targets);
            wforms.extend(p0.weight_forms.clone());
            wtargets.extend(&p0.weights);
            let checked = linear::verify(
                32,
                &w_model.root,
                attempt,
                plan.layout_digest,
                &wforms,
                &wtargets,
                &wpcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert_eq!(checked.unwrap_err(), "C71 matrix sumcheck MAC rejected");
                continue;
            }
            assert_eq!(checked.unwrap(), wdigest);
            let (aforms, atargets) = range::verify(
                32,
                &a_model.root,
                attempt,
                sources.bytes.layout_digest,
                sources.bytes.live,
                range::Alphabet::Byte,
                &arange,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let mut aforms = Vec::from(aforms);
            let mut atargets = Vec::from(atargets);
            let (extra, targets) = auxiliary_forms(&sources, &plan, &p0, &rms, &rne_targets);
            aforms.extend(extra);
            atargets.extend(targets.into_iter().map(|(k, s)| Key::new(k.k + delta * s)));
            assert_eq!(
                linear::verify(
                    32,
                    &a_model.root,
                    attempt,
                    sources.bytes.layout_digest,
                    &aforms,
                    &atargets,
                    &apcs,
                    delta,
                    &mut fs,
                    &mut vrows
                )
                .unwrap(),
                adigest
            );
            assert!(vrows.next().is_none());
        }
    }
}
