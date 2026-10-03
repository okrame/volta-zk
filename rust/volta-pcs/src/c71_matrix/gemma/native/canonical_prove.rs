//! Canonical security §3 prover body, using the verifier's original endpoints.
//! CPU reference only: component workspaces are not the admitted H100 schedule.
//! The owner must supply immutable prepared values; this body neither prepares
//! witnesses nor imports/promotes acceptance. All errors terminate its caller.
use super::super::protocol::{Batch, SourceModel, Writer};
use super::*;

impl Canonical {
    pub(super) fn prove_body(
        &self,
        s: &caller::P0Statement<'_>,
        tables: &profile::Tables<'_>,
        parts: &[kv::Segment<'_>],
        header: &[u8],
        weights: SourceModel<'_>,
        current: SourceModel<'_>,
        previous: &[SourceModel<'_>],
        compact: impl FnOnce(&[Vec<Fp3>]) -> Result<Vec<caller::Compact>, String>,
        read: impl Fn(usize, usize, usize, usize) -> u8,
        tail: impl Fn(usize, usize, usize) -> i16,
        fs: &mut Fs,
        rows: &mut impl ExactSizeIterator<Item = Auth>,
    ) -> Result<(Vec<u8>, [u8; 32]), String> {
        let a = &self.sources.attention;
        let rope = &a.rope;
        let gu = &rope.gate_up;
        let g = &gu.gelu;
        let rms = &g.rms;
        let b = self.bytes();
        if s.quantization != self.recipes.digest
            || s.auxiliary_layout.layout.layout_digest != b.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != self.plan.layout_digest
            || s.weight_gamma != gamma(&Domain::Flat(35).config()?)
            || s.auxiliary_gamma != gamma(&Domain::Flat(34).config()?)
            || weights.identity() != (Domain::Flat(35), s.weights)
            || current.identity() != (Domain::Flat(34), s.auxiliary)
            || previous.len() != usize::from(s.attempt.slot)
            || parts.len() != previous.len() + 1
            || previous.iter().zip(parts).any(|(m, p)| m.identity() != (Domain::Flat(34), p.root))
        {
            return Err("canonical prover context differs".into());
        }
        let owned = caller::P0Statement {
            weights: s.weights,
            auxiliary: s.auxiliary,
            weight_gamma: s.weight_gamma,
            auxiliary_gamma: s.auxiliary_gamma,
            auxiliary_layout: &b.scalar,
            quantization: self.recipes.digest,
            tokens: s.tokens,
            attempt: s.attempt,
        };
        let s = &owned;
        let required = self.recipes.required(
            &self.plan,
            &self.sources,
            &self.output,
            &self.softmax,
            s,
            tables,
        )?;
        if rows.len() != required {
            return Err("canonical prover reservation differs".into());
        }
        let ks = a.kv_statement(s, parts)?;
        let word = |id, r, c| {
            // These are the original biased-i16 bytes, not a field cast.
            (i32::from(u16::from_le_bytes([read(id, r, c, 0), read(id, r, c, 1)])) - 32768) as i16
        };
        let raw = |id, r, c| std::array::from_fn(|j| read(id, r, c, j));
        let shift = |t: Auth, bias| Auth::new(t.x + bias, t.m);
        let mut wire = Writer::canonical(header);
        let (mut bw, mut ba) = (Batch::new(), Batch::new());
        for (f, bias) in self.public_forms(s, fs)? {
            ba.add(f, Auth::new(bias, Fp3::ZERO));
        }
        wire.raw(0, &[], fs)?;
        let (proof, p0) = self.plan.prove_p0(s, compact, fs, rows)?;
        wire.put(1, &proof, fs)?;
        bw.forms = p0.weight_forms.clone();
        bw.targets = p0.weights.clone();
        let (f, bias) = b.forms(&self.plan, &p0)?;
        ba.extend(
            f,
            bias,
            p0.cuts
                .iter()
                .map(|c| c.original)
                .chain(p0.inputs.iter().map(|i| i.original))
                .collect(),
            shift,
        )?;
        let (proof, norms) = rms.prove_rms(s, &self.recipes.rms, &read, fs, rows)?;
        wire.put(2, &proof, fs)?;
        let (f, bias, t) = rms.rms_forms(&norms)?;
        ba.extend(f, bias, t, shift)?;
        let requests = self.recipes.original_rne(&self.plan, &self.sources, &p0, &norms)?;
        let mut proofs = Vec::with_capacity(requests.len());
        for (r, rounding) in requests {
            let rs = rne::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view: r.view,
                attempt: s.attempt,
                output_point: &r.point,
                shape: r.shape,
                shift: rounding,
            };
            let (proof, point, original) = rne::prove(
                &rs,
                r.original,
                |j| {
                    raw(
                        r.source,
                        j / r.shape[1].next_power_of_two(),
                        j % r.shape[1].next_power_of_two(),
                    )
                },
                fs,
                rows,
            )?;
            ba.add(b.source_rne_form(r.source, &point)?, original);
            proofs.push(proof);
        }
        wire.put(3, &proofs, fs)?;
        let pairs = self.recipes.table_pairs(&self.plan)?;
        let (proof, pending) = b.prove_table_rne(&self.plan, s, &pairs, &read, fs, rows)?;
        wire.put(4, &proof, fs)?;
        let (f, bias, t) = b.table_rne_forms(&self.plan, &pairs, &pending)?;
        ba.extend(f, bias, t, shift)?;
        let (proof, pending) = g.prove_lookup(s, tables.gelu, &read, fs, rows)?;
        wire.put(5, &proof, fs)?;
        let (f, bias) = g.forms(&pending.point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let statement = gu.statement(s, fs)?;
        let (proof, pending) = gate_up::prove(
            &statement,
            |i| {
                let (layer, row, col) =
                    gu.cell(i).expect("compiled gate cell").expect("live gate cell");
                (
                    word(g.gelu[layer].output, row, col),
                    word(gu.products[layer].up, row, col),
                    raw(gu.products[layer].raw, row, col),
                )
            },
            fs,
            rows,
        )?;
        wire.put(6, &proof, fs)?;
        let (f, bias) = gu.forms(&pending.raw_point, &pending.input_point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let statement = rope.statement(s, tables.rope, fs)?;
        let (proof, pending) = kernel::rope::prove(
            &statement,
            |i| {
                let (rotation, row, col) =
                    rope.cell(i).expect("compiled RoPE cell").expect("live RoPE cell");
                let r = &rope.rotations[rotation];
                (raw(r.raw, row, col), word(rms.norms[r.norm].output, row, col))
            },
            fs,
            rows,
        )?;
        wire.put(7, &proof, fs)?;
        let (f, bias) = rope.forms(&pending.raw_point, &pending.input_point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let mut requests = Vec::with_capacity(120);
        for (layer, l) in a.layers.iter().enumerate() {
            let statement = a.statement(s, layer, fs)?;
            let (proof, q) = kernel::attention::prove_qk(
                &statement,
                |h, r, c| raw(l.raw_score, h * 256 + r, c),
                |r, h, c| word(l.q, r, h * l.lanes + c),
                |r, h, c| tail(l.k, r, h * l.lanes + c),
                fs,
                rows,
            )?;
            wire.put(8 + 2 * layer as u16, &proof, fs)?;
            let (f, bias, t, k) = a.qk_routes(layer, &q)?;
            ba.extend(f.into(), bias.into(), t.into(), shift)?;
            let (proof, v) = kernel::attention::prove_pv(
                &statement,
                |r, h, c| raw(l.raw_output, r, h * l.lanes + c),
                |h, r, c| word(l.pi, h * 256 + r, c),
                |r, h, c| tail(l.v, r, h * l.lanes + c),
                fs,
                rows,
            )?;
            wire.put(9 + 2 * layer as u16, &proof, fs)?;
            let (f, bias, t, v) = a.pv_routes(layer, &v)?;
            ba.extend(f.into(), bias.into(), t.into(), shift)?;
            requests.extend([k, v]);
        }
        let (proof, mut openings) =
            kv::prove(&ks, &requests, |i, j| previous[i].byte(j), fs, rows)?;
        wire.put(128, &proof, fs)?;
        let opening = openings.pop().ok_or("canonical current KV opening missing")?;
        ba.add(opening.form, opening.original);
        let (proof, pending) = self.output.prove_lookup(
            b,
            s,
            lookup::Table {
                profile: tables.softcap.profile,
                lower: tables.softcap.lower,
                outputs: tables.softcap.outputs,
            },
            &read,
            fs,
            rows,
        )?;
        wire.put(129, &proof, fs)?;
        let (f, bias) = self.output.forms(b, &pending.point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let (proof, pending) = self.softmax.prove(b, s, tables.exp30, &read, fs, rows)?;
        wire.put(130, &proof, fs)?;
        let (f, bias, t) = self.softmax.forms(b, &pending)?;
        ba.extend(f, bias, t, shift)?;
        for (kind, model, layout, live, alphabet, batch) in [
            (
                131,
                &weights,
                self.plan.layout_digest,
                self.plan.live,
                range::Alphabet::Symmetric(32767),
                &mut bw,
            ),
            (132, &current, b.layout_digest, b.live, range::Alphabet::Byte, &mut ba),
        ] {
            let (proof, forms, targets) =
                model.range(s.attempt, layout, live, alphabet, fs, rows)?;
            wire.put(kind, &proof, fs)?;
            for (f, t) in forms.into_iter().zip(targets) {
                batch.add(f, t);
            }
        }
        if bw.targets.len() != 775 || ba.targets.len() != 4446 || openings.len() != previous.len() {
            return Err("canonical original endpoint closure census differs".into());
        }
        let (proof, _) =
            weights.close(s.attempt, self.plan.layout_digest, &bw.forms, &bw.targets, fs, rows)?;
        wire.raw(
            133,
            &codec::encode_linear(Domain::Flat(35), &proof).map_err(|e| e.to_string())?,
            fs,
        )?;
        for (i, opening) in openings.into_iter().enumerate() {
            let (proof, _) = previous[i].close(
                s.attempt,
                parts[i].bytes.layout_digest,
                &[opening.form],
                &[opening.original],
                fs,
                rows,
            )?;
            wire.raw(
                134 + i as u16,
                &codec::encode_linear(Domain::Flat(34), &proof).map_err(|e| e.to_string())?,
                fs,
            )?;
        }
        let (proof, _) =
            current.close(s.attempt, b.layout_digest, &ba.forms, &ba.targets, fs, rows)?;
        wire.raw(
            134 + previous.len() as u16,
            &codec::encode_linear(Domain::Flat(34), &proof).map_err(|e| e.to_string())?,
            fs,
        )?;
        if rows.len() != 0 {
            return Err("canonical prover reservation was not consumed exactly".into());
        }
        Ok(wire.finish(fs))
    }
}
