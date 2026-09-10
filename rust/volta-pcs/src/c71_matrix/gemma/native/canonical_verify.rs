//! Canonical security §3 body. This internal consumer does not own or promote
//! accepted history: only a complete registry/pool wrapper may authorize it.
//! The inherited bounded transport cap is not a full-certificate size claim.
use super::super::protocol::{Batch, Reader};
use super::*;

impl Canonical {
    fn public_forms(
        &self,
        s: &caller::P0Statement<'_>,
        fs: &mut Fs,
    ) -> Result<Vec<(Vec<Cube>, Fp3)>, String> {
        let b = self.bytes();
        Ok(vec![
            b.affine_zero_form(&self.plan, s, &self.recipes.affine, fs)?,
            b.argmax_zero_form(
                &self.plan,
                s,
                self.output.output,
                self.output.slack,
                self.output.token_offset,
                fs,
            )?,
            self.sources.attention.mask_zero_form(&self.plan, s, fs)?,
            self.softmax.zero_form(b, s, fs)?,
        ])
    }

    /// All inputs are owned by the registry wrapper, never certificate
    /// metadata. `parts` must originate in its accepted registry, and `rows`
    /// must already be the one durably burned reservation. No Acceptance is
    /// constructed here, and a digest cannot promote the bounded wrapper.
    pub(super) fn verify_body(
        &self,
        s: &caller::P0Statement<'_>,
        tables: &profile::Tables<'_>,
        parts: &[kv::Segment<'_>],
        header: &[u8],
        certificate: &[u8],
        delta: Fp3,
        fs: &mut Fs,
        rows: &mut std::vec::IntoIter<Key>,
    ) -> Result<[u8; 32], String> {
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
        {
            return Err("canonical dispatcher context differs".into());
        }
        // Digests are comparisons, not authority for a caller-created Sources
        // object. Every kernel receives this compiler's actual source layout.
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
        // In particular, do not expand public query arrays or advance FS when
        // the complete reservation is missing. The wrapper owns terminal Stop.
        if rows.len() != required {
            return Err("canonical dispatcher reservation differs".into());
        }
        let ks = a.kv_statement(s, parts)?;
        let mut reader = Reader::new(certificate, header)?;
        let shift = |t: Key, bias: Fp3| Key::new(t.k + delta * bias);
        let (mut bw, mut ba) = (Batch::new(), Batch::new());
        let (body, frame) = reader.raw(0)?;
        if !body.is_empty() {
            return Err("public targets have no prover payload".into());
        }
        for (f, bias) in self.public_forms(s, fs)? {
            ba.add(f, Key::new(delta * bias));
        }
        Reader::record(fs, frame);

        let (proof, frame) = reader.get(1)?;
        let p0 = self.plan.verify_p0(s, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
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
        let (proof, frame) = reader.get(2)?;
        let norms = rms.verify_rms(s, &self.recipes.rms, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias, t) = rms.rms_forms(&norms)?;
        ba.extend(f, bias, t, shift)?;

        let (proofs, frame) = reader.get::<Vec<rne::Proof>>(3)?;
        let requests = self.recipes.original_rne(&self.plan, &self.sources, &p0, &norms)?;
        if proofs.len() != requests.len() {
            return Err("canonical original RNE cardinality differs".into());
        }
        for ((r, rounding), proof) in requests.into_iter().zip(proofs) {
            let rs = rne::Statement {
                root: s.auxiliary,
                profile: s.auxiliary_gamma,
                view: r.view,
                attempt: s.attempt,
                output_point: &r.point,
                shape: r.shape,
                shift: rounding,
            };
            let (point, original) = rne::verify(&rs, r.original, &proof, delta, fs, rows)?;
            ba.add(b.source_rne_form(r.source, &point)?, original);
        }
        Reader::record(fs, frame);
        let pairs = self.recipes.table_pairs(&self.plan)?;
        let (proof, frame) = reader.get(4)?;
        let pending = b.verify_table_rne(&self.plan, s, &pairs, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias, t) = b.table_rne_forms(&self.plan, &pairs, &pending)?;
        ba.extend(f, bias, t, shift)?;
        let (proof, frame) = reader.get(5)?;
        let pending = g.verify_lookup(s, tables.gelu, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias) = g.forms(&pending.point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let (proof, frame) = reader.get(6)?;
        let statement = gu.statement(s, fs)?;
        let pending = gate_up::verify(&statement, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias) = gu.forms(&pending.raw_point, &pending.input_point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let (proof, frame) = reader.get(7)?;
        let statement = rope.statement(s, tables.rope, fs)?;
        let pending = kernel::rope::verify(&statement, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias) = rope.forms(&pending.raw_point, &pending.input_point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;

        let mut kv_requests = Vec::new();
        for layer in 0..60 {
            let (proof, frame) = reader.get(8 + 2 * layer as u16)?;
            let statement = a.statement(s, layer, fs)?;
            let q = kernel::attention::verify_qk(&statement, &proof, delta, fs, rows)?;
            Reader::record(fs, frame);
            let (f, bias, t, k) = a.qk_routes(layer, &q)?;
            ba.extend(f.into(), bias.into(), t.into(), shift)?;
            let (proof, frame) = reader.get(9 + 2 * layer as u16)?;
            let v = kernel::attention::verify_pv(&statement, &proof, delta, fs, rows)?;
            Reader::record(fs, frame);
            let (f, bias, t, v) = a.pv_routes(layer, &v)?;
            ba.extend(f.into(), bias.into(), t.into(), shift)?;
            kv_requests.extend([k, v]);
        }
        let (proof, frame) = reader.get(128)?;
        let mut openings = kv::verify(&ks, &kv_requests, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let current = openings.pop().ok_or("canonical current KV opening missing")?;
        ba.add(current.form, current.original);
        let (proof, frame) = reader.get(129)?;
        let pending = self.output.verify_lookup(
            b,
            s,
            lookup::Table {
                profile: tables.softcap.profile,
                lower: tables.softcap.lower,
                outputs: tables.softcap.outputs,
            },
            &proof,
            delta,
            fs,
            rows,
        )?;
        Reader::record(fs, frame);
        let (f, bias) = self.output.forms(b, &pending.point)?;
        ba.extend(f.into(), bias.into(), pending.originals.into(), shift)?;
        let (proof, frame) = reader.get(130)?;
        let pending = self.softmax.verify(b, s, tables.exp30, &proof, delta, fs, rows)?;
        Reader::record(fs, frame);
        let (f, bias, t) = self.softmax.forms(b, &pending)?;
        ba.extend(f, bias, t, shift)?;
        for (kind, domain, root, layout, live, alphabet, batch) in [
            (
                131,
                Domain::Flat(35),
                s.weights,
                self.plan.layout_digest,
                self.plan.live,
                range::Alphabet::Symmetric(32767),
                &mut bw,
            ),
            (
                132,
                Domain::Flat(34),
                s.auxiliary,
                b.layout_digest,
                b.live,
                range::Alphabet::Byte,
                &mut ba,
            ),
        ] {
            let (proof, frame) = reader.get(kind)?;
            let (forms, targets) = range::verify(
                domain, root, s.attempt, layout, live, alphabet, &proof, delta, fs, rows,
            )?;
            Reader::record(fs, frame);
            for (f, t) in forms.into_iter().zip(targets) {
                batch.add(f, t);
            }
        }
        if bw.targets.len() != 775
            || ba.targets.len() != 4446
            || openings.len() != usize::from(s.attempt.slot)
        {
            return Err("canonical original endpoint closure census differs".into());
        }
        let (body, frame) = reader.raw(133)?;
        let proof = codec::decode_linear(Domain::Flat(35), body).map_err(|e| e.to_string())?;
        linear::verify(
            Domain::Flat(35),
            s.weights,
            s.attempt,
            self.plan.layout_digest,
            &bw.forms,
            &bw.targets,
            &proof,
            delta,
            fs,
            rows,
        )?;
        Reader::record(fs, frame);
        for (i, opening) in openings.into_iter().enumerate() {
            let (body, frame) = reader.raw(134 + i as u16)?;
            let proof = codec::decode_linear(Domain::Flat(34), body).map_err(|e| e.to_string())?;
            linear::verify(
                Domain::Flat(34),
                parts[i].root,
                s.attempt,
                parts[i].bytes.layout_digest,
                &[opening.form],
                &[opening.original],
                &proof,
                delta,
                fs,
                rows,
            )?;
            Reader::record(fs, frame);
        }
        let (body, frame) = reader.raw(134 + u16::from(s.attempt.slot))?;
        let proof = codec::decode_linear(Domain::Flat(34), body).map_err(|e| e.to_string())?;
        linear::verify(
            Domain::Flat(34),
            s.auxiliary,
            s.attempt,
            b.layout_digest,
            &ba.forms,
            &ba.targets,
            &proof,
            delta,
            fs,
            rows,
        )?;
        Reader::record(fs, frame);
        if rows.len() != 0 {
            return Err("canonical reservation was not consumed exactly".into());
        }
        reader.finish(fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_native_dispatch_canonical_preflight_and_public_prefix_reject_incomplete_p0() {
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (sources, output, softmax) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&sources, &output, &softmax)
                .into_iter()
                .map(|id| (id, 0))
                .collect();
        for l in &softmax.layers {
            exponents.insert(l.pi, -14);
            exponents.insert(l.score, 128);
        }
        let profiles: Vec<_> =
            (0..3).map(|slot| Canonical::compile(slot, &[0; 772], &exponents).unwrap()).collect();
        let w = C61Commitment::new(vec![[1; 32]]);
        let roots: Vec<_> = (2..=4).map(|id| C61Commitment::new(vec![[id; 32]])).collect();
        let (wg, ag) = (
            gamma(&Domain::Flat(35).config().unwrap()),
            gamma(&Domain::Flat(34).config().unwrap()),
        );
        // As in the public reservation test: exact EXP30 at exponent 128,
        // shape-only other tables. No numerical or acceptance credit.
        let zeros = vec![0; 65535];
        let mut exp = vec![0; 65535];
        exp[0] = 1 << 30;
        let gelu: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I16(&zeros),
            })
            .collect();
        let exp30: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I32(&exp),
            })
            .collect();
        let cap =
            lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&zeros) };
        let local = vec![vec![[1 << 30, 0]; 128]; 150];
        let global = vec![vec![[1 << 30, 0]; 64]; 150];
        let header = b"canonical dispatcher prefix diagnostic, no accepted inference";
        for (slot, p) in profiles.iter().enumerate() {
            let rope = [
                kernel::rope::Table { position: 150 * slot, rows: &local },
                kernel::rope::Table { position: 150 * slot, rows: &global },
            ];
            let tables = profile::Tables { gelu: &gelu, exp30: &exp30, softcap: &cap, rope: &rope };
            let mut s = caller::P0Statement {
                weights: &w,
                auxiliary: &roots[slot],
                weight_gamma: &wg,
                auxiliary_gamma: &ag,
                auxiliary_layout: &p.bytes().scalar,
                quantization: p.recipes.digest,
                tokens: &[0; 150],
                attempt: AttemptContext {
                    session: [5; 32],
                    capacity: [6; 32],
                    slot: slot as u8,
                    predecessor: if slot == 0 { [0; 32] } else { [7; 32] },
                    nonce: [8; 32],
                },
            };
            let parts: Vec<_> = (0..=slot)
                .map(|i| kv::Segment {
                    root: &roots[i],
                    profile: &ag,
                    bytes: profiles[i].bytes(),
                    model: w.roots()[0],
                    quantization: p.recipes.digest,
                    tokens: 150,
                    receipt: if i == slot { [0; 32] } else { [7; 32] },
                })
                .collect();
            let required = p
                .recipes
                .required(&p.plan, &p.sources, &p.output, &p.softmax, &s, &tables)
                .unwrap();
            let mut fs = Fs::new(header, 0);
            let before = fs.digest();
            assert_eq!(
                p.verify_body(
                    &s,
                    &tables,
                    &parts,
                    header,
                    &[],
                    Fp3::ONE,
                    &mut fs,
                    &mut Vec::new().into_iter()
                )
                .unwrap_err(),
                "canonical dispatcher reservation differs"
            );
            assert_eq!(fs.digest(), before);
            let mut keys = vec![Key::new(Fp3::ZERO); required].into_iter();
            s.quantization[0] ^= 1;
            assert_eq!(
                p.verify_body(&s, &tables, &parts, header, &[], Fp3::ONE, &mut fs, &mut keys)
                    .unwrap_err(),
                "canonical dispatcher context differs"
            );
            assert_eq!(fs.digest(), before);
            s.quantization[0] ^= 1;
            // Mandatory public frame, then a canonically encoded P0 proof with
            // zero cohorts: the dispatcher must reach and reject the 773 guard.
            let mut certificate = header.to_vec();
            certificate.extend([0u8; 6]);
            certificate.extend(1u16.to_le_bytes());
            certificate.extend(52u32.to_le_bytes());
            certificate.extend([0u8; 52]);
            let mut expected = Fs::new(header, 1_000_000);
            assert_eq!(p.public_forms(&s, &mut expected).unwrap().len(), 4);
            Reader::record(&mut expected, &[0; 6]);
            let mut fs = Fs::new(header, 1_000_000);
            assert_eq!(
                p.verify_body(
                    &s,
                    &tables,
                    &parts,
                    header,
                    &certificate,
                    Fp3::ONE,
                    &mut fs,
                    &mut keys
                )
                .unwrap_err(),
                "Gemma P0 verifier capacity or cohort proof shape differs"
            );
            assert_eq!(keys.len(), required);
            assert_eq!(fs.digest(), expected.digest());
            assert!(fs.requests() > 0);
            certificate[header.len()] = 1; // cannot skip frame zero
            let mut fs = Fs::new(header, 0);
            assert!(p
                .verify_body(
                    &s,
                    &tables,
                    &parts,
                    header,
                    &certificate,
                    Fp3::ONE,
                    &mut fs,
                    &mut keys
                )
                .is_err());
            assert_eq!(fs.digest(), before);
        }
    }
}
