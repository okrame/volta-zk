//! Fresh O=0 attention source routes. Q/K reuse original RoPE, V original
//! RMS, and PV's quantized output is the original o-projection P0 input.
//! Pi's softmax producer and accepted prior KV roots remain separate work.

use super::caller::{P0Statement, PendingP0};
use super::*;
use crate::c71_matrix::{attention as kernel, Fs};

pub(in crate::c71_matrix) struct Layer {
    pub q: usize,
    pub k: usize,
    pub v: usize,
    pub raw_score: usize,
    pub score: usize,
    pub pi: usize,
    pub raw_output: usize,
    pub output: usize,
    pub o_projection: usize,
    pub groups: usize,
    pub repeats: usize,
    pub lanes: usize,
}

pub(in crate::c71_matrix) struct Sources {
    pub rope: rope::Sources,
    pub layers: Vec<Layer>,
    pub view: [u8; 32],
}

impl Plan {
    pub fn attention_sources(&self) -> Result<Sources, String> {
        let rope = self.rope_sources()?;
        let base = rope.gate_up.gelu.rms.bytes.scalar.layout.sources.len();
        let (mut layers, mut extra) = (Vec::new(), Vec::new());
        for layer in 0..60 {
            let find = |query| {
                rope.rotations
                    .iter()
                    .find(|r| r.layer == layer && r.query == query)
                    .ok_or("attention original RoPE route missing")
            };
            let (q, k) = (find(true)?, find(false)?);
            let norms = &rope.gate_up.gelu.rms.norms;
            let v = norms
                .iter()
                .find(|n| n.layer == Some(u64::from(layer)) && n.operation == "v_norm")
                .ok_or("attention original V normalization missing")?;
            let mut o = self
                .cohorts
                .iter()
                .enumerate()
                .filter(|(_, c)| c.layer == Some(u64::from(layer)) && c.operation == "o_proj");
            let (o_id, o_cohort) = o.next().ok_or("attention o-projection missing")?;
            let route = self.input_route(o_id)?;
            if o.next().is_some()
                || o_cohort.kind != Kind::Matrix
                || q.heads != 32
                || k.width != q.width
                || v.rows != 150 * k.heads
                || v.heads != k.heads
                || v.columns != k.width
                || route.producer != (Some(u64::from(layer)), "pv_matmul".into())
                || route.row_offset != 0
                || route.selected_rows != 150
                || [route.rows, route.columns] != [150, 32 * q.width]
            {
                return Err("attention source axes or original P0 PV route differs".into());
            }
            let l = layers.len();
            layers.push(Layer {
                q: q.output,
                k: k.output,
                v: v.output,
                raw_score: base + 4 * l,
                score: base + 4 * l + 1,
                pi: base + 4 * l + 2,
                raw_output: base + 4 * l + 3,
                output: rope.gate_up.gelu.rms.bytes.scalar.input_sources[o_id - 1],
                o_projection: o_id,
                groups: k.heads,
                repeats: 32 / k.heads,
                lanes: q.width,
            });
            // ponytail: retain the existing 2-D byte layout. Query padding is
            // an explicit zero word per head; compact 3-D packing needs new forms.
            for (name, rows, cols, width) in [
                ("R", 32 * 256, 150, 6),
                ("X", 32 * 256, 150, 2),
                ("Pi", 32 * 256, 150, 2),
                ("Y", 150, 32 * q.width, 6),
            ] {
                extra.push((format!("attention/{layer}/{name}"), rows, cols, width));
            }
        }
        let rope = rope.append(extra)?;
        let mut digest = blake3::Hasher::new();
        digest
            .update(b"C71-attention-source-v1;fresh-O0;100+50;head-query-key;explicit-query-pad\0");
        digest.update(&rope.view);
        for l in &layers {
            for id in [
                l.q,
                l.k,
                l.v,
                l.raw_score,
                l.score,
                l.pi,
                l.raw_output,
                l.output,
                l.o_projection,
                l.groups,
                l.repeats,
                l.lanes,
            ] {
                digest.update(&(id as u64).to_le_bytes());
            }
        }
        Ok(Sources { rope, layers, view: *digest.finalize().as_bytes() })
    }
}

impl Sources {
    pub(super) fn append(
        mut self,
        extra: Vec<(String, usize, usize, usize)>,
    ) -> Result<Self, String> {
        self.rope = self.rope.append(extra)?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"C71-attention-view-A-extension-v1\0");
        digest.update(&self.view);
        digest.update(&self.rope.view);
        self.view = *digest.finalize().as_bytes();
        Ok(self)
    }

    pub fn qk_forms<T: Copy>(
        &self,
        layer: usize,
        p: &kernel::QkPending<T>,
    ) -> Result<([Vec<Cube>; 3], [Fp3; 3], [T; 3]), String> {
        let l = self.layers.get(layer).ok_or("attention QK layer missing")?;
        let cols = bits(32 * l.lanes);
        if p.raw_point.len() != 21
            || p.q_point.len() != 8 + cols
            || p.k_point.len() != 8 + bits(l.groups * l.lanes)
        {
            return Err("attention original QK source point differs".into());
        }
        let bytes = &self.rope.gate_up.gelu.rms.bytes;
        let parts = [
            bytes.word_form(l.raw_score, &p.raw_point[..13], &p.raw_point[13..], Fp3::ONE)?,
            bytes.word_form(l.q, &p.q_point[..8], &p.q_point[8..], Fp3::ONE)?,
            bytes.word_form(l.k, &p.k_point[..8], &p.k_point[8..], Fp3::ONE)?,
        ];
        let shifts = std::array::from_fn(|i| parts[i].1);
        Ok((parts.map(|p| p.0), shifts, p.originals))
    }

    pub fn pv_forms<T: Copy>(
        &self,
        layer: usize,
        p: &kernel::PvPending<T>,
    ) -> Result<([Vec<Cube>; 3], [Fp3; 3], [T; 3]), String> {
        let l = self.layers.get(layer).ok_or("attention PV layer missing")?;
        if p.raw_point.len() != 8 + bits(32 * l.lanes)
            || p.pi_point.len() != 21
            || p.v_point.len() != 8 + bits(l.groups * l.lanes)
        {
            return Err("attention original PV source point differs".into());
        }
        let bytes = &self.rope.gate_up.gelu.rms.bytes;
        let parts = [
            bytes.word_form(l.raw_output, &p.raw_point[..8], &p.raw_point[8..], Fp3::ONE)?,
            bytes.word_form(l.pi, &p.pi_point[..13], &p.pi_point[13..], Fp3::ONE)?,
            bytes.word_form(l.v, &p.v_point[..8], &p.v_point[8..], Fp3::ONE)?,
        ];
        let shifts = std::array::from_fn(|i| parts[i].1);
        Ok((parts.map(|p| p.0), shifts, p.originals))
    }

    pub fn score_rne_pairs(&self, shifts: &[i32]) -> Result<Vec<bytes::quantize::Pair>, String> {
        if shifts.len() != self.layers.len() {
            return Err("attention score RNE shifts differ".into());
        }
        Ok(self
            .layers
            .iter()
            .zip(shifts)
            .map(|(l, &shift)| bytes::quantize::Pair { raw: l.raw_score, output: l.score, shift })
            .collect())
    }

    pub fn output_rne_requests<T: Copy>(
        &self,
        plan: &Plan,
        pending: &PendingP0<T>,
    ) -> Result<Vec<bytes::RneRequest<T>>, String> {
        let bytes = &self.rope.gate_up.gelu.rms.bytes;
        if bytes.scalar.weight_layout != plan.layout_digest
            || pending.inputs.len() + 1 != plan.cohorts.len()
        {
            return Err("attention original P0 inputs differ".into());
        }
        self.layers
            .iter()
            .enumerate()
            .map(|(layer, l)| {
                let p = &pending.inputs[l.o_projection - 1];
                let route = plan.input_route(l.o_projection)?;
                if p.cohort != l.o_projection
                    || route.producer != (Some(layer as u64), "pv_matmul".into())
                    || route.row_offset != 0
                    || route.selected_rows != 150
                    || [route.rows, route.columns] != [150, 32 * l.lanes]
                    || p.point.len() != 8 + bits(32 * l.lanes)
                {
                    return Err("attention original o-projection point or producer differs".into());
                }
                let (view, shape) = bytes.source_rne_view(l.raw_output)?;
                Ok(bytes::RneRequest {
                    consumer: l.o_projection,
                    source: l.raw_output,
                    view,
                    shape,
                    point: p.point.clone(),
                    original: p.original,
                })
            })
            .collect()
    }

    pub fn statement<'a>(
        &'a self,
        s: &'a P0Statement<'_>,
        layer: usize,
        fs: &mut Fs,
    ) -> Result<kernel::Statement<'a>, String> {
        let l = self.layers.get(layer).ok_or("attention layer missing")?;
        let bytes = &self.rope.gate_up.gelu.rms.bytes;
        if s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.tokens.len() != 150
            || s.auxiliary_layout.layout.layout_digest != bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != bytes.scalar.weight_layout
        {
            return Err("attention fixed W/A or quantization context differs".into());
        }
        let mut transcript =
            b"C71-canonical-attention-B12-v1;original-W-A;fresh-O0;100+50\0".to_vec();
        transcript.extend(s.weights.roots()[0]);
        transcript.extend(s.auxiliary.roots()[0]);
        for g in [s.weight_gamma, s.auxiliary_gamma] {
            transcript.extend((g.len() as u64).to_le_bytes());
            transcript.extend(g);
        }
        transcript.extend(s.quantization);
        transcript.extend(s.attempt.encode());
        transcript.extend(self.view);
        transcript.extend((layer as u64).to_le_bytes());
        fs.set_phase(0x1220);
        fs.record(0xf5, &transcript);
        Ok(kernel::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.view,
            attempt: s.attempt,
            layer: layer as u8,
            old: 0,
            prompt: 100,
            tokens: 150,
            groups: l.groups,
            repeats: l.repeats,
            lanes: l.lanes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::caller::InputOpening;
    use super::*;
    use crate::c71_matrix::{signed, AttemptContext, C61Commitment};

    #[test]
    fn c71_b12_gemma_attention_sources_reuse_original_rope_rms_p0_and_recount_d34() {
        let plan = compile().unwrap();
        let before = plan.rope_sources().unwrap();
        let sources = plan.attention_sources().unwrap();
        let bytes = &sources.rope.gate_up.gelu.rms.bytes;
        assert_eq!(sources.layers.len(), 60);
        assert_eq!(bytes.scalar.layout.sources.len(), 2926);
        assert_eq!(bytes.live, 11641220238);
        assert_eq!(bits(bytes.live), 34);
        assert_ne!(sources.rope.view, before.view);
        for (old, new) in before.rotations.iter().zip(&sources.rope.rotations) {
            assert_eq!([old.norm, old.raw, old.output], [new.norm, new.raw, new.output]);
        }
        let point = |n| (0..n).map(|i| signed(i as i64 + 3)).collect::<Vec<_>>();
        let mut cube_count = 0;
        for (layer, l) in sources.layers.iter().enumerate() {
            assert_eq!(
                [l.groups, l.repeats, l.lanes],
                if layer % 6 == 5 { [4, 8, 512] } else { [16, 2, 256] }
            );
            for (id, op) in
                [(l.q, "q_rope"), (l.k, "k_rope"), (l.v, "v_norm"), (l.output, "pv_matmul")]
            {
                assert_eq!(bytes.scalar.layout.sources[id].name, format!("X/{layer}/{op}"));
            }
            assert_eq!(bytes.scalar.layout.sources[l.raw_score].rows, 8192);
            assert_eq!(bytes.scalar.layout.sources[l.raw_score].cols, 150);
            let q = kernel::QkPending {
                raw_point: point(21),
                q_point: point(8 + bits(32 * l.lanes)),
                k_point: point(8 + bits(l.groups * l.lanes)),
                originals: [6 * layer, 6 * layer + 1, 6 * layer + 2],
            };
            let (f, _, targets) = sources.qk_forms(layer, &q).unwrap();
            assert_eq!(targets, q.originals);
            assert_eq!(f.each_ref().map(Vec::len), [8, 4, 4]);
            cube_count += f.iter().map(Vec::len).sum::<usize>();
            let v = kernel::PvPending {
                raw_point: point(8 + bits(32 * l.lanes)),
                pi_point: point(21),
                v_point: point(8 + bits(l.groups * l.lanes)),
                originals: [6 * layer + 3, 6 * layer + 4, 6 * layer + 5],
            };
            let (f, _, targets) = sources.pv_forms(layer, &v).unwrap();
            assert_eq!(targets, v.originals);
            assert_eq!(f.each_ref().map(Vec::len), [8, 4, 4]);
            cube_count += f.iter().map(Vec::len).sum::<usize>();
        }
        assert_eq!(cube_count, 1920);
        let pairs = sources.score_rne_pairs(&[0; 60]).unwrap();
        let pending: Vec<_> = sources
            .layers
            .iter()
            .enumerate()
            .map(|(i, l)| {
                assert_eq!((pairs[i].raw, pairs[i].output), (l.raw_score, l.score));
                bytes::quantize::Opening {
                    output_point: point(21),
                    output: 2 * i,
                    raw_point: point(24),
                    raw: 2 * i + 1,
                }
            })
            .collect();
        let (forms, _, targets) = bytes.table_rne_forms(&plan, &pairs, &pending).unwrap();
        assert_eq!(targets, (0..120).collect::<Vec<_>>());
        assert_eq!(forms.iter().map(Vec::len).sum::<usize>(), 720);
        assert!(bytes.table_rne_required(&plan, &pairs).is_err());
        let p0 = PendingP0 {
            cuts: Vec::new(),
            weight_forms: Vec::new(),
            weights: Vec::new(),
            inputs: (1..plan.cohorts.len())
                .map(|id| {
                    let route = plan.input_route(id).unwrap();
                    InputOpening {
                        cohort: id,
                        point: point(bits(route.selected_rows) + bits(route.columns)),
                        route,
                        original: id,
                    }
                })
                .collect(),
        };
        let requests = sources.output_rne_requests(&plan, &p0).unwrap();
        assert_eq!(requests.len(), 60);
        let mut dims = 0;
        let mut cubes = 0;
        for (r, l) in requests.iter().zip(&sources.layers) {
            assert_eq!(r.source, l.raw_output);
            assert_eq!(r.consumer, l.o_projection);
            assert_eq!(r.original, p0.inputs[l.o_projection - 1].original);
            assert_eq!(r.point, p0.inputs[l.o_projection - 1].point);
            assert_eq!(r.shape, [150, 32 * l.lanes]);
            dims += r.point.len();
            cubes += bytes.source_rne_form(r.source, &point(r.point.len() + 3)).unwrap().len();
        }
        assert_eq!(dims, 1270);
        assert_eq!(cubes, 480);
        assert_eq!(61947 + cube_count + 720 + cubes, 65067);
        assert_eq!(3649 + 360 + 120 + 60, 4189);
        assert!(4189 <= crate::c71_matrix::linear::MAX_TARGETS);
        assert!(65067 <= crate::c71_matrix::linear::MAX_CUBES);
        let root = C61Commitment::new(vec![[1; 32]]);
        let wroot = C61Commitment::new(vec![[2; 32]]);
        let profile = [3; 32];
        let tokens = [0; 150];
        let context = P0Statement {
            weights: &wroot,
            auxiliary: &root,
            weight_gamma: &profile,
            auxiliary_gamma: &profile,
            auxiliary_layout: &bytes.scalar,
            quantization: [4; 32],
            tokens: &tokens,
            attempt: AttemptContext {
                session: [1; 32],
                capacity: [2; 32],
                slot: 0,
                predecessor: [0; 32],
                nonce: [3; 32],
            },
        };
        let mut fs = Fs::new(b"canonical attention metadata only", 1000);
        for layer in 0..60 {
            let s = sources.statement(&context, layer, &mut fs).unwrap();
            assert_eq!([s.old, s.prompt, s.tokens], [0, 100, 150]);
            assert!(s.qk_required().is_err()); // no D27/D28 execution
        }
        assert_eq!(fs.requests(), 0);
        assert!(sources.statement(&context, 60, &mut fs).is_err());
        assert!(sources
            .statement(&P0Statement { tokens: &tokens[..149], ..context }, 0, &mut fs)
            .is_err());
        assert_eq!(
            sources.rope.forms(&point(27), &point(27)).unwrap().0.each_ref().map(Vec::len),
            [960, 480]
        );
        assert_eq!(
            sources.rope.gate_up.forms(&point(28), &point(28)).unwrap().0.each_ref().map(Vec::len),
            [1440, 720, 720]
        );
        assert_eq!(
            sources.rope.gate_up.gelu.forms(&point(28)).unwrap().0.each_ref().map(Vec::len),
            [720, 720, 960]
        );
    }
}
