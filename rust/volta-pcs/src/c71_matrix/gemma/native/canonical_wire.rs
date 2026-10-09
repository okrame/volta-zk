//! Synthetic encodings and complete framing. No witness or valid proof.
use super::*;
use kernel::wire::Wire;
use kernel::wire::HeapCapacity;

#[derive(Default)]
struct FrameCapacity {
    largest_body: usize,
    largest_heap_upper: usize,
    largest_decoder_peak_upper: usize,
    largest_proof_and_moving_body_upper: usize,
}
impl FrameCapacity {
    fn include(&mut self, heap: HeapCapacity, body: usize) {
        assert!(heap.retained <= heap.shape_upper);
        // Enclosing bound for these honest fixed schemas, including Option
        // inline objects and salt matrix Vec descriptors; not a Wire API bound.
        assert!(heap.shape_upper <= 16 * body.max(1));
        self.largest_body = self.largest_body.max(body);
        self.largest_heap_upper = self.largest_heap_upper.max(heap.shape_upper);
        self.largest_decoder_peak_upper = self.largest_decoder_peak_upper.max(heap.decoder_peak_upper());
        // Vec<u8> append growth can retain <=2L and move old< L +new<=2L.
        // The proof stays live while Writer::put/codec constructs this body.
        self.largest_proof_and_moving_body_upper = self.largest_proof_and_moving_body_upper
            .max(heap.shape_upper + 3 * body.max(8));
    }
}

fn fields(n: usize) -> Vec<u8> {
    vec![0; 24 * n]
}
fn vector(rows: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let rows: Vec<_> = rows.into_iter().collect();
    [(rows.len() as u32).to_le_bytes().to_vec(), rows.concat()].concat()
}
fn reduction(c: usize, cubic: bool) -> Vec<u8> {
    [vector((0..c).map(|_| vector((0..if cubic { 5 } else { 4 }).map(|_| fields(1))))), fields(4)]
        .concat()
}
fn tree(depth: usize, top: usize) -> Vec<u8> {
    vector((0..depth).rev().map(|i| [vector((0..top + i).map(|_| fields(5))), fields(8)].concat()))
}
fn lookup(cells: usize) -> Vec<u8> {
    [fields(2), tree(bits(cells), 0), fields(7)].concat()
}
fn byte_function(c: usize) -> Vec<u8> {
    [tree(8, c), fields(3)].concat()
}
fn joint_upper(c: usize) -> Vec<u8> {
    let rounds = vector(
        (0..c)
            .map(|_| vector((0..5).map(|_| fields(1))))
            .chain((0..28).map(|_| vector((0..4).map(|_| fields(1))))),
    );
    [
        vector((0..128).map(|_| [rounds.clone(), fields(4)].concat())),
        fields(2),
        byte_function(c + 4),
    ]
    .concat()
}
fn rne_record(c: usize, shift: i32) -> Vec<u8> {
    let terminals = (kernel::rne::wire_bytes(c, shift) - kernel::rne::wire_min_bytes(c)) / 24;
    [
        vector((0..c).map(|_| fields(9))),
        vector((0..terminals).map(|_| fields(1))),
        fields(3),
        byte_function(c + 3),
    ]
    .concat()
}
fn checked<T: Wire>(bytes: Vec<u8>, frames: &mut Vec<Vec<u8>>, capacities: &mut FrameCapacity) -> usize {
    let mut input = bytes.as_slice();
    let proof = T::read(&mut input).unwrap();
    assert!(input.is_empty(), "{} has trailing bytes", std::any::type_name::<T>());
    let mut output = Vec::new();
    proof.write(&mut output);
    assert_eq!(output, bytes);
    let n = bytes.len();
    capacities.include(proof.heap_capacity(), n);
    frames.push(bytes);
    n
}

#[test]
fn c71_b12_native_canonical_wire_body_geometry() {
    let plan = super::super::super::compile().unwrap();
    let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
    let mut exponents: BTreeMap<_, _> =
        profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
    for l in &sm.layers {
        exponents.insert(l.pi, -14);
    }
    for slot in 0..3 {
        let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
        let a = &p.sources.attention;
        let rope = &a.rope;
        let gu = &rope.gate_up;
        let g = &gu.gelu;
        let rms = &g.rms;
        let (t, k) = (bits(150), bits(150 * (slot + 1)));
        // Includes the outer headers for PCS frames, but no PCS payload/header.
        let mut body = 6 * (135 + slot) + 26;
        let mut frames = vec![Vec::new()];
        let mut capacities = FrameCapacity::default();
        macro_rules! record {
            ($ty:ty, $bytes:expr, $expected:expr) => {{
                let n = checked::<$ty>($bytes, &mut frames, &mut capacities);
                assert_eq!(n, $expected, "{} slot={slot}", stringify!($ty));
                body += n;
            }};
        }
        let cohorts = vector(p.plan.cohorts.iter().map(|c| {
            let proof = match c.kind {
                Kind::Lookup => vec![0],
                Kind::Norm => [vec![1], reduction(bits(c.columns), true)].concat(),
                Kind::Matrix => [vec![1], reduction(bits(c.inner), false)].concat(),
            };
            [fields(1), proof].concat()
        }));
        record!(caller::Proof, [cohorts, fields(2)].concat(), 1_153_889);
        let statistics = vector(
            rms.norms
                .iter()
                .map(|n| [fields(1), reduction(bits(n.rows) + bits(n.columns), true)].concat()),
        );
        record!(
            rms::caller::Proof,
            [statistics, fields(2), joint_upper(bits(rms.cells))].concat(),
            1_132_420 + 868_224
        );
        let table = p.recipes.table_pairs(&p.plan).unwrap();
        let table_ids: BTreeSet<_> = table.iter().map(|r| r.raw).collect();
        let mut original = Vec::new();
        for step in &p.steps {
            if let Producer::Rne(pair) = step {
                if !table_ids.contains(&pair.raw) {
                    original.push(*pair);
                }
            }
        }
        assert_eq!((original.len(), table.len()), (410, 482));
        let encode_rne = |pair: &Pair| {
            let (_, shape) = p.bytes().source_rne_view(pair.raw).unwrap();
            rne_record(bits(shape[0]) + bits(shape[1]), pair.shift)
        };
        let first = checked::<Vec<kernel::rne::Proof>>(
            vector(original.iter().map(encode_rne)),
            &mut frames,
            &mut capacities,
        );
        let second = checked::<bytes::quantize::Proof>(
            [vector((0..482).map(|_| fields(1))), vector(table.iter().map(encode_rne))].concat(),
            &mut frames,
            &mut capacities,
        );
        assert_eq!(first + second, p.rne_wire_bytes().unwrap().2 + 11_580);
        body += first + second;
        record!(kernel::lookup::Proof, lookup(g.cells), 51_068);
        record!(
            gate_up::Proof,
            [fields(1), reduction(bits(gu.cells), true), fields(2)].concat(),
            3_644
        );
        record!(
            kernel::rope::Proof,
            [fields(1), vector((0..bits(rope.cells)).map(|_| fields(4))), fields(2)].concat(),
            2_668
        );
        let (mut qk, mut pv) = (0, 0);
        for layer in &a.layers {
            qk += checked::<kernel::attention::QkProof>(
                [
                    fields(1),
                    reduction(t + k + bits(layer.groups) + bits(layer.lanes), true),
                    fields(2),
                ]
                .concat(),
                &mut frames,
                &mut capacities,
            );
            pv += checked::<kernel::attention::PvProof>(
                [
                    fields(1),
                    reduction(bits(layer.groups) + k, true),
                    fields(2),
                    vector((0..t + k).map(|_| fields(4))),
                    fields(2),
                ]
                .concat(),
                &mut frames,
                &mut capacities,
            );
        }
        assert_eq!((qk, pv), if slot == 0 { (217_400, 192_400) } else { (224_840, 205_600) });
        body += qk + pv;
        record!(kv::Proof, vector((0..slot).map(|_| fields(1))), 4 + 24 * slot);
        let output = &p.bytes().scalar.layout.sources[p.output.input];
        record!(kernel::lookup::Proof, lookup(output.rows * output.cols + 65535), 38_044);
        let exp_cells: usize = p
            .softmax
            .layers
            .iter()
            .map(|l| {
                let s = &p.bytes().scalar.layout.sources[l.difference];
                s.rows * s.cols + 65535
            })
            .sum();
        let ratio = joint_upper(19 + k);
        let ratio_bytes = ratio.len();
        assert_eq!(ratio_bytes, if slot == 0 { 834_560 } else { 851_392 });
        record!(
            softmax::Proof,
            [tree(k, 19), fields(3), lookup(exp_cells), ratio].concat(),
            if slot == 0 { 23_244 + 47_632 + 834_560 } else { 26_680 + 51_068 + 851_392 }
        );
        for (c, alphabet, expected) in [(35, 65535, 1_651_252), (34, 256, 80_280)] {
            record!(
                kernel::range::Proof,
                [vector((0..alphabet).map(|_| fields(1))), fields(3), tree(c, 0), fields(3)]
                    .concat(),
                expected
            );
        }
        assert_eq!(body, [36_913_833, 37_028_767, 37_028_797][slot]);
        // Replace the selected RNE terminal census by its universal upper.
        let (_, lower_rne, selected_rne) = p.rne_wire_bytes().unwrap();
        assert_eq!(
            body - selected_rne + lower_rne + 24 * 892 * 77,
            [37_329_009, 37_443_943, 37_443_973][slot]
        );
        let mut pcs_capacity = Vec::new();
        for h in std::iter::once(35).chain((0..=slot).map(|_| 34)) {
            let bytes = codec::tests::maximal_linear_fixture(h);
            let proof = codec::decode_linear(Domain::Flat(h), &bytes).unwrap();
            let heap = codec::tests::matrix_heap_capacity(&proof);
            capacities.include(heap.total, bytes.len());
            pcs_capacity.push(serde_json::json!({"dimension":h,
                "body_bytes":bytes.len(),"decoded_heap_capacity_bytes":heap.total.retained,
                "honest_typed_heap_upper_bytes":heap.total.shape_upper,
                "decoder_moving_peak_upper_bytes":heap.total.decoder_peak_upper(),
                "opening_heap_upper_class3":heap.openings.shape_upper,
                "blinded_reveal_heap_upper_class11":heap.blinded_reveals.shape_upper,
                "other_heap_upper_class5":heap.other.shape_upper}));
            frames.push(bytes);
        }
        assert_eq!(frames.len(), 135 + slot);
        // Header-sized fixture, not the registry's actual acceptance context.
        let header = vec![0; 5875 + 720 * slot];
        let mut fs = Fs::new(&header, 0);
        let mut writer = super::super::protocol::Writer::canonical(&header);
        for (kind, frame) in frames.iter().enumerate() {
            writer.raw(kind as u16, frame, &mut fs).unwrap();
        }
        let (mut certificate, digest) = writer.finish(&mut fs);
        assert_eq!(certificate.len(), body + header.len() + 13_941_532 + (slot + 1) * 13_776_828);
        assert_eq!(certificate.len(), [64_638_068, 78_530_550, 92_308_128][slot]);
        // Exponents change the <=77 RNE terminal fields, not the remaining
        // schema. Add their entire universal budget rather than crediting
        // this zero-exponent fixture's selected smaller terminal vectors.
        let rne_terminal_heap = 892 * kernel::wire::vector_shape_upper::<kernel::Fp3>(77);
        let rne_terminal_wire = 892 * 77 * 24;
        let decoder_upper = capacities.largest_decoder_peak_upper + rne_terminal_heap;
        let proof_and_body_upper = capacities.largest_proof_and_moving_body_upper
            + rne_terminal_heap + 3 * rne_terminal_wire;
        println!("C71_CANONICAL_WIRE_HEAP {}",serde_json::json!({"slot":slot,
            "W_targets":775,"A_targets":4446,"rne_records":892,"pcs_batches":12,
            "p0_proof_inline_bytes":std::mem::size_of::<kernel::p0::Proof>(),
            "p0_optional_proof_inline_bytes":std::mem::size_of::<Option<kernel::p0::Proof>>(),
            "p0_cohort_inline_bytes":std::mem::size_of::<(kernel::Fp3,Option<kernel::p0::Proof>)>(),
            "max_selected_frame_bytes":capacities.largest_body,
            "max_typed_heap_upper_bytes":capacities.largest_heap_upper + rne_terminal_heap,
            "max_decoder_heap_moving_upper_bytes":decoder_upper,
            "max_proof_and_body_encode_moving_upper_bytes":proof_and_body_upper,
            "writer_capacity_bytes":kernel::wire::CANONICAL_MAX_BYTES,
            "P_encode_wire_class_upper_bytes":kernel::wire::CANONICAL_MAX_BYTES + proof_and_body_upper,
            "P_certificate_and_V_receive_and_decoder_class_upper_bytes":
                2 * kernel::wire::CANONICAL_MAX_BYTES + decoder_upper,
            "pcs":pcs_capacity,"credit":false,"scope":"typed honest pinned schema; no numeric witness, GPU, canonical allocator peak or joint admission; opening and blinded reveal payloads partitioned to avoid cross-class duplication"}));
        assert!(certificate.len() < kernel::wire::CANONICAL_MAX_BYTES);
        assert!(super::super::protocol::Reader::new(&certificate, &header).is_err());
        assert_eq!(read_transport(&certificate, &header, frames.len()).unwrap(), digest);
        assert!(
            read_transport(&certificate[..certificate.len() - 1], &header, frames.len()).is_err()
        );
        certificate[header.len()] ^= 1;
        assert!(read_transport(&certificate, &header, frames.len()).is_err());
        certificate[header.len()] ^= 1;
        certificate.push(0);
        assert!(read_transport(&certificate, &header, frames.len()).is_err());
    }
}

fn read_transport(certificate: &[u8], header: &[u8], count: usize) -> Result<[u8; 32], String> {
    use super::super::protocol::Reader;
    let mut reader = Reader::canonical(certificate, header)?;
    let mut fs = Fs::new(header, 0);
    for kind in 0..count {
        let (_, frame) = reader.raw(kind as u16)?;
        Reader::record(&mut fs, frame);
    }
    reader.finish(&mut fs)
}
