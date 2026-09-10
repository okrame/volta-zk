//! Synthetic encodings and complete framing. No witness or valid proof.
use super::*;
use kernel::wire::Wire;

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
fn checked<T: Wire>(bytes: Vec<u8>, frames: &mut Vec<Vec<u8>>) -> usize {
    let mut input = bytes.as_slice();
    let proof = T::read(&mut input).unwrap();
    assert!(input.is_empty(), "{} has trailing bytes", std::any::type_name::<T>());
    let mut output = Vec::new();
    proof.write(&mut output);
    assert_eq!(output, bytes);
    let n = bytes.len();
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
        macro_rules! record {
            ($ty:ty, $bytes:expr, $expected:expr) => {{
                let n = checked::<$ty>($bytes, &mut frames);
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
        );
        let second = checked::<bytes::quantize::Proof>(
            [vector((0..482).map(|_| fields(1))), vector(table.iter().map(encode_rne))].concat(),
            &mut frames,
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
        frames.push(codec::tests::maximal_linear_fixture(35));
        for _ in 0..=slot {
            frames.push(codec::tests::maximal_linear_fixture(34));
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
