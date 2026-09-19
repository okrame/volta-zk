//! C71-SOFTMAX-EXP30-v1. Original scores and Pi, maximum/differences,
//! exponential lookup, denominator and exact RNE all close in the SAME A.

use super::caller::P0Statement;

component_wire!(Proof { maximum, max_leaf_tag, max_products, lookup, ratio });
use super::rms::prefix;
use super::*;
use crate::c71_matrix::{
    byte_function, lookup, range, record_values, rms as circuit, signed, Auth, Fs, Key,
};
use circuit::gkr;
use volta_field::Fp;

pub(in crate::c71_matrix) struct Layer {
    pub score: usize,
    pub pi: usize,
    pub maximum: usize,
    pub difference: usize, // signed i16 D-32767; encoded word is D+1
    pub exponential: usize,
    pub denominator: usize,
    pub histogram: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c71_matrix::{
        from_p3, gamma, linear, matrix_config, AttemptContext, C61Commitment, MatrixRng, Model, E,
    };
    use rand_010::{RngExt, SeedableRng};

    #[test]
    fn c71_exp30_ratio_cache_matches_original_bytes_and_causal_padding() {
        for old in [0, 2, 5] {
            let sm = Softmax {
                layers: (0..2)
                    .map(|i| Layer {
                        score: i * 7,
                        pi: i * 7 + 1,
                        maximum: i * 7 + 2,
                        difference: i * 7 + 3,
                        exponential: i * 7 + 4,
                        denominator: i * 7 + 5,
                        histogram: i * 7 + 6,
                    })
                    .collect(),
                heads: 2,
                queries: 3,
                old,
            };
            let read = |id, row, col, b| ((id * 71 + row * 23 + col * 11 + b) % 256) as u8;
            let calls = std::cell::Cell::new(0);
            let cache = RatioFrames::build(&sm, &|id, row, col, b| {
                calls.set(calls.get() + 1);
                read(id, row, col, b)
            })
            .unwrap();
            assert_eq!(calls.get(), 6 * (cache.cells.len() + cache.denominators.len()));
            for i in 0..1 << (sm.row_bits() + sm.key_bits()) {
                let mut expected = [0; 12];
                if let Some((layer, row, key)) = sm.cell(i) {
                    let l = &sm.layers[layer];
                    for (id, col, offset, width) in
                        [(l.exponential, key, 0, 4), (l.denominator, 0, 4, 6), (l.pi, key, 10, 2)]
                    {
                        for b in 0..width {
                            expected[offset + b] = read(id, row, col, b);
                        }
                    }
                }
                assert_eq!(cache.frame(&sm, i), expected);
            }
        }
    }

    #[test]
    fn maximum_checkpoint_and_source_tree_match_dense_transcript() {
        let sm = Softmax {
            layers: vec![Layer {
                score: 0,
                pi: 0,
                maximum: 0,
                difference: 0,
                exponential: 0,
                denominator: 0,
                histogram: 0,
            }],
            heads: 1,
            queries: 3,
            old: 1,
        };
        let q = [[-1i32, 0, 2, 5], [7, 0, 3, 1], [9, 4, 0, 6], [1; 4]];
        let read = |_: usize, row: usize, key: usize, byte: usize| {
            let encoded = ((q[row][key] - 32767) as i16).to_le_bytes();
            encoded[byte] ^ if byte == 1 { 128 } else { 0 }
        };
        let domain = 1usize << (sm.row_bits() + sm.key_bits());
        let mut bottom = vec![[Fp3::ZERO, Fp3::ONE]; domain];
        for (index, value) in bottom.iter_mut().enumerate() {
            if let Some((layer, row, key)) = sm.cell(index) {
                value[1] =
                    signed(Softmax::word(&read, sm.layers[layer].difference, row, key, 2) + 32767);
            }
        }
        let mut tree = vec![bottom];
        for _ in 0..sm.key_bits() {
            tree.push(
                tree.last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| [Fp3::ZERO, pair[0][1] * pair[1][1]])
                    .collect(),
            );
        }
        let mut checkpoint = MaximumCheckpoint::default();
        for layer in 0..sm.key_bits() {
            for index in 0..1usize << (sm.row_bits() + layer) {
                let pair = &tree[sm.key_bits() - 1 - layer][2 * index..2 * index + 2];
                assert_eq!(
                    checkpoint.children(&sm, &read, layer, index),
                    [pair[0][0], pair[0][1], pair[1][0], pair[1][1]]
                );
            }
        }
        assert_eq!(checkpoint.work.checkpoint_builds, sm.key_bits() as u64);
        assert_eq!(checkpoint.work.source_byte_getter_calls, 36);
        assert_eq!(checkpoint.work.base_field_products, 9);
        assert_eq!(checkpoint.work.checkpoint_scalar_writes, 24);
        assert!(checkpoint.work.checkpoint_capacity_peak_bytes <= 4 * domain);

        let point = vec![signed(3), signed(5)];
        let claims = [Auth::new(signed(7), signed(11)), Auth::new(signed(13), signed(17))];
        let mut rng = MatrixRng::from_seed([199; 32]);
        let correlations = (0..4096)
            .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
            .collect::<Vec<_>>();
        let start = || Fs::new(b"maximum dense/source transcript", 10000);
        let mut dense_fs = start();
        let mut dense_rows = correlations.clone().into_iter();
        let mut dense_triples = Vec::new();
        let (dense_layers, dense_point, dense_claims) = range::prove_tree(
            &tree,
            point.clone(),
            claims,
            &mut dense_fs,
            &mut dense_rows,
            &mut dense_triples,
        );
        let mut source_fs = start();
        let mut source_rows = correlations.into_iter();
        let mut source_triples = Vec::new();
        let source_checkpoint = std::cell::RefCell::new(MaximumCheckpoint::default());
        let (source_layers, source_point, source_claims, _) = range::prove_tree_sourcewise(
            sm.key_bits(),
            point,
            claims,
            |layer, index| source_checkpoint.borrow_mut().children(&sm, &read, layer, index),
            &mut source_fs,
            &mut source_rows,
            &mut source_triples,
        );
        let mut dense_wire = Vec::new();
        let mut source_wire = Vec::new();
        crate::c71_matrix::wire::Wire::write(&dense_layers, &mut dense_wire);
        crate::c71_matrix::wire::Wire::write(&source_layers, &mut source_wire);
        assert_eq!(dense_wire, source_wire);
        assert_eq!(dense_point, source_point);
        assert_eq!(dense_claims.map(|a| (a.x, a.m)), source_claims.map(|a| (a.x, a.m)));
        assert_eq!(
            dense_triples.iter().flatten().map(|a| (a.x, a.m)).collect::<Vec<_>>(),
            source_triples.iter().flatten().map(|a| (a.x, a.m)).collect::<Vec<_>>()
        );
        let dense_products =
            range::prove_products(&dense_triples, dense_rows.next().unwrap(), &mut dense_fs);
        let source_products =
            range::prove_products(&source_triples, source_rows.next().unwrap(), &mut source_fs);
        assert_eq!(dense_products, source_products);
        assert_eq!(dense_fs.requests(), source_fs.requests());
        assert_eq!(dense_fs.fp3(), source_fs.fp3());
        assert_eq!(dense_rows.len(), source_rows.len());
    }

    #[test]
    fn c71_b12_softmax_original_scores_exp30_denominator_rne_and_mask_share_one_a() {
        let plan = crate::c71_matrix::gemma::rms::tests::toy_plan(3, 2);
        let bytes = plan.auxiliary_bytes().unwrap();
        let base = bytes.scalar.layout.sources.len();
        let sm = Softmax {
            layers: vec![Layer {
                score: base,
                pi: base + 1,
                maximum: base + 2,
                difference: base + 3,
                exponential: base + 4,
                denominator: base + 5,
                histogram: base + 6,
            }],
            heads: 1,
            queries: 3,
            old: 1,
        };
        let bytes = bytes
            .append(vec![
                ("sm/score".into(), 4, 4, 2),
                ("sm/Pi".into(), 4, 4, 2),
                ("sm/max".into(), 4, 1, 2),
                ("sm/D".into(), 4, 4, 2),
                ("sm/E".into(), 4, 4, 4),
                ("sm/Z".into(), 4, 1, 6),
                ("sm/M".into(), 1, 8, 4),
            ])
            .unwrap();
        assert!(bytes.live <= 1024);
        let profile = gamma(&matrix_config(32).unwrap());
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        // Certified eScore=0 prefix, D=0..7. The canonical table spans 65535 D values.
        let exp =
            [1073741824i32, 395007542, 145315154, 53458458, 19666268, 7234816, 2661540, 979126];
        let tables =
            [lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I32(&exp) }];
        let delta = signed(53);
        for fault in 0..7u8 {
            let score = [[0i64, 0, -3, 2], [-1, 0, -2, 3], [1, 1, -1, -2], [0; 4]];
            let mut used = score;
            if fault == 5 {
                used[0][1] = -1;
            }
            let (mut maximum, mut difference, mut exponential, mut denominator, mut pi) =
                ([0i64; 4], [[0i64; 4]; 4], [[0i64; 4]; 4], [0i64; 4], [[0i64; 4]; 4]);
            for r in 0..4 {
                if r < 3 {
                    maximum[r] = *used[r][..=1 + r].iter().max().unwrap();
                }
                if fault == 1 && r == 1 {
                    maximum[r] += 1;
                }
                for c in 0..4 {
                    let allowed = r < 3 && c <= 1 + r;
                    if allowed {
                        difference[r][c] = maximum[r] - used[r][c];
                    }
                    exponential[r][c] = i64::from(exp[difference[r][c] as usize]);
                    if fault == 2 && r == 1 && c == 0 {
                        exponential[r][c] += 1;
                    }
                    if allowed {
                        denominator[r] += exponential[r][c];
                    }
                }
                if fault == 3 && r == 1 {
                    denominator[r] += 1;
                }
                for c in 0..4 {
                    if r < 3 && c <= 1 + r {
                        let n = 16384 * exponential[r][c];
                        let z = denominator[r];
                        let q = n / z;
                        let rem = n % z;
                        pi[r][c] = q + i64::from(2 * rem > z || (2 * rem == z && q % 2 == 1));
                    }
                }
            }
            if fault == 4 {
                pi[1][0] += 1;
            }
            if fault == 6 {
                pi[0][3] = 1;
            }
            let value = |id, r: usize, c: usize| -> i64 {
                if id < base {
                    return 0;
                }
                match id - base {
                    0 => score[r][c],
                    1 => pi[r][c],
                    2 => maximum[r],
                    3 => difference[r][c] - 32767,
                    4 => exponential[r][c],
                    5 => denominator[r],
                    6 => difference.iter().flatten().filter(|&&d| d == c as i64).count() as i64,
                    _ => unreachable!(),
                }
            };
            let read = |id: usize, r: usize, c: usize, b: usize| {
                ((value(id, r, c) as u64 >> (8 * b)) as u8)
                    ^ if b + 1 == bytes.widths[id] { 128 } else { 0 }
            };
            let mut packed = Vec::new();
            for (id, s) in bytes.scalar.layout.sources.iter().enumerate() {
                for r in 0..s.rows {
                    for c in 0..s.cols {
                        packed
                            .extend_from_slice(&value(id, r, c).to_le_bytes()[..bytes.widths[id]]);
                    }
                }
            }
            assert_eq!(packed.len(), bytes.live);
            let model = Model::new(
                32,
                (0..1024)
                    .map(|i| {
                        bytes
                            .virtual_to_packed(i)
                            .unwrap()
                            .map_or(0, |(a, x)| i16::from(packed[a] ^ x))
                    })
                    .collect(),
            )
            .unwrap();
            let context = P0Statement {
                weights: &model.root,
                auxiliary: &model.root,
                weight_gamma: &profile,
                auxiliary_gamma: &profile,
                auxiliary_layout: &bytes.scalar,
                quantization: [7; 32],
                attempt,
                tokens: &[0, 1, 2],
            };
            let count = sm.required(&bytes, &context, &tables).unwrap()
                + range::required(10, range::Alphabet::Byte)
                + 32;
            let mut rng = MatrixRng::from_seed([142 + fault; 32]);
            let rows = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect::<Vec<_>>();
            let keys = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect::<Vec<_>>();
            let start = || Fs::new(b"original EXP30 one ranged A", 100000);
            let zeros = |fs: &mut Fs| {
                let (f, b) = sm.zero_form(&bytes, &context, fs).unwrap();
                let (mask, mb) =
                    bytes.causal_zero_form(&plan, &context, &[base + 1], 1, 3, 1, fs).unwrap();
                (vec![f, mask], vec![b, mb])
            };
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (mut forms, zb) = zeros(&mut fs);
            let mut targets = zb.iter().map(|&b| Auth::new(b, Fp3::ZERO)).collect::<Vec<_>>();
            let before_softmax = fs.requests();
            let (proof, pending) =
                sm.prove(&bytes, &context, &tables, read, &mut fs, &mut prows).unwrap();
            assert_eq!(fs.requests() - before_softmax, 2360);
            let (f, b, t) = sm.forms(&bytes, &pending).unwrap();
            forms.extend(f);
            targets.extend(t.iter().zip(b).map(|(a, b)| Auth::new(a.x + b, a.m)));
            let (range, f, t) = range::prove(
                &model,
                attempt,
                bytes.layout_digest,
                bytes.live,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            forms.extend(f);
            targets.extend(t);
            let (pcs, digest) = linear::prove(
                &model,
                attempt,
                bytes.layout_digest,
                &forms,
                &targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert_eq!(prows.len(), 0);
            let requests = fs.requests();
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let (mut forms, zb) = zeros(&mut fs);
            let mut targets = zb.iter().map(|&b| Key::new(delta * b)).collect::<Vec<_>>();
            let result = (|| {
                let pending =
                    sm.verify(&bytes, &context, &tables, &proof, delta, &mut fs, &mut vrows)?;
                let (f, b, t) = sm.forms(&bytes, &pending)?;
                forms.extend(f);
                targets.extend(t.iter().zip(b).map(|(k, b)| Key::new(k.k + delta * b)));
                let (f, t) = range::verify(
                    32,
                    &model.root,
                    attempt,
                    bytes.layout_digest,
                    bytes.live,
                    range::Alphabet::Byte,
                    &range,
                    delta,
                    &mut fs,
                    &mut vrows,
                )?;
                forms.extend(f);
                targets.extend(t);
                linear::verify(
                    32,
                    &model.root,
                    attempt,
                    bytes.layout_digest,
                    &forms,
                    &targets,
                    &pcs,
                    delta,
                    &mut fs,
                    &mut vrows,
                )
            })();
            if fault == 0 {
                assert_eq!(result.unwrap(), digest);
                assert_eq!(vrows.len(), 0);
                assert_eq!(fs.requests(), requests);
                assert_eq!(count, 8096);
                let mut fs = start();
                let mut short =
                    vec![Auth::ZERO; sm.required(&bytes, &context, &tables).unwrap() - 1]
                        .into_iter();
                let before = short.len();
                assert!(sm
                    .prove(
                        &bytes,
                        &context,
                        &tables,
                        |_, _, _, _| panic!("getter before capacity"),
                        &mut fs,
                        &mut short
                    )
                    .is_err());
                assert_eq!(short.len(), before);
                assert_eq!(fs.requests(), 0);
                assert!(sm
                    .required(
                        &bytes,
                        &context,
                        &[lookup::Table {
                            profile: 0,
                            lower: -32767,
                            outputs: lookup::Outputs::I16(&[0; 8])
                        }]
                    )
                    .is_err());
            } else {
                assert!(result.is_err(), "fault {fault} accepted");
                eprintln!("EXP30 fault {fault}: {}", result.unwrap_err());
            }
        }
    }

    #[test]
    fn c71_b12_softmax_canonical_sources_and_vertex_forms_cover_all_three_attempts() {
        let plan = compile().unwrap();
        let w = C61Commitment::new(vec![[1; 32]]);
        let a = C61Commitment::new(vec![[2; 32]]);
        let profile = [3; 32];
        let tokens = [0; 150];
        let point = |n, salt| (0..n).map(|i| signed(i as i64 + salt)).collect::<Vec<_>>();
        let ratio = circuit::compile_ratio(14).unwrap();
        assert_eq!(ratio.levels.len(), 94);
        assert!(ratio.ports <= 98 && ratio.levels.iter().all(|l| l.len() <= 4096));
        for (slot, old) in [0, 150, 300].into_iter().enumerate() {
            let (sources, _, sm) = plan.softmax_sources_at(old).unwrap();
            let bytes = &sources.attention.rope.gate_up.gelu.rms.bytes;
            let allowed_cells =
                sm.layers.len() * sm.heads * (sm.queries * old + sm.queries * (sm.queries + 1) / 2);
            eprintln!(
                "canonical_EXP30_GKR O={old} {}",
                gkr::work_census(
                    std::slice::from_ref(&ratio),
                    &[allowed_cells as u64],
                    sm.row_bits() + sm.key_bits()
                )
                .unwrap()
            );
            assert_eq!(bytes.scalar.layout.sources.len(), 3471);
            assert_eq!(bits(bytes.live), 34);
            for (l, original) in sm.layers.iter().zip(&sources.attention.layers) {
                assert_eq!([l.score, l.pi], [original.score, original.pi]);
            }
            let rectangles = bytes::mask::allowed_rectangles(150, old).unwrap();
            let mut coverage = vec![0u8; 256 * (old + 150)];
            for &[q, h, k, w] in &rectangles {
                for r in q..q + h {
                    for c in k..k + w {
                        coverage[r * (old + 150) + c] += 1;
                    }
                }
            }
            for r in 0..256 {
                for c in 0..old + 150 {
                    assert_eq!(coverage[r * (old + 150) + c], u8::from(r < 150 && c <= old + r));
                }
            }
            let context = P0Statement {
                weights: &w,
                auxiliary: &a,
                weight_gamma: &profile,
                auxiliary_gamma: &profile,
                auxiliary_layout: &bytes.scalar,
                quantization: [4; 32],
                tokens: &tokens,
                attempt: AttemptContext {
                    session: [5; 32],
                    capacity: [6; 32],
                    slot: slot as u8,
                    predecessor: if slot == 0 { [0; 32] } else { [7; 32] },
                    nonce: [8; 32],
                },
            };
            let cb = sm.row_bits() + sm.key_bits();
            let pending = Pending {
                maximum_point: point(cb, 2),
                maximum: 0usize,
                lookup: lookup::Pending {
                    point: point(bits(sm.lookup_layout(bytes).1), 3),
                    originals: [1, 2, 3],
                },
                ratio_point: point(cb + 4, 4),
                ratio: 4,
            };
            let (f, _, t) = sm.forms(bytes, &pending).unwrap();
            assert_eq!(t, [0, 1, 2, 3, 4]);
            let mut fs = Fs::new(b"canonical EXP30 metadata only", 100000);
            let (zf, _) = sm.zero_form(bytes, &context, &mut fs).unwrap();
            assert_eq!(fs.requests(), cb + 1);
            assert_eq!(bytes.live, [13154672538, 14334320538, 15513968538][slot]);
            assert_eq!(rectangles.len(), [280, 402, 432][slot]);
            assert_eq!(
                f.iter().map(Vec::len).collect::<Vec<_>>(),
                [60 * rectangles.len(), 240, 240, 960, 240 * rectangles.len()]
            );
            assert_eq!(zf.len(), 360 + 180 * rectangles.len());
            let all_cubes =
                [103506, 111306, 110466][slot] + f.iter().map(Vec::len).sum::<usize>() + zf.len();
            assert_eq!(all_cubes, [239706, 306066, 319626][slot]);
            assert!(all_cubes < linear::MAX_CUBES);
        }
    }
}

pub(in crate::c71_matrix) struct Softmax {
    pub layers: Vec<Layer>,
    pub heads: usize,
    pub queries: usize,
    pub old: usize,
}

pub(in crate::c71_matrix) struct Proof {
    maximum: Vec<range::Layer>,
    max_leaf_tag: Fp3,
    max_products: [Fp3; 2],
    lookup: lookup::Proof,
    ratio: gkr::Proof,
}

pub(in crate::c71_matrix) struct Pending<T> {
    pub maximum_point: Vec<Fp3>,
    pub maximum: T,
    pub lookup: lookup::Pending<T>,
    pub ratio_point: Vec<Fp3>,
    pub ratio: T,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
struct MaximumCheckpointWork {
    source_byte_getter_calls: u64,
    base_field_products: u64,
    checkpoint_scalar_writes: u64,
    checkpoint_builds: u64,
    checkpoint_capacity_peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
struct MaximumSourceWork {
    checkpoint: MaximumCheckpointWork,
    tree: range::SourceTreeWork,
}

// Original E/Pi bytes for causal cells, and one original Z per live row.
// This is a bounded component cache, not another committed source or full A.
struct RatioFrames {
    cells: Vec<[u8; 6]>,
    denominators: Vec<[u8; 6]>,
}

impl RatioFrames {
    fn build(
        sm: &Softmax,
        read: &impl Fn(usize, usize, usize, usize) -> u8,
    ) -> Result<Self, String> {
        let per_head = sm.queries * sm.old + sm.queries * (sm.queries + 1) / 2;
        let cells = sm.layers.len() * sm.heads * per_head;
        let rows = sm.layers.len() * sm.heads * sm.queries;
        if 6 * (cells + rows) > 1 << 30 {
            return Err("EXP30 original frame cache exceeds component cap".into());
        }
        let mut cache = Self { cells: vec![[0; 6]; cells], denominators: vec![[0; 6]; rows] };
        for (layer, l) in sm.layers.iter().enumerate() {
            for head in 0..sm.heads {
                for q in 0..sm.queries {
                    let row = head * sm.queries.next_power_of_two() + q;
                    let begin = (layer * sm.heads + head) * per_head + q * sm.old + q * (q + 1) / 2;
                    for (id, offset, width) in [(l.exponential, 0, 4), (l.pi, 4, 2)] {
                        for k in 0..sm.old + q + 1 {
                            for b in 0..width {
                                cache.cells[begin + k][offset + b] = read(id, row, k, b);
                            }
                        }
                    }
                    for b in 0..6 {
                        cache.denominators[(layer * sm.heads + head) * sm.queries + q][b] =
                            read(l.denominator, row, 0, b);
                    }
                }
            }
        }
        #[cfg(test)]
        if std::env::var_os("C71_INTEGRATED_TRACE").is_some() {
            eprintln!(
                "C71_EXP30_RATIO_CACHE {}",
                serde_json::json!({
                "source_byte_getter_calls":6*(cells+rows),
                "payload_bytes":6*(cells+rows),
                "capacity_bytes":6*(cache.cells.capacity()+cache.denominators.capacity()),
                "full_A_materialized":false})
            );
        }
        Ok(cache)
    }

    fn frame(&self, sm: &Softmax, index: usize) -> [u8; 12] {
        let mut frame = [0; 12];
        if let Some((layer, row, key)) = sm.cell(index) {
            let (head, q) =
                (row / sm.queries.next_power_of_two(), row % sm.queries.next_power_of_two());
            let per_head = sm.queries * sm.old + sm.queries * (sm.queries + 1) / 2;
            let cell = (layer * sm.heads + head) * per_head + q * sm.old + q * (q + 1) / 2 + key;
            frame[..4].copy_from_slice(&self.cells[cell][..4]);
            frame[4..10]
                .copy_from_slice(&self.denominators[(layer * sm.heads + head) * sm.queries + q]);
            frame[10..].copy_from_slice(&self.cells[cell][4..]);
        }
        frame
    }
}

enum MaximumCheckpointData {
    Empty,
    Products(Vec<[Fp; 2]>),
    Leaves(Vec<[i32; 2]>),
}

struct MaximumCheckpoint {
    layer: Option<usize>,
    data: MaximumCheckpointData,
    work: MaximumCheckpointWork,
}

impl Default for MaximumCheckpoint {
    fn default() -> Self {
        Self { layer: None, data: MaximumCheckpointData::Empty, work: Default::default() }
    }
}

impl MaximumCheckpoint {
    fn leaf(
        softmax: &Softmax,
        read: &impl Fn(usize, usize, usize, usize) -> u8,
        row: usize,
        key: usize,
        work: &mut MaximumCheckpointWork,
    ) -> i32 {
        let index = (row << softmax.key_bits()) | key;
        if let Some((layer, source_row, source_key)) = softmax.cell(index) {
            work.source_byte_getter_calls += 2;
            (Softmax::word(read, softmax.layers[layer].difference, source_row, source_key, 2)
                + 32767) as i32
        } else {
            1
        }
    }

    fn rebuild(
        &mut self,
        softmax: &Softmax,
        read: &impl Fn(usize, usize, usize, usize) -> u8,
        layer: usize,
    ) {
        let (row_bits, key_bits) = (softmax.row_bits(), softmax.key_bits());
        assert!(layer < key_bits);
        // Drop the preceding layer before allocating its replacement.
        self.data = MaximumCheckpointData::Empty;
        self.layer = None;
        let entries = 1usize << (row_bits + layer);
        if layer + 1 == key_bits {
            let mut values = Vec::with_capacity(entries);
            for index in 0..entries {
                let row = index >> layer;
                let prefix = index & ((1usize << layer) - 1);
                values.push([
                    Self::leaf(softmax, read, row, 2 * prefix, &mut self.work),
                    Self::leaf(softmax, read, row, 2 * prefix + 1, &mut self.work),
                ]);
            }
            self.work.checkpoint_scalar_writes += 2 * entries as u64;
            self.work.checkpoint_capacity_peak_bytes = self
                .work
                .checkpoint_capacity_peak_bytes
                .max(values.capacity() * core::mem::size_of::<[i32; 2]>());
            self.data = MaximumCheckpointData::Leaves(values);
        } else {
            let block = 1usize << (key_bits - layer - 1);
            let mut values = Vec::with_capacity(entries);
            for index in 0..entries {
                let row = index >> layer;
                let prefix = index & ((1usize << layer) - 1);
                let mut children = [Fp::ONE; 2];
                for (side, child) in children.iter_mut().enumerate() {
                    let begin = (2 * prefix + side) * block;
                    for key in begin..begin + block {
                        let global = (row << key_bits) | key;
                        if softmax.cell(global).is_some() {
                            *child = *child
                                * signed(i64::from(Self::leaf(
                                    softmax,
                                    read,
                                    row,
                                    key,
                                    &mut self.work,
                                )))
                                .c0;
                            self.work.base_field_products += 1;
                        }
                    }
                }
                values.push(children);
            }
            self.work.checkpoint_scalar_writes += 2 * entries as u64;
            self.work.checkpoint_capacity_peak_bytes = self
                .work
                .checkpoint_capacity_peak_bytes
                .max(values.capacity() * core::mem::size_of::<[Fp; 2]>());
            self.data = MaximumCheckpointData::Products(values);
        }
        self.work.checkpoint_builds += 1;
        self.layer = Some(layer);
    }

    fn children(
        &mut self,
        softmax: &Softmax,
        read: &impl Fn(usize, usize, usize, usize) -> u8,
        layer: usize,
        index: usize,
    ) -> [Fp3; 4] {
        if self.layer != Some(layer) {
            self.rebuild(softmax, read, layer);
        }
        let pair = match &self.data {
            MaximumCheckpointData::Products(values) => {
                let [left, right] = values[index];
                [Fp3::from_base(left), Fp3::from_base(right)]
            }
            MaximumCheckpointData::Leaves(values) => {
                let [left, right] = values[index];
                [signed(i64::from(left)), signed(i64::from(right))]
            }
            MaximumCheckpointData::Empty => unreachable!(),
        };
        [Fp3::ZERO, pair[0], Fp3::ZERO, pair[1]]
    }
}

impl Plan {
    pub fn softmax_sources_at(
        &self,
        old: usize,
    ) -> Result<(residual::Sources, output::Output, Softmax), String> {
        let (mut sources, output) = self.output_sources_at(old)?;
        let base = sources.attention.rope.gate_up.gelu.rms.bytes.scalar.layout.sources.len();
        let (mut layers, mut extra) = (Vec::new(), Vec::new());
        for (i, a) in sources.attention.layers.iter().enumerate() {
            layers.push(Layer {
                score: a.score,
                pi: a.pi,
                maximum: base + 5 * i,
                difference: base + 5 * i + 1,
                exponential: base + 5 * i + 2,
                denominator: base + 5 * i + 3,
                histogram: base + 5 * i + 4,
            });
            for (name, rows, cols, width) in [
                ("max", 8192, 1, 2),
                ("D", 8192, old + 150, 2),
                ("E", 8192, old + 150, 4),
                ("Z", 8192, 1, 6),
                ("M", 1, 65535, 4),
            ] {
                extra.push((format!("softmax/{i}/{name}"), rows, cols, width));
            }
        }
        sources.attention = sources.attention.append(extra)?;
        Ok((sources, output, Softmax { layers, heads: 32, queries: 150, old }))
    }
}

impl Softmax {
    pub fn row_bits(&self) -> usize {
        bits(self.layers.len()) + bits(self.heads) + bits(self.queries)
    }
    pub fn key_bits(&self) -> usize {
        bits(self.old + self.queries)
    }

    fn validate(&self, bytes: &bytes::Bytes, s: &P0Statement<'_>) -> Result<(), String> {
        bytes::mask::allowed_rectangles(self.queries, self.old)?;
        if self.layers.is_empty()
            || self.layers.len() > 60
            || !self.heads.is_power_of_two()
            || self.heads > 32
            || s.tokens.len() != self.queries
            || s.weights.num_roots() != 1
            || s.auxiliary.num_roots() != 1
            || s.weight_gamma.is_empty()
            || s.auxiliary_gamma.is_empty()
            || s.quantization == [0; 32]
            || !s.attempt.valid()
            || s.auxiliary_layout.layout.layout_digest != bytes.scalar.layout.layout_digest
            || s.auxiliary_layout.weight_layout != bytes.scalar.weight_layout
            || (self.queries == 150 && self.old != 150 * usize::from(s.attempt.slot))
        {
            return Err("EXP30 fixed source context or axes differ".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for l in &self.layers {
            for (id, rows, cols, width) in [
                (
                    l.score,
                    self.heads * self.queries.next_power_of_two(),
                    self.old + self.queries,
                    2,
                ),
                (l.pi, self.heads * self.queries.next_power_of_two(), self.old + self.queries, 2),
                (l.maximum, self.heads * self.queries.next_power_of_two(), 1, 2),
                (
                    l.difference,
                    self.heads * self.queries.next_power_of_two(),
                    self.old + self.queries,
                    2,
                ),
                (
                    l.exponential,
                    self.heads * self.queries.next_power_of_two(),
                    self.old + self.queries,
                    4,
                ),
                (l.denominator, self.heads * self.queries.next_power_of_two(), 1, 6),
            ] {
                let a = bytes.scalar.layout.sources.get(id).ok_or("EXP30 source missing")?;
                if !seen.insert(id) || [a.rows, a.cols] != [rows, cols] || bytes.widths[id] != width
                {
                    return Err("EXP30 original source codec, identity or shape differs".into());
                }
            }
            let m =
                bytes.scalar.layout.sources.get(l.histogram).ok_or("EXP30 histogram missing")?;
            if !seen.insert(l.histogram)
                || m.rows != 1
                || m.cols == 0
                || m.cols > 65535
                || bytes.widths[l.histogram] != 4
            {
                return Err("EXP30 histogram shape or codec differs".into());
            }
        }
        Ok(())
    }

    fn bind(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        fs: &mut Fs,
    ) -> Result<[u8; 32], String> {
        self.validate(bytes, s)?;
        let mut frame =
            b"C71-SOFTMAX-EXP30-v1;original-score-Pi;max-product;RNE14;one-A\0".to_vec();
        frame.extend(s.weights.roots()[0]);
        frame.extend(s.auxiliary.roots()[0]);
        for gamma in [s.weight_gamma, s.auxiliary_gamma] {
            frame.extend((gamma.len() as u64).to_le_bytes());
            frame.extend(gamma);
        }
        frame.extend(bytes.layout_digest);
        frame.extend(s.quantization);
        frame.extend(s.attempt.encode());
        for n in [self.layers.len(), self.heads, self.queries, self.old] {
            frame.extend((n as u64).to_le_bytes());
        }
        for l in &self.layers {
            for id in
                [l.score, l.pi, l.maximum, l.difference, l.exponential, l.denominator, l.histogram]
            {
                frame.extend((id as u64).to_le_bytes());
            }
        }
        let view = *blake3::hash(&frame).as_bytes();
        fs.set_phase(0x1800);
        fs.record(0xc0, &frame);
        Ok(view)
    }

    fn cell(&self, index: usize) -> Option<(usize, usize, usize)> {
        let kb = self.key_bits();
        let rows = self.heads * self.queries.next_power_of_two();
        let (row, key) = (index >> kb, index % (1 << kb));
        let (layer, row) = (row / rows, row % rows);
        (layer < self.layers.len()
            && row % self.queries.next_power_of_two() < self.queries
            && key <= self.old + row % self.queries.next_power_of_two()
            && key < self.old + self.queries)
            .then_some((layer, row, key))
    }

    fn live_rows(&self, point: &[Fp3]) -> Fp3 {
        let lb = bits(self.layers.len());
        byte_function::live_mass(self.layers.len(), &point[..lb])
            * byte_function::live_mass(self.queries, &point[lb + bits(self.heads)..])
    }

    fn lookup_layout(&self, bytes: &bytes::Bytes) -> (Vec<Tile>, usize) {
        tiles(
            &self
                .layers
                .iter()
                .map(|l| bytes.scalar.layout.sources[l.difference].clone())
                .chain(self.layers.iter().map(|l| bytes.scalar.layout.sources[l.histogram].clone()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn lookup_blocks(&self, bytes: &bytes::Bytes) -> Vec<lookup::Block> {
        self.lookup_layout(bytes)
            .0
            .iter()
            .map(|t| {
                if t.tensor < self.layers.len() {
                    lookup::Block::Query { profile: t.tensor as u8, len: t.rows * t.cols }
                } else {
                    lookup::Block::Table {
                        index: t.tensor - self.layers.len(),
                        first: t.col,
                        len: t.cols,
                    }
                }
            })
            .collect()
    }

    fn prepare(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
    ) -> Result<(Vec<circuit::Circuit>, usize), String> {
        self.validate(bytes, s)?;
        let cb = self.row_bits() + self.key_bits();
        if cb>28 || tables.len()!=self.layers.len() || tables.iter().zip(&self.layers).enumerate().any(|(i,(t,l))|
            t.profile!=i as u8 || t.lower != -32767
                || !matches!(t.outputs,lookup::Outputs::I32(v) if v.first()==Some(&(1<<30)) && v.iter().all(|&e|(0..=1<<30).contains(&e)))
                || t.outputs.len()!=bytes.scalar.layout.sources[l.histogram].cols) {
            return Err("EXP30 D28 envelope or certified table differs".into());
        }
        let programs = vec![circuit::compile_ratio(14)?];
        let blocks = self.lookup_blocks(bytes);
        let ls = lookup::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: bytes.layout_digest,
            attempt: s.attempt,
            blocks: &blocks,
            tables,
        };
        let k = self.key_bits();
        let r = self.row_bits();
        let count = gkr::required(&programs, cb)?
            + ls.required()?
            + 4 * (k * r + k * k.saturating_sub(1) / 2)
            + 7 * k
            + 1;
        Ok((programs, count))
    }

    pub fn required(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
    ) -> Result<usize, String> {
        Ok(self.prepare(bytes, s, tables)?.1)
    }

    // Signed source words are obtained from their biased bytes. No getter
    // may inspect the unspent MAC rows. The full caller owns the fixed trace.
    fn word(
        read: &impl Fn(usize, usize, usize, usize) -> u8,
        id: usize,
        row: usize,
        col: usize,
        width: usize,
    ) -> i64 {
        (0..width).fold(0i64, |v, b| v + (i64::from(read(id, row, col, b)) << (8 * b)))
            - (1i64 << (8 * width - 1))
    }

    pub fn prove(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
        read: impl Fn(usize, usize, usize, usize) -> u8,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Auth>,
    ) -> Result<(Proof, Pending<Auth>), String> {
        let (programs, count) = self.prepare(bytes, s, tables)?;
        if correlations.len() < count {
            return Err("EXP30 prover capacity exhausted".into());
        }
        let assignment = |i| self.cell(i).map(|_| 0);
        let assignments =
            gkr::Assignments::new(1 << (self.row_bits() + self.key_bits()), &assignment);
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        let view = self.bind(bytes, s, fs)?;
        let row_point = (0..self.row_bits()).map(|_| fs.fp3()).collect::<Vec<_>>();
        let mut triples = Vec::new();
        let top = Auth::new(Fp3::ONE - self.live_rows(&row_point), Fp3::ZERO);
        // `read` is the immutable getter for the already-bound auxiliary root.
        // The checkpoint is replaced only between public tree layers.
        let checkpoint = std::cell::RefCell::new(MaximumCheckpoint::default());
        let (maximum, maximum_point, claims, tree_work) = range::prove_tree_sourcewise(
            self.key_bits(),
            row_point,
            [Auth::ZERO, top],
            |layer, index| checkpoint.borrow_mut().children(self, &read, layer, index),
            fs,
            &mut rows,
            &mut triples,
        );
        let maximum_work =
            MaximumSourceWork { checkpoint: checkpoint.into_inner().work, tree: tree_work };
        #[cfg(test)]
        eprintln!("C71_MAXIMUM_SOURCE_WORK {}", serde_json::to_string(&maximum_work).unwrap());
        let max_leaf_tag = claims[0].m;
        fs.set_phase(0x1801);
        record_values(fs, 0xc1, &[max_leaf_tag]);
        let max_products = range::prove_products(&triples, rows.next().unwrap(), fs);
        let (tiles, _) = self.lookup_layout(bytes);
        let blocks = self.lookup_blocks(bytes);
        let ls = lookup::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view,
            attempt: s.attempt,
            blocks: &blocks,
            tables,
        };
        let (lookup, lp) = lookup::prove_wide(
            &ls,
            |i| {
                let t = &tiles[tiles.partition_point(|t| t.offset <= i) - 1];
                let l = &self.layers[t.tensor];
                let (r, c) = (t.row + (i - t.offset) / t.cols, t.col + (i - t.offset) % t.cols);
                (
                    Self::word(&read, l.difference, r, c, 2) as i16,
                    Self::word(&read, l.exponential, r, c, 4) as i32,
                )
            },
            |mut j| {
                for l in &self.layers {
                    let n = bytes.scalar.layout.sources[l.histogram].cols;
                    if j < n {
                        return Self::word(&read, l.histogram, 0, j, 4) as i32;
                    }
                    j -= n;
                }
                unreachable!()
            },
            fs,
            &mut rows,
        )?;
        let gs = gkr::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view,
            attempt: s.attempt,
            programs: &programs,
            assignments,
        };
        let frames = RatioFrames::build(self, &read)?;
        let (ratio, ratio_point, ratio_tag) =
            gkr::prove_patterns(&gs, |i| frames.frame(self, i), fs, &mut rows)?;
        drop(frames);
        debug_assert!(rows.next().is_none());
        Ok((
            Proof { maximum, max_leaf_tag, max_products, lookup, ratio },
            Pending {
                maximum_point,
                maximum: claims[1],
                lookup: lp,
                ratio_point,
                ratio: ratio_tag,
            },
        ))
    }

    pub fn verify(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        tables: &[lookup::Table<'_>],
        proof: &Proof,
        delta: Fp3,
        fs: &mut Fs,
        correlations: &mut std::vec::IntoIter<Key>,
    ) -> Result<Pending<Key>, String> {
        let (programs, count) = self.prepare(bytes, s, tables)?;
        if correlations.len() < count
            || !range::tree_shape(&proof.maximum, self.key_bits(), self.row_bits())
        {
            return Err("EXP30 verifier capacity or tree shape differs".into());
        }
        let assignment = |i| self.cell(i).map(|_| 0);
        let assignments =
            gkr::Assignments::new(1 << (self.row_bits() + self.key_bits()), &assignment);
        let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
        let view = self.bind(bytes, s, fs)?;
        let point = (0..self.row_bits()).map(|_| fs.fp3()).collect::<Vec<_>>();
        let top = Key::new(delta * (Fp3::ONE - self.live_rows(&point)));
        let mut triples = Vec::new();
        let (maximum_point, claims) = range::verify_tree(
            &proof.maximum,
            point,
            [Key::ZERO, top],
            delta,
            fs,
            &mut rows,
            &mut triples,
        )?;
        if claims[0].k != proof.max_leaf_tag {
            return Err("EXP30 max numerator MAC rejected".into());
        }
        fs.set_phase(0x1801);
        record_values(fs, 0xc1, &[proof.max_leaf_tag]);
        range::verify_products(&triples, rows.next().unwrap(), proof.max_products, delta, fs)?;
        let blocks = self.lookup_blocks(bytes);
        let ls = lookup::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view,
            attempt: s.attempt,
            blocks: &blocks,
            tables,
        };
        let lp = lookup::verify(&ls, &proof.lookup, delta, fs, &mut rows)?;
        let gs = gkr::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view,
            attempt: s.attempt,
            programs: &programs,
            assignments,
        };
        let (ratio_point, ratio) = gkr::verify(&gs, &proof.ratio, delta, fs, &mut rows)?;
        debug_assert!(rows.next().is_none());
        Ok(Pending { maximum_point, maximum: claims[1], lookup: lp, ratio_point, ratio })
    }

    fn allowed(
        &self,
        point: &[Fp3],
        mut emit: impl FnMut(usize, &[Fp3], &[Fp3], Fp3) -> Result<(), String>,
    ) -> Result<(), String> {
        let (rb, kb) = (self.row_bits(), self.key_bits());
        if point.len() != rb + kb {
            return Err("EXP30 original cell point differs".into());
        }
        let lb = bits(self.layers.len());
        let hb = bits(self.heads);
        let qb = bits(self.queries);
        let query = &point[lb + hb..rb];
        let key = &point[rb..];
        for l in 0..self.layers.len() {
            for [q, h, k, w] in bytes::mask::allowed_rectangles(self.queries, self.old)? {
                let (qs, ks) = (qb - bits(h), kb - bits(w));
                let coefficient = eq_index(&point[..lb], l)
                    * eq_index(&query[..qs], q / h)
                    * eq_index(&key[..ks], k / w);
                let row = point[lb..lb + hb]
                    .iter()
                    .copied()
                    .chain(prefix(q, h, self.queries, &query[qs..]))
                    .collect::<Vec<_>>();
                let col = prefix(k, w, self.old + self.queries, &key[ks..]);
                emit(l, &row, &col, coefficient)?;
            }
        }
        Ok(())
    }

    pub fn maximum_form(
        &self,
        bytes: &bytes::Bytes,
        point: &[Fp3],
    ) -> Result<(Vec<Cube>, Fp3), String> {
        let (mut form, mut mass) = (Vec::new(), Fp3::ZERO);
        self.allowed(point, |l, r, c, a| {
            form.extend(bytes.word_form(self.layers[l].difference, r, c, a)?.0);
            mass += a;
            Ok(())
        })?;
        // Q_leaf = mask*D + 1-mask, encoded D is D+1.
        Ok((form, mass + mass - Fp3::ONE))
    }

    pub fn ratio_form(&self, bytes: &bytes::Bytes, point: &[Fp3]) -> Result<Vec<Cube>, String> {
        let cb = self.row_bits() + self.key_bits();
        if point.len() != cb + 4 {
            return Err("EXP30 original ratio byte point differs".into());
        }
        let mut form = Vec::new();
        self.allowed(&point[..cb], |l, r, c, a| {
            let l = &self.layers[l];
            form.extend(bytes.view_form(l.exponential, r, c, &point[cb..], 0, a)?);
            form.extend(bytes.view_form(l.denominator, r, &[], &point[cb..], 4, a)?);
            form.extend(bytes.view_form(l.pi, r, c, &point[cb..], 10, a)?);
            Ok(())
        })?;
        Ok(form)
    }

    pub fn lookup_forms(
        &self,
        bytes: &bytes::Bytes,
        point: &[Fp3],
    ) -> Result<([Vec<Cube>; 3], [Fp3; 3]), String> {
        let (tiles, cells) = self.lookup_layout(bytes);
        let d = bits(cells);
        if point.len() != d {
            return Err("EXP30 original lookup point differs".into());
        }
        let mut forms = std::array::from_fn(|_| Vec::new());
        let mut bias = [Fp3::ZERO; 3];
        for t in tiles {
            let table = t.tensor >= self.layers.len();
            let l = &self.layers[t.tensor % self.layers.len()];
            let low = bits(t.rows) + bits(t.cols);
            let coefficient = eq_index(&point[..d - low], t.offset / (t.rows * t.cols));
            for (lane, id) in [(0, l.difference), (1, l.exponential), (2, l.histogram)] {
                if (lane == 2) != table {
                    continue;
                }
                let src = &bytes.scalar.layout.sources[id];
                let r = prefix(t.row, t.rows, src.rows, &point[d - low..d - bits(t.cols)]);
                let c = prefix(t.col, t.cols, src.cols, &point[d - bits(t.cols)..]);
                let (f, b) = bytes.word_form(id, &r, &c, coefficient)?;
                forms[lane].extend(f);
                bias[lane] += b;
            }
        }
        Ok((forms, bias))
    }

    pub fn forms<T: Copy>(
        &self,
        bytes: &bytes::Bytes,
        p: &Pending<T>,
    ) -> Result<(Vec<Vec<Cube>>, Vec<Fp3>, Vec<T>), String> {
        let (f, b) = self.maximum_form(bytes, &p.maximum_point)?;
        let (mut forms, mut bias, mut tags) = (vec![f], vec![b], vec![p.maximum]);
        let (f, b) = self.lookup_forms(bytes, &p.lookup.point)?;
        forms.extend(f);
        bias.extend(b);
        tags.extend(p.lookup.originals);
        forms.push(self.ratio_form(bytes, &p.ratio_point)?);
        bias.push(Fp3::ZERO);
        tags.push(p.ratio);
        Ok((forms, bias, tags))
    }

    /// Two exact integer identities in one fresh random zero form:
    /// encoded_D = 1 + mask*(encoded_M-encoded_score), Z = sum(mask*E).
    /// Every query padding word has D=0 and Z=0. No additional MAC is issued.
    pub fn zero_form(
        &self,
        bytes: &bytes::Bytes,
        s: &P0Statement<'_>,
        fs: &mut Fs,
    ) -> Result<(Vec<Cube>, Fp3), String> {
        self.bind(bytes, s, fs)?;
        let (rb, kb) = (self.row_bits(), self.key_bits());
        let lb = bits(self.layers.len());
        let point = (0..rb + kb).map(|_| fs.fp3()).collect::<Vec<_>>();
        let lambda = fs.fp3();
        let (mut form, mut bias) = (
            Vec::new(),
            byte_function::live_mass(self.layers.len(), &point[..lb])
                * byte_function::live_mass(self.old + self.queries, &point[rb..]),
        );
        for (l, src) in self.layers.iter().enumerate() {
            let a = eq_index(&point[..lb], l);
            let r = &point[lb..rb];
            form.extend(bytes.word_form(src.difference, r, &point[rb..], a)?.0);
            let (f, b) = bytes.word_form(src.denominator, r, &[], a * lambda)?;
            form.extend(f);
            bias += b;
        }
        self.allowed(&point, |l, r, c, a| {
            let l = &self.layers[l];
            form.extend(bytes.word_form(l.maximum, r, &[], -a)?.0);
            form.extend(bytes.word_form(l.score, r, c, a)?.0);
            Ok(())
        })?;
        let sum_point =
            point[..rb].iter().copied().chain(vec![signed(2).inv(); kb]).collect::<Vec<_>>();
        self.allowed(&sum_point, |l, r, c, a| {
            let (f, b) =
                bytes.word_form(self.layers[l].exponential, r, c, -lambda * a * signed(1 << kb))?;
            form.extend(f);
            bias += b;
            Ok(())
        })?;
        Ok((form, bias))
    }
}
