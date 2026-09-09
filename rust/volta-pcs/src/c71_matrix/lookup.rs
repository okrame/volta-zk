//! Public i16 lookup, with X/Y and the fixed histogram in the SAME source.
//! Reuses range's fraction GKR; it does not commit inverses or a trace.

use super::*;

pub(super) struct Table<'a> {
    pub profile: u8,
    pub lower: i16,
    // Consecutive signed inputs. MIN is an overflow marker, never an output.
    pub outputs: &'a [i16],
}

pub(super) struct Statement<'a> {
    pub root: &'a C61Commitment,
    pub profile: &'a [u8],
    pub view: [u8; 32],
    pub attempt: AttemptContext,
    pub query_profiles: &'a [u8],
    pub tables: &'a [Table<'a>],
}

pub(super) struct Proof {
    roots: [Fp3; 2], // denominator and inverse; numerator is PUBLIC zero
    layers: Vec<range::Layer>,
    leaves: [Fp3; 5], // original X/Y/M corrections, then two affine tags
    products: [Fp3; 2],
}

pub(super) struct Pending<T> {
    pub point: Vec<Fp3>,   // combined query/table/dummy domain, MSB first
    pub originals: [T; 3], // weighted X, Y, histogram; no reauthentication
}

pub(super) fn required(bits: usize) -> usize {
    2 * bits * bits + 5 * bits + 6
}

fn tag(x: i16, y: i16, profile: u8) -> Fp3 {
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    signed(i64::from(x)) + omega * signed(i64::from(y)) + omega * omega * signed(i64::from(profile))
}

impl Statement<'_> {
    fn public_tags(&self) -> Result<Vec<Fp3>, String> {
        if self.query_profiles.is_empty()
            || self.query_profiles.len() > 256
            || self.tables.is_empty()
            || self.tables.len() > 60
            || self.root.num_roots() != 1
            || self.profile.is_empty()
            || self.view == [0; 32]
            || !self.attempt.valid()
        {
            return Err("B12 lookup fixed context or native query cap differs".into());
        }
        let mut seen = [false; 60];
        let mut rows = 0usize;
        for t in self.tables {
            if t.profile >= 60
                || seen[t.profile as usize]
                || t.outputs.is_empty()
                || t.outputs.len() > 65535
                || t.lower == i16::MIN
                || i64::from(t.lower) + t.outputs.len() as i64 - 1 > 32767
            {
                return Err("B12 lookup public table domain or profile differs".into());
            }
            seen[t.profile as usize] = true;
            rows += t.outputs.len();
        }
        if rows > 65535 || self.query_profiles.iter().any(|&p| p >= 60 || !seen[p as usize]) {
            return Err("B12 lookup public rows or query profiles differ".into());
        }
        Ok(self
            .tables
            .iter()
            .flat_map(|t| {
                t.outputs.iter().enumerate().map(move |(j, &y)| {
                    tag(
                        (i64::from(t.lower) + j as i64) as i16,
                        y,
                        t.profile + if y == i16::MIN { 60 } else { 0 },
                    )
                })
            })
            .collect())
    }

    pub fn required(&self) -> Result<usize, String> {
        Ok(required(
            (self.query_profiles.len() + self.public_tags()?.len()).next_power_of_two().ilog2()
                as usize,
        ))
    }

    fn bind(&self, fs: &mut Fs) -> Result<(Vec<Fp3>, usize, Fp3), String> {
        let tags = self.public_tags()?;
        let bits = (self.query_profiles.len() + tags.len()).next_power_of_two().ilog2() as usize;
        let mut bytes =
            b"C71-lookup-B12-v1;fixed-X-Y-M;query-table-dummy;overflow-profile-plus-60;original-A"
                .to_vec();
        bytes.extend(self.root.roots()[0]);
        bytes.extend((self.profile.len() as u64).to_le_bytes());
        bytes.extend(self.profile);
        bytes.extend(self.view);
        bytes.extend(self.attempt.encode());
        bytes.extend((self.query_profiles.len() as u64).to_le_bytes());
        bytes.extend(self.query_profiles);
        bytes.extend((self.tables.len() as u64).to_le_bytes());
        for t in self.tables {
            bytes.push(t.profile);
            bytes.extend(t.lower.to_le_bytes());
            bytes.extend((t.outputs.len() as u64).to_le_bytes());
            for y in t.outputs {
                bytes.extend(y.to_le_bytes());
            }
        }
        fs.set_phase(0xd00);
        fs.record(0xb0, &bytes);
        let alpha = fs.fp3();
        // Every honest query tag is public-table-valued. Rejecting ALL public
        // poles makes the honest abort decision independent of the witness.
        if tags.contains(&alpha) {
            return Err("B12 lookup public pole".into());
        }
        Ok((tags, bits, alpha))
    }

    fn leaf_constants(&self, tags: &[Fp3], point: &[Fp3], alpha: Fp3) -> (Fp3, Fp3) {
        let weights = eq(point);
        let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
        let mut query = Fp3::ZERO;
        let mut denominator = Fp3::ZERO;
        let n = self.query_profiles.len();
        for (i, &weight) in weights.iter().enumerate() {
            if i < n {
                query += weight;
                denominator +=
                    weight * (alpha - omega * omega * signed(i64::from(self.query_profiles[i])));
            } else if let Some(&t) = tags.get(i - n) {
                denominator += weight * (alpha - t);
            } else {
                denominator += weight;
            }
        }
        (query, denominator)
    }
}

pub(super) fn prove(
    s: &Statement<'_>,
    read_query: impl Fn(usize) -> (i16, i16),
    read_histogram: impl Fn(usize) -> i32,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(Proof, Pending<Auth>), String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (tags, bits, alpha) = s.bind(fs)?;
    let n = s.query_profiles.len();
    // ponytail: dense D<=17 component. Full Gemma needs the documented
    // subtree replay schedule and canonical source caller, not this array.
    let mut bottom = vec![[Fp3::ZERO, Fp3::ONE]; 1 << bits];
    for i in 0..n {
        let (x, y) = read_query(i);
        bottom[i] = [Fp3::ONE, alpha - tag(x, y, s.query_profiles[i])];
    }
    for (j, &t) in tags.iter().enumerate() {
        bottom[n + j] = [-signed(i64::from(read_histogram(j))), alpha - t];
    }
    let mut tree = vec![bottom];
    while tree.last().unwrap().len() > 1 {
        tree.push(
            tree.last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| {
                    let ([p, q], [r, s]) = (pair[0], pair[1]);
                    [p * s + r * q, q * s]
                })
                .collect(),
        );
    }
    let denominator = tree.last().unwrap()[0][1];
    if denominator == Fp3::ZERO {
        return Err("B12 lookup witness pole".into());
    }
    let (roots, root) = range::authenticate([denominator, denominator.inv()], &mut rows);
    fs.set_phase(0xd01);
    record_values(fs, 0xb1, &roots);
    let mut triples = vec![[root[0], root[1], Auth::new(Fp3::ONE, Fp3::ZERO)]];
    let (layers, point, claims) =
        range::prove_tree(&tree, Vec::new(), [Auth::ZERO, root[0]], fs, &mut rows, &mut triples);
    let weights = eq(&point);
    let mut values = [Fp3::ZERO; 3];
    for i in 0..n {
        let (x, y) = read_query(i);
        values[0] += weights[i] * signed(i64::from(x));
        values[1] += weights[i] * signed(i64::from(y));
    }
    for j in 0..tags.len() {
        values[2] += weights[n + j] * signed(i64::from(read_histogram(j)));
    }
    let (wire, original) = range::authenticate(values, &mut rows);
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    let leaves = [
        wire[0],
        wire[1],
        wire[2],
        claims[0].m + original[2].m,
        claims[1].m + original[0].m + omega * original[1].m,
    ];
    fs.set_phase(0xd02);
    record_values(fs, 0xb2, &leaves);
    let products = range::prove_products(&triples, rows.next().unwrap(), fs);
    debug_assert!(rows.next().is_none());
    Ok((Proof { roots, layers, leaves, products }, Pending { point, originals: original }))
}

pub(super) fn verify(
    s: &Statement<'_>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<Pending<Key>, String> {
    let count = s.required()?;
    if correlations.len() < count {
        return Err("B12 lookup verifier capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count).collect::<Vec<_>>().into_iter();
    let (tags, bits, alpha) = s.bind(fs)?;
    if !range::tree_shape(&proof.layers, bits, 0) {
        return Err("B12 lookup tree shape differs".into());
    }
    let root = range::correct(proof.roots, delta, &mut rows);
    fs.set_phase(0xd01);
    record_values(fs, 0xb1, &proof.roots);
    let mut triples = vec![[root[0], root[1], Key::new(delta)]];
    let (point, claims) = range::verify_tree(
        &proof.layers,
        Vec::new(),
        [Key::ZERO, root[0]],
        delta,
        fs,
        &mut rows,
        &mut triples,
    )?;
    let original =
        range::correct([proof.leaves[0], proof.leaves[1], proof.leaves[2]], delta, &mut rows);
    let (query, denominator) = s.leaf_constants(&tags, &point, alpha);
    let omega = Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO);
    if claims[0].k + original[2].k - delta * query != proof.leaves[3]
        || claims[1].k + original[0].k + omega * original[1].k - delta * denominator
            != proof.leaves[4]
    {
        return Err("B12 lookup original leaf MAC rejected".into());
    }
    fs.set_phase(0xd02);
    record_values(fs, 0xb2, &proof.leaves);
    range::verify_products(&triples, rows.next().unwrap(), proof.products, delta, fs)?;
    debug_assert!(rows.next().is_none());
    Ok(Pending { point, originals: original })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::{RngExt, SeedableRng};

    fn source(xy: &[(i16, i16)], m: &[i32]) -> Vec<i16> {
        let mut bytes = Vec::new();
        for lane in 0..2 {
            for &(x, y) in xy {
                let x = if lane == 0 { x } else { y };
                bytes.extend(
                    (i32::from(x) + 32768).to_le_bytes()[..2].iter().map(|&b| i16::from(b)),
                );
            }
        }
        for &x in m {
            bytes.extend(
                (i64::from(x) + (1 << 31)).to_le_bytes()[..4].iter().map(|&b| i16::from(b)),
            );
        }
        bytes.resize(1024, 0);
        bytes
    }

    fn forms(point: &[Fp3]) -> ([Vec<Cube>; 3], [Fp3; 3]) {
        let weights = eq(point);
        let mut shifts = [Fp3::ZERO; 3];
        let forms = std::array::from_fn(|lane| {
            let (offset, first, count, bytes) = [(0, 0, 4, 2), (8, 0, 4, 2), (16, 4, 6, 4)][lane];
            let mut form = Vec::new();
            for i in 0..count {
                let coefficient = weights[first + i];
                shifts[lane] += coefficient * signed(1 << (8 * bytes - 1));
                for b in 0..bytes {
                    form.push(Cube {
                        offset: offset + bytes * i + b,
                        point: Vec::new(),
                        coefficient: coefficient * signed(1 << (8 * b)),
                    });
                }
            }
            form
        });
        (forms, shifts)
    }

    #[test]
    fn c71_b12_lookup_rejects_wrong_gelu_overflow_and_detached_original_histogram() {
        // Certified scalar vectors from C71-GELU-RNE-v1 at input -1,0,1:
        // exponents (0,0) and (0,-16). This is a restricted-domain component,
        // not a calibrated full Gemma table or a producer-RNE proof.
        let tables = [
            Table { profile: 0, lower: -1, outputs: &[0, 0, 1] },
            Table { profile: 1, lower: -1, outputs: &[-10408, 0, i16::MIN] },
        ];
        let honest = [(-1, 0), (-1, -10408), (1, 1), (0, 0)];
        let histogram = [1, 0, 1, 1, 1, 0];
        let profile = gamma(&matrix_config(32).unwrap());
        let layout = [64; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        for fault in 0..4 {
            let mut used = honest;
            let mut counts = histogram;
            if fault == 1 {
                used[0].1 = 1;
            }
            if fault == 2 {
                used[0].0 = 0; // same rounded Y; update histogram consistently
                counts[0] = 0;
                counts[1] = 1;
            }
            if fault == 3 {
                used[3] = (1, i16::MIN);
                counts[4] = 0;
                counts[5] = 1; // overflow row has profile 61, NEVER query 1
            }
            let model = Model::new(
                32,
                if fault == 2 { source(&honest, &histogram) } else { source(&used, &counts) },
            )
            .unwrap();
            let s = Statement {
                root: &model.root,
                profile: &profile,
                view: layout,
                attempt,
                query_profiles: &[0, 1, 0, 1],
                tables: &tables,
            };
            assert_eq!(s.required().unwrap(), 58);
            let count = s.required().unwrap() + 510 + 32;
            assert_eq!(count, 600);
            let mut rng = MatrixRng::from_seed([149; 32]);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let start = || Fs::new(b"lookup original query and histogram bytes", 100_000);
            let mut fs = start();
            let mut prows = rows.into_iter();
            let (proof, p) = prove(&s, |i| used[i], |j| counts[j], &mut fs, &mut prows).unwrap();
            assert_eq!(fs.requests(), 16);
            let (range_proof, ranges, targets) = range::prove(
                &model,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            let (extra, shifts) = forms(&p.point);
            let all_forms: Vec<_> = ranges.into_iter().chain(extra).collect();
            let all_targets: Vec<_> = targets
                .into_iter()
                .chain(p.originals.into_iter().zip(shifts).map(|(a, s)| Auth::new(a.x + s, a.m)))
                .collect();
            let (pcs, digest) = linear::prove(
                &model,
                attempt,
                layout,
                &all_forms,
                &all_targets,
                &mut fs,
                &mut prows,
            )
            .unwrap();
            assert!(prows.next().is_none());
            let mut fs = start();
            let mut vrows = keys.into_iter();
            let result = verify(&s, &proof, delta, &mut fs, &mut vrows);
            if fault == 1 || fault == 3 {
                assert!(result.is_err(), "invalid lookup or overflow passed its GKR");
                continue;
            }
            let p = result.unwrap();
            assert_eq!(fs.requests(), 16);
            let (ranges, targets) = range::verify(
                32,
                &model.root,
                attempt,
                layout,
                40,
                range::Alphabet::Byte,
                &range_proof,
                delta,
                &mut fs,
                &mut vrows,
            )
            .unwrap();
            let (extra, shifts) = forms(&p.point);
            let all_forms: Vec<_> = ranges.into_iter().chain(extra).collect();
            let all_targets: Vec<_> = targets
                .into_iter()
                .chain(p.originals.into_iter().zip(shifts).map(|(k, s)| Key::new(k.k + delta * s)))
                .collect();
            let result = linear::verify(
                32,
                &model.root,
                attempt,
                layout,
                &all_forms,
                &all_targets,
                &pcs,
                delta,
                &mut fs,
                &mut vrows,
            );
            if fault == 2 {
                assert_eq!(result.unwrap_err(), "C71 matrix sumcheck MAC rejected");
            } else {
                assert_eq!(result.unwrap(), digest);
            }
            assert!(vrows.next().is_none());
        }
        let root = C61Commitment::new(vec![[1; 32]]);
        let s = Statement {
            root: &root,
            profile: &profile,
            view: layout,
            attempt,
            query_profiles: &[0, 1, 0, 1],
            tables: &tables,
        };
        let mut exhausted = vec![Auth::ZERO; 57].into_iter();
        assert!(prove(
            &s,
            |_| panic!("exhaustion read witness"),
            |_| panic!("exhaustion read histogram"),
            &mut Fs::new(b"exhausted lookup", 100),
            &mut exhausted
        )
        .is_err());
        assert_eq!(exhausted.len(), 57);
        let mut wrong = Statement { query_profiles: &[60], ..s };
        assert!(wrong.required().is_err());
        wrong.query_profiles = &[2];
        assert!(wrong.required().is_err());
        assert_ne!(tag(1, i16::MIN, 1), tag(1, i16::MIN, 61));
    }
}
