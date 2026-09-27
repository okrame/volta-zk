//! P0 compact matrix/weighted-norm reductions over Fp3. The caller fixes the
//! output/input sources before the output point, then closes ORIGINAL C/X/W
//! MACs at the returned points. Lookup is a direct linear W target.

use super::*;

component_wire!(Proof { rounds, terminal });
use range::{authenticate, correct};

pub(super) struct Proof {
    rounds: Vec<Vec<Fp3>>,
    terminal: [Fp3; 4], // original X, W, product corrections; zero-MAC tag
}

pub(super) fn required(bits: usize, norm: bool) -> usize {
    (if norm { 4 } else { 3 }) * bits + 3
}

fn bind(bits: usize, column_point: Option<&[Fp3]>, fs: &mut Fs) -> Result<(), String> {
    if bits > 32 || column_point.is_some_and(|p| p.len() != bits) {
        return Err("B12 P0 compact dimension mismatch".into());
    }
    let mut bytes = b"C71-P0-B12-v1;MSB-first;original-C-X-W-MACs".to_vec();
    bytes.extend((bits as u32).to_le_bytes());
    bytes.push(u8::from(column_point.is_some()));
    for &r in column_point.unwrap_or(&[]) {
        bytes.extend(r.to_bytes());
    }
    fs.set_phase(0x700);
    fs.record(0x50, &bytes);
    Ok(())
}

// Xbar is the row contraction of the actual producer. For matrices Wbar
// is the output-column contraction; for norms W is the shared channel vector.
// Neither vector is a new independently committed witness. Output C's MAC
// and its correction must already be recorded, under the caller's cohort ID.
#[allow(clippy::type_complexity)]
pub(super) fn prove(
    x: Vec<Fp3>,
    w: Vec<Fp3>,
    target: Auth,
    column_point: Option<&[Fp3]>,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Vec<Fp3>, [Auth; 3]), String> {
    if x.len() != w.len() || !x.len().is_power_of_two() {
        return Err("B12 P0 compact source lengths differ".into());
    }
    let bits = x.len().ilog2() as usize;
    bind(bits, column_point, fs)?;
    prove_inner(x, w, target, column_point.map(eq), fs, correlations)
}

// Public-weight mode: the caller fixes the expected MLE (e.g. the exact
// attention rectangle) in its context before this sumcheck. It evaluates
// the SAME public MLE at the verifier endpoint; no private F is accepted.
fn bind_public(bits: usize, fs: &mut Fs) -> Result<(), String> {
    if bits > 32 {
        return Err("B12 P0 public-weight dimension exceeds D32".into());
    }
    let mut bytes = b"C71-P0-public-weight-B12-v1;caller-fixed-MLE;original-left-right\0".to_vec();
    bytes.extend((bits as u32).to_le_bytes());
    fs.set_phase(0x730);
    fs.record(0x55, &bytes);
    Ok(())
}

pub(super) fn prove_public(
    x: Vec<Fp3>,
    w: Vec<Fp3>,
    target: Auth,
    public: Vec<Fp3>,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Vec<Fp3>, [Auth; 3]), String> {
    if x.len() != w.len() || x.len() != public.len() || !x.len().is_power_of_two() {
        return Err("B12 P0 public-weight source lengths differ".into());
    }
    bind_public(x.len().ilog2() as usize, fs)?;
    prove_inner(x, w, target, Some(public), fs, correlations)
}

fn prove_inner(
    mut x: Vec<Fp3>,
    mut w: Vec<Fp3>,
    mut target: Auth,
    mut equality: Option<Vec<Fp3>>,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Proof, Vec<Fp3>, [Auth; 3]), String> {
    let bits = x.len().ilog2() as usize;
    let count = required(bits, equality.is_some());
    if correlations.len() < count {
        return Err("B12 P0 prover capacity exhausted".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let (mut point, mut rounds) = (Vec::new(), Vec::new());
    for round in 0..bits {
        let half = x.len() / 2;
        let mut c = vec![Fp3::ZERO; if equality.is_some() { 4 } else { 3 }];
        for i in 0..half {
            let dx = x[i + half] - x[i];
            let dw = w[i + half] - w[i];
            let v = [x[i] * w[i], dx * w[i] + x[i] * dw, dx * dw];
            if let Some(e) = &equality {
                let de = e[i + half] - e[i];
                for j in 0..3 {
                    c[j] += e[i] * v[j];
                    c[j + 1] += de * v[j];
                }
            } else {
                for j in 0..3 {
                    c[j] += v[j];
                }
            }
        }
        let (mut wire, a): (Vec<_>, Vec<_>) = c
            .into_iter()
            .map(|v| {
                let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), v);
                (c.value(), a)
            })
            .unzip();
        wire.push(a[0].m + a.iter().fold(Fp3::ZERO, |s, a| s + a.m) - target.m);
        fs.set_phase(0x710 + round as u16);
        record_values(fs, 0x51, &wire);
        let r = fs.fp3();
        target = a.iter().rev().fold(Auth::ZERO, |s, &a| s.scale(r).add(a));
        fold(&mut x, r);
        fold(&mut w, r);
        if let Some(e) = &mut equality {
            fold(e, r);
        }
        point.push(r);
        rounds.push(wire);
    }
    let (wire, original) = authenticate([x[0], w[0], x[0] * w[0]], &mut rows);
    let e = equality.as_ref().map_or(Fp3::ONE, |v| v[0]);
    let terminal = [wire[0], wire[1], wire[2], e * original[2].m - target.m];
    fs.set_phase(0x720);
    record_values(fs, 0x52, &terminal);
    debug_assert!(rows.next().is_none());
    Ok((Proof { rounds, terminal }, point, original))
}

// The returned triple goes to the COMMON product batch; X and W go to their
// original source openings. Returning success here does not discharge them.
pub(super) fn verify(
    bits: usize,
    target: Key,
    column_point: Option<&[Fp3]>,
    proof: &Proof,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<(Vec<Fp3>, [Key; 3]), String> {
    bind(bits, column_point, fs)?;
    verify_inner(
        bits,
        column_point.is_some(),
        target,
        proof,
        delta,
        |u| {
            column_point.map_or(Fp3::ONE, |p| {
                p.iter()
                    .zip(u)
                    .fold(Fp3::ONE, |v, (&p, &r)| v * ((Fp3::ONE - p) * (Fp3::ONE - r) + p * r))
            })
        },
        fs,
        correlations,
    )
}

pub(super) fn verify_public(
    bits: usize,
    target: Key,
    proof: &Proof,
    delta: Fp3,
    public_at: impl Fn(&[Fp3]) -> Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<(Vec<Fp3>, [Key; 3]), String> {
    bind_public(bits, fs)?;
    verify_inner(bits, true, target, proof, delta, public_at, fs, correlations)
}

#[allow(clippy::too_many_arguments)]
fn verify_inner(
    bits: usize,
    weighted: bool,
    mut target: Key,
    proof: &Proof,
    delta: Fp3,
    public_at: impl Fn(&[Fp3]) -> Fp3,
    fs: &mut Fs,
    correlations: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<(Vec<Fp3>, [Key; 3]), String> {
    let degree = if weighted { 3 } else { 2 };
    let count = required(bits, weighted);
    if proof.rounds.len() != bits
        || proof.rounds.iter().any(|r| r.len() != degree + 2)
        || correlations.len() < count
    {
        return Err("B12 P0 proof shape or capacity mismatch".into());
    }
    let mut rows = correlations.by_ref().take(count);
    let mut point = Vec::new();
    for (round, wire) in proof.rounds.iter().enumerate() {
        let keys: Vec<_> =
            wire[..degree + 1].iter().map(|&c| correct([c], delta, &mut rows)[0]).collect();
        if keys[0].k + keys.iter().fold(Fp3::ZERO, |s, k| s + k.k) - target.k != wire[degree + 1] {
            return Err("B12 P0 sumcheck MAC rejected".into());
        }
        fs.set_phase(0x710 + round as u16);
        record_values(fs, 0x51, wire);
        let r = fs.fp3();
        target = keys.iter().rev().fold(Key::ZERO, |s, &k| s.scale(r).add(k));
        point.push(r);
    }
    let original =
        correct([proof.terminal[0], proof.terminal[1], proof.terminal[2]], delta, &mut rows);
    if public_at(&point) * original[2].k - target.k != proof.terminal[3] {
        return Err("B12 P0 terminal MAC rejected".into());
    }
    fs.set_phase(0x720);
    record_values(fs, 0x52, &proof.terminal);
    debug_assert!(rows.next().is_none());
    Ok((point, original))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linear::Cube;
    use rand_010::RngExt;

    fn evaluate(values: &[i16], point: &[Fp3]) -> Fp3 {
        values.iter().zip(eq(point)).fold(Fp3::ZERO, |s, (&v, r)| s + signed(i64::from(v)) * r)
    }

    fn cube(offset: usize, point: Vec<Fp3>) -> Vec<Cube> {
        vec![Cube { offset, point, coefficient: Fp3::ONE }]
    }

    #[test]
    fn c71_b12_p0_matrix_norm_lookup_keep_one_ranged_w_and_original_auxiliary_macs() {
        let n = 32;
        let layout = [8; 32];
        let attempt = AttemptContext {
            session: [1; 32],
            capacity: [2; 32],
            slot: 0,
            predecessor: [0; 32],
            nonce: [3; 32],
        };
        let delta = Fp3::new(Fp::new(5), Fp::new(7), Fp::new(11));
        let mut rng = MatrixRng::from_seed([117; 32]);
        for wrong_cut in [false, true] {
            let mut weights = vec![0i16; n * n];
            weights[..16].copy_from_slice(&[1, -2, 3, -4, 5, -6, 7, 0, -1, 2, 0, 3, 4, -5, 6, -7]);
            weights[16..20].copy_from_slice(&[2, -3, 5, 0]);
            weights[24..32].copy_from_slice(&[1, -2, 3, -4, 5, -6, 7, 0]);
            let mut auxiliary = vec![0i16; n * n];
            auxiliary[..8].copy_from_slice(&[2, 1, -3, 2, -1, 3, 1, -2]);
            auxiliary[16..24].copy_from_slice(&[2, -1, 3, 0, 1, 2, -2, 0]);
            // Actual raw operator execution, before challenge generation.
            for t in 0..2 {
                for j in 0..4 {
                    auxiliary[8 + 4 * t + j] =
                        (0..4).map(|k| auxiliary[4 * t + k] * weights[4 * j + k]).sum();
                    auxiliary[24 + 4 * t + j] = auxiliary[16 + 4 * t + j] * weights[16 + j];
                }
                for j in 0..2 {
                    auxiliary[32 + 2 * t + j] = weights[24 + 2 * [2, 0][t] + j];
                }
            }
            if wrong_cut {
                auxiliary[8] += 1;
            }
            let model = Model::new(n, weights.clone()).unwrap();
            let aux = Model::new(n, auxiliary.clone()).unwrap();
            let mut statement =
                b"B12 tiny P0 caller; W matrix/norm/embedding; A X/C; tokens 2,0".to_vec();
            statement.extend(model.root.roots()[0]);
            statement.extend(aux.root.roots()[0]);
            statement.extend(layout);
            statement.extend(attempt.encode());
            let start = || Fs::new(&statement, 2 * request_limit(&matrix_config(n).unwrap()) + 256);
            let count = range::required(10, 7) + 24 + 2 * 32;
            assert_eq!(count, 357);
            let rows: Vec<_> = (0..count)
                .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
                .collect();
            let keys: Vec<_> = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
            let mut rows = rows.into_iter();
            let mut fs = start();
            let (range_proof, range_forms, range_targets) =
                range::prove(&model, attempt, layout, 32, 7, &mut fs, &mut rows).unwrap();
            let mut w_forms = range_forms.to_vec();
            let mut w_targets = range_targets.to_vec();
            let (mut a_forms, mut a_targets, mut products, mut proofs) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for norm in [false, true] {
                let output_point: Vec<_> = (0..3).map(|_| fs.fp3()).collect();
                let (rp, cp) = output_point.split_at(1);
                let (x_offset, c_offset, w_offset) = if norm { (16, 24, 16) } else { (0, 8, 0) };
                let c = evaluate(&auxiliary[c_offset..c_offset + 8], &output_point);
                let (wire, c) = authenticate([c], &mut rows);
                record_values(&mut fs, 0x53, &wire);
                let xbar: Vec<_> = (0..4)
                    .map(|k| {
                        (0..2).zip(eq(rp)).fold(Fp3::ZERO, |s, (t, r)| {
                            s + r * signed(i64::from(auxiliary[x_offset + 4 * t + k]))
                        })
                    })
                    .collect();
                let wbar: Vec<_> = (0..4)
                    .map(|k| {
                        if norm {
                            signed(i64::from(weights[16 + k]))
                        } else {
                            (0..4).zip(eq(cp)).fold(Fp3::ZERO, |s, (j, r)| {
                                s + r * signed(i64::from(weights[4 * j + k]))
                            })
                        }
                    })
                    .collect();
                let (proof, point, original) =
                    prove(xbar, wbar, c[0], norm.then_some(cp), &mut fs, &mut rows).unwrap();
                let mut xp = rp.to_vec();
                xp.extend(&point);
                let mut wp = if norm { Vec::new() } else { cp.to_vec() };
                wp.extend(point);
                a_forms.extend([cube(c_offset, output_point), cube(x_offset, xp)]);
                a_targets.extend([c[0], original[0]]);
                w_forms.push(cube(w_offset, wp));
                w_targets.push(original[1]);
                products.push(original);
                proofs.push((wire[0], proof));
            }
            let lookup_point: Vec<_> = (0..2).map(|_| fs.fp3()).collect();
            let (wire, lookup) =
                authenticate([evaluate(&auxiliary[32..36], &lookup_point)], &mut rows);
            record_values(&mut fs, 0x54, &wire);
            a_forms.push(cube(32, lookup_point.clone()));
            a_targets.push(lookup[0]);
            w_forms.push(
                [2, 0]
                    .into_iter()
                    .zip(eq(&lookup_point[..1]))
                    .map(|(token, r)| Cube {
                        offset: 24 + 2 * token,
                        point: lookup_point[1..].to_vec(),
                        coefficient: r,
                    })
                    .collect(),
            );
            w_targets.push(lookup[0]); // same lookup MAC in A and W
            let product_wire = range::prove_products(&products, rows.next().unwrap(), &mut fs);
            let (w_pcs, _) =
                linear::prove(&model, attempt, layout, &w_forms, &w_targets, &mut fs, &mut rows)
                    .unwrap();
            let (a_pcs, digest) =
                linear::prove(&aux, attempt, layout, &a_forms, &a_targets, &mut fs, &mut rows)
                    .unwrap();
            assert!(rows.next().is_none());
            let check = |detach_input: bool| -> Result<_, String> {
                let mut rows = keys.clone().into_iter();
                let mut fs = start();
                let (forms, targets) = range::verify(
                    n,
                    &model.root,
                    attempt,
                    layout,
                    32,
                    7,
                    &range_proof,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                let (mut wf, mut wt, mut af, mut at, mut products) =
                    (forms.to_vec(), targets.to_vec(), Vec::new(), Vec::new(), Vec::new());
                for (norm, (correction, proof)) in [false, true].into_iter().zip(&proofs) {
                    let output: Vec<_> = (0..3).map(|_| fs.fp3()).collect();
                    let (rp, cp) = output.split_at(1);
                    let c = correct([*correction], delta, &mut rows)[0];
                    record_values(&mut fs, 0x53, &[*correction]);
                    let (point, original) =
                        verify(2, c, norm.then_some(cp), proof, delta, &mut fs, &mut rows)?;
                    let mut xp = rp.to_vec();
                    xp.extend(&point);
                    let mut wp = if norm { Vec::new() } else { cp.to_vec() };
                    wp.extend(point);
                    af.extend([
                        cube(if norm { 24 } else { 8 }, output),
                        cube(if norm { 16 } else { 0 }, xp),
                    ]);
                    at.extend([c, original[0]]);
                    wf.push(cube(if norm { 16 } else { 0 }, wp));
                    wt.push(original[1]);
                    products.push(original);
                }
                let point: Vec<_> = (0..2).map(|_| fs.fp3()).collect();
                let lookup = correct(wire, delta, &mut rows)[0];
                record_values(&mut fs, 0x54, &wire);
                af.push(cube(32, point.clone()));
                at.push(lookup);
                wf.push(
                    [2, 0]
                        .into_iter()
                        .zip(eq(&point[..1]))
                        .map(|(token, r)| Cube {
                            offset: 24 + 2 * token,
                            point: point[1..].to_vec(),
                            coefficient: r,
                        })
                        .collect(),
                );
                wt.push(lookup);
                range::verify_products(
                    &products,
                    rows.next().unwrap(),
                    product_wire,
                    delta,
                    &mut fs,
                )?;
                linear::verify(
                    n,
                    &model.root,
                    attempt,
                    layout,
                    &wf,
                    &wt,
                    &w_pcs,
                    delta,
                    &mut fs,
                    &mut rows,
                )?;
                if detach_input {
                    at[1].k += Fp3::ONE;
                }
                let checked = linear::verify(
                    n, &aux.root, attempt, layout, &af, &at, &a_pcs, delta, &mut fs, &mut rows,
                )?;
                assert!(rows.next().is_none());
                Ok(checked)
            };
            if wrong_cut {
                assert_eq!(check(false).unwrap_err(), "B12 P0 sumcheck MAC rejected");
            } else {
                assert_eq!(check(false).unwrap(), digest);
                assert!(check(true).is_err());
            }
        }
        for bits in [16, 26, 29, 32] {
            let mut fs = Fs::new(b"public P0 geometry only", 0);
            bind(bits, None, &mut fs).unwrap();
            bind(bits, Some(&vec![Fp3::ONE; bits]), &mut fs).unwrap();
            bind_public(bits, &mut fs).unwrap();
            assert_eq!(fs.requests(), 0);
        }
        for (bits, point) in [(33, None), (2, Some(&[Fp3::ONE][..]))] {
            let mut fs = Fs::new(b"bad P0 shape", 0);
            assert!(bind(bits, point, &mut fs).is_err());
        }
        assert!(prove(
            Vec::new(),
            Vec::new(),
            Auth::ZERO,
            None,
            &mut Fs::new(b"empty P0", 0),
            &mut Vec::new().into_iter()
        )
        .is_err());
    }
}
