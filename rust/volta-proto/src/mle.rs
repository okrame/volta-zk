//! Multilinear-extension utilities, LSB-first variable order throughout
//! (index bit 0 ↔ first variable — same convention as volta-bench::logup).

use volta_field::{Fp, Fp2};

/// eq(r, ·) table over 2^len entries.
pub fn eq_vec(point: &[Fp2]) -> Vec<Fp2> {
    let mut t = vec![Fp2::ONE];
    // Each pass makes the processed variable the table LSB → reverse order.
    for &ri in point.iter().rev() {
        let mut next = Vec::with_capacity(t.len() * 2);
        for &v in &t {
            let v1 = v * ri;
            next.push(v - v1);
            next.push(v1);
        }
        t = next;
    }
    t
}

/// Bind the first (LSB) variable to `r`, in place.
pub fn fold_low(v: &mut Vec<Fp2>, r: Fp2) {
    let half = v.len() / 2;
    for i in 0..half {
        let d = v[2 * i + 1] - v[2 * i];
        v[i] = v[2 * i] + d * r;
    }
    v.truncate(half);
}

/// Evaluate the MLE of `values` (zero-padded to 2^point.len()) at `point`.
pub fn eval_mle(values: &[Fp2], point: &[Fp2]) -> Fp2 {
    let size = 1usize << point.len();
    assert!(values.len() <= size);
    let mut v = values.to_vec();
    v.resize(size, Fp2::ZERO);
    let mut p = point;
    let mut rest;
    while !p.is_empty() {
        fold_low(&mut v, p[0]);
        rest = &p[1..];
        p = rest;
    }
    v[0]
}

/// eq(a, b) for two equal-length points.
pub fn eq_points(a: &[Fp2], b: &[Fp2]) -> Fp2 {
    a.iter().zip(b).fold(Fp2::ONE, |acc, (&x, &y)| {
        let xy = x * y;
        acc * (xy + xy - x - y + Fp2::ONE)
    })
}

/// Quadratic Lagrange weights at `r` for nodes {0, 1, 2}.
pub fn lagrange3(r: Fp2) -> [Fp2; 3] {
    let two_inv = Fp::new(2).inv();
    let r1 = r - Fp2::ONE;
    let r2 = r - Fp2::from_base(Fp::new(2));
    [(r1 * r2).mul_base(two_inv), Fp2::ZERO - r * r2, (r * r1).mul_base(two_inv)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
    }

    #[test]
    fn eq_vec_is_lsb_first_and_eval_matches_direct() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(41);
        let point: Vec<Fp2> = (0..4).map(|_| rand_fp2(&mut rng)).collect();
        let eq = eq_vec(&point);
        for idx in 0u64..16 {
            let direct = (0..4).fold(Fp2::ONE, |p, j| {
                p * if (idx >> j) & 1 == 1 { point[j] } else { Fp2::ONE - point[j] }
            });
            assert_eq!(eq[idx as usize], direct, "index {idx}");
        }
        // eval via eq-inner-product == eval via folding
        let values: Vec<Fp2> = (0..16).map(|_| rand_fp2(&mut rng)).collect();
        let by_eq = values.iter().zip(&eq).fold(Fp2::ZERO, |a, (&v, &e)| a + v * e);
        assert_eq!(eval_mle(&values, &point), by_eq);
    }

    #[test]
    fn lagrange3_interpolates_quadratics() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..20 {
            let (a, b, c) = (rand_fp2(&mut rng), rand_fp2(&mut rng), rand_fp2(&mut rng));
            let g = |t: Fp2| a + b * t + c * t * t;
            let r = rand_fp2(&mut rng);
            let w = lagrange3(r);
            let interp =
                w[0] * g(Fp2::ZERO) + w[1] * g(Fp2::ONE) + w[2] * g(Fp2::from_base(Fp::new(2)));
            assert_eq!(interp, g(r));
        }
    }
}
