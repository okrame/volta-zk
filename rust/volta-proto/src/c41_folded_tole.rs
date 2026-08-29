//! Minimal prover seam for the C4.1 folded-query typed OLE experiment.

use volta_accel::{AccelError, Backend, DeviceBuffer, Fp2Repr};
use volta_field::Fp2;

pub const C41_TYPED_POLYNOMIAL_LANES: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41FoldedQueries {
    pub a: [Fp2; C41_TYPED_POLYNOMIAL_LANES],
    pub b: [Fp2; C41_TYPED_POLYNOMIAL_LANES],
}

/// Reference for the two folded queries, with coefficient-major setup slabs.
pub fn c41_fold_typed_queries_reference(
    a: &[Fp2],
    b: &[Fp2],
    query: &[Fp2],
    correction_bitmap: &[u8],
) -> Result<C41FoldedQueries, &'static str> {
    let cells = query.len();
    let bitmap_bytes = cells.checked_add(7).ok_or("C4.1 cell count overflow")? / 8;
    let slab_len =
        C41_TYPED_POLYNOMIAL_LANES.checked_mul(cells).ok_or("C4.1 slab length overflow")?;
    if cells == 0
        || correction_bitmap.len() != bitmap_bytes
        || a.len() != slab_len
        || b.len() != a.len()
        || (cells % 8 != 0 && correction_bitmap[bitmap_bytes - 1] >> (cells % 8) != 0)
    {
        return Err("invalid C4.1 folded-query geometry or correction bit");
    }
    let mut folded = C41FoldedQueries {
        a: [Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES],
        b: [Fp2::ZERO; C41_TYPED_POLYNOMIAL_LANES],
    };
    for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
        for cell in 0..cells {
            let weight = query[cell];
            folded.a[lane] += weight * a[lane * cells + cell];
            let signed_weight = if (correction_bitmap[cell / 8] >> (cell % 8)) & 1 == 0 {
                weight
            } else {
                Fp2::ZERO - weight
            };
            folded.b[lane] += signed_weight * b[lane * cells + cell];
        }
    }
    Ok(folded)
}

/// Resident prover path. Output layout is the 12 `a` coefficients followed by
/// the 12 `(1-2e)b` coefficients and stays on device for the degree-12 close.
pub fn c41_fold_typed_queries_resident(
    backend: &mut Backend,
    a: &DeviceBuffer<Fp2Repr>,
    b: &DeviceBuffer<Fp2Repr>,
    query: &DeviceBuffer<Fp2Repr>,
    correction_bitmap: &DeviceBuffer<u8>,
    cells: usize,
) -> Result<DeviceBuffer<Fp2Repr>, AccelError> {
    backend.c41_fold_typed_queries_device(a, b, query, correction_bitmap, cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;

    #[test]
    fn folded_queries_match_direct_signed_sums_and_reject_non_bits() {
        let f = |x| Fp2::from_base(Fp::new(x));
        let query = [f(2), f(3), f(5)];
        let bitmap = [0b010];
        let mut a = Vec::new();
        let mut b = Vec::new();
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES as u64 {
            a.extend([f(lane + 1), f(lane + 2), f(lane + 3)]);
            b.extend([f(2 * lane + 1), f(2 * lane + 2), f(2 * lane + 3)]);
        }
        let folded = c41_fold_typed_queries_reference(&a, &b, &query, &bitmap).unwrap();
        for lane in 0..C41_TYPED_POLYNOMIAL_LANES {
            assert_eq!(
                folded.a[lane],
                query[0] * a[3 * lane] + query[1] * a[3 * lane + 1] + query[2] * a[3 * lane + 2]
            );
            assert_eq!(
                folded.b[lane],
                query[0] * b[3 * lane] - query[1] * b[3 * lane + 1] + query[2] * b[3 * lane + 2]
            );
        }
        assert!(c41_fold_typed_queries_reference(&a, &b, &query, &[0b1000]).is_err());
    }
}
