//! Row-wise bit-packing codec for the PUBLIC band-logits download
//! (P7 prep, handoff spec §4.6.E).
//!
//! Transport-only: the logits matrix is public response output (never in
//! the transcript); the verifier decodes bit-exact i64 values and runs the
//! same public argmax / binding checks on them, so no protocol or soundness
//! surface is touched. Real logits rows have a range far below 2^64, so a
//! per-row (min, fixed bit-width) layout packs them at the row's true
//! entropy width without any model of the data.
//!
//! Format "VLPK1\0\0\0": magic (8 B), rows u32, cols u32; then per row:
//! min i64, width u8 (bits per value, 0..=64), ceil(cols·width/8) bytes of
//! little-endian bit-packed offsets `(v − min)` as u64.

const MAGIC: &[u8; 8] = b"VLPK1\0\0\0";

/// Width in bits needed to store every offset in `[0, range]`.
fn width_for(range: u128) -> u8 {
    (128 - range.leading_zeros()) as u8
}

/// Pack a rows×cols i64 matrix (row-major). Panics if shapes disagree.
pub fn pack_logits(rows: usize, cols: usize, data: &[i64]) -> Vec<u8> {
    assert_eq!(data.len(), rows * cols);
    let mut out = Vec::with_capacity(24 + rows * (9 + cols * 4));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(rows as u32).to_le_bytes());
    out.extend_from_slice(&(cols as u32).to_le_bytes());
    for r in 0..rows {
        let row = &data[r * cols..(r + 1) * cols];
        let min = row.iter().copied().min().unwrap_or(0);
        let max = row.iter().copied().max().unwrap_or(0);
        let width = width_for((max as i128 - min as i128) as u128);
        out.extend_from_slice(&min.to_le_bytes());
        out.push(width);
        // Bit cursor: accumulate LSB-first into a u128 spill buffer.
        let mut acc: u128 = 0;
        let mut nbits: u32 = 0;
        for &v in row {
            let off = (v as i128 - min as i128) as u128;
            acc |= off << nbits;
            nbits += width as u32;
            while nbits >= 8 {
                out.push((acc & 0xFF) as u8);
                acc >>= 8;
                nbits -= 8;
            }
        }
        if nbits > 0 {
            out.push((acc & 0xFF) as u8);
        }
    }
    out
}

/// Unpack; returns (rows, cols, data) or None on malformed input.
pub fn unpack_logits(buf: &[u8]) -> Option<(usize, usize, Vec<i64>)> {
    if buf.len() < 16 || &buf[..8] != MAGIC {
        return None;
    }
    let rows = u32::from_le_bytes(buf[8..12].try_into().ok()?) as usize;
    let cols = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
    let mut data = Vec::with_capacity(rows.checked_mul(cols)?);
    let mut pos = 16usize;
    for _ in 0..rows {
        let min = i64::from_le_bytes(buf.get(pos..pos + 8)?.try_into().ok()?);
        let width = *buf.get(pos + 8)? as u32;
        if width > 64 {
            return None;
        }
        pos += 9;
        let nbytes = (cols * width as usize).div_ceil(8);
        let packed = buf.get(pos..pos + nbytes)?;
        pos += nbytes;
        let mask: u128 = if width == 0 { 0 } else { (u128::MAX) >> (128 - width) };
        let mut acc: u128 = 0;
        let mut nbits: u32 = 0;
        let mut bytes = packed.iter();
        for _ in 0..cols {
            while nbits < width {
                acc |= (*bytes.next()? as u128) << nbits;
                nbits += 8;
            }
            let off = acc & mask;
            acc >>= width;
            nbits -= width;
            data.push((min as i128 + off as i128) as i64);
        }
    }
    if pos != buf.len() {
        return None;
    }
    Some((rows, cols, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(rows: usize, cols: usize, data: &[i64]) -> usize {
        let buf = pack_logits(rows, cols, data);
        let (r, c, dec) = unpack_logits(&buf).expect("well-formed");
        assert_eq!((r, c), (rows, cols));
        assert_eq!(dec, data, "codec must be bit-exact");
        buf.len()
    }

    #[test]
    fn roundtrip_random_rows() {
        // xorshift so the test has no dependency on `rand` in the lib target
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // Logits-like magnitudes: a few rows around ±2^30.
        let (rows, cols) = (5, 1237);
        let data: Vec<i64> = (0..rows * cols).map(|_| (next() as i64) >> 34).collect();
        let packed = roundtrip(rows, cols, &data);
        assert!(packed < rows * cols * 8, "must beat raw i64 on ranged data");
    }

    #[test]
    fn roundtrip_constant_and_empty_width() {
        let data = vec![42i64; 300];
        let packed = roundtrip(1, 300, &data);
        // width 0: header + row header only.
        assert_eq!(packed, 16 + 9);
    }

    #[test]
    fn roundtrip_full_i64_range() {
        // max−min needs the full 64-bit width (and i128 arithmetic).
        let data = vec![i64::MIN, i64::MAX, 0, -1, 1, i64::MIN + 1];
        roundtrip(2, 3, &data);
        roundtrip(1, 6, &data);
    }

    #[test]
    fn rejects_malformed() {
        assert!(unpack_logits(b"nope").is_none());
        let mut buf = pack_logits(1, 4, &[1, 2, 3, 4]);
        buf.push(0); // trailing garbage
        assert!(unpack_logits(&buf).is_none());
        buf.pop();
        buf.truncate(buf.len() - 1); // truncated payload
        assert!(unpack_logits(&buf).is_none());
    }
}
