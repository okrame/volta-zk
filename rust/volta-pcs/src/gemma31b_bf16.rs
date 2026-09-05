//! GemmaQuantV1 tensor-local BF16 scanner/packer, using only integer arithmetic.
//!
//! This is a CPU building block, not the authenticated safetensors ingester.
//! The caller must bind tensor lengths/order and shard hashes before publishing
//! the packed model. One source read uses one caller-budgeted tensor buffer;
//! scanning and conversion reuse that buffer. No full-model allocation exists.

use std::io::{self, Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantError {
    NonFinite,
    Overflow,
    OddLength,
}

/// Exact RNE(BF16 / 2^e), with symmetric [-32767, 32767] and no saturation.
pub fn quantize(bits: u16, exponent: i32) -> Result<i16, QuantError> {
    let encoded = (bits >> 7) & 255;
    let fraction = bits & 127;
    if encoded == 255 {
        return Err(QuantError::NonFinite);
    }
    let (significand, power) = if encoded == 0 {
        (u32::from(fraction), -133_i64)
    } else {
        (128 + u32::from(fraction), i64::from(encoded) - 134)
    };
    if significand == 0 {
        return Ok(0);
    }
    let shift = power - i64::from(exponent);
    let magnitude = if shift >= 0 {
        if shift >= 15 || significand > (32767 >> shift) {
            return Err(QuantError::Overflow);
        }
        significand << shift
    } else if shift < -9 {
        0
    } else {
        let divisor = 1_u32 << -shift;
        let quotient = significand / divisor;
        let remainder = significand % divisor;
        quotient
            + u32::from(2 * remainder > divisor || (2 * remainder == divisor && quotient & 1 != 0))
    };
    if magnitude > 32767 {
        return Err(QuantError::Overflow);
    }
    Ok(if bits & 0x8000 == 0 { magnitude as i16 } else { -(magnitude as i16) })
}

/// Nonnegative finite BF16 magnitudes are ordered by their raw bit patterns.
pub fn scan_max_abs(body: &[u8]) -> Result<u16, QuantError> {
    if body.len() % 2 != 0 {
        return Err(QuantError::OddLength);
    }
    let mut max_bits = 0;
    for pair in body.chunks_exact(2) {
        let magnitude = u16::from_le_bytes([pair[0], pair[1]]) & 0x7fff;
        if magnitude >= 0x7f80 {
            return Err(QuantError::NonFinite);
        }
        max_bits = max_bits.max(magnitude);
    }
    Ok(max_bits)
}

/// e = floor(log2(max |x|)) - 14 for nonzero BF16. The scaled significand
/// is an exact integer in [16384, 32640], and e-1 necessarily overflows.
pub fn minimum_exponent(max_abs_bits: u16) -> Result<i32, QuantError> {
    if max_abs_bits >= 0x7f80 {
        return Err(QuantError::NonFinite);
    }
    if max_abs_bits == 0 {
        return Ok(0);
    }
    let encoded = max_abs_bits >> 7;
    Ok(if encoded == 0 { max_abs_bits.ilog2() as i32 - 147 } else { i32::from(encoded) - 141 })
}

/// Convert in place after the complete tensor has passed scan_max_abs.
/// On error a prefix may have changed; callers must discard that buffer.
pub fn convert_in_place(body: &mut [u8], exponent: i32) -> Result<(), QuantError> {
    if body.len() % 2 != 0 {
        return Err(QuantError::OddLength);
    }
    for pair in body.chunks_exact_mut(2) {
        let value = quantize(u16::from_le_bytes([pair[0], pair[1]]), exponent)?;
        pair.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedTensor {
    pub exponent: i32,
    pub max_abs_bits: u16,
    pub source_bytes: usize,
}

/// The budget check precedes source I/O. The scratch slice holds exactly one
/// BF16 tensor; output reuses it as i16, with no second tensor-sized buffer.
/// A truncated/nonfinite tensor produces no output. Output I/O errors can leave
/// a partial destination; publication/rollback belongs to the outer ingester.
pub fn pack_tensor<R: Read, W: Write>(
    source: &mut R,
    output: &mut W,
    elements: usize,
    scratch: &mut [u8],
) -> io::Result<PackedTensor> {
    let bytes =
        elements.checked_mul(2).ok_or_else(|| io::Error::other("tensor length overflow"))?;
    if bytes == 0 || bytes > scratch.len() {
        return Err(io::Error::other("tensor does not fit the caller's scratch budget"));
    }
    let body = &mut scratch[..bytes];
    source.read_exact(body)?;
    let invalid = |error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"));
    let max_abs_bits = scan_max_abs(body).map_err(invalid)?;
    let exponent = minimum_exponent(max_abs_bits).map_err(invalid)?;
    convert_in_place(body, exponent).map_err(invalid)?;
    output.write_all(body)?;
    Ok(PackedTensor { exponent, max_abs_bits, source_bytes: bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn every_bf16_pattern_and_exponent_matches_independent_dyadic_reference() {
        // BF16 -> f32 -> f64 and power-of-two scaling are exact in this range.
        // This reference does not reuse the integer implementation's branches.
        for exponent in -149..=114 {
            let scale = 2_f64.powi(exponent);
            for bits in 0..=u16::MAX {
                let value = f64::from(f32::from_bits(u32::from(bits) << 16));
                let expected = if !value.is_finite() {
                    Err(QuantError::NonFinite)
                } else {
                    let rounded = (value / scale).round_ties_even();
                    if rounded.abs() > 32767.0 {
                        Err(QuantError::Overflow)
                    } else {
                        Ok(rounded as i16)
                    }
                };
                assert_eq!(quantize(bits, exponent), expected, "bits={bits:04x}, e={exponent}");
            }
        }
    }

    #[test]
    fn every_finite_nonzero_magnitude_has_the_minimum_exponent() {
        assert_eq!(minimum_exponent(0), Ok(0));
        for bits in 1..0x7f80 {
            let e = minimum_exponent(bits).unwrap();
            let q = quantize(bits, e).unwrap();
            assert!((16384..=32640).contains(&q));
            assert_eq!(quantize(bits, e - 1), Err(QuantError::Overflow));
            assert_eq!(quantize(bits | 0x8000, e).unwrap(), -q);
        }
        assert_eq!(quantize(0x3f80, i32::MAX), Ok(0));
        assert_eq!(quantize(0x3f80, i32::MIN), Err(QuantError::Overflow));
        assert_eq!(quantize(0x8000, i32::MIN), Ok(0));
    }

    #[test]
    fn source_once_tensor_buffer_and_no_output_on_invalid_input() {
        let raw = [0x80, 0x3f, 0x40, 0x40, 0, 0x80, 0xaa, 0xbb];
        let mut source = Cursor::new(raw);
        let mut scratch = [0_u8; 6];
        let mut packed = Vec::new();
        let result = pack_tensor(&mut source, &mut packed, 3, &mut scratch).unwrap();
        assert_eq!(source.position(), 6); // sentinel bytes belong to the next tensor
        assert_eq!(result, PackedTensor { exponent: -13, max_abs_bits: 0x4040, source_bytes: 6 });
        assert_eq!(packed, [0, 0x20, 0, 0x60, 0, 0]);
        for input in [&[0, 0x7f, 0x80, 0x7f][..], &[1, 0, 3][..]] {
            let mut source = Cursor::new(input);
            let mut output = Vec::new();
            assert!(pack_tensor(&mut source, &mut output, 2, &mut scratch).is_err());
            assert!(output.is_empty());
        }
        let mut source = Cursor::new(raw);
        assert!(pack_tensor(&mut source, &mut Vec::new(), 4, &mut scratch).is_err());
        assert_eq!(source.position(), 0);
        assert_eq!(scan_max_abs(&[0]), Err(QuantError::OddLength));
    }
}
