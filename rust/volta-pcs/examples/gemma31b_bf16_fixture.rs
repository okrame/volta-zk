//! Bounded cross-language test driver, not a checkpoint ingester.
//! stdin: raw BF16 tensor, <= 1 MiB. stdout: e:i32le | max_abs:u16le | i16 bytes.
#[path = "../src/gemma31b_bf16.rs"]
mod gemma31b_bf16;

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut raw)?;
    if raw.is_empty() || raw.len() > 1_048_576 || raw.len() % 2 != 0 {
        return Err(io::Error::other("fixture must be a nonempty even tensor <= 1 MiB"));
    }
    let mut scratch = vec![0; raw.len()];
    let mut packed = Vec::new();
    let count = raw.len() / 2;
    let result = gemma31b_bf16::pack_tensor(&mut &raw[..], &mut packed, count, &mut scratch)?;
    let mut output = io::stdout().lock();
    output.write_all(&result.exponent.to_le_bytes())?;
    output.write_all(&result.max_abs_bits.to_le_bytes())?;
    output.write_all(&packed)
}
