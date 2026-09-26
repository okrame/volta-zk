#[path = "../src/gemma31b_bf16.rs"]
mod gemma31b_bf16;

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let limit: usize = match arguments.as_slice() {
        [limit] => limit.parse().map_err(|_| io::Error::other("invalid tensor byte limit"))?,
        _ => return Err(io::Error::other("usage: gemma31b_bf16_pack MAX_TENSOR_BYTES")),
    };
    if limit == 0 || limit % 2 != 0 {
        return Err(io::Error::other("tensor byte limit must be positive and even"));
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut header = [0; 8];
        if input.read(&mut header[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut header[1..])?;
        let bytes = usize::try_from(u64::from_le_bytes(header))
            .map_err(|_| io::Error::other("tensor byte length overflow"))?;
        if bytes == 0 || bytes % 2 != 0 || bytes > limit {
            return Err(io::Error::other("tensor exceeds byte budget or has invalid length"));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(bytes).map_err(io::Error::other)?;
        body.resize(bytes, 0);
        input.read_exact(&mut body)?;
        let invalid = |error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"));
        let maximum = gemma31b_bf16::scan_max_abs(&body).map_err(invalid)?;
        let exponent = gemma31b_bf16::minimum_exponent(maximum).map_err(invalid)?;
        gemma31b_bf16::convert_in_place(&mut body, exponent).map_err(invalid)?;
        output.write_all(&exponent.to_le_bytes())?;
        output.write_all(&maximum.to_le_bytes())?;
        output.write_all(&body)?;
        output.flush()?;
    }
}
