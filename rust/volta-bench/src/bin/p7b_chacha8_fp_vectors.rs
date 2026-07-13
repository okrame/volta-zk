//! CPU oracle for `cuda/p7b_chacha8_fp_diff.cu`.
//!
//! This intentionally calls `volta_field::FpStream`, so the expected vectors
//! come from the repository's rand_chacha 0.3.1 implementation rather than a
//! second hand-written ChaCha implementation.

use std::env;
use std::process::ExitCode;
use volta_field::FpStream;

const DEFAULT_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Fp,
    Fp2,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "fp" => Ok(Self::Fp),
            "fp2" => Ok(Self::Fp2),
            _ => Err(format!("invalid mode {value:?}; expected fp or fp2")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Fp => "fp",
            Self::Fp2 => "fp2",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    mode: Mode,
    seed: [u8; 32],
    seed_hex: String,
    base_domain: u64,
    rows: u64,
    count: u64,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} [--mode fp|fp2] [--seed-hex 64_HEX] \
         [--base-domain U64] [--rows U64] [--count U64]\n\
         defaults: --mode fp --seed-hex {DEFAULT_SEED_HEX} \
         --base-domain 0x0123456789abcdef --rows 3 --count 10"
    )
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid {name} value {value:?}"))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_seed(value: &str) -> Result<([u8; 32], String), String> {
    let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    if value.len() != 64 {
        return Err(format!("seed must contain exactly 64 hex digits, got {}", value.len()));
    }
    let mut seed = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| format!("invalid seed hex at digit {}", 2 * index))?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| format!("invalid seed hex at digit {}", 2 * index + 1))?;
        seed[index] = (hi << 4) | lo;
    }
    let normalized = seed.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Ok((seed, normalized))
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let program = args.next().unwrap_or_else(|| "p7b_chacha8_fp_vectors".into());
    let (default_seed, default_seed_hex) = parse_seed(DEFAULT_SEED_HEX)?;
    let mut parsed = Args {
        mode: Mode::Fp,
        seed: default_seed,
        seed_hex: default_seed_hex,
        base_domain: 0x0123_4567_89ab_cdef,
        rows: 3,
        count: 10,
    };
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("{}", usage(&program));
            return Ok(None);
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {flag:?}\n{}", usage(&program)))?;
        match flag.as_str() {
            "--mode" => parsed.mode = Mode::parse(&value)?,
            "--seed-hex" => {
                (parsed.seed, parsed.seed_hex) = parse_seed(&value)?;
            }
            "--base-domain" => parsed.base_domain = parse_u64(&value, "base domain")?,
            "--rows" => parsed.rows = parse_u64(&value, "rows")?,
            "--count" => parsed.count = parse_u64(&value, "count")?,
            _ => return Err(format!("unknown argument {flag:?}\n{}", usage(&program))),
        }
    }
    if parsed.rows != 0 {
        parsed
            .base_domain
            .checked_add(parsed.rows - 1)
            .ok_or_else(|| "base_domain + row overflows u64".to_string())?;
    }
    parsed
        .rows
        .checked_mul(parsed.count)
        .ok_or_else(|| "rows * count overflows u64".to_string())?;
    Ok(Some(parsed))
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:016x}")
}

fn emit(args: &Args) {
    println!("{{");
    println!("  \"schema\":\"p7b-chacha8-fp-diff-v1\",");
    println!("  \"mode\":\"{}\",", args.mode.as_str());
    println!("  \"seed_hex\":\"{}\",", args.seed_hex);
    println!("  \"base_domain\":\"{}\",", hex_u64(args.base_domain));
    println!("  \"rows\":{},", args.rows);
    println!("  \"count\":{},", args.count);
    println!("  \"values\":[");
    for row in 0..args.rows {
        let domain = args.base_domain + row;
        let mut stream = FpStream::domain_separated(args.seed, domain);
        print!("    [");
        for index in 0..args.count {
            if index != 0 {
                print!(",");
            }
            match args.mode {
                Mode::Fp => print!("\"{}\"", hex_u64(stream.next_fp().value())),
                Mode::Fp2 => {
                    let value = stream.next_fp2();
                    print!("[\"{}\",\"{}\"]", hex_u64(value.c0.value()), hex_u64(value.c1.value()));
                }
            }
        }
        println!("]{}", if row + 1 == args.rows { "" } else { "," });
    }
    println!("  ]");
    println!("}}");
}

fn main() -> ExitCode {
    match parse_args(env::args()) {
        Ok(Some(args)) => {
            emit(&args);
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_parser_normalizes_case_and_prefix() {
        let (seed, normalized) =
            parse_seed(&format!("0x{}", DEFAULT_SEED_HEX.to_uppercase())).unwrap();
        assert_eq!(seed[0], 0);
        assert_eq!(seed[31], 31);
        assert_eq!(normalized, DEFAULT_SEED_HEX);
    }

    #[test]
    fn row_domains_are_checked_for_overflow() {
        let args = ["vectors", "--base-domain", "0xffffffffffffffff", "--rows", "2"]
            .into_iter()
            .map(str::to_string);
        assert!(parse_args(args).unwrap_err().contains("overflows u64"));
    }

    #[test]
    fn oracle_vector_spans_chacha_blocks() {
        let (seed, _) = parse_seed(DEFAULT_SEED_HEX).unwrap();
        let mut stream = FpStream::domain_separated(seed, 0x0123_4567_89ab_cdef);
        let expected = [
            0xcab1_608b_e19d_e75c,
            0x3a54_a2ab_49bd_3a62,
            0xe9f7_9eec_956b_f3db,
            0xdef9_6cc2_1ee6_b9b4,
            0x19ed_3e57_18c8_f07d,
            0xcbb3_9f9a_abfd_401d,
            0x08ab_f290_b06c_eab3,
            0x2266_ecf8_eb5b_8330,
            0x2f22_922e_ddf1_dd9b,
            0x1dfe_eb83_441e_54fa,
            0x0a04_76c6_e86d_f9e8,
            0xe59b_6ccb_9bd3_671d,
        ];
        let got: Vec<u64> = (0..expected.len()).map(|_| stream.next_fp().value()).collect();
        assert_eq!(got, expected);
    }
}
