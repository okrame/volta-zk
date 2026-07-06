//! Dumps a JSON snapshot of one synthetic-weight/synthetic-input layer
//! forward pass, for cross-validation against scripts/gpt2_fixed.py.
//!
//! Usage: `cargo run --release -p volta-gpt2 --example dump_witness <seed> <t>`
//!
//! Mirrors `layer.rs` test convention: weights from `synthetic_weights(seed)`,
//! input from `synthetic_input(seed.wrapping_add(1), t)` (note the input seed
//! offset — the Python reference must reproduce it exactly), LUTs from
//! `build_luts(LutParams::default())`.
//!
//! Hand-rolled JSON printing (no serde dependency): every emitted array is a
//! flat JSON array of integers, printed via a tiny helper. `ffn_up_q` is
//! truncated to its first 1000 entries when `t >= 32` to keep stdout bounded
//! (t=100 would otherwise emit 307,200 entries just for that one field); for
//! t=8 (the small validation case) it is printed in full.

use std::env;

use volta_gpt2::luts::{build_luts, LutParams};
use volta_gpt2::layer::{forward_layer, synthetic_input, synthetic_weights, TableId};

fn print_i16_array(name: &str, v: &[i16], trailing_comma: bool) {
    print!("\"{name}\":[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{x}");
    }
    print!("]");
    if trailing_comma {
        print!(",");
    }
}

fn print_i64_array(name: &str, v: &[i64], trailing_comma: bool) {
    print!("\"{name}\":[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{x}");
    }
    print!("]");
    if trailing_comma {
        print!(",");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3, "usage: dump_witness <seed> <t>");
    let seed: u64 = args[1].parse().expect("seed must be a u64");
    let t: usize = args[2].parse().expect("t must be a usize");

    let luts = build_luts(LutParams::default());
    let w = synthetic_weights(seed);
    let x = synthetic_input(seed.wrapping_add(1), t);
    let wit = forward_layer(&x, &w, &luts, t);

    println!("{{");

    print_i16_array("k", &wit.k, true);
    println!();
    print_i16_array("v", &wit.v, true);
    println!();
    print_i16_array("q", &wit.q, true);
    println!();
    print_i16_array("ln1_out", &wit.ln1_out, true);
    println!();
    print_i64_array("denoms", &wit.denoms, true);
    println!();
    print_i16_array("recips", &wit.recips, true);
    println!();
    print_i16_array("attn_block_out", &wit.attn_block_out, true);
    println!();
    print_i16_array("ffn_block_out", &wit.ffn_block_out, true);
    println!();

    // ffn_up_q: truncated for large t to keep output bounded.
    let ffn_up_q_slice: &[i16] =
        if t >= 32 { &wit.ffn_up_q[..1000.min(wit.ffn_up_q.len())] } else { &wit.ffn_up_q };
    print_i16_array("ffn_up_q", ffn_up_q_slice, true);
    println!();

    // Lookup counts, in TableId::ALL (budget) order.
    print!("\"lookup_counts\":[");
    for (i, (name, n)) in wit.lookup_counts().iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{{\"name\":\"{name}\",\"count\":{n}}}");
    }
    println!("],");

    // First 16 entries + checksum (sum of all entries as i64) per nonlinear LUT.
    let dump_lut = |label: &str, tab: &[i16], trailing_comma: bool| {
        let head: Vec<i64> = tab.iter().take(16).map(|&v| v as i64).collect();
        let checksum: i64 = tab.iter().map(|&v| v as i64).sum();
        print!("\"{label}_head16\":[");
        for (i, v) in head.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            print!("{v}");
        }
        print!("],\"{label}_checksum\":{checksum}");
        if trailing_comma {
            println!(",");
        } else {
            println!();
        }
    };
    dump_lut("exp", &luts.exp, true);
    dump_lut("gelu", &luts.gelu, true);
    dump_lut("ln_rsqrt", &luts.ln_rsqrt, true);
    dump_lut("softmax_recip", &luts.softmax_recip, false);

    println!("}}");

    // Silence unused-import-style concerns without pulling in serde: touch
    // TableId so the enum stays part of the compiled example surface (the
    // budget order it defines is exactly the array above).
    let _ = TableId::ALL;
}
