//! Independent optimized-Rust reference for the P7 CUDA PCS hash spike.

use rayon::prelude::*;
use serde::Serialize;
use std::time::Instant;

const P: u64 = 0xFFFF_FFFF_0000_0001;

#[derive(Serialize)]
struct Report {
    rows: usize,
    cols: usize,
    threads: usize,
    reps: usize,
    cpu_s: f64,
    root: String,
}

fn root(encoded: &[u64], rows: usize, cols: usize) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = (0..cols)
        .into_par_iter()
        .map(|j| {
            let mut bytes = vec![0u8; rows * 8];
            for i in 0..rows {
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&encoded[i * cols + j].to_le_bytes());
            }
            *blake3::hash(&bytes).as_bytes()
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut h = blake3::Hasher::new();
                h.update(&pair[0]);
                h.update(&pair[1]);
                *h.finalize().as_bytes()
            })
            .collect();
    }
    level[0]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 5, "ROWS COLS REPS THREADS");
    let rows: usize = args[1].parse().unwrap();
    let cols: usize = args[2].parse().unwrap();
    let reps: usize = args[3].parse().unwrap();
    let threads: usize = args[4].parse().unwrap();
    assert!(cols.is_power_of_two() && rows % 8 == 0);
    rayon::ThreadPoolBuilder::new().num_threads(threads).build_global().unwrap();
    let encoded: Vec<u64> = (0..rows * cols)
        .into_par_iter()
        .map(|i| (i as u64).wrapping_mul(0x9E37_79B9).wrapping_add(17) % P)
        .collect();

    let warm = root(&encoded, rows, cols);
    let mut times = Vec::with_capacity(reps);
    let mut got = warm;
    for _ in 0..reps {
        let t0 = Instant::now();
        got = root(&encoded, rows, cols);
        times.push(t0.elapsed().as_secs_f64());
    }
    assert_eq!(got, warm);
    times.sort_by(f64::total_cmp);
    let report = Report {
        rows,
        cols,
        threads,
        reps,
        cpu_s: times[times.len() / 2],
        root: got.iter().map(|b| format!("{b:02x}")).collect(),
    };
    println!("{}", serde_json::to_string(&report).unwrap());
}
