use rayon::prelude::*;
use serde::Serialize;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_proto::C6Nbr2TwoPointEvaluationPlan;

const PROFILE: &str = "C6NBR2-verifier-two-point-v1";
const SOURCE_COUNT: usize = 4_975_525;
const DIMENSION: usize = 23;
const THREADS: usize = 4;
const WARMUPS: usize = 5;
const SAMPLES: usize = 21;
const GATE_SECONDS: f64 = 0.034_327_610;

#[derive(Serialize)]
struct Machine {
    architecture: &'static str,
    available_parallelism: usize,
    rayon_threads: usize,
}

#[derive(Serialize)]
struct Timing {
    samples_seconds: Vec<f64>,
    median_seconds: f64,
    p95_seconds: f64,
    maximum_seconds: f64,
    gate_seconds: f64,
    p95_pass: bool,
}

#[derive(Serialize)]
struct Report {
    profile: &'static str,
    git_sha: String,
    git_dirty: bool,
    credit: bool,
    source_count: usize,
    padded_dimension: usize,
    padded_elements: usize,
    coefficient_bytes_read_per_evaluation: usize,
    points: usize,
    machine: Machine,
    timing: Timing,
    result_digest: String,
}

fn git_output(args: &[&str]) -> String {
    let output = Command::new("git").args(args).output().expect("run git");
    assert!(output.status.success(), "git command failed");
    String::from_utf8(output.stdout).expect("git output is UTF-8").trim().to_owned()
}

fn fixture() -> (Vec<Fp2>, [Vec<Fp2>; 2]) {
    let coefficients = (0..SOURCE_COUNT)
        .into_par_iter()
        .map(|index| {
            let index = index as u64;
            Fp2::new(
                Fp::new(index.wrapping_mul(0x9e37_79b9).wrapping_add(17)),
                Fp::new(index.wrapping_mul(0xd1b5_4a32).wrapping_add(29)),
            )
        })
        .collect();
    let points = [
        (0..DIMENSION)
            .map(|index| {
                Fp2::new(Fp::new(101 + 17 * index as u64), Fp::new(211 + 19 * index as u64))
            })
            .collect(),
        (0..DIMENSION)
            .map(|index| {
                Fp2::new(Fp::new(307 + 23 * index as u64), Fp::new(401 + 29 * index as u64))
            })
            .collect(),
    ];
    (coefficients, points)
}

fn digest(values: [Fp2; 2]) -> String {
    let mut bytes = Vec::with_capacity(32);
    for value in values {
        bytes.extend_from_slice(&value.c0.value().to_le_bytes());
        bytes.extend_from_slice(&value.c1.value().to_le_bytes());
    }
    blake3::hash(&bytes).to_hex().to_string()
}

fn main() {
    let date = std::env::var("C61_RECORD_DATE").expect("set C61_RECORD_DATE=YYYY-MM-DD");
    let git_sha = git_output(&["rev-parse", "HEAD"]);
    assert!(git_output(&["status", "--porcelain"]).is_empty(), "run of record requires clean tree");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .thread_name(|index| format!("c6nbr2-verifier-{index}"))
        .build()
        .expect("build four-thread verifier pool");
    let (coefficients, points) = pool.install(fixture);
    let plan = C6Nbr2TwoPointEvaluationPlan::new([&points[0], &points[1]])
        .expect("valid C6NBR2 evaluator points");
    let evaluate = || {
        pool.install(|| {
            plan.evaluate(black_box(&coefficients))
                .expect("valid C6NBR2 evaluator geometry")
        })
    };
    let expected = evaluate();
    for _ in 0..WARMUPS {
        assert_eq!(evaluate(), expected);
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        assert_eq!(black_box(evaluate()), expected);
        samples.push(started.elapsed().as_secs_f64());
    }
    let mut ordered = samples.clone();
    ordered.sort_by(f64::total_cmp);
    let median = ordered[ordered.len() / 2];
    let p95 = ordered[((ordered.len() * 95).div_ceil(100)).saturating_sub(1)];
    let maximum = *ordered.last().unwrap();
    let report = Report {
        profile: PROFILE,
        git_sha: git_sha.clone(),
        git_dirty: false,
        credit: false,
        source_count: SOURCE_COUNT,
        padded_dimension: DIMENSION,
        padded_elements: 1usize << DIMENSION,
        coefficient_bytes_read_per_evaluation: SOURCE_COUNT * std::mem::size_of::<Fp2>(),
        points: 2,
        machine: Machine {
            architecture: std::env::consts::ARCH,
            available_parallelism: std::thread::available_parallelism().unwrap().get(),
            rayon_threads: pool.current_num_threads(),
        },
        timing: Timing {
            samples_seconds: samples,
            median_seconds: median,
            p95_seconds: p95,
            maximum_seconds: maximum,
            gate_seconds: GATE_SECONDS,
            p95_pass: p95 < GATE_SECONDS,
        },
        result_digest: digest(expected),
    };
    let short_sha = &git_sha[..7];
    let path = PathBuf::from("../benchmarks/results")
        .join(format!("c6nbr2-verifier-{date}-{short_sha}.json"));
    fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).expect("write run of record");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    println!("record={}", path.display());
    assert!(report.timing.p95_pass, "C6NBR2 verifier marginal gate missed");
}
