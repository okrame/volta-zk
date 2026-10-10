//! Reduced bridge from retained Gamma recipes to exact producer outputs,
//! original Boolean predicates, packed replay and coefficient support.
//! Synthetic private values grant no calibration, quality, CUDA or PCS credit.

use super::super::{compile, Integer};
use super::patterns::PackedReplay;
use super::*;

#[derive(Clone, Copy)]
struct Recipe {
    columns: usize,
    ex: i32,
    ew: i32,
    ey: i32,
    weighted: bool,
}

#[derive(Clone, Copy)]
struct Case {
    program: usize,
    p: i64,
    s: i64,
    y: i64,
    accepted: bool,
}

impl Case {
    fn frame(self, weighted: bool) -> [u8; 12] {
        let mut frame = [0; 12];
        let mut offset = 0;
        for (value, bytes) in [(self.p, if weighted { 4 } else { 2 }), (self.s, 6), (self.y, 2)] {
            let biased = (value + (1i64 << (8 * bytes - 1))) as u64;
            for bit in 0..bytes {
                frame[offset + bit] = (biased >> (8 * bit)) as u8;
            }
            offset += bytes;
        }
        frame
    }
}

fn retained_recipe(recipe: Recipe, sources: [u32; 2]) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bundle = root.join("artifact/c7.1-pod/h100-components-20261009T194100Z/gamma-inputs");
    let body = std::fs::read(bundle.join("candidate.json")).unwrap();
    assert_eq!(body.len(), 75_661);
    let candidate: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let oracle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bundle.join("oracle-plan-original.json")).unwrap())
            .unwrap();
    let context = &oracle["contexts"][0];
    assert_eq!(context["old_tokens"], 0);
    let norm = context["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["kind"] == "norm"
                && step["inputs"][0] == sources[0]
                && step["outputs"].as_array().unwrap().last()
                    == Some(&serde_json::json!(sources[1]))
        })
        .unwrap();
    assert_eq!(norm["parameters"]["columns"], recipe.columns);
    assert_eq!(norm["parameters"]["recipe"], serde_json::json!([recipe.ex, recipe.ew, recipe.ey]));
    let scales = &candidate["activation_exponents_by_source"];
    assert_eq!(scales[sources[0].to_string()], recipe.ex);
    assert_eq!(scales[sources[1].to_string()], recipe.ey);
    let weight_id = &norm["parameters"]["weight"];
    assert_eq!(!weight_id.is_null(), recipe.weighted);
    if recipe.weighted {
        let weight =
            context["weights"].as_array().unwrap().iter().find(|w| w["id"] == *weight_id).unwrap();
        assert_eq!(
            candidate["weight_exponents_by_tensor"][weight["name"].as_str().unwrap()],
            recipe.ew
        );
    }
    // Original SHA256 provenance is in the retained-input verification record;
    // this digest identifies precisely the bytes read by this component fixture.
    blake3::hash(&body).to_hex().to_string()
}

fn planes(
    program: &Circuit,
    cells: &[(usize, Option<usize>)],
    cases: &[Case],
    p: usize,
) -> (Vec<u64>, u64) {
    let mut input = vec![0; program.ports];
    for (lane, &(index, assignment)) in cells.iter().enumerate() {
        if assignment != Some(p) {
            continue;
        }
        input[1] |= 1u64 << lane;
        let frame = cases[index].frame(program.product_bits == 32);
        for bit in 0..program.ports - 2 {
            input[bit + 2] |= u64::from(frame[bit / 8] >> (bit % 8) & 1) << lane;
        }
    }
    let live = input[1];
    (input, live)
}

fn add_case(cases: &mut Vec<Case>, program: usize, p: i64, s: i64, y: i64) {
    cases.push(Case { program, p, s, y, accepted: true });
    for altered in [y - 1, y + 1, if y == 0 { 1 } else { -y }, -32768] {
        assert!((-32768..=32767).contains(&altered));
        cases.push(Case { program, p, s, y: altered, accepted: false });
    }
}

fn check_thresholds(base: Recipe, integer: &Integer, cases: &mut Vec<Case>) -> usize {
    // Predicate-only tuples exercise exact ties. They are deliberately not
    // claimed to be coupled P=XW/S=sum X^2 rows or new calibration witnesses.
    let (p0, p1, statistic) =
        if base.weighted { (64i64, 192i64, 0i64) } else { (3479, 10437, 415_871_066_112) };
    let [a, b, c] = integer.coefficients();
    let mut ties = 0;
    for (p, floor, rounded) in [(p0, 62i64, 62i64), (p1, 187, 188)] {
        assert_eq!(
            4 * a * (p as u128).pow(2),
            (b + c * statistic as u128) * (2 * floor as u128 + 1).pow(2)
        );
        for sign in [-1, 1] {
            assert_eq!(integer.round(sign * p, statistic).unwrap(), sign * rounded);
            add_case(cases, 0, sign * p, statistic, sign * rounded);
            ties += 1;
        }
        if !base.weighted {
            // Adjacent integer S brackets the very same exact half threshold.
            for (s, expected) in [(statistic - 1, floor + 1), (statistic + 1, floor)] {
                let distance = 4 * a * (p as u128).pow(2);
                let half = (b + c * s as u128) * (2 * floor as u128 + 1).pow(2);
                assert_eq!(distance > half, s < statistic);
                assert_ne!(distance, half);
                for sign in [-1, 1] {
                    assert_eq!(integer.round(sign * p, s).unwrap(), sign * expected);
                    add_case(cases, 0, sign * p, s, sign * expected);
                }
            }
        } else {
            for adjacent in [p - 1, p + 1] {
                let y = integer.round(adjacent, statistic).unwrap();
                for sign in [-1, 1] {
                    add_case(cases, 0, sign * adjacent, statistic, sign * y);
                }
            }
        }
    }
    ties
}

fn check_support(programs: &[Circuit], geometry: &[usize], good: &[Case]) {
    let assignments = [Some(0), Some(1), None, Some(2), Some(0), None, Some(2), Some(1)];
    let cases: Vec<_> = assignments.iter().map(|p| p.map_or(good[0], |p| good[p])).collect();
    for depth in [1, 32] {
        let width = geometry[depth - 1];
        let cells: Vec<_> = assignments.iter().enumerate().map(|(i, &p)| (i, p)).collect();
        let mut packed = PackedReplay::new(programs, depth - 1, width).unwrap();
        packed
            .load(&cells, &|i| {
                assert!(assignments[i].is_some());
                cases[i].frame(programs[0].product_bits == 32)
            })
            .unwrap();
        let literal: Vec<_> = programs
            .iter()
            .enumerate()
            .map(|(p, program)| {
                let (input, live) = planes(program, &cells, &cases, p);
                program.replay_layer(&input, live, (depth - 1).min(program.levels.len())).unwrap().0
            })
            .collect();
        let field = |n| Fp3::new(Fp::new(n), Fp::new(2 * n + 1), Fp::new(3 * n + 5));
        let weights: Vec<_> = (0..geometry[depth]).map(|i| field(i as u64 + 2)).collect();
        let selectors = eq(&[field(3), field(7), field(11)]);
        for prefix in [vec![], vec![field(13)]] {
            let selector = |i: usize| Ok(assignments[i].map(|p| (p, selectors[i])));
            let mut actual_work = SourceCellWork::default();
            let actual = source_cell_coefficients::<true>(
                programs,
                depth,
                width,
                8,
                &prefix,
                &|i, out| packed.row(i, out),
                &selector,
                &weights,
                &mut actual_work,
            )
            .unwrap();
            let expected = source_cell_coefficients::<false>(
                programs,
                depth,
                width,
                8,
                &prefix,
                &|i, out| {
                    let p = assignments[i].unwrap();
                    out.fill(Fp3::ZERO);
                    for (v, &bits) in out.iter_mut().zip(&literal[p]) {
                        *v = Fp3::ONE.mul_bool(bits >> i & 1 == 1);
                    }
                    Ok(())
                },
                &selector,
                &weights,
                &mut SourceCellWork::default(),
            )
            .unwrap();
            assert_eq!(actual, expected);
            let active = 8 >> prefix.len();
            let half = active / 2;
            let mut selected = 0;
            let mut saved = 0;
            let mut unsupported = 0;
            for pair in 0..half {
                let mut present = [false; 3];
                for side in 0..2 {
                    for pre in 0..1 << prefix.len() {
                        if let Some(p) = assignments[pair + side * half + pre * active] {
                            present[p] = true;
                        }
                    }
                }
                for (p, program) in programs.iter().enumerate() {
                    if present[p] {
                        selected += gates(program, depth).len() as u64;
                    } else {
                        saved += gates(program, depth).len() as u64;
                        unsupported += 1;
                    }
                }
            }
            assert_eq!(actual_work.gate_cell_iterations, selected);
            assert_eq!(actual_work.unsupported_gate_iterations_saved, saved);
            assert_eq!(actual_work.unsupported_program_cells, unsupported);
            assert_eq!(actual_work.logical_gate_cell_iterations, selected + saved);
            assert_eq!(actual_work.row_source_callbacks, 6);
            assert_eq!(actual_work.selector_source_callbacks, 8);
            if prefix.is_empty() {
                assert!(actual_work.boolean_first_round_gate_products_saved > 0);
            }
            println!(
                "C71_GAMMA_REDUCED_SUPPORT {}",
                serde_json::json!({"depth":depth,"prefix":prefix.len(),"work":actual_work,"literal_Fp3_coefficients_exact":true,"support_enumeration_exact":true,"credit":false})
            );
        }
    }
}

fn fixture(base: Recipe, sources: [u32; 2]) {
    let candidate_blake3 = retained_recipe(base, sources);
    let variants = [
        base,
        Recipe { ex: base.ex + base.ex.rem_euclid(2), ey: base.ey + base.ey.rem_euclid(2), ..base },
        Recipe { ex: base.ex - base.ex.rem_euclid(2), ey: base.ey - base.ey.rem_euclid(2), ..base },
    ];
    let programs: Vec<_> = variants
        .iter()
        .map(|r| compile(r.columns, r.ex, r.ew, r.ey, r.weighted).unwrap())
        .collect();
    let geometry = widths(&programs).unwrap();
    let source: Vec<_> = (0..base.columns).map(|i| 4 * ((i % 17) as i64 - 8)).collect();
    let weights: Vec<_> = (0..base.columns)
        .map(|i| (257 + i % 17) as i16 * if i % 3 == 0 { -1 } else { 1 })
        .collect();
    let mut cases = Vec::new();
    let mut good = Vec::new();
    let mut signs = [0usize; 3];
    for (p, recipe) in variants.iter().enumerate() {
        assert_eq!(recipe.ew, base.ew);
        let inputs: Vec<_> = source
            .iter()
            .map(|&x| {
                if recipe.ex > base.ex {
                    x / 2
                } else if recipe.ex < base.ex {
                    x * 2
                } else {
                    x
                }
            })
            .collect();
        let min_ex = recipe.ex.min(base.ex);
        for (&x, &y) in source.iter().zip(&inputs) {
            assert_eq!(x * (1 << (base.ex - min_ex)), y * (1 << (recipe.ex - min_ex)));
        }
        let integer =
            Integer::new(recipe.columns, recipe.ex, recipe.ew, recipe.ey, recipe.weighted).unwrap();
        assert_eq!(integer.coefficients(), programs[p].coefficients);
        let (s, products, output) =
            integer.row(&inputs, recipe.weighted.then_some(weights.as_slice())).unwrap();
        assert_eq!(s, inputs.iter().map(|x| x * x).sum::<i64>());
        for (i, &x) in inputs.iter().enumerate() {
            assert_eq!(products[i], x * if recipe.weighted { i64::from(weights[i]) } else { 1 });
        }
        assert!(output.iter().any(|&y| y != 0));
        for &i in &[0, 1, 8, base.columns / 2, base.columns - 1] {
            signs[if output[i] < 0 {
                0
            } else if output[i] == 0 {
                1
            } else {
                2
            }] += 1;
            add_case(&mut cases, p, products[i], s, output[i]);
        }
        good.push(Case { program: p, p: products[0], s, y: output[0], accepted: true });
    }
    assert!(signs.iter().all(|&n| n > 0));
    let integer = Integer::new(base.columns, base.ex, base.ew, base.ey, base.weighted).unwrap();
    let row_cases = cases.len();
    let exact_ties = check_thresholds(base, &integer, &mut cases);
    let program_owned_bytes = programs.capacity() * core::mem::size_of::<Circuit>()
        + programs
            .iter()
            .map(|p| {
                p.levels.capacity() * core::mem::size_of::<Vec<Gate>>()
                    + p.levels
                        .iter()
                        .map(|l| l.capacity() * core::mem::size_of::<Gate>())
                        .sum::<usize>()
            })
            .sum::<usize>();
    for depth in [0, 32, geometry.len() - 1] {
        let width = geometry[depth];
        let mut packed = PackedReplay::new(&programs, depth, width).unwrap();
        for chunk in (0..cases.len()).collect::<Vec<_>>().chunks(60) {
            let mut cells = Vec::new();
            for (i, &index) in chunk.iter().enumerate() {
                cells.push((index, Some(cases[index].program)));
                if i % 15 == 14 {
                    cells.push((usize::MAX, None));
                }
            }
            let seen = std::cell::RefCell::new(Vec::new());
            packed
                .load(&cells, &|i| {
                    seen.borrow_mut().push(i);
                    cases[i].frame(base.weighted)
                })
                .unwrap();
            assert_eq!(
                *seen.borrow(),
                cells.iter().filter_map(|&(i, p)| p.map(|_| i)).collect::<Vec<_>>()
            );
            let mut expected = vec![0u64; width];
            for (p, program) in programs.iter().enumerate() {
                let (input, live) = planes(program, &cells, &cases, p);
                let full = program.replay(&input, live).unwrap();
                let selected = depth.min(program.levels.len());
                let (layer, _) = program.replay_layer(&input, live, selected).unwrap();
                assert_eq!(layer, full[selected]);
                for (v, &bits) in expected.iter_mut().zip(&layer) {
                    *v |= bits;
                }
            }
            assert_eq!(packed.planes(), expected);
            let allowed = if cells.len() == 64 { u64::MAX } else { (1u64 << cells.len()) - 1 };
            assert!(packed.planes().iter().all(|&v| v & !allowed == 0));
            if depth == geometry.len() - 1 {
                for (lane, &(i, p)) in cells.iter().enumerate() {
                    assert_eq!(
                        packed.planes()[0] >> lane & 1,
                        u64::from(p.is_some_and(|_| cases[i].accepted))
                    );
                }
            }
        }
        let work = packed.work();
        assert!(work.plan_build_capacity_upper_bytes >= work.plan_capacity_bytes);
        assert!(work.scratch_moving_capacity_upper_bytes >= work.scratch_capacity_bytes);
        assert_eq!(work.fixed_frame_stack_bytes, 64 * 12);
        assert_eq!(work.dag_word_operations, work.dag_word_and + work.dag_word_xor);
        assert!(work.dag_word_operations <= work.original_scalar_gate_equivalent);
        packed.load(&[], &|_| panic!("empty getter")).unwrap();
        assert!(packed.planes().iter().all(|&v| v == 0));
        assert_eq!(
            packed.work().scratch_capacity_bytes,
            work.scratch_capacity_bytes,
            "empty load retains charged scratch"
        );
        println!(
            "C71_GAMMA_REDUCED_RMS {}",
            serde_json::json!({"source_ids":sources,"baseline_candidate_blake3":candidate_blake3,"recipes":variants.iter().map(|r|[r.ex,r.ew,r.ey]).collect::<Vec<_>>(),"columns":base.columns,"weighted":base.weighted,"depth":depth,"cases":cases.len(),"row_cases":row_cases,"predicate_only_threshold_cases":cases.len()-row_cases,"exact_signed_half_ties":exact_ties,"synthetic_row_output_sign_counts":signs,"same_physical_input_and_W_for_row_cases":true,"original_Integer_Boolean_and_packed_exact":true,"program_owned_bytes":program_owned_bytes,"packed_work":work,"memory_scope":"three reduced circuits and packed adapter; excludes numeric/reference fixture vectors, allocator, complete two-role lifetime, PCG, PCS and hardware peak","quality_checked":false,"real_weights":false,"credit":false,"GPU_execution":false})
        );
    }
    check_support(&programs, &geometry, &good);
}

#[test]
fn c71_gamma_reduced_weighted_rms_original_predicate_packed_and_support() {
    fixture(Recipe { columns: 256, ex: -5, ew: -18, ey: -13, weighted: true }, [779, 1379]);
}

#[test]
fn c71_gamma_reduced_unweighted_rms_original_predicate_packed_and_support() {
    fixture(Recipe { columns: 512, ex: -5, ew: 0, ey: -9, weighted: false }, [889, 1523]);
}
