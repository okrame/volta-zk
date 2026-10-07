//! Integer row producer over the verifier-owned canonical DAG.
//! No FS, MAC, PCG, commitment, dense A or automatic scale selection.
//! Tables must already belong to a validated public profile. This internal
//! primitive does not authenticate a getter or certify calibration quality.
use super::*;

#[derive(Default)]
pub(super) struct Row {
    // Consecutive physical rows; RMS emits one statistic/product row per head.
    pub(super) values: Vec<(usize, usize, Vec<i64>)>,
    // Original histogram entry visits. The caller adds them exactly once.
    pub(super) histogram: Option<(usize, Vec<usize>)>,
    pub(super) token: Option<u32>,
}

/// Public-address dense batch over original rows, never padded token rows.
/// The same descriptor fixes CPU reconstruction and the native GEMM layout.
pub(super) struct MatrixBatch {
    pub input: usize,
    pub input_first: usize,
    pub tensor: usize,
    pub weight_offset: usize,
    pub rows: usize,
    pub columns: usize,
    pub inner: usize,
}

pub(super) struct EmbeddingBatch {
    pub tensor: usize,
    pub weight_offset: usize,
    pub vocabulary: usize,
    pub columns: usize,
}
impl EmbeddingBatch {
    pub(super) fn new(
        plan: &Plan,
        b: &bytes::Bytes,
        first: usize,
        tokens: &[u32],
    ) -> Result<Self, String> {
        let c = plan.cohorts.first().ok_or("embedding cohort missing")?;
        let w = plan.sources.get(c.tensor).ok_or("embedding W missing")?;
        let output = b.scalar.layout.sources.first().ok_or("embedding source missing")?;
        if b.scalar.weight_layout != plan.layout_digest
            || c.kind != Kind::Lookup
            || c.operation != "embedding_lookup"
            || c.heads != 1
            || b.widths.first() != Some(&2)
            || (output.rows, output.cols) != (c.rows, c.columns)
            || w.cols != c.columns
            || !(1..=21504).contains(&w.cols)
            || !(1..=262144).contains(&w.rows)
            || tokens.is_empty()
            || tokens.len() > 150
            || first.checked_add(tokens.len()).is_none_or(|end| end > c.rows)
            || tokens.iter().any(|&token| token as usize >= w.rows)
            || w.rows.checked_mul(w.cols).and_then(|n| w.packed_offset.checked_add(n)).is_none()
        {
            return Err("embedding original shape, token or rows differ".into());
        }
        Ok(Self {
            tensor: c.tensor,
            weight_offset: w.packed_offset,
            vocabulary: w.rows,
            columns: w.cols,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn c71_b12_native_canonical_numeric_rows_original_routes() {
        let plan = super::super::super::super::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut scales: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            scales.insert(l.pi, -14);
        }
        let v_norm = s
            .attention
            .rope
            .gate_up
            .gelu
            .rms
            .norms
            .iter()
            .find(|n| n.layer == Some(0) && n.operation == "v_norm")
            .unwrap();
        scales.insert(v_norm.output, -1); // Catch accidental reuse of [0; 3] RMS recipes.
                                          // Identity/constant tables are explicit test inputs, NOT calibrated Gamma.
        let identity: Vec<i16> = (-32767..=32767).map(|x| x as i16).collect();
        let exponential = vec![1i32 << 30; 65535];
        let gelu: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I16(&identity),
            })
            .collect();
        let exp30: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I32(&exponential),
            })
            .collect();
        let rope_local = vec![vec![[1 << 30, 0]; 128]; 150];
        let rope_global = vec![vec![[1 << 30, 0]; 64]; 150];
        let absent = |_, _, _| -> Result<i64, String> { panic!("unexpected producer read") };
        for slot in 0..3 {
            let p = Canonical::compile(slot, &[0; 772], &scales).unwrap();
            let mut batches = 0;
            for (raw, c) in p.plan.cohorts.iter().enumerate() {
                if c.kind != Kind::Matrix {
                    continue;
                }
                let batch = p.matrix_batch(raw, 0, c.rows).unwrap();
                assert_eq!((batch.rows, batch.columns, batch.inner), (c.rows, c.columns, c.inner));
                assert_eq!(batch.input, p.bytes().scalar.input_sources[raw - 1]);
                assert_eq!(batch.input_first, p.plan.input_route(raw).unwrap().row_offset);
                assert_eq!(batch.weight_offset, p.plan.sources[c.tensor].packed_offset);
                assert_eq!(
                    p.matrix_batch(raw, c.rows - 1, 1).unwrap().input_first,
                    batch.input_first + c.rows - 1
                );
                for (first, rows) in
                    [(0, 0), (0, 151), (c.rows, 1), (usize::MAX, 1), (1, usize::MAX)]
                {
                    assert!(p.matrix_batch(raw, first, rows).is_err());
                }
                batches += 1;
            }
            eprintln!("C71_MATRIX_BATCH_GEOMETRY slot={slot} batches={batches} execution=false");
            let rope = [
                kernel::rope::Table { position: slot * 150, rows: &rope_local },
                kernel::rope::Table { position: slot * 150, rows: &rope_global },
            ];
            let tables =
                profile::Tables { gelu: &gelu, exp30: &exp30, softcap: &gelu[0], rope: &rope };
            let b = p.bytes();
            let rms = &p.sources.attention.rope.gate_up.gelu.rms;
            let a = &p.sources.attention;
            let w = |_, _, c| Ok((c % 3) as i64 - 1);
            let x = |_, _, c| Ok((c % 3) as i64 - 1);
            let embedded =
                p.prepare_row(&Producer::Embedding, 149, 7, &tables, w, absent, absent).unwrap();
            assert_eq!(embedded.values[0].1, 149);
            assert_eq!(embedded.values[0].2[0..3], [-1, 0, 1]);
            assert!(p
                .prepare_row(&Producer::Embedding, 150, 7, &tables, absent, absent, absent)
                .is_err());
            assert!(p
                .prepare_row(&Producer::Embedding, 0, u32::MAX, &tables, absent, absent, absent)
                .is_err());
            assert!(p
                .prepare_row(
                    &Producer::Embedding,
                    0,
                    7,
                    &tables,
                    |_, _, _| Ok(-32768),
                    absent,
                    absent
                )
                .is_err());

            // Canonical selected lm_head input: fail at its FIRST read, before
            // running the 1.4-billion-product row. This checks the actual route.
            let head = p.plan.cohorts.len() - 1;
            let route = p.plan.input_route(head).unwrap();
            let seen = Cell::new(false);
            assert!(p
                .prepare_row(
                    &Producer::Matrix(head),
                    49,
                    0,
                    &tables,
                    absent,
                    |id, r, c| {
                        assert_eq!(
                            (id, r, c),
                            (b.scalar.input_sources[head - 1], 49 + route.row_offset, 0)
                        );
                        seen.set(true);
                        Err("stop after original selected address".into())
                    },
                    absent
                )
                .is_err());
            assert!(seen.get());

            if slot == 0 {
                // One actual canonical projection row, not a full inference.
                let id = p
                    .plan
                    .cohorts
                    .iter()
                    .position(|c| c.layer == Some(0) && c.operation == "v_source")
                    .unwrap();
                let c = &p.plan.cohorts[id];
                let reads = Cell::new(0usize);
                let raw = p
                    .prepare_row(
                        &Producer::Matrix(id),
                        1,
                        0,
                        &tables,
                        |tensor, _, _| {
                            assert_eq!(tensor, c.tensor);
                            reads.set(reads.get() + 1);
                            Ok(2)
                        },
                        |source, r, _| {
                            assert_eq!((source, r), (b.scalar.input_sources[id - 1], 1));
                            Ok(1)
                        },
                        absent,
                    )
                    .unwrap();
                assert_eq!(reads.get(), c.inner * c.columns);
                assert!(raw.values[0].2.iter().all(|&v| v == 2 * c.inner as i64));
                let input_reads = Cell::new(0usize);
                reads.set(0);
                let workspace = 3 * c.inner * 2 + 3 * c.columns * 16;
                let batch = p
                    .prepare_matrix_batch(
                        id,
                        147,
                        3,
                        workspace,
                        |tensor, j, k| {
                            assert_eq!(tensor, c.tensor);
                            reads.set(reads.get() + 1);
                            Ok((j as i64 % 5 - 2) * (k as i64 % 3 - 1))
                        },
                        |source, r, k| {
                            assert_eq!(source, b.scalar.input_sources[id - 1]);
                            input_reads.set(input_reads.get() + 1);
                            Ok((r as i64 - 148) * (k as i64 % 3 - 1))
                        },
                    )
                    .unwrap();
                assert_eq!(reads.get(), c.inner * c.columns);
                assert_eq!(input_reads.get(), 3 * c.inner);
                assert_eq!((batch.values[0].0, batch.values[0].1), (id, 147));
                let norm = (0..c.inner).map(|k| (k as i64 % 3 - 1).pow(2)).sum::<i64>();
                for (r, values) in batch.values[0].2.chunks_exact(c.columns).enumerate() {
                    for (j, &v) in values.iter().enumerate() {
                        assert_eq!(v, (r as i64 - 1) * (j as i64 % 5 - 2) * norm);
                    }
                }
                assert!(p.prepare_matrix_batch(id, 147, 3, workspace - 1, absent, absent).is_err());
                assert!(p.prepare_matrix_batch(0, 0, 1, usize::MAX, absent, absent).is_err());
                assert!(p
                    .prepare_matrix_batch(id, 0, 1, usize::MAX, absent, |_, _, _| Ok(-32768))
                    .is_err());
                assert!(p
                    .prepare_matrix_batch(
                        id,
                        0,
                        1,
                        usize::MAX,
                        |_, _, _| Ok(-32768),
                        |_, _, _| Ok(0)
                    )
                    .is_err());
                assert_eq!(
                    p.prepare_matrix_batch(id, 0, 1, usize::MAX, absent, |_, _, _| Err(
                        "input failure".into()
                    ))
                    .err()
                    .unwrap(),
                    "input failure"
                );
                assert_eq!(
                    p.prepare_matrix_batch(
                        id,
                        0,
                        1,
                        usize::MAX,
                        |_, _, _| Err("weight failure".into()),
                        |_, _, _| Ok(0)
                    )
                    .err()
                    .unwrap(),
                    "weight failure"
                );
                eprintln!("C71_MATRIX_BATCH_EXECUTED rows=3 first=147 inner={} columns={} W_reads={} workspace={workspace} gpu=false",c.inner,c.columns,reads.get());
                let pair = *p.recipes.matrix.iter().find(|pair| pair.raw == id).unwrap();
                let rounded = p
                    .prepare_row(
                        &Producer::Rne(pair),
                        1,
                        0,
                        &tables,
                        absent,
                        |_, _, j| Ok(raw.values[0].2[j]),
                        absent,
                    )
                    .unwrap();
                assert_eq!(rounded.values[0].2, raw.values[0].2);
            }

            // Head reshaping and true nonzero producer outputs, including V/K alias.
            for name in ["q_norm", "k_norm", "v_norm"] {
                let i = rms
                    .norms
                    .iter()
                    .position(|n| n.layer == Some(0) && n.operation == name)
                    .unwrap();
                let n = &rms.norms[i];
                let r = p.prepare_row(&Producer::Norm(i), 1, 0, &tables, w, x, absent).unwrap();
                let source = &b.scalar.layout.sources[n.input];
                let input: Vec<_> = (0..source.cols).map(|c| x(n.input, 1, c).unwrap()).collect();
                let weights: Vec<_> = (0..n.columns).map(|c| w(0, 0, c).unwrap() as i16).collect();
                let (s, products, y) = n
                    .prepare_row(p.recipes.rms[i], &input, n.cohort.map(|_| weights.as_slice()))
                    .unwrap();
                assert_eq!(r.values[r.values.len() - 2], (n.statistic, n.heads, s));
                assert_eq!(r.values.last().unwrap(), &(n.output, 1, y));
                if name == "v_norm" {
                    assert!(r
                        .values
                        .last()
                        .unwrap()
                        .2
                        .iter()
                        .enumerate()
                        .all(|(c, &v)| v == 2 * x(0, 0, c).unwrap()));
                }
                if let Some(id) = n.cohort {
                    assert_eq!(r.values[0], (id, n.heads, products));
                }
            }
            for i in [0, 10] {
                // local and global families, with omitted global pairs
                let r = &a.rope.rotations[i];
                let raw =
                    p.prepare_row(&Producer::Rope(i), 1, 0, &tables, absent, x, absent).unwrap();
                assert_eq!(raw.values[0].0, r.raw);
                assert!(raw.values[0]
                    .2
                    .iter()
                    .enumerate()
                    .all(|(c, &v)| v == x(0, 0, c).unwrap() * (1 << 30)));
                let pair = p.recipes.rope[i];
                let rounded = p
                    .prepare_row(
                        &Producer::Rne(pair),
                        1,
                        0,
                        &tables,
                        absent,
                        |id, r, c| {
                            assert_eq!((id, r), (pair.raw, 1));
                            Ok(raw.values[0].2[c])
                        },
                        absent,
                    )
                    .unwrap();
                assert!(rounded.values[0]
                    .2
                    .iter()
                    .enumerate()
                    .all(|(c, &v)| v == x(0, 0, c).unwrap()));
            }
            let affine = p.recipes.affine.iter().position(|r| r.inputs[1].1 == 0).unwrap();
            let r = &p.recipes.affine[affine];
            let linear = p
                .prepare_row(
                    &Producer::Affine(affine),
                    1,
                    0,
                    &tables,
                    absent,
                    |id, _, _| {
                        assert_eq!(id, r.inputs[0].0);
                        Ok(2)
                    },
                    absent,
                )
                .unwrap();
            assert!(linear.values[0].2.iter().all(|&v| v == 2 * r.inputs[0].1));
            let g = &a.rope.gate_up.gelu.gelu[0];
            let gelu_row =
                p.prepare_row(&Producer::Gelu(0), 1, 0, &tables, absent, x, absent).unwrap();
            assert_eq!(gelu_row.histogram.as_ref().unwrap().0, g.histogram);
            let gate = p
                .prepare_row(
                    &Producer::Gate(0),
                    1,
                    0,
                    &tables,
                    absent,
                    |id, _, c| {
                        if id == g.output {
                            Ok(gelu_row.values[0].2[c])
                        } else {
                            Ok(2)
                        }
                    },
                    absent,
                )
                .unwrap();
            assert!(gate.values[0]
                .2
                .iter()
                .enumerate()
                .all(|(c, &v)| v == 2 * x(0, 0, c).unwrap()));

            // QK -> EXP30 -> PV uses original head/query/key rows. Fresh and
            // historical tails deliberately differ; any future read panics.
            let live = slot * 150 + 2;
            let l = &a.layers[0];
            let sm = &p.softmax.layers[0];
            let score = p
                .prepare_row(
                    &Producer::Qk(0),
                    257,
                    0,
                    &tables,
                    absent,
                    |id, r, c| {
                        assert_eq!((id, r), (l.q, 1));
                        assert!((l.lanes..2 * l.lanes).contains(&c));
                        Ok(1)
                    },
                    |id, t, c| {
                        assert_eq!(id, l.k);
                        assert!(t < live);
                        assert!(c < l.lanes);
                        Ok(if t < slot * 150 { 2 } else { 1 })
                    },
                )
                .unwrap();
            assert!(score.values[0].2[..slot * 150].iter().all(|&v| v == 2 * l.lanes as i64));
            assert_eq!(score.values[0].2[slot * 150], l.lanes as i64);
            assert!(score.values[0].2[live..].iter().all(|&v| v == 0));
            let soft = p
                .prepare_row(
                    &Producer::Softmax(0),
                    257,
                    0,
                    &tables,
                    absent,
                    |id, r, c| {
                        assert_eq!((id, r), (sm.score, 257));
                        Ok(score.values[0].2[c])
                    },
                    absent,
                )
                .unwrap();
            let pi = &soft.values.iter().find(|v| v.0 == sm.pi).unwrap().2;
            let expected = i64::from(kernel::rne::divide(16384, live as i64).unwrap());
            assert!(pi[..live].iter().all(|&v| v == expected));
            assert!(pi[live..].iter().all(|&v| v == 0));
            let visits = &soft.histogram.as_ref().unwrap().1;
            assert_eq!(visits.len(), slot * 150 + 150);
            assert!(visits[live..].iter().all(|&i| i == 0));
            let pv = p
                .prepare_row(
                    &Producer::Pv(0),
                    1,
                    0,
                    &tables,
                    absent,
                    |id, r, c| {
                        assert_eq!(id, l.pi);
                        assert_eq!(r % 256, 1);
                        Ok(pi[c])
                    },
                    |id, t, c| {
                        assert_eq!(id, l.v);
                        assert!(t < live);
                        assert!(c < l.groups * l.lanes);
                        Ok(2)
                    },
                )
                .unwrap();
            assert!(pv.values[0].2.iter().all(|&v| v == 2 * live as i64 * expected));
            assert!(p
                .prepare_row(&Producer::Qk(0), 150, 0, &tables, absent, absent, absent)
                .is_err());
            assert!(p
                .prepare_row(&Producer::Softmax(0), 150, 0, &tables, absent, absent, absent)
                .is_err());
            for row in [150, 255, 31 * 256 + 255] {
                assert_eq!(p.padding_word(sm.difference, row, 0).unwrap(), Some(-32767));
                assert_eq!(
                    p.padding_word(sm.exponential, row, slot * 150 + 149).unwrap(),
                    Some(1 << 30)
                );
                for id in [l.raw_score, l.score, l.pi, sm.maximum, sm.denominator] {
                    assert_eq!(p.padding_word(id, row, 0).unwrap(), Some(0));
                }
            }
            assert_eq!(p.padding_word(sm.difference, 149, 0).unwrap(), None);
            assert!(p.padding_word(sm.exponential, 8192, 0).is_err());
            let (entry, padded) = p.padding_histogram(sm.histogram).unwrap();
            assert_eq!(entry, 0);
            assert_eq!(padded + 32 * 150 * (slot * 150 + 150), 32 * 256 * (slot * 150 + 150));
            assert_eq!(p.padding_histogram(g.histogram), None);

            let softcap = p
                .prepare_row(
                    &Producer::Softcap,
                    49,
                    0,
                    &tables,
                    absent,
                    |_, _, c| Ok(if c == 3 || c == 5 { 2 } else { 0 }),
                    absent,
                )
                .unwrap();
            let argmax = p
                .prepare_row(
                    &Producer::Argmax,
                    49,
                    0,
                    &tables,
                    absent,
                    |id, r, c| {
                        assert_eq!((id, r), (p.output.output, 49));
                        Ok(softcap.values[0].2[c])
                    },
                    absent,
                )
                .unwrap();
            assert_eq!(argmax.token, Some(3));
            assert_eq!(argmax.values[0].2[3], -32768);
            assert_eq!(argmax.values[0].2[0], -32767);
            assert_eq!(argmax.values[0].2[5], -32768);

            // Every head/query row is scheduled once; the last token only
            // populates the continuation and never predicts a 51st token.
            assert_eq!(p.rows_at_token(&Producer::Matrix(head), 98).unwrap(), Vec::<usize>::new());
            assert_eq!(p.rows_at_token(&Producer::Matrix(head), 99).unwrap(), vec![0]);
            assert_eq!(p.rows_at_token(&Producer::Matrix(head), 148).unwrap(), vec![49]);
            assert!(p.rows_at_token(&Producer::Matrix(head), 149).unwrap().is_empty());
            assert_eq!(
                p.rows_at_token(&Producer::Softmax(0), 149).unwrap(),
                (0..32).map(|h| h * 256 + 149).collect::<Vec<_>>()
            );
            let final_norm = rms.norms.iter().position(|n| n.operation == "final_rms").unwrap();
            assert!(p.rows_at_token(&Producer::Norm(final_norm), 149).unwrap().is_empty());

            // Execute the real streaming driver on a bounded suffix. The
            // preceding canonical layers are NOT executed by this fixture.
            let mut suffix = p;
            suffix.steps.retain(|s| matches!(s, Producer::Softcap | Producer::Argmax));
            let rows = std::cell::RefCell::new(BTreeMap::<(usize, usize), Vec<i64>>::new());
            let visits = Cell::new(0);
            let mut tokens = [0; 150];
            let getter = |id, r, c| {
                if id == suffix.output.input {
                    Ok(if c == 3 || c == 5 { 2 } else { 0 })
                } else {
                    rows.borrow()
                        .get(&(id, r))
                        .map(|v| v[c])
                        .ok_or("consumer preceded producer".into())
                }
            };
            for t in [98, 99, 148, 149] {
                suffix
                    .prepare_token(
                        t,
                        &mut tokens,
                        &tables,
                        &absent,
                        &getter,
                        &absent,
                        |out| {
                            for (id, r, v) in out.values {
                                assert!(rows.borrow_mut().insert((id, r), v).is_none());
                            }
                            if let Some((id, entries)) = out.histogram {
                                assert_eq!(id, suffix.output.histogram);
                                visits.set(visits.get() + entries.len());
                            }
                            Ok(())
                        },
                        |_| Ok(()),
                    )
                    .unwrap();
            }
            assert_eq!((tokens[100], tokens[149]), (3, 3));
            assert_eq!(rows.borrow().len(), 4);
            assert_eq!(visits.get(), 2 * 262144);
            let mut failed_tokens = [0; 150];
            assert!(suffix
                .prepare_token(
                    99,
                    &mut failed_tokens,
                    &tables,
                    &absent,
                    &getter,
                    &absent,
                    |_| Err("sink failed".into()),
                    |_| Ok(())
                )
                .is_err());
            assert_eq!(failed_tokens[100], 0);
        }
        let marker = [i16::MIN];
        assert!(lookup_row(
            &lookup::Table { profile: 0, lower: 0, outputs: lookup::Outputs::I16(&marker) },
            &[0]
        )
        .is_err());
        eprintln!("C71_CANONICAL_NUMERIC_ROWS offsets=0/150/300 calibrated=false full_model=false");
    }
}

fn lookup_row(table: &lookup::Table<'_>, input: &[i64]) -> Result<(Vec<i64>, Vec<usize>), String> {
    let mut values = Vec::with_capacity(input.len());
    let mut entries = Vec::with_capacity(input.len());
    for &x in input {
        let index = usize::try_from(x - i64::from(table.lower))
            .map_err(|_| "canonical lookup input below table")?;
        let value = match table.outputs {
            lookup::Outputs::I16(v) => {
                v.get(index).filter(|&&v| v != i16::MIN).map(|&v| i64::from(v))
            }
            lookup::Outputs::I32(v) => {
                v.get(index).filter(|&&v| v != i32::MIN).map(|&v| i64::from(v))
            }
        }
        .ok_or("canonical lookup outside table or overflow marker")?;
        values.push(value);
        entries.push(index);
    }
    Ok((values, entries))
}

impl MatrixBatch {
    pub(super) fn new(
        plan: &Plan,
        b: &bytes::Bytes,
        raw: usize,
        first: usize,
        rows: usize,
    ) -> Result<MatrixBatch, String> {
        let c = plan.cohorts.get(raw).ok_or("matrix batch cohort missing")?;
        if c.kind != Kind::Matrix
            || c.heads != 1
            || rows == 0
            || rows > 150
            || first.checked_add(rows).is_none_or(|end| end > c.rows)
            || c.inner == 0
            || c.inner > 21504
            || c.columns == 0
            || c.columns > 262144
        {
            return Err("matrix batch shape outside canonical dense bounds".into());
        }
        let input = *b
            .scalar
            .input_sources
            .get(raw.checked_sub(1).ok_or("matrix batch input missing")?)
            .ok_or("matrix batch input missing")?;
        let x = b.scalar.layout.sources.get(input).ok_or("matrix batch source missing")?;
        let y = b.scalar.layout.sources.get(raw).ok_or("matrix batch output missing")?;
        let w = plan.sources.get(c.tensor).ok_or("matrix batch W missing")?;
        let route = plan.input_route(raw)?;
        let input_first = first.checked_add(route.row_offset).ok_or("matrix batch row overflow")?;
        if b.widths[input] != 2
            || b.widths[raw] != 6
            || x.cols != c.inner
            || (y.rows, y.cols) != (c.rows, c.columns)
            || (w.rows, w.cols) != (c.columns, c.inner)
            || input_first.checked_add(rows).is_none_or(|end| end > x.rows)
        {
            return Err("matrix batch original layout differs".into());
        }
        Ok(MatrixBatch {
            input,
            input_first,
            tensor: c.tensor,
            weight_offset: w.packed_offset,
            rows,
            columns: c.columns,
            inner: c.inner,
        })
    }
}

impl Canonical {
    pub(super) fn matrix_batch(
        &self,
        raw: usize,
        first: usize,
        rows: usize,
    ) -> Result<MatrixBatch, String> {
        MatrixBatch::new(&self.plan, self.bytes(), raw, first, rows)
    }

    /// Explicit CPU reference batch. Read each original W coefficient once,
    /// applying it to all selected rows. No expanded W, rounding or zero shortcut.
    /// Native execution must use resident handles, not download a Row as spill.
    pub(super) fn prepare_matrix_batch(
        &self,
        raw: usize,
        first: usize,
        rows: usize,
        workspace: usize,
        weight: impl Fn(usize, usize, usize) -> Result<i64, String>,
        get: impl Fn(usize, usize, usize) -> Result<i64, String>,
    ) -> Result<Row, String> {
        let batch = self.matrix_batch(raw, first, rows)?;
        // Includes a second raw capacity for the scanner's row retention.
        let input_words = batch.rows * batch.inner;
        let output_words = batch.rows * batch.columns;
        if input_words * 2 + output_words * 16 > workspace {
            return Err("matrix batch workspace budget exceeded".into());
        }
        let mut x = Vec::with_capacity(input_words);
        for row in 0..rows {
            for k in 0..batch.inner {
                let v = get(batch.input, batch.input_first + row, k)?;
                if !(-32767..=32767).contains(&v) {
                    return Err("matrix batch input outside symmetric i16".into());
                }
                x.push(v as i16);
            }
        }
        let mut y = vec![0i64; output_words];
        for j in 0..batch.columns {
            for k in 0..batch.inner {
                let w = weight(batch.tensor, j, k)?;
                if !(-32767..=32767).contains(&w) {
                    return Err("matrix batch weight outside symmetric i16".into());
                }
                for row in 0..rows {
                    y[row * batch.columns + j] += i64::from(x[row * batch.inner + k]) * w;
                }
            }
        }
        Ok(Row { values: vec![(raw, first, y)], ..Row::default() })
    }

    /// Padding INSIDE the original A rectangles is not root-domain zero.
    /// EXP30's lookup includes it: encoded D=1, E=2^30, Z=Pi=0.
    pub(super) fn padding_word(
        &self,
        source: usize,
        row: usize,
        col: usize,
    ) -> Result<Option<i64>, String> {
        let s = self.bytes().scalar.layout.sources.get(source).ok_or("padding source missing")?;
        if row >= s.rows || col >= s.cols {
            return Err("padding address outside original source".into());
        }
        if row % 256 < 150 {
            return Ok(None);
        }
        for (a, sm) in self.sources.attention.layers.iter().zip(&self.softmax.layers) {
            if source == sm.difference {
                return Ok(Some(-32767));
            }
            if source == sm.exponential {
                return Ok(Some(1 << 30));
            }
            if [a.raw_score, a.score, a.pi, sm.maximum, sm.denominator].contains(&source) {
                return Ok(Some(0));
            }
        }
        Ok(None)
    }

    /// Add once to each EXP30 histogram at finalization, alongside emitted
    /// live-query visits. Public constants need neither W reads nor a replay.
    pub(super) fn padding_histogram(&self, source: usize) -> Option<(usize, usize)> {
        self.softmax
            .layers
            .iter()
            .any(|l| l.histogram == source)
            .then_some((0, 32 * (256 - 150) * (self.sources.attention.rope.old + 150)))
    }

    /// Expand one causal token into the original producer row addresses.
    /// Query padding is supplied by padding_word/padding_histogram, not replay.
    pub(super) fn rows_at_token(
        &self,
        step: &Producer,
        token: usize,
    ) -> Result<Vec<usize>, String> {
        if token >= 150 {
            return Err("canonical token outside fixed response".into());
        }
        let decision = match step {
            Producer::Matrix(i) => *i == self.output.raw,
            Producer::Rne(p) => p.raw == self.output.raw,
            Producer::Softcap | Producer::Argmax => true,
            _ => false,
        };
        if decision {
            let first = self.plan.input_route(self.output.raw)?.row_offset;
            return Ok((first..first + 50)
                .contains(&token)
                .then(|| token - first)
                .into_iter()
                .collect());
        }
        let scores = matches!(step, Producer::Rne(p) if self.sources.attention.layers.iter().any(|l|l.raw_score==p.raw));
        if scores || matches!(step, Producer::Qk(_) | Producer::Softmax(_)) {
            return Ok((0..32).map(|head| head * 256 + token).collect());
        }
        let output = match step {
            Producer::Norm(i) => self.sources.attention.rope.gate_up.gelu.rms.norms[*i].output,
            _ => self.ports(step).1[0],
        };
        Ok((token < self.bytes().scalar.layout.sources[output].rows)
            .then_some(token)
            .into_iter()
            .collect())
    }

    /// Caller-owned streaming storage. Emit then release each row bundle;
    /// histograms add the returned visits once. A failed attempt is discarded.
    /// This is a reference driver, not a GPU/arena implementation or public API.
    pub(super) fn prepare_token(
        &self,
        token_index: usize,
        tokens: &mut [u32; 150],
        tables: &profile::Tables<'_>,
        weight: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        get: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        tail: &dyn Fn(usize, usize, usize) -> Result<i64, String>,
        emit: impl FnMut(Row) -> Result<(), String>,
        after_step: impl FnMut(usize) -> Result<(), String>,
    ) -> Result<(), String> {
        self.prepare_token_with(
            token_index,
            tokens,
            |step, row, token| self.prepare_row(step, row, token, tables, weight, get, tail),
            emit,
            after_step,
        )
    }

    pub(super) fn prepare_token_with(
        &self,
        token_index: usize,
        tokens: &mut [u32; 150],
        mut produce: impl FnMut(&Producer, usize, u32) -> Result<Row, String>,
        mut emit: impl FnMut(Row) -> Result<(), String>,
        mut after_step: impl FnMut(usize) -> Result<(), String>,
    ) -> Result<(), String> {
        let token = *tokens.get(token_index).ok_or("canonical token outside fixed response")?;
        let mut next = None;
        for (step_index, step) in self.steps.iter().enumerate() {
            for row in self.rows_at_token(step, token_index)? {
                let result = produce(step, row, token)
                    .map_err(|error| format!("producer={step_index} row={row}: {error}"))?;
                if let Some(t) = result.token {
                    if next.replace(t).is_some() {
                        return Err("canonical token has two decisions".into());
                    }
                }
                emit(result)?;
            }
            after_step(step_index)?;
        }
        if (99..149).contains(&token_index) != next.is_some() {
            return Err("canonical causal decision count differs".into());
        }
        if let Some(t) = next {
            *tokens
                .get_mut(token_index + 1)
                .ok_or("canonical decision after final absorption")? = t;
        }
        Ok(())
    }

    /// `row` is a token row except QK/score/softmax, where it is head*256+query,
    /// and selected lm_head/output rows, where it is the original 0..50 row.
    /// `tail` addresses absolute accepted/current K/V tokens; only causal
    /// positions are requested. No source is inferred from caller metadata.
    pub(super) fn prepare_row(
        &self,
        step: &Producer,
        row: usize,
        token: u32,
        tables: &profile::Tables<'_>,
        weight: impl Fn(usize, usize, usize) -> Result<i64, String>,
        get: impl Fn(usize, usize, usize) -> Result<i64, String>,
        tail: impl Fn(usize, usize, usize) -> Result<i64, String>,
    ) -> Result<Row, String> {
        let a = &self.sources.attention;
        let gu = &a.rope.gate_up;
        let rms = &gu.gelu.rms;
        let b = self.bytes();
        let sources = &b.scalar.layout.sources;
        let read = |id: usize, r: usize, c: usize| -> Result<i64, String> {
            let s = sources.get(id).ok_or("canonical input source missing")?;
            if r >= s.rows || c >= s.cols {
                return Err("canonical input address outside source".into());
            }
            let v = get(id, r, c)?;
            let bound = 1i64 << (8 * b.widths[id] - 1);
            if v < -bound || v >= bound || (b.widths[id] == 2 && v == -32768) {
                return Err("canonical input outside original codec".into());
            }
            Ok(v)
        };
        let input = |id: usize, r: usize| {
            (0..sources[id].cols).map(|c| read(id, r, c)).collect::<Result<Vec<_>, _>>()
        };
        let w = |id: usize, r: usize, c: usize| -> Result<i64, String> {
            let s = self.plan.sources.get(id).ok_or("canonical weight tensor missing")?;
            if r >= s.rows || c >= s.cols {
                return Err("canonical weight address outside tensor".into());
            }
            let v = weight(id, r, c)?;
            if !(-32767..=32767).contains(&v) {
                return Err("canonical weight outside symmetric i16".into());
            }
            Ok(v)
        };
        let history = |id: usize, t: usize, c: usize| -> Result<i64, String> {
            if t >= a.rope.old + 150 || c >= sources[id].cols {
                return Err("canonical KV address outside fixed run".into());
            }
            let v = tail(id, t, c)?;
            if !(-32767..=32767).contains(&v) {
                return Err("canonical KV outside symmetric i16".into());
            }
            Ok(v)
        };
        let mut out = Row::default();
        match step {
            Producer::Embedding => {
                let batch = EmbeddingBatch::new(&self.plan, b, row, &[token])?;
                out.values.push((
                    0,
                    row,
                    (0..batch.columns)
                        .map(|c| w(batch.tensor, token as usize, c))
                        .collect::<Result<_, _>>()?,
                ));
            }
            Producer::Matrix(i) => {
                return self.prepare_matrix_batch(*i, row, 1, usize::MAX, &weight, &get);
            }
            Producer::Norm(i) => {
                let n = &rms.norms[*i];
                if row >= n.rows / n.heads {
                    return Err("canonical RMS row outside source".into());
                }
                let x = input(n.input, row)?;
                let weights = n
                    .cohort
                    .map(|i| {
                        (0..n.columns)
                            .map(|c| w(self.plan.cohorts[i].tensor, 0, c).map(|v| v as i16))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?;
                let (s, p, y) = n.prepare_row(self.recipes.rms[*i], &x, weights.as_deref())?;
                if let Some(id) = n.cohort {
                    out.values.push((id, row * n.heads, p));
                }
                out.values.extend([(n.statistic, row * n.heads, s), (n.output, row, y)]);
            }
            Producer::Rne(pair) => {
                let x = input(pair.raw, row)?;
                out.values.push((pair.output, row, b.prepare_rne_row(&self.plan, pair, &x)?));
            }
            Producer::Affine(i) => {
                let r = &self.recipes.affine[*i];
                // Zero terms are absent from the DAG and must not read a source.
                let mut x = [Vec::new(), Vec::new()];
                for j in 0..2 {
                    x[j] = if r.inputs[j].1 == 0 {
                        vec![0; sources[r.raw].cols]
                    } else {
                        input(r.inputs[j].0, row)?
                    };
                }
                out.values.push((r.raw, row, b.prepare_affine_row(r, [&x[0], &x[1]])?));
            }
            Producer::Gelu(i) => {
                let g = &gu.gelu.gelu[*i];
                let table = tables.gelu.get(*i).ok_or("canonical GELU table missing")?;
                if table.profile as usize != *i
                    || table.lower != -32767
                    || !matches!(table.outputs, lookup::Outputs::I16(_))
                    || table.outputs.len() != 65535
                {
                    return Err("canonical GELU table shape differs".into());
                }
                let (y, entries) = lookup_row(table, &input(g.input, row)?)?;
                out.values.push((g.output, row, y));
                out.histogram = Some((g.histogram, entries));
            }
            Producer::Gate(i) => {
                let p = &gu.products[*i];
                let x = input(gu.gelu.gelu[*i].output, row)?;
                let y = input(p.up, row)?;
                out.values.push((p.raw, row, x.iter().zip(y).map(|(&x, y)| x * y).collect()));
            }
            Producer::Rope(i) => {
                let r = &a.rope.rotations[*i];
                let table = tables.rope.get(r.family).ok_or("canonical RoPE table missing")?;
                if row >= r.rows || table.position != a.rope.old || table.rows.len() != 150 {
                    return Err("canonical RoPE absolute window differs".into());
                }
                let pairs = &table.rows[row];
                if pairs.len() != if r.family == 0 { 128 } else { 64 }
                    || pairs.iter().flatten().any(|&x| !(-(1 << 30)..=1 << 30).contains(&x))
                {
                    return Err("canonical RoPE coefficient shape/range differs".into());
                }
                let x = input(rms.norms[r.norm].output, row)?;
                let mut y = vec![0; x.len()];
                let half = r.width / 2;
                for head in 0..r.heads {
                    for j in 0..half {
                        let [cos, sin] =
                            pairs.get(j).copied().unwrap_or([1 << 30, 0]).map(i64::from);
                        let first = head * r.width + j;
                        let second = first + half;
                        y[first] = cos * x[first] - sin * x[second];
                        y[second] = sin * x[first] + cos * x[second];
                    }
                }
                out.values.push((r.raw, row, y));
            }
            Producer::Qk(i) => {
                let l = &a.layers[*i];
                let (head, query) = (row / 256, row % 256);
                if head >= 32 || query >= 150 {
                    return Err("canonical QK row is padding/outside source".into());
                }
                let mut scores = vec![0; a.rope.old + 150];
                for lane in 0..l.lanes {
                    let q = read(l.q, query, head * l.lanes + lane)?;
                    for (t, v) in scores[..=a.rope.old + query].iter_mut().enumerate() {
                        *v += q * history(l.k, t, (head / l.repeats) * l.lanes + lane)?;
                    }
                }
                out.values.push((l.raw_score, row, scores));
            }
            Producer::Softmax(i) => {
                let s = &self.softmax.layers[*i];
                let (head, query) = (row / 256, row % 256);
                if head >= 32 || query >= 150 {
                    return Err("canonical softmax row is padding/outside source".into());
                }
                let live = a.rope.old + query + 1;
                let x = input(s.score, row)?;
                if x[live..].iter().any(|&v| v != 0) {
                    return Err("canonical future scores must be zero".into());
                }
                let maximum = *x[..live].iter().max().unwrap();
                let d = x
                    .iter()
                    .enumerate()
                    .map(|(k, &v)| if k < live { maximum - v - 32767 } else { -32767 })
                    .collect::<Vec<_>>();
                let table = tables.exp30.get(*i).ok_or("canonical EXP30 table missing")?;
                if table.profile as usize != *i
                    || table.lower != -32767
                    || !matches!(table.outputs, lookup::Outputs::I32(v) if v.first() == Some(&(1 << 30)))
                    || table.outputs.len() != 65535
                {
                    return Err("canonical EXP30 table shape differs".into());
                }
                let (e, entries) = lookup_row(table, &d)?;
                if e.iter().any(|&e| !(0..=1 << 30).contains(&e)) {
                    return Err("canonical EXP30 output range differs".into());
                }
                let z: i64 = e[..live].iter().sum();
                let pi = e
                    .iter()
                    .enumerate()
                    .map(|(k, &e)| {
                        if k < live {
                            kernel::rne::divide(16384 * e, z).map(i64::from)
                        } else {
                            Ok(0)
                        }
                    })
                    .collect::<Result<_, _>>()?;
                out.values.extend([
                    (s.maximum, row, vec![maximum]),
                    (s.difference, row, d),
                    (s.exponential, row, e),
                    (s.denominator, row, vec![z]),
                    (s.pi, row, pi),
                ]);
                out.histogram = Some((s.histogram, entries));
            }
            Producer::Pv(i) => {
                let l = &a.layers[*i];
                if row >= 150 {
                    return Err("canonical PV row outside source".into());
                }
                let mut y = vec![0; 32 * l.lanes];
                for head in 0..32 {
                    for t in 0..=a.rope.old + row {
                        let pi = read(l.pi, head * 256 + row, t)?;
                        for lane in 0..l.lanes {
                            y[head * l.lanes + lane] +=
                                pi * history(l.v, t, (head / l.repeats) * l.lanes + lane)?;
                        }
                    }
                }
                out.values.push((l.raw_output, row, y));
            }
            Producer::Softcap => {
                let o = &self.output;
                let table = tables.softcap;
                if table.profile != 0
                    || table.lower != o.lower
                    || !matches!(table.outputs, lookup::Outputs::I16(_))
                    || table.outputs.len() != 65535
                {
                    return Err("canonical softcap table shape differs".into());
                }
                let (y, entries) = lookup_row(table, &input(o.input, row)?)?;
                out.values.push((o.output, row, y));
                out.histogram = Some((o.histogram, entries));
            }
            Producer::Argmax => {
                let y = input(self.output.output, row)?;
                let mut best = 0;
                for j in 1..y.len() {
                    if y[j] > y[best] {
                        best = j;
                    }
                }
                out.values.push((
                    self.output.slack,
                    row,
                    y.iter()
                        .enumerate()
                        .map(|(j, &v)| y[best] - v - i64::from(j < best) - 32768)
                        .collect(),
                ));
                out.token = Some(best as u32);
            }
        }
        // Publish nothing on codec/shape failure. The caller also discards a
        // partial response after any later producer failure.
        for (id, first, values) in &out.values {
            let s = &sources[*id];
            let bound = 1i64 << (8 * b.widths[*id] - 1);
            if values.is_empty()
                || values.len() % s.cols != 0
                || first.checked_add(values.len() / s.cols).is_none_or(|last| last > s.rows)
                || values.iter().any(|&v| {
                    v < -bound
                        || v >= bound
                        || (b.widths[*id] == 2 && v == -32768 && *id != self.output.slack)
                })
            {
                return Err("canonical producer output shape/codec differs".into());
            }
        }
        Ok(out)
    }
}
