//! Same bounded inference as B12, with one state root and no historical PCS.
//! Test-only: unpadded original RNE batch; no canonical work/security credit.
use super::*;
use rand_010::RngExt;

const W: usize = 4096;
const BANK: usize = 1536; // relative to the auxiliary block, beyond all current sources
const WD: Domain = Domain::JointTest { bits: 12, exposures: 1, first: 4 };
const SD: Domain = Domain::JointTest { bits: 13, exposures: 2, first: 5 };
const AD: Domain = Domain::Flat(11);
const MAGIC: &[u8] =
    b"C71-joint-inference-test-v1;W4096;A2048;bank1536;zero-quarter;unpadded-RNE-weighted-first-GKR-v2\0";

// Keep the seven original reductions; batch only their byte-function checks.
// The groups cover 224 cells exactly (128+64+32), with no added padding.
use byte_function::batch;
struct JointRne {
    reductions: Vec<rne::Reduction>,
    groups: Vec<batch::Proof>,
}
component_wire!(JointRne { reductions, groups });
fn rne_groups<T>(requests: &[(bytes::RneRequest<T>, i32)]) -> Result<Vec<Vec<usize>>, String> {
    if requests.len() != 7 || requests.iter().any(|(r, _)| r.point.len() != 2) {
        return Err("joint RNE bounded profile shape".into());
    }
    batch::unpadded_groups(&[5; 7])
}
fn rne_statements<'a, T>(
    s: &'a caller::P0Statement<'a>,
    requests: &'a [(bytes::RneRequest<T>, i32)],
) -> Vec<rne::Statement<'a>> {
    requests
        .iter()
        .map(|(r, shift)| rne::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: r.view,
            attempt: s.attempt,
            output_point: &r.point,
            shape: r.shape,
            shift: *shift,
        })
        .collect()
}
fn rne_form<T>(
    p: &Profile,
    requests: &[(bytes::RneRequest<T>, i32)],
    group: &[usize],
    point: &[Fp3],
) -> Result<Vec<Cube>, String> {
    let local: Vec<_> = group.iter().map(|&i| requests[i].0.point.len() + 3).collect();
    let (d, offsets) = batch::geometry(&local)?;
    if d != point.len() || (1usize << d) != local.iter().map(|&b| 1usize << b).sum::<usize>() {
        return Err("joint RNE unpadded geometry".into());
    }
    let mut form = Vec::new();
    for (j, &i) in group.iter().enumerate() {
        let prefix = d - local[j];
        let c = point[..prefix].iter().enumerate().fold(Fp3::ONE, |v, (k, &r)| {
            v * if offsets[j] >> (d - 1 - k) & 1 == 1 { r } else { Fp3::ONE - r }
        });
        for mut cube in p.bytes().source_rne_form(requests[i].0.source, &point[prefix..])? {
            cube.coefficient = cube.coefficient * c;
            form.push(cube);
        }
    }
    Ok(form)
}
fn prove_rne(
    p: &Profile,
    snapshot: &Snapshot,
    s: &caller::P0Statement<'_>,
    requests: Vec<(bytes::RneRequest<Auth>, i32)>,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Auth>,
) -> Result<(Vec<u8>, Batch<Auth>), String> {
    let groups = rne_groups(&requests)?;
    let statements = rne_statements(s, &requests);
    let raw = |i: usize, j: usize| {
        let r = &requests[i].0;
        snapshot.word6(
            p,
            r.source,
            j / r.shape[1].next_power_of_two(),
            j % r.shape[1].next_power_of_two(),
        )
    };
    let (mut reductions, mut pending) = (Vec::new(), Vec::new());
    for (i, rs) in statements.iter().enumerate() {
        let (proof, claim) =
            rne::prove_reduction(rs, requests[i].0.original, |j| raw(i, j), fs, rows)?;
        reductions.push(proof);
        pending.push(claim);
    }
    let mut proofs = Vec::new();
    let mut ba = Batch::new();
    for group in groups {
        let bs: Vec<_> = group.iter().map(|&i| pending[i].statement(&statements[i])).collect();
        let originals: Vec<_> = group.iter().map(|&i| pending[i].aggregate).collect();
        let (proof, point, original) = batch::prove(
            &bs,
            &originals,
            |k, j| {
                let i = group[k];
                if statements[i].live(j / 8) && j % 8 < 6 {
                    raw(i, j / 8)[j % 8]
                } else {
                    0
                }
            },
            fs,
            rows,
        )?;
        ba.add(rne_form(p, &requests, &group, &point)?, original);
        proofs.push(proof);
    }
    let mut body = Vec::new();
    JointRne { reductions, groups: proofs }.write(&mut body);
    Ok((body, ba))
}
fn verify_rne(
    p: &Profile,
    s: &caller::P0Statement<'_>,
    requests: Vec<(bytes::RneRequest<Key>, i32)>,
    mut body: &[u8],
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut std::vec::IntoIter<Key>,
) -> Result<Batch<Key>, String> {
    let groups = rne_groups(&requests)?;
    let proof = JointRne::read(&mut body)?;
    if !body.is_empty()
        || proof.reductions.len() != requests.len()
        || proof.groups.len() != groups.len()
    {
        return Err("joint RNE cardinality/trailing bytes".into());
    }
    let statements = rne_statements(s, &requests);
    let pending: Vec<_> = statements
        .iter()
        .enumerate()
        .map(|(i, rs)| {
            rne::verify_reduction(rs, requests[i].0.original, &proof.reductions[i], delta, fs, rows)
        })
        .collect::<Result<_, _>>()?;
    let mut ba = Batch::new();
    for (group, proof) in groups.iter().zip(&proof.groups) {
        let bs: Vec<_> = group.iter().map(|&i| pending[i].statement(&statements[i])).collect();
        let originals: Vec<_> = group.iter().map(|&i| pending[i].aggregate).collect();
        let (point, original) = batch::verify(&bs, &originals, proof, delta, fs, rows)?;
        ba.add(rne_form(p, &requests, group, &point)?, original);
    }
    Ok(ba)
}

fn auxiliary_live(p: &Profile) -> usize {
    if p.old == 0 {
        p.bytes().live
    } else {
        BANK + 8 * p.old
    }
}
fn required(p: &Profile, s: &caller::P0Statement<'_>) -> Result<usize, String> {
    Ok(p.required(s)? - 7 * byte_function::required(5)
        + [7, 6, 5].into_iter().map(batch::required).sum::<usize>()
        - p.old / 2
        - 32
        - (p.old / 2 + 1) * 38
        - range::required(12, range::Alphabet::Byte)
        + range::required(11, range::Alphabet::Byte)
        + (if p.old == 0 { 38 } else { 41 })
        + 41
        + 1
        + usize::from(p.old != 0))
}
fn header(
    state: &State,
    root: &C61Commitment,
    tokens: [u32; 2],
    nonce: [u8; 32],
    count: usize,
) -> Result<Vec<u8>, String> {
    if state.next_slot != state.accepted.len()
        || state.next_slot >= 3
        || root.num_roots() != 1
        || root == &state.weight
        || state.accepted.iter().any(|a| &a.root == root)
        || tokens.iter().any(|&t| t >= 2)
        || nonce == [0; 32]
    {
        return Err("joint inference context".into());
    }
    let p = &state.profiles[state.next_slot];
    let mut h = MAGIC.to_vec();
    h.extend(p.digest);
    h.extend(state.weight.roots()[0]);
    h.extend(state.accepted.last().map_or(state.weight.roots()[0], |a| a.root.roots()[0]));
    h.extend(root.roots()[0]);
    h.extend(state.attempt(nonce).encode());
    h.extend(state.epoch.to_le_bytes());
    for n in [state.cursor, 3 * count, p.old, p.bytes().live, BANK] {
        h.extend((n as u64).to_le_bytes());
    }
    for t in tokens {
        h.extend(t.to_le_bytes());
    }
    for d in [WD, SD] {
        let g = gamma(&d.config()?);
        h.extend((g.len() as u64).to_le_bytes());
        h.extend(g);
    }
    Ok(h)
}
fn view(values: Vec<i16>, root: C61Commitment) -> Result<Model, String> {
    if values.len() > 2048 {
        return Err("joint A view too large".into());
    }
    Ok(Model {
        domain: AD,
        weights: values,
        root,
        seed: [0; 32],
        salt_seed: [0; 32],
        retained: None,
    })
}
fn kv_ids(p: &Profile) -> [usize; 2] {
    [p.rotations[1][1], p.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output]
}
fn add_offset(mut f: Vec<Cube>, offset: usize) -> Vec<Cube> {
    for c in &mut f {
        c.offset += offset;
    }
    f
}
fn dot(m: &Model, f: &[Cube]) -> Fp3 {
    f.iter().fold(Fp3::ZERO, |s, c| {
        s + c.coefficient
            * eq(&c.point).iter().enumerate().fold(Fp3::ZERO, |v, (i, &e)| {
                v + e * signed(i64::from(m.weights.get(c.offset + i).copied().unwrap_or(0)))
            })
    })
}
fn scalar(offset: usize, coefficient: Fp3) -> Cube {
    Cube { offset, point: vec![], coefficient }
}
fn bank_word(token: usize, kind: usize, lane: usize, coefficient: Fp3) -> Vec<Cube> {
    let offset = BANK + 8 * token + 4 * kind + 2 * lane;
    vec![scalar(offset, coefficient), scalar(offset + 1, coefficient * signed(256))]
}
// Public forms for BOTH roles; current canonical sources and accepted KV bank
// are in the same A block. All incoming QK/PV MACs remain original.
fn kv_forms<T>(
    p: &Profile,
    s: &caller::P0Statement<'_>,
    requests: &[kv::Request<T>],
    fs: &mut Fs,
) -> Result<(Vec<Cube>, Fp3, Vec<Fp3>), String> {
    let total = p.old + 2;
    let ids = kv_ids(p);
    if requests.len() != 2
        || requests
            .iter()
            .zip(ids)
            .any(|(r, id)| r.source != id || r.point.len() != bits(total) + 1)
    {
        return Err("joint KV original request shape".into());
    }
    let mut bound = b"joint-KV-bank-public-forms-v1".to_vec();
    bound.extend(p.digest);
    bound.extend(s.attempt.encode());
    for r in requests {
        bound.extend((r.source as u64).to_le_bytes());
        for x in &r.point {
            bound.extend(x.to_bytes());
        }
    }
    fs.record(0x1500, &bound);
    let lambda = fs.fp3();
    let coefficients = vec![Fp3::ONE, lambda];
    let (mut form, mut bias) = (Vec::new(), Fp3::ZERO);
    for (kind, (r, &coefficient)) in requests.iter().zip(&coefficients).enumerate() {
        let row = &r.point[..bits(total)];
        let col = &r.point[bits(total)..];
        let rows = eq(row);
        let cols = eq(col);
        for t in 0..p.old {
            for lane in 0..2 {
                let c = coefficient * rows[t] * cols[lane];
                form.extend(bank_word(t, kind, lane, c));
                bias += c * signed(32768);
            }
        }
        let (f, b) = p.bytes().kv_segment_form(r.source, p.old, total, row, col, coefficient)?;
        form.extend(f);
        bias += b;
    }
    Ok((form, bias, coefficients))
}
fn links(
    p: &Profile,
    previous: Option<&Profile>,
    fs: &mut Fs,
) -> Result<Vec<(Vec<Cube>, Vec<Cube>)>, String> {
    let w =
        vec![Cube { offset: 0, point: (0..12).map(|_| fs.fp3()).collect(), coefficient: Fp3::ONE }];
    let mut result = vec![(w.clone(), w)];
    if let Some(prev) = previous {
        let point: Vec<_> = (0..bits(4 * p.old)).map(|_| fs.fp3()).collect();
        let weights = eq(&point);
        let (mut old, mut new) = (Vec::new(), Vec::new());
        let ids = kv_ids(prev);
        for t in 0..p.old {
            for kind in 0..2 {
                for lane in 0..2 {
                    let c = weights[4 * t + 2 * kind + lane];
                    new.extend(add_offset(bank_word(t, kind, lane, c), W));
                    if t < prev.old {
                        old.extend(add_offset(bank_word(t, kind, lane, c), W));
                    } else {
                        let (f, _) = prev.bytes().word_form(
                            ids[kind],
                            &[signed((t - prev.old) as i64)],
                            &[signed(lane as i64)],
                            c,
                        )?;
                        old.extend(add_offset(f, W));
                    }
                }
            }
        }
        result.push((old, new));
    }
    Ok(result)
}
fn zero_forms(p: &Profile, fs: &mut Fs) -> Vec<Vec<Cube>> {
    let mut forms = Vec::new();
    for (mut start, end) in [
        (1024, W),
        (W + 2048, 2 * W),
        (W + p.bytes().live, W + if p.old == 0 { 2048 } else { BANK }),
    ] {
        while start < end {
            let mut size = 1usize << start.trailing_zeros();
            while size > end - start {
                size /= 2;
            }
            forms.push(vec![Cube {
                offset: start,
                point: (0..size.ilog2()).map(|_| fs.fp3()).collect(),
                coefficient: Fp3::ONE,
            }]);
            start += size;
        }
    }
    forms
}
fn merge<T: Copy>(bw: Batch<T>, ba: Batch<T>) -> Batch<T> {
    let mut out = bw;
    for (f, t) in ba.forms.into_iter().zip(ba.targets) {
        out.add(add_offset(f, W), t);
    }
    out
}
fn prove_joint(
    state: &State,
    w: &Installed,
    snapshot: &Snapshot,
    old: &[Snapshot],
    previous: &Model,
    current: &Model,
    nonce: [u8; 32],
    rows: &mut std::vec::IntoIter<Auth>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let slot = state.next_slot;
    let p = &state.profiles[slot];
    let wg = gamma(&DOMAIN_W.config()?);
    let ag = gamma(&AD.config()?);
    let s =
        p.context(&current.root, &current.root, &snapshot.tokens, state.attempt(nonce), &wg, &ag);
    let h = header(state, &current.root, snapshot.tokens, nonce, required(p, &s)?)?;
    let weight_view = w.source_view(current.root.clone());
    let Body { mut fs, mut wire, bw, ba, openings } = prove_components(
        state,
        p,
        &weight_view,
        snapshot,
        old,
        &s,
        &h,
        rows,
        auxiliary_live(p),
        |requests, fs, rows| prove_rne(p, snapshot, &s, requests, fs, rows),
        |requests, fs, _rows| {
            let (form, bias, coefficients) = kv_forms(p, &s, requests, fs)?;
            let target = requests
                .iter()
                .zip(coefficients)
                .fold(Auth::ZERO, |v, (r, c)| v.add(r.original.scale(c)));
            Ok((vec![], vec![kv::Opening { form, original: ashift(target, bias) }]))
        },
    )?;
    if !openings.is_empty() {
        return Err("joint inference added a historical PCS".into());
    }
    let mut current_batch = merge(bw, ba);
    let mut previous_batch = Batch::new();
    let mut corrections = Vec::new();
    for (old, new) in
        links(p, slot.checked_sub(1).map(|index| state.profiles[index].as_ref()), &mut fs)?
    {
        let (c, a) = c7_fp3_transfer_prover(rows.next().unwrap(), dot(previous, &old));
        corrections.push(c.value());
        previous_batch.add(old, a);
        current_batch.add(new, a);
    }
    record_values(&mut fs, 0x1501, &corrections);
    wire.put(15, &corrections, &mut fs)?;
    for f in zero_forms(p, &mut fs) {
        current_batch.add(f, Auth::ZERO);
    }
    for (i, (model, batch)) in
        [(previous, previous_batch), (current, current_batch)].into_iter().enumerate()
    {
        let (proof, _) =
            linear::prove(model, s.attempt, p.digest, &batch.forms, &batch.targets, &mut fs, rows)?;
        wire.raw(
            16 + i as u16,
            &codec::encode_linear(model.domain, &proof).map_err(|e| e.to_string())?,
            &mut fs,
        )?;
    }
    if rows.len() != 0 {
        return Err("joint inference prover reservation".into());
    }
    Ok(wire.finish(&mut fs))
}
fn verify_joint(
    state: &mut State,
    root: &C61Commitment,
    tokens: [u32; 2],
    prompt: u32,
    nonce: [u8; 32],
    certificate: &[u8],
    delta: Fp3,
    keys: &mut std::vec::IntoIter<Key>,
) -> Result<[u8; 32], String> {
    if !state.live {
        return Err("joint inference terminated".into());
    }
    state.live = false;
    let slot = state.next_slot;
    let p = state.profiles.get(slot).ok_or("joint inference exhausted")?;
    if tokens[0] != prompt {
        return Err("joint inference prompt differs".into());
    }
    let wg = gamma(&DOMAIN_W.config()?);
    let ag = gamma(&AD.config()?);
    let s = p.context(root, root, &tokens, state.attempt(nonce), &wg, &ag);
    let count = required(p, &s)?;
    let h = header(state, root, tokens, nonce, count)?;
    if keys.len() < count {
        return Err("joint inference capacity exhausted".into());
    }
    let mut rows = keys.by_ref().take(count).collect::<Vec<_>>().into_iter();
    state.next_slot += 1;
    state.cursor += 3 * count;
    let Body { mut fs, mut wire, bw, ba, openings } = verify_components(
        p,
        &s,
        &h,
        certificate,
        delta,
        &mut rows,
        (AD, auxiliary_live(p)),
        |requests, body, fs, rows| verify_rne(p, &s, requests, body, delta, fs, rows),
        |requests, body, fs, _rows| {
            if !body.is_empty() {
                return Err("joint KV frame has payload".into());
            }
            let (form, bias, coefficients) = kv_forms(p, &s, requests, fs)?;
            let target = requests
                .iter()
                .zip(coefficients)
                .fold(Key::ZERO, |v, (r, c)| v.add(r.original.scale(c)));
            Ok(vec![kv::Opening { form, original: Key::new(target.k + delta * bias) }])
        },
    )?;
    if !openings.is_empty() {
        return Err("joint inference historical closure".into());
    }
    let link_forms =
        links(p, slot.checked_sub(1).map(|index| state.profiles[index].as_ref()), &mut fs)?;
    let (corrections, frame) = wire.get::<Vec<Fp3>>(15)?;
    if corrections.len() != link_forms.len() {
        return Err("joint link cardinality".into());
    }
    let mut previous_batch = Batch::new();
    let mut current_batch = merge(bw, ba);
    for ((old, new), c) in link_forms.into_iter().zip(&corrections) {
        let target =
            c7_fp3_transfer_verifier(rows.next().unwrap(), delta, C7Fp3TransferCorrection::new(*c));
        previous_batch.add(old, target);
        current_batch.add(new, target);
    }
    record_values(&mut fs, 0x1501, &corrections);
    Reader::record(&mut fs, frame);
    for f in zero_forms(p, &mut fs) {
        current_batch.add(f, Key::ZERO);
    }
    let prior = state.accepted.last().map_or(&state.weight, |a| &a.root);
    for (i, (domain, root, batch)) in
        [(if slot == 0 { WD } else { SD }, prior, previous_batch), (SD, root, current_batch)]
            .into_iter()
            .enumerate()
    {
        let (body, frame) = wire.raw(16 + i as u16)?;
        let proof = codec::decode_linear(domain, body).map_err(|e| e.to_string())?;
        linear::verify(
            domain,
            root,
            s.attempt,
            p.digest,
            &batch.forms,
            &batch.targets,
            &proof,
            delta,
            &mut fs,
            &mut rows,
        )?;
        Reader::record(&mut fs, frame);
    }
    if rows.len() != 0 {
        return Err("joint inference verifier reservation".into());
    }
    let receipt = wire.finish(&mut fs)?;
    state.promote(root.clone(), tokens, receipt);
    Ok(receipt)
}

#[test]
fn c71_joint_inference_same_model_conversation_has_two_pcs_and_complete_valid_certificates() {
    compare(false);
}
#[test]
fn c71_joint_inference_changed_last_kv_cannot_promote() {
    compare(true);
}
fn compare(changed_kv: bool) {
    let (mut bp, mut bv) = tests::fixture();
    let profile = Profile::small(0).unwrap();
    let packed = tests::weights(&profile);
    let mut w =
        Installed::new_with_source(&profile, packed, |v| Model::new_with_retention(WD, v, true))
            .unwrap();
    let mut state = State::new(w.root().clone(), [31; 32], 1, [32; 32]).unwrap();
    let delta = signed(67);
    let mut rng = MatrixRng::from_seed([153; 32]);
    let count: usize = (0..3)
        .map(|slot| {
            let p = &state.profiles[slot];
            let g = gamma(&AD.config().unwrap());
            let s = p.context(
                w.root(),
                w.root(),
                &[0, 0],
                AttemptContext { slot: slot as u8, ..state.attempt([9; 32]) },
                &g,
                &g,
            );
            required(p, &s).unwrap()
        })
        .sum();
    let all: Vec<_> = (0..count)
        .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
        .collect();
    let mut rows = all.clone().into_iter();
    let mut keys = all.iter().map(|a| Key::new(a.m + delta * a.x)).collect::<Vec<_>>().into_iter();
    let mut accepted: Vec<Snapshot> = Vec::new();
    let mut previous = None;
    for slot in 0..3 {
        let prompt = (slot % 2) as u32;
        let nonce = [9 + slot as u8; 32];
        let baseline = bp.prepare_response(prompt, nonce).unwrap();
        let ba = bv.verify_response(prompt, &baseline).unwrap();
        bp.promote(ba).unwrap();
        if changed_kv && slot == 1 {
            let prev = &state.profiles[0];
            accepted[0].corrupt_value(prev, kv_ids(prev)[0], 1, 0);
        }
        let p = &state.profiles[slot];
        let mut snapshot =
            Snapshot::prepare_with_source(p, &w, &accepted, prompt, |v| view(v, w.root().clone()))
                .unwrap();
        assert_eq!(snapshot.tokens, baseline.tokens);
        if !changed_kv {
            assert_eq!(snapshot.source.weights, bp.accepted.last().unwrap().source.weights);
        }
        assert!(p.bytes().live < BANK && auxiliary_live(p) <= 2048);
        snapshot.source.weights.resize(auxiliary_live(p), 0);
        for t in 0..p.old {
            let oldp = &state.profiles[t / 2];
            for (kind, id) in kv_ids(oldp).into_iter().enumerate() {
                for lane in 0..2 {
                    for b in 0..2 {
                        snapshot.source.weights[BANK + 8 * t + 4 * kind + 2 * lane + b] =
                            i16::from(accepted[t / 2].byte(oldp, id, t % 2, lane, b));
                    }
                }
            }
        }
        let mut values = vec![0; 2 * W];
        values[..w.dense_model().weights.len()].copy_from_slice(&w.dense_model().weights);
        values[W..W + snapshot.source.weights.len()].copy_from_slice(&snapshot.source.weights);
        let current = Model::new_with_retention(SD, values, true).unwrap();
        snapshot.source.root = current.root.clone();
        let g = gamma(&AD.config().unwrap());
        let s =
            p.context(&current.root, &current.root, &snapshot.tokens, state.attempt(nonce), &g, &g);
        let n = required(p, &s).unwrap();
        let mut reserved = rows.by_ref().take(n).collect::<Vec<_>>().into_iter();
        let (bytes, receipt) = prove_joint(
            &state,
            &w,
            &snapshot,
            &accepted,
            previous.as_ref().unwrap_or(w.dense_model()),
            &current,
            nonce,
            &mut reserved,
        )
        .unwrap();
        if !changed_kv && slot == 1 {
            // Counterfactual verifier checks of this single emitted certificate.
            // No additional prover run or source exposure.
            let h = header(&state, &current.root, snapshot.tokens, nonce, n).unwrap();
            let mut offset = h.len();
            for _ in 0..3 {
                offset += 6 + u32::from_le_bytes(bytes[offset + 2..offset + 6].try_into().unwrap())
                    as usize;
            }
            for fault in 0..2 {
                let mut damaged = bytes.clone();
                if fault == 0 {
                    damaged.pop();
                } else {
                    damaged[offset + 6..offset + 10].copy_from_slice(&6u32.to_le_bytes());
                }
                let mut shadow = tests::fork_state(&state);
                let mut shadow_keys = keys.clone();
                assert!(verify_joint(
                    &mut shadow,
                    &current.root,
                    snapshot.tokens,
                    prompt,
                    nonce,
                    &damaged,
                    delta,
                    &mut shadow_keys
                )
                .is_err());
                assert!(!shadow.live);
                assert_eq!(shadow.accepted.len(), state.accepted.len());
                assert_eq!(
                    (shadow.cursor - state.cursor, keys.len() - shadow_keys.len()),
                    (3 * n, n)
                );
            }
            eprintln!("joint inference late truncation and RNE cardinality rejected; full burn; no promotion");
        }
        let before = (state.cursor, keys.len(), state.accepted.len());
        let checked = verify_joint(
            &mut state,
            &current.root,
            snapshot.tokens,
            prompt,
            nonce,
            &bytes,
            delta,
            &mut keys,
        );
        if changed_kv && slot == 1 {
            assert!(checked.is_err(), "changed final accepted K must fail");
            assert!(!state.live);
            assert_eq!(state.accepted.len(), before.2);
            assert_eq!((state.cursor - before.0, before.1 - keys.len()), (3 * n, n));
            let consumed = (state.cursor, keys.len());
            assert!(verify_joint(
                &mut state,
                &current.root,
                snapshot.tokens,
                prompt,
                nonce,
                &bytes,
                delta,
                &mut keys
            )
            .is_err());
            assert_eq!((state.cursor, keys.len()), consumed);
            eprintln!("joint inference changed last accepted K rejected after full Prepare/prove; burn={n}; no promotion; error={:?}",checked.err());
            return;
        }
        assert_eq!(checked.unwrap(), receipt);
        assert!(bytes.len() < baseline.certificate.len());
        assert_eq!(state.accepted.len(), slot + 1);
        eprintln!("joint inference slot={slot} tokens={:?} baseline_bytes={} joint_bytes={} PCS=2 ideal_Fp3_rows={n}",snapshot.tokens,baseline.certificate.len(),bytes.len());
        accepted.push(snapshot);
        previous = Some(current);
        // Installation is exposed once. Keep numerical W, release its PCS cache.
        w.release_retained();
    }
    assert!(rows.next().is_none() && keys.next().is_none() && !state.live);
    assert!(3 * count < bv.state.cursor);
    eprintln!("joint inference baseline_total_ideal_Fp3_rows={}", bv.state.cursor / 3);
    eprintln!("joint inference total_ideal_Fp3_rows={count} original_RNE=false RNE_groups=3 RNE_cells=224 full_canonical_work_admitted=false");
}
