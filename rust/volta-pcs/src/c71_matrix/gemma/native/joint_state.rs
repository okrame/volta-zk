//! Experimental state transition with real PCS/range proofs and ideal MAC rows.
//! Synthetic sources, no inference/RNE composition or canonical work admission.
use super::{Batch, Reader, Writer};
use crate::c71_matrix::linear::Cube;
use crate::c71_matrix::*;

const W: usize = 4096;
const A: usize = 2048;
const LAYOUT: [u8; 32] = [41; 32];
const MAGIC: &[u8] = b"C71-joint-state-kernel-test-v1\0";
const WD: Domain = Domain::JointTest { bits: 12, exposures: 1, first: 4 };
const SD: Domain = Domain::JointTest { bits: 13, exposures: 2, first: 5 };

fn required(slot: usize) -> usize {
    1 + usize::from(slot != 0)
        + range::required(12, 32767)
        + range::required(11, range::Alphabet::Byte)
        + 3 * (if slot == 0 { 12 } else { 13 })
        + 2
        + 3 * 13
        + 2
}
fn context(slot: usize, previous: [u8; 32]) -> AttemptContext {
    AttemptContext {
        session: [42; 32],
        capacity: [43; 32],
        slot: slot as u8,
        predecessor: previous,
        nonce: [44 + slot as u8; 32],
    }
}
fn header(
    installed: &C61Commitment,
    old: &C61Commitment,
    new: &C61Commitment,
    slot: usize,
    receipt: [u8; 32],
) -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.extend(context(slot, receipt).encode());
    for root in [installed, old, new] {
        b.extend(root.roots()[0]);
    }
    b.extend(LAYOUT);
    b.extend((2 * slot as u32).to_le_bytes()); // accepted KV length, verifier-owned
    for d in [WD, SD] {
        let g = gamma(&d.config().unwrap());
        b.extend((g.len() as u32).to_le_bytes());
        b.extend(g);
    }
    b
}
fn start(h: &[u8]) -> Fs {
    let mut fs = Fs::new(
        MAGIC,
        4096 + request_limit(&WD.config().unwrap()) + 2 * request_limit(&SD.config().unwrap()),
    );
    fs.record(0x70, h);
    fs
}
fn cube(offset: usize, bits: usize, fs: &mut Fs) -> Vec<Cube> {
    vec![Cube { offset, point: (0..bits).map(|_| fs.fp3()).collect(), coefficient: Fp3::ONE }]
}
fn forms(slot: usize, fs: &mut Fs) -> (Vec<Vec<Cube>>, Vec<Cube>) {
    let mut links = vec![cube(0, 12, fs)];
    if slot != 0 {
        links.push(cube(W, (2 * slot).ilog2() as usize, fs));
    }
    (links, cube(W + A, 11, fs))
}
fn value(model: &Model, form: &[Cube]) -> Fp3 {
    form.iter().fold(Fp3::ZERO, |s, c| {
        s + c.coefficient
            * eq(&c.point).iter().enumerate().fold(Fp3::ZERO, |v, (i, &e)| {
                v + e * signed(i64::from(model.weights[c.offset + i]))
            })
    })
}
fn rebase(forms: [Vec<Cube>; 2], offset: usize) -> [Vec<Cube>; 2] {
    forms.map(|mut f| {
        for c in &mut f {
            c.offset += offset;
        }
        f
    })
}
fn state_values(w: &[i16], slot: usize) -> Vec<i16> {
    let mut values = vec![0; 2 * W];
    values[..W].copy_from_slice(w);
    for i in 0..2 * (slot + 1) {
        values[W + i] = (51 + i) as i16;
    }
    values[W + 128] = 71 + slot as i16; // current auxiliary, allowed to change
    values
}
fn state(w: &[i16], slot: usize) -> Model {
    Model::new_with_retention(SD, state_values(w, slot), true).unwrap()
}

fn prove(
    installed: &C61Commitment,
    old: &Model,
    new: &Model,
    slot: usize,
    receipt: [u8; 32],
    rows: &mut std::vec::IntoIter<Auth>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let h = header(installed, &old.root, &new.root, slot, receipt);
    let mut fs = start(&h);
    let mut out = Writer::new(&h);
    let (links, zero) = forms(slot, &mut fs);
    let mut previous = Batch::new();
    let mut current = Batch::new();
    let mut corrections = Vec::new();
    for f in links {
        let (correction, target) = c7_fp3_transfer_prover(rows.next().unwrap(), value(old, &f));
        corrections.push(correction.value());
        previous.add(f.clone(), target);
        current.add(f, target);
    }
    record_values(&mut fs, 0x71, &corrections);
    out.put(0, &corrections, &mut fs)?;
    current.add(zero, Auth::ZERO);
    // These are source views only, never separately committed or PCS-opened.
    // Their range MACs are rebased and closed against the actual single S root.
    for (i, (offset, bits, alphabet)) in
        [(0, 12, range::Alphabet::Symmetric(32767)), (W, 11, range::Alphabet::Byte)]
            .into_iter()
            .enumerate()
    {
        let view = Model {
            domain: Domain::Flat(bits),
            weights: new.weights[offset..offset + (1 << bits)].to_vec(),
            root: new.root.clone(),
            seed: [0; 32],
            salt_seed: [0; 32],
            retained: None,
        };
        let (proof, f, t) = range::prove(
            &view,
            context(slot, receipt),
            LAYOUT,
            1 << bits,
            alphabet,
            &mut fs,
            rows,
        )?;
        for (f, t) in rebase(f, offset).into_iter().zip(t) {
            current.add(f, t);
        }
        out.put(1 + i as u16, &proof, &mut fs)?;
    }
    for (i, (model, batch)) in [(old, previous), (new, current)].into_iter().enumerate() {
        let (proof, _) = linear::prove(
            model,
            context(slot, receipt),
            LAYOUT,
            &batch.forms,
            &batch.targets,
            &mut fs,
            rows,
        )?;
        let body = codec::encode_linear(model.domain, &proof).map_err(|e| e.to_string())?;
        out.raw(3 + i as u16, &body, &mut fs)?;
    }
    if rows.next().is_some() {
        return Err("joint proof has unused rows".into());
    }
    Ok(out.finish(&mut fs))
}

#[derive(Clone)]
struct Verifier {
    installed: C61Commitment,
    head: C61Commitment,
    receipt: [u8; 32],
    slot: usize,
    cursor: usize,
    live: bool,
    delta: Fp3,
    keys: Vec<Key>,
    seen: std::collections::HashSet<[u8; 32]>,
}
impl Verifier {
    fn verify(&mut self, root: &C61Commitment, bytes: &[u8]) -> Result<[u8; 32], String> {
        if !self.live {
            return Err("joint run terminated".into());
        }
        self.live = false;
        let count = required(self.slot);
        if self.slot >= 3 || self.cursor + count > self.keys.len() {
            return Err("joint capacity exhausted".into());
        }
        let mut rows = self.keys[self.cursor..self.cursor + count].to_vec().into_iter();
        self.cursor += count; // reserve/burn before parsing or any early rejection
        if root.num_roots() != 1 || self.seen.contains(&root.roots()[0]) {
            return Err("joint state root not fresh".into());
        }
        let h = header(&self.installed, &self.head, root, self.slot, self.receipt);
        let mut input = Reader::new(bytes, &h)?;
        let mut fs = start(&h);
        let (links, zero) = forms(self.slot, &mut fs);
        let (corrections, frame) = input.get::<Vec<Fp3>>(0)?;
        if corrections.len() != links.len() {
            return Err("joint link cardinality".into());
        }
        let mut previous = Batch::new();
        let mut current = Batch::new();
        for (f, &c) in links.into_iter().zip(&corrections) {
            let target = c7_fp3_transfer_verifier(
                rows.next().unwrap(),
                self.delta,
                C7Fp3TransferCorrection::new(c),
            );
            previous.add(f.clone(), target);
            current.add(f, target);
        }
        record_values(&mut fs, 0x71, &corrections);
        Reader::record(&mut fs, frame);
        current.add(zero, Key::ZERO);
        for (i, (offset, bits, alphabet)) in
            [(0, 12, range::Alphabet::Symmetric(32767)), (W, 11, range::Alphabet::Byte)]
                .into_iter()
                .enumerate()
        {
            let (proof, frame) = input.get::<range::Proof>(1 + i as u16)?;
            let (f, t) = range::verify(
                Domain::Flat(bits),
                root,
                context(self.slot, self.receipt),
                LAYOUT,
                1 << bits,
                alphabet,
                &proof,
                self.delta,
                &mut fs,
                &mut rows,
            )?;
            for (f, t) in rebase(f, offset).into_iter().zip(t) {
                current.add(f, t);
            }
            Reader::record(&mut fs, frame);
        }
        for (i, (domain, root, batch)) in
            [(if self.slot == 0 { WD } else { SD }, &self.head, previous), (SD, root, current)]
                .into_iter()
                .enumerate()
        {
            let (body, frame) = input.raw(3 + i as u16)?;
            let proof = codec::decode_linear(domain, body).map_err(|e| e.to_string())?;
            linear::verify(
                domain,
                root,
                context(self.slot, self.receipt),
                LAYOUT,
                &batch.forms,
                &batch.targets,
                &proof,
                self.delta,
                &mut fs,
                &mut rows,
            )?;
            Reader::record(&mut fs, frame);
        }
        if rows.next().is_some() {
            return Err("joint verifier has unused rows".into());
        }
        let receipt = input.finish(&mut fs)?;
        self.seen.insert(root.roots()[0]);
        self.head = root.clone();
        self.receipt = receipt;
        self.slot += 1;
        self.live = self.slot < 3;
        Ok(receipt)
    }
}

fn fixture() -> (Model, Vec<Auth>, Verifier) {
    let w: Vec<_> = (0..W).map(|i| (i % 31) as i16 - 15).collect();
    let installed = Model::new_with_retention(WD, w, true).unwrap();
    let delta = Fp3::new(Fp::new(19), Fp::new(23), Fp::new(29));
    // Deterministic ideal-MAC fixture, not a real PCG or a privacy experiment.
    let rows: Vec<_> = (0..(0..3).map(required).sum::<usize>())
        .map(|i| {
            let x = Fp3::new(Fp::new(i as u64 + 1), Fp::new(7), Fp::new(11));
            let m = Fp3::new(Fp::new(i as u64 + 101), Fp::new(13), Fp::new(17));
            Auth::new(x, m)
        })
        .collect();
    let keys = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect();
    let verifier = Verifier {
        installed: installed.root.clone(),
        head: installed.root.clone(),
        receipt: [0; 32],
        slot: 0,
        cursor: 0,
        live: true,
        delta,
        keys,
        seen: std::collections::HashSet::from([installed.root.roots()[0]]),
    };
    (installed, rows, verifier)
}

#[test]
fn c71_joint_state_three_transitions_keep_installed_w_and_original_range_kv_macs() {
    let (installed, rows, mut verifier) = fixture();
    let installed_root = installed.root.clone();
    let weights = installed.weights.clone();
    let mut old = installed;
    let mut used = 0;
    for slot in 0..3 {
        let new = state(&weights, slot);
        let count = required(slot);
        let (bytes, receipt) = prove(
            &installed_root,
            &old,
            &new,
            slot,
            verifier.receipt,
            &mut rows[used..used + count].to_vec().into_iter(),
        )
        .unwrap();
        // Counterfactual verifier replay of one emitted certificate, not row reuse.
        let mut rejected = verifier.clone();
        let head = rejected.head.clone();
        assert!(rejected.verify(&new.root, &bytes[..bytes.len() - 1]).is_err());
        assert_eq!(rejected.head, head);
        assert_eq!(rejected.cursor, used + count);
        assert!(!rejected.live);
        assert!(rejected.verify(&new.root, &bytes).is_err());
        assert_eq!(rejected.cursor, used + count);
        let mut exhausted = verifier.clone();
        exhausted.keys.truncate(used);
        assert!(exhausted.verify(&new.root, &bytes).is_err());
        assert!(!exhausted.live && exhausted.cursor == used);
        assert_eq!(exhausted.head, verifier.head);
        if slot == 2 {
            let expired = *verifier
                .seen
                .iter()
                .find(|&&r| r != verifier.head.roots()[0] && r != installed_root.roots()[0])
                .unwrap();
            let mut reused = verifier.clone();
            assert!(reused.verify(&C61Commitment::new(vec![expired]), &[]).is_err());
            assert!(!reused.live && reused.cursor == used + count);
            assert_eq!(reused.head, verifier.head);
        }
        assert_eq!(verifier.verify(&new.root, &bytes).unwrap(), receipt);
        used += count;
        assert_eq!(verifier.cursor, used);
        assert_eq!(verifier.head, new.root);
        assert_eq!(verifier.seen.len(), slot + 2);
        assert!(new.retained.is_some());
        eprintln!(
            "joint state slot={slot} PCS=2 certificate_bytes={} ideal_rows={count} cursor={used}",
            bytes.len()
        );
        old = new;
    }
    assert!(!verifier.live && verifier.slot == 3);
    assert_eq!(used, rows.len());
}

#[test]
fn c71_joint_state_changed_installed_w_padding_or_range_cannot_promote() {
    for (index, replacement) in [(0, -14), (W + A, 1), (W + 128, 256), (0, -32768)] {
        let (installed, rows, mut verifier) = fixture();
        let mut values = state_values(&installed.weights, 0);
        values[index] = replacement;
        let bad = Model::new_with_retention(SD, values, true).unwrap();
        let (bytes, _) = prove(
            &installed.root,
            &installed,
            &bad,
            0,
            [0; 32],
            &mut rows[..required(0)].to_vec().into_iter(),
        )
        .unwrap();
        let old = verifier.head.clone();
        assert!(verifier.verify(&bad.root, &bytes).is_err());
        assert_eq!(verifier.head, old);
        assert_eq!(verifier.slot, 0);
        assert_eq!(verifier.cursor, required(0));
        assert!(!verifier.live);
    }
}

#[test]
fn c71_joint_state_changed_last_accepted_kv_cannot_promote() {
    let (installed, rows, mut verifier) = fixture();
    let first = state(&installed.weights, 0);
    let (bytes, _) = prove(
        &installed.root,
        &installed,
        &first,
        0,
        [0; 32],
        &mut rows[..required(0)].to_vec().into_iter(),
    )
    .unwrap();
    verifier.verify(&first.root, &bytes).unwrap();
    let mut values = state_values(&installed.weights, 1);
    values[W + 1] += 1; // final KV of the accepted predecessor
    let bad = Model::new_with_retention(SD, values, true).unwrap();
    let (bytes, _) = prove(
        &installed.root,
        &first,
        &bad,
        1,
        verifier.receipt,
        &mut rows[required(0)..required(0) + required(1)].to_vec().into_iter(),
    )
    .unwrap();
    assert!(verifier.verify(&bad.root, &bytes).is_err());
    assert_eq!(verifier.head, first.root);
    assert_eq!(verifier.slot, 1);
    assert_eq!(verifier.cursor, required(0) + required(1));
    assert!(!verifier.live);
}
