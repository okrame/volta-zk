use super::*;
use rand_010::RngExt;

fn weights(p: &Profile) -> Vec<i16> {
    p.plan
        .sources
        .iter()
        .flat_map(|s| {
            (0..s.rows).flat_map(move |r| {
                (0..s.cols).map(move |c| if s.rows == 1 || r == c { 1 } else { 0 })
            })
        })
        .collect()
}

#[test]
fn c71_b12_native_prepare_covers_all_sources_and_absorbs_final_token() {
    let p = Profile::small(0).unwrap();
    let installed = Installed::new(&p, weights(&p)).unwrap();
    let mut snapshots = Vec::new();
    for slot in 0..3 {
        let profile = Profile::small(slot).unwrap();
        assert_eq!(profile.digest, p.digest);
        let s = Snapshot::prepare(&profile, &installed, &snapshots, (slot % 2) as u32).unwrap();
        assert_eq!(s.tokens[0], (slot % 2) as u32);
        let value = profile.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output;
        assert!((0..2).any(|c| s.value(&profile, value, 1, c) != 0));
        eprintln!(
            "slot={slot} sources={} live={} tokens={:?}",
            profile.bytes().widths.len(),
            profile.bytes().live,
            s.tokens
        );
        snapshots.push(s);
    }
    assert!(Profile::small(3).is_err());
    assert!(Snapshot::prepare(&p, &installed, &[], 2).is_err());
    let mut outside_table = weights(&p);
    outside_table[p.plan.sources[p.plan.cohorts[10].tensor].packed_offset] = 3;
    let private_failure = Installed::new(&p, outside_table).unwrap();
    assert_eq!(
        Snapshot::prepare(&p, &private_failure, &[], 0).err().as_deref(),
        Some("private preparation Stop")
    );
    for (n, d, want) in [(-5, 2, -2), (-3, 2, -2), (3, 2, 2), (5, 2, 2)] {
        assert_eq!(super::super::prepare::rne(n, d), want);
    }
}

fn fixture() -> (Prover, Verifier) {
    let p = Profile::small(0).unwrap();
    let model = Installed::new(&p, weights(&p)).unwrap();
    let state = || State::new(model.model.root.clone(), [31; 32], 1, [32; 32]).unwrap();
    let (ps, vs) = (state(), state());
    let mut count = 0;
    for slot in 0..3 {
        let p = &ps.profiles[slot];
        let (wg, ag) = (gamma(&DOMAIN_W.config().unwrap()), gamma(&DOMAIN_A.config().unwrap()));
        let context = AttemptContext {
            session: ps.session,
            capacity: ps.seal,
            slot: slot as u8,
            predecessor: if slot == 0 { [0; 32] } else { [1; 32] },
            nonce: [2; 32],
        };
        let root = C61Commitment::new(vec![[42; 32]]);
        let s = p.context(&ps.weight, &root, &[0, 0], context, &wg, &ag);
        count += p.required(&s).unwrap();
    }
    let delta = signed(67);
    let mut rng = MatrixRng::from_seed([43; 32]);
    let rows = (0..count)
        .map(|_| Auth::new(from_p3(rng.random::<E>()), from_p3(rng.random::<E>())))
        .collect::<Vec<_>>();
    let keys = rows.iter().map(|a| Key::new(a.m + delta * a.x)).collect::<Vec<_>>();
    (
        Prover { state: ps, model, rows: rows.into_iter(), accepted: Vec::new(), pending: None },
        Verifier { state: vs, delta, keys: keys.into_iter() },
    )
}

#[test]
fn c71_b12_native_composed_three_attempts_close_one_fs_and_promote_same_w_kv() {
    let (mut prover, mut verifier) = fixture();
    for slot in 0..3 {
        let response = prover.prepare_response((slot % 2) as u32, [51 + slot as u8; 32]).unwrap();
        assert_eq!(prover.accepted.len(), slot);
        assert_eq!(prover.state.accepted.len(), slot);
        assert!(!prover.state.live);
        let accepted = verifier.verify_response((slot % 2) as u32, &response).unwrap();
        assert_eq!(accepted.receipt, prover.pending.as_ref().unwrap().1);
        prover.promote(accepted).unwrap();
        assert_eq!(prover.state.cursor, verifier.state.cursor);
        assert_eq!(prover.state.next_slot, slot + 1);
        assert_eq!(prover.state.accepted[slot].receipt, verifier.state.accepted[slot].receipt);
        eprintln!(
            "native slot={slot}, certificate={} bytes, base_cursor={}",
            response.certificate.len(),
            verifier.state.cursor
        );
    }
    assert_eq!(prover.rows.len(), 0);
    assert_eq!(verifier.keys.len(), 0);
    assert!(!prover.state.live && !verifier.state.live);
    assert!(prover.prepare_response(0, [60; 32]).is_err());
}

// Diagnostic forks of the verifier's already established state, solely to
// check counterfactual corruptions of ONE proof. No clone/import API exists
// in the native protocol; these are not extra honest PCS exposures.
fn fork(v: &Verifier) -> Verifier {
    let mut state =
        State::new(v.state.weight.clone(), v.state.session, v.state.epoch, v.state.seal).unwrap();
    state.cursor = v.state.cursor;
    state.next_slot = v.state.next_slot;
    state.live = v.state.live;
    state.accepted = v
        .state
        .accepted
        .iter()
        .map(|a| Accepted { root: a.root.clone(), tokens: a.tokens, receipt: a.receipt })
        .collect();
    Verifier { state, delta: v.delta, keys: v.keys.as_slice().to_vec().into_iter() }
}

fn frames(v: &Verifier, r: &Response) -> Vec<std::ops::Range<usize>> {
    let p = &v.state.profiles[v.state.next_slot];
    let (wg, ag) = (gamma(&DOMAIN_W.config().unwrap()), gamma(&DOMAIN_A.config().unwrap()));
    let s = p.context(&v.state.weight, &r.root, &r.tokens, v.state.attempt(r.nonce), &wg, &ag);
    let header = v.state.header(&r.root, r.tokens, r.nonce, p.required(&s).unwrap()).unwrap();
    let mut offset = header.len();
    let mut result = Vec::new();
    for i in 0..17 + v.state.next_slot {
        let frame = &r.certificate[offset..];
        assert_eq!(u16::from_le_bytes(frame[..2].try_into().unwrap()) as usize, i);
        let len = u32::from_le_bytes(frame[2..6].try_into().unwrap()) as usize + 6;
        result.push(offset..offset + len);
        offset += len;
    }
    result
}

fn rejected(v: &Verifier, r: &Response) {
    let mut shadow = fork(v);
    let (before, keys) = (shadow.state.cursor, shadow.keys.len());
    let roots =
        shadow.state.accepted.iter().map(|a| (a.root.clone(), a.receipt)).collect::<Vec<_>>();
    assert!(shadow.verify_response(r.tokens[0], r).is_err());
    assert!(!shadow.state.live);
    assert_eq!(
        shadow.state.accepted.iter().map(|a| (a.root.clone(), a.receipt)).collect::<Vec<_>>(),
        roots
    );
    assert_eq!(shadow.state.cursor - before, 3 * (keys - shadow.keys.len()));
    let cursor = shadow.state.cursor;
    let remaining = shadow.keys.len();
    assert!(shadow.verify_response(r.tokens[0], r).is_err());
    assert_eq!((shadow.state.cursor, shadow.keys.len()), (cursor, remaining));
}

#[test]
fn c71_b12_native_certificate_rejects_order_cardinality_framing_and_noncanonical_fields() {
    let (mut prover, verifier) = fixture();
    let response = prover.prepare_response(0, [71; 32]).unwrap();
    let spans = frames(&verifier, &response);
    for fault in 0..7 {
        let mut r = response.clone();
        match fault {
            0 => {
                r.certificate.drain(spans[5].clone());
            }
            1 => {
                let copied = r.certificate[spans[5].clone()].to_vec();
                r.certificate.splice(spans[5].start..spans[5].start, copied);
            }
            2 => {
                let swapped =
                    [&r.certificate[spans[5].clone()], &r.certificate[spans[4].clone()]].concat();
                r.certificate.splice(spans[4].start..spans[5].end, swapped);
            }
            3 => {
                r.certificate[spans[3].start + 6..spans[3].start + 10]
                    .copy_from_slice(&6u32.to_le_bytes());
            }
            4 => {
                r.certificate.push(0);
            }
            5 => {
                r.certificate[spans[1].start + 6..spans[1].start + 10]
                    .copy_from_slice(&u32::MAX.to_le_bytes());
            }
            6 => {
                r.certificate[spans[1].start + 10..spans[1].start + 18]
                    .copy_from_slice(&volta_field::P.to_le_bytes());
            }
            _ => unreachable!(),
        }
        rejected(&verifier, &r);
    }
    assert_eq!(prover.accepted.len(), 0);
    prover.stop();
    assert!(prover.pending.is_none());
}

#[test]
fn c71_b12_native_interrupted_and_late_rejection_burn_without_kv_promotion() {
    let (mut prover, verifier) = fixture();
    let response = prover.prepare_response(0, [72; 32]).unwrap();
    let spans = frames(&verifier, &response);
    // Every mandatory component boundary, including the final PCS before END.
    for span in &spans {
        let mut r = response.clone();
        r.certificate.truncate(span.end);
        rejected(&verifier, &r);
    }
    let mut r = response.clone();
    r.certificate[spans.last().unwrap().end - 24] ^= 1;
    rejected(&verifier, &r);
    prover.stop();
    assert_eq!(prover.accepted.len(), 0);
    assert!(prover.prepare_response(0, [73; 32]).is_err());
}

#[test]
fn c71_b12_native_context_binds_w_predecessor_profile_tokens_and_epoch() {
    let (mut prover, mut verifier) = fixture();
    let first = prover.prepare_response(0, [74; 32]).unwrap();
    let acceptance = verifier.verify_response(0, &first).unwrap();
    prover.promote(acceptance).unwrap();
    let response = prover.prepare_response(1, [75; 32]).unwrap();
    for fault in 0..6 {
        let mut r = response.clone();
        let mut shadow = fork(&verifier);
        match fault {
            0 => {
                r.certificate[MAGIC.len() + 32] ^= 1;
            } // installed W
            1 => {
                shadow.state.accepted[0].receipt[0] ^= 1;
            }
            2 => {
                r.certificate[MAGIC.len()] ^= 1;
            } // expected numeric profile
            3 => {
                r.tokens[1] ^= 1;
            }
            4 => {
                shadow.state.epoch += 1;
            }
            5 => {
                r.nonce[0] ^= 1;
            }
            _ => unreachable!(),
        }
        rejected(&shadow, &r);
    }
    rejected(&verifier, &first); // replay cannot select the old branch
    assert_eq!(verifier.state.accepted.len(), 1);
    assert_eq!(prover.accepted.len(), 1);
    let acceptance = verifier.verify_response(1, &response).unwrap();
    prover.promote(acceptance).unwrap();
}

#[test]
fn c71_b12_native_consistent_inference_under_changed_w_cannot_replace_installed_w() {
    let (mut prover, mut verifier) = fixture();
    // Compute all inference and GKR inputs consistently under another W,
    // while retaining the ORIGINAL committed W body/root for range and PCS.
    prover.model.corrupt_weight(0, 0);
    let response = prover.prepare_response(0, [76; 32]).unwrap();
    assert!(verifier.verify_response(0, &response).is_err());
    assert_eq!(verifier.state.accepted.len(), 0);
    prover.stop();
    assert_eq!(prover.accepted.len(), 0);
}

#[test]
fn c71_b12_native_exhaustion_and_private_stop_cannot_reuse_slots_or_publish_a() {
    let (mut prover, mut verifier) = fixture();
    prover.rows = Vec::new().into_iter();
    assert_eq!(prover.prepare_response(0, [77; 32]).err().as_deref(), Some("Stop"));
    assert!(!prover.state.live);
    assert!(prover.pending.is_none());
    assert_eq!(prover.state.cursor, 0);
    assert_eq!(prover.accepted.len(), 0);
    verifier.keys = Vec::new().into_iter();
    let r = Response {
        root: C61Commitment::new(vec![[80; 32]]),
        tokens: [0, 0],
        nonce: [79; 32],
        certificate: Vec::new(),
    };
    assert!(verifier.verify_response(0, &r).is_err());
    assert!(!verifier.state.live);
    assert_eq!(verifier.state.cursor, 0);
    assert_eq!(verifier.state.accepted.len(), 0);
}

#[test]
fn c71_b12_native_changed_predecessor_final_kv_getter_cannot_promote_continuation() {
    let (mut prover, mut verifier) = fixture();
    let first = prover.prepare_response(0, [81; 32]).unwrap();
    let accepted = verifier.verify_response(0, &first).unwrap();
    prover.promote(accepted).unwrap();
    let p = &prover.state.profiles[0];
    // Change the emitted token's K, keeping its accepted original A root.
    prover.accepted[0].corrupt_value(p, p.rotations[1][1], 1, 0);
    let response = prover.prepare_response(1, [82; 32]).unwrap();
    assert!(verifier.verify_response(1, &response).is_err());
    assert_eq!(verifier.state.accepted.len(), 1);
    prover.stop();
    assert_eq!(prover.accepted.len(), 1);
    assert!(!prover.state.live && !verifier.state.live);
    assert_eq!(prover.state.cursor, verifier.state.cursor);
}
