//! Real fixed-run AES/journal adapter. No row iterator is accepted from a peer.
//! Full bounded inference needs 797,139 base rows: do not bootstrap it on the VM.
use super::*;
use std::io;
use volta_pcg::c71_lifetime::{Attempt, ModelBinding, Pool};

fn io_error(e: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn field(words: [u64; 3]) -> Result<Fp3, String> {
    let bytes: [u8; 24] = std::array::from_fn(|i| words[i / 8].to_le_bytes()[i % 8]);
    Fp3::from_bytes(&bytes).map_err(|e| e.to_string())
}

fn auths(rows: &[[u64; 4]]) -> Result<std::vec::IntoIter<Auth>, String> {
    if rows.len() % 3 != 0 {
        return Err("incomplete native correlation triple".into());
    }
    let u = field([0, 1, 0])?;
    rows.chunks_exact(3)
        .map(|r| {
            let tag = |r: [u64; 4]| field([r[1], r[2], r[3]]);
            Ok(Auth::new(
                field([r[0][0], r[1][0], r[2][0]])?,
                tag(r[0])? + u * tag(r[1])? + u * u * tag(r[2])?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_iter)
}

fn keys(
    rows: &[[u64; 3]],
    delta: Option<&[u64; 3]>,
) -> Result<(Fp3, std::vec::IntoIter<Key>), String> {
    if rows.len() % 3 != 0 {
        return Err("incomplete native key triple".into());
    }
    // B11 m=k+Delta*x becomes native k=m+(-Delta)*x in ALL consumers.
    let delta = Fp3::ZERO - field(*delta.ok_or("missing verifier Delta")?)?;
    let u = field([0, 1, 0])?;
    let keys = rows
        .chunks_exact(3)
        .map(|r| Ok(Key::new(field(r[0])? + u * field(r[1])? + u * u * field(r[2])?)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok((delta, keys.into_iter()))
}

impl State {
    fn binding(&self) -> ModelBinding {
        ModelBinding {
            anchor: self.weight.roots()[0],
            root: self.weight.roots()[0],
            semantics: self.profiles[0].digest,
        }
    }
    fn check_pool(&self, context: (ModelBinding, [u8; 32], Attempt)) -> Result<(), String> {
        let (model, session, a) = context;
        if model != self.binding() || session != self.session {
            return Err("pool installed model/semantics/session differ".into());
        }
        self.check_burn(&a)
    }
    fn check_burn(&self, a: &Attempt) -> Result<(), String> {
        if a.capacity != self.seal
            || a.setup != self.epoch
            || a.ordinal != self.next_slot as u64 + 1
            || a.first_base_row != self.cursor as u64
            || a.predecessor != self.accepted.last().map_or([0; 32], |a| a.receipt)
            || self.next_slot != self.accepted.len()
            || self.next_slot >= 3
        {
            return Err("pool reservation differs from native accepted registry".into());
        }
        Ok(())
    }
    fn from_pool(
        weight: C61Commitment,
        context: (ModelBinding, [u8; 32], Attempt),
    ) -> Result<Self, String> {
        let state = Self::new(weight, context.1, context.2.setup, context.2.capacity)?;
        state.check_pool(context)?;
        Ok(state)
    }
}

impl Prover {
    fn from_pool(model: Installed, pool: &Pool<'_, [u64; 4]>) -> Result<Self, String> {
        let state = State::from_pool(
            model.model.root.clone(),
            pool.fixed_run_context().map_err(|e| e.to_string())?,
        )?;
        Ok(Self {
            state,
            model,
            accepted: Vec::new(),
            pending: None,
            #[cfg(test)]
            rows: Vec::new().into_iter(),
        })
    }

    /// The continuation receives a verifier-created Acceptance, never an ACK.
    /// Both journals finish before the corresponding native registry promotes.
    fn respond_with_pool(
        &mut self,
        prompt: u32,
        nonce: [u8; 32],
        pool: &mut Pool<'_, [u64; 4]>,
        verify: impl FnOnce(&Response) -> Result<Acceptance, String>,
    ) -> Result<(), String> {
        if !self.state.live || self.pending.is_some() {
            pool.stop();
            self.stop();
            return Err("Stop".into());
        }
        self.state.live = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.state.check_pool(pool.fixed_run_context().map_err(|e| e.to_string())?)?;
            let p = &self.state.profiles[self.state.next_slot];
            let (wg, ag) = (gamma(&DOMAIN_W.config()?), gamma(&DOMAIN_A.config()?));
            let attempt = self.state.attempt(nonce);
            let required = p.required(&p.context(
                &self.state.weight,
                &self.state.weight,
                &[prompt, 0],
                attempt,
                &wg,
                &ag,
            ))?;
            if pool.remaining_fp3() < required {
                return Err("capacity exhausted before private preparation".into());
            }
            // No unused rows, keys or Delta are visible to Prepare.
            let snapshot = Snapshot::prepare(p, &self.model, &self.accepted, prompt)?;
            let acceptance = pool
                .attempt(required, |a, base, delta| {
                    self.state.check_burn(&a).map_err(io_error)?;
                    if delta.is_some() {
                        return Err(io_error("prover received verifier state".into()));
                    }
                    let p = &self.state.profiles[self.state.next_slot];
                    let s = p.context(
                        &self.state.weight,
                        &snapshot.source.root,
                        &snapshot.tokens,
                        attempt,
                        &wg,
                        &ag,
                    );
                    let header = self
                        .state
                        .header(&snapshot.source.root, snapshot.tokens, nonce, required)
                        .map_err(io_error)?;
                    self.state.next_slot += 1;
                    self.state.cursor += 3 * required;
                    let mut rows = auths(&base).map_err(io_error)?;
                    let (certificate, receipt) = prove_schedule(
                        &self.state,
                        p,
                        &self.model,
                        &snapshot,
                        &self.accepted,
                        &s,
                        &header,
                        &mut rows,
                    )
                    .map_err(io_error)?;
                    let response = Response {
                        root: snapshot.source.root.clone(),
                        tokens: snapshot.tokens,
                        nonce,
                        certificate,
                    };
                    self.pending = Some((snapshot, receipt));
                    let acceptance = verify(&response).map_err(io_error)?;
                    self.check_acceptance(&acceptance).map_err(io_error)?;
                    Ok((acceptance, Some(receipt)))
                })
                .map_err(|e| e.to_string())?;
            self.promote(acceptance)
        }))
        .map_err(|_| "Stop".to_string())
        .and_then(|r| r);
        if result.is_err() {
            pool.stop();
            self.stop();
        }
        result.map_err(stop)
    }
}

impl Verifier {
    fn from_pool(weight: C61Commitment, pool: &Pool<'_, [u64; 3]>) -> Result<Self, String> {
        let state = State::from_pool(weight, pool.fixed_run_context().map_err(|e| e.to_string())?)?;
        Ok(Self {
            state,
            #[cfg(test)]
            delta: Fp3::ZERO,
            #[cfg(test)]
            keys: Vec::new().into_iter(),
        })
    }
    fn verify_with_pool(
        &mut self,
        prompt: u32,
        response: &Response,
        pool: &mut Pool<'_, [u64; 3]>,
    ) -> Result<Acceptance, String> {
        if !self.state.live {
            pool.stop();
            return Err("Stop".into());
        }
        self.state.live = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.state.check_pool(pool.fixed_run_context().map_err(|e| e.to_string())?)?;
            if response.tokens[0] != prompt {
                return Err("prompt prefix differs".into());
            }
            let slot = self.state.next_slot;
            let p = &self.state.profiles[slot];
            let (wg, ag) = (gamma(&DOMAIN_W.config()?), gamma(&DOMAIN_A.config()?));
            let s = p.context(
                &self.state.weight,
                &response.root,
                &response.tokens,
                self.state.attempt(response.nonce),
                &wg,
                &ag,
            );
            let required = p.required(&s)?;
            let header =
                self.state.header(&response.root, response.tokens, response.nonce, required)?;
            let acceptance = pool
                .attempt(required, |a, base, delta| {
                    self.state.check_burn(&a).map_err(io_error)?;
                    let p = &self.state.profiles[slot];
                    let s = p.context(
                        &self.state.weight,
                        &response.root,
                        &response.tokens,
                        self.state.attempt(response.nonce),
                        &wg,
                        &ag,
                    );
                    self.state.next_slot += 1;
                    self.state.cursor += 3 * required;
                    let (delta, mut rows) = keys(&base, delta).map_err(io_error)?;
                    let receipt = verify_schedule(
                        &self.state,
                        p,
                        &s,
                        &header,
                        &response.certificate,
                        delta,
                        &mut rows,
                    )
                    .map_err(io_error)?;
                    Ok((
                        Acceptance {
                            root: response.root.clone(),
                            tokens: response.tokens,
                            receipt,
                            session: self.state.session,
                            epoch: self.state.epoch,
                            slot,
                        },
                        Some(receipt),
                    ))
                })
                .map_err(|e| e.to_string())?;
            self.state.promote(acceptance.root.clone(), acceptance.tokens, acceptance.receipt);
            Ok(acceptance)
        }))
        .map_err(|_| "Stop".to_string())
        .and_then(|r| r);
        if result.is_err() {
            pool.stop();
        }
        result.map_err(stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_native_pool_packing_and_registry_bind_every_base_row() {
        let d = field([2, 3, 5]).unwrap();
        let base = [[7, 11, 13, 17], [19, 23, 29, 31], [37, 41, 43, 47]];
        let key_base: Vec<_> = base
            .iter()
            .map(|r| {
                let k = field([r[1], r[2], r[3]]).unwrap() - d * field([r[0], 0, 0]).unwrap();
                let b = k.to_bytes();
                std::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()))
            })
            .collect();
        let a = auths(&base).unwrap().next().unwrap();
        let (native, mut k) = keys(&key_base, Some(&[2, 3, 5])).unwrap();
        assert_eq!(native, Fp3::ZERO - d);
        assert_eq!(k.next().unwrap().k, a.m + native * a.x);
        assert!(auths(&base[..2]).is_err());
        assert!(keys(&key_base, None).is_err());
        let mut bad = base;
        bad[2][3] = volta_field::P;
        assert!(auths(&bad).is_err());
        let state = State::new(C61Commitment::new(vec![[1; 32]]), [2; 32], 1, [3; 32]).unwrap();
        for fault in 0..9 {
            let mut model = state.binding();
            let mut session = state.session;
            let mut attempt = Attempt {
                capacity: state.seal,
                setup: 1,
                ordinal: 1,
                predecessor: [0; 32],
                first_base_row: 0,
            };
            match fault {
                0 => {}
                1 => model.root[0] ^= 1,
                2 => model.semantics[0] ^= 1,
                3 => session[0] ^= 1,
                4 => attempt.capacity[0] ^= 1,
                5 => attempt.setup += 1,
                6 => attempt.ordinal += 1,
                7 => attempt.predecessor[0] ^= 1,
                8 => attempt.first_base_row += 3,
                _ => unreachable!(),
            }
            assert_eq!(state.check_pool((model, session, attempt)).is_ok(), fault == 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn c71_b12_native_pool_real_shortage_stops_both_roles_before_prepare_or_decode() {
        use volta_pcg::c71_lifetime::Lifetime;
        let p = Profile::small(0).unwrap();
        let model = Installed::new(&p, super::super::tests::weights(&p)).unwrap();
        let root = model.model.root.clone();
        let binding =
            ModelBinding { anchor: root.roots()[0], root: root.roots()[0], semantics: p.digest };
        let dir = std::env::temp_dir().join(format!(
            "c71-native-pool-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let (pp, vp) = (dir.join("prover"), dir.join("verifier"));
        let (pc, vc) = std::os::unix::net::UnixStream::pair().unwrap();
        for c in [&pc, &vc] {
            c.set_read_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
            c.set_write_timeout(Some(std::time::Duration::from_secs(40))).unwrap();
        }
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut store = Lifetime::install(&pp, binding).unwrap();
                {
                    let mut pool = store.prover_fixed_run(pc, [2; 32], [3; 32], 3).unwrap();
                    assert_eq!(pool.remaining_fp3(), 1);
                    let mut prover = Prover::from_pool(model, &pool).unwrap();
                    assert!(prover
                        .respond_with_pool(0, [4; 32], &mut pool, |_| panic!(
                            "capacity shortage emitted a certificate"
                        ))
                        .is_err());
                    assert_eq!(prover.state.cursor, 0);
                    assert!(prover.pending.is_none() && prover.accepted.is_empty());
                    assert!(pool.fixed_run_context().is_err());
                    assert_eq!(pool.remaining_fp3(), 0);
                    assert!(pool
                        .attempt::<()>(1, |_, _, _| panic!("stopped native pool reused"))
                        .is_err());
                }
                assert_eq!(store.counters(), (1, 0));
                assert_eq!(store.accepted_head(), [0; 32]);
            });
            let mut store = Lifetime::install(&vp, binding).unwrap();
            {
                let mut pool = store.verifier_fixed_run(vc, [2; 32], [3; 32], 3).unwrap();
                assert!(Verifier::from_pool(C61Commitment::new(vec![[99; 32]]), &pool).is_err());
                let mut verifier = Verifier::from_pool(root, &pool).unwrap();
                let response = Response {
                    root: C61Commitment::new(vec![[98; 32]]),
                    tokens: [0, 0],
                    nonce: [4; 32],
                    certificate: Vec::new(),
                };
                assert!(verifier.verify_with_pool(0, &response, &mut pool).is_err());
                assert!(!verifier.state.live && verifier.state.accepted.is_empty());
                assert_eq!(verifier.state.cursor, 0);
                assert!(pool.fixed_run_context().is_err());
                assert!(pool
                    .attempt::<()>(1, |_, _, _| panic!("stopped verifier pool reused"))
                    .is_err());
            }
            assert_eq!(store.counters(), (1, 0));
            assert_eq!(store.accepted_head(), [0; 32]);
        });
        for path in [pp, vp] {
            assert!(Lifetime::open(&path, binding).is_err());
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
    }
}
