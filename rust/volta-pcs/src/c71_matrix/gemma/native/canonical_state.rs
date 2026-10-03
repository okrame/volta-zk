//! Internal canonical acceptance machine, conditional on valid public tables.
//! No public admission API: numerical certification, positive composition and
//! complete transport sizing remain prerequisites for the canonical runner.
use super::super::protocol::{
    acceptance_transport,
    pool::{ProverCapacity, VerifierCapacity},
    SourceModel,
};
use super::*;
use std::io;
use std::sync::Arc;
use volta_pcg::c71_lifetime::{Attempt, ModelBinding};

#[cfg(all(unix, feature = "c71-seed6-reference"))]
#[path = "canonical_runner.rs"]
pub(in crate::c71_matrix) mod runner;

pub(super) struct Public<'a> {
    pub(super) profiles: Vec<Arc<Canonical>>,
    pub(super) tables: [profile::Tables<'a>; 3],
    digest: [u8; 32],
    pub(super) required: [usize; 3],
    wg: Vec<u8>,
    ag: Vec<u8>,
}

impl<'a> Public<'a> {
    pub(super) fn compile(
        weights: &[i32],
        exponents: &BTreeMap<usize, i32>,
        tables: [profile::Tables<'a>; 3],
    ) -> Result<Self, String> {
        let profiles = (0..3)
            .map(|slot| Canonical::compile(slot, weights, exponents))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_profiles(profiles, tables)
    }

    pub(super) fn from_profiles(
        profiles: Vec<Canonical>,
        tables: [profile::Tables<'a>; 3],
    ) -> Result<Self, String> {
        Self::from_shared(profiles.into_iter().map(Arc::new).collect(), tables)
    }

    fn from_shared(
        profiles: Vec<Arc<Canonical>>,
        tables: [profile::Tables<'a>; 3],
    ) -> Result<Self, String> {
        if profiles.len() != 3
            || profiles
                .iter()
                .enumerate()
                .any(|(slot, profile)| profile.sources.attention.rope.old != slot * 150)
        {
            return Err("canonical fixed-run profile order differs".into());
        }
        let mut public = Self {
            profiles,
            tables,
            digest: [0; 32],
            required: [0; 3],
            wg: gamma(&Domain::Flat(35).config()?),
            ag: gamma(&Domain::Flat(34).config()?),
        };
        let root = C61Commitment::new(vec![[1; 32]]);
        // Full body identity, not numerical certification. Hash incrementally.
        let mut h = blake3::Hasher::new();
        h.update(b"C71B12-Gemma-public-v1\0");
        h.update(&(kernel::wire::CANONICAL_MAX_BYTES as u64).to_le_bytes());
        let mut common = None;
        for slot in 0..3 {
            let p = &public.profiles[slot];
            let t = &public.tables[slot];
            let s = public.statement(
                slot,
                &root,
                &root,
                &[0; 150],
                AttemptContext {
                    session: [2; 32],
                    capacity: [3; 32],
                    slot: slot as u8,
                    predecessor: if slot == 0 { [0; 32] } else { [4; 32] },
                    nonce: [5; 32],
                },
            );
            public.required[slot] =
                p.recipes.required(&p.plan, &p.sources, &p.output, &p.softmax, &s, t)?;
            let mut tables_hash = blake3::Hasher::new();
            for family in [t.gelu, t.exp30, std::slice::from_ref(t.softcap)] {
                tables_hash.update(&(family.len() as u64).to_le_bytes());
                for table in family {
                    tables_hash.update(&[table.profile]);
                    tables_hash.update(&table.lower.to_le_bytes());
                    tables_hash.update(&(table.outputs.len() as u64).to_le_bytes());
                    match table.outputs {
                        lookup::Outputs::I16(v) => {
                            tables_hash.update(&[2]);
                            for x in v {
                                tables_hash.update(&x.to_le_bytes());
                            }
                        }
                        lookup::Outputs::I32(v) => {
                            tables_hash.update(&[4]);
                            for x in v {
                                tables_hash.update(&x.to_le_bytes());
                            }
                        }
                    }
                }
            }
            let identity = (p.recipes.digest, *tables_hash.finalize().as_bytes());
            if common.is_some_and(|expected| expected != identity) {
                return Err("canonical common tables/recipes changed across slots".into());
            }
            common = Some(identity);
            h.update(&(slot as u64).to_le_bytes());
            h.update(&p.plan.layout_digest);
            h.update(&p.bytes().layout_digest);
            h.update(&identity.0);
            h.update(&identity.1);
            h.update(&(t.rope.len() as u64).to_le_bytes());
            for table in t.rope {
                h.update(&(table.position as u64).to_le_bytes());
                h.update(&(table.rows.len() as u64).to_le_bytes());
                for row in table.rows {
                    h.update(&(row.len() as u64).to_le_bytes());
                    for pair in row {
                        for x in pair {
                            h.update(&x.to_le_bytes());
                        }
                    }
                }
            }
            h.update(&(public.required[slot] as u64).to_le_bytes());
        }
        public.digest = *h.finalize().as_bytes();
        Ok(public)
    }

    fn binding(&self, weight: &C61Commitment) -> Result<ModelBinding, String> {
        if weight.num_roots() != 1 || weight.roots()[0] == [0; 32] {
            return Err("canonical installation needs one nonzero W root".into());
        }
        Ok(ModelBinding {
            anchor: weight.roots()[0],
            root: weight.roots()[0],
            semantics: self.digest,
        })
    }

    pub(super) fn statement<'s>(
        &'s self,
        slot: usize,
        weight: &'s C61Commitment,
        root: &'s C61Commitment,
        tokens: &'s [u32; 150],
        attempt: AttemptContext,
    ) -> caller::P0Statement<'s> {
        caller::P0Statement {
            weights: weight,
            auxiliary: root,
            weight_gamma: &self.wg,
            auxiliary_gamma: &self.ag,
            auxiliary_layout: &self.profiles[slot].bytes().scalar,
            quantization: self.profiles[slot].recipes.digest,
            tokens,
            attempt,
        }
    }
}

struct Response {
    root: C61Commitment,
    tokens: [u32; 150],
    nonce: [u8; 32],
    certificate: Vec<u8>,
}

struct Acceptance {
    root: C61Commitment,
    tokens: [u32; 150],
    receipt: [u8; 32],
}

struct Registry<'a> {
    public: Public<'a>,
    weight: C61Commitment,
    session: [u8; 32],
    seal: [u8; 32],
    cursor: usize,
    next_slot: usize,
    accepted: Vec<Acceptance>,
    live: bool,
}

type Verifier<'a> = Registry<'a>;

impl<'a> Registry<'a> {
    fn new(
        public: Public<'a>,
        weight: C61Commitment,
        pool: &VerifierCapacity<'_, '_>,
    ) -> Result<Self, String> {
        Self::from_context(public, weight, pool.fixed_run_context().map_err(|e| e.to_string())?)
    }

    fn from_context(
        public: Public<'a>,
        weight: C61Commitment,
        context: (ModelBinding, [u8; 32], Attempt),
    ) -> Result<Self, String> {
        let v = Self {
            public,
            weight,
            session: context.1,
            seal: context.2.capacity,
            cursor: 0,
            next_slot: 0,
            accepted: Vec::new(),
            live: true,
        };
        v.check_pool(context)?;
        Ok(v)
    }

    fn check_pool(
        &self,
        (model, session, a): (ModelBinding, [u8; 32], Attempt),
    ) -> Result<(), String> {
        if model != self.public.binding(&self.weight)?
            || session != self.session
            || session == [0; 32]
        {
            return Err("canonical installed pool context differs".into());
        }
        self.check_burn(&a)
    }

    fn check_burn(&self, a: &Attempt) -> Result<(), String> {
        if self.next_slot != self.accepted.len()
            || self.next_slot >= 3
            || self.seal == [0; 32]
            || a.capacity != self.seal
            || a.setup != 1
            || a.ordinal != self.next_slot as u64 + 1
            || a.first_base_row != self.cursor as u64
            || a.predecessor != self.accepted.last().map_or([0; 32], |a| a.receipt)
        {
            return Err("canonical pool reservation differs from accepted registry".into());
        }
        Ok(())
    }

    fn attempt(&self, nonce: [u8; 32]) -> AttemptContext {
        AttemptContext {
            session: self.session,
            capacity: self.seal,
            slot: self.next_slot as u8,
            predecessor: self.accepted.last().map_or([0; 32], |a| a.receipt),
            nonce,
        }
    }

    fn header(&self, prompt: &[u32], r: &Response) -> Result<Vec<u8>, String> {
        if self.next_slot != self.accepted.len()
            || self.next_slot >= 3
            || prompt.len() != 100
            || r.tokens[..100] != *prompt
            || r.tokens.iter().any(|&t| t >= 262144)
            || r.nonce == [0; 32]
            || r.root.num_roots() != 1
            || r.root == self.weight
            || self.accepted.iter().any(|a| a.root == r.root)
        {
            return Err("canonical response context differs".into());
        }
        let mut h = b"C71B12-Gemma-FixedRun-v1\0".to_vec();
        h.extend(self.public.digest);
        h.extend(self.weight.roots()[0]);
        h.extend(self.session);
        h.extend(1u64.to_le_bytes());
        h.extend(self.seal);
        for n in [
            self.next_slot,
            self.cursor,
            3 * self.public.required[self.next_slot],
            self.accepted.len(),
        ] {
            h.extend((n as u64).to_le_bytes());
        }
        for (slot, a) in self.accepted.iter().enumerate() {
            h.extend((slot as u64).to_le_bytes());
            h.extend((150 * slot as u64).to_le_bytes());
            h.extend(a.root.roots()[0]);
            h.extend(self.public.profiles[slot].bytes().layout_digest);
            h.extend(150u64.to_le_bytes());
            for token in a.tokens {
                h.extend(token.to_le_bytes());
            }
            h.extend(a.receipt);
        }
        h.extend(r.root.roots()[0]);
        h.extend(self.public.profiles[self.next_slot].bytes().layout_digest);
        h.extend(r.nonce);
        for g in [&self.public.wg, &self.public.ag] {
            h.extend((g.len() as u64).to_le_bytes());
            h.extend(g);
        }
        for tokens in [prompt, &r.tokens] {
            h.extend((tokens.len() as u64).to_le_bytes());
            for token in tokens {
                h.extend(token.to_le_bytes());
            }
        }
        Ok(h)
    }

    fn verify_response(
        &mut self,
        prompt: &[u32],
        r: &Response,
        pool: &mut VerifierCapacity<'_, '_>,
    ) -> Result<(), String> {
        if !self.live {
            pool.stop();
            return Err("Stop".into());
        }
        self.live = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_pool(pool.fixed_run_context().map_err(|e| e.to_string())?)?;
            let header = self.header(prompt, r)?;
            let slot = self.next_slot;
            let attempt = self.attempt(r.nonce);
            let required = self.public.required[slot];
            let acceptance = pool
                .attempt(required, |a, mut rows, delta| {
                    let error = |e| io::Error::new(io::ErrorKind::InvalidData, e);
                    self.check_burn(&a).map_err(error)?;
                    self.cursor += 3 * required;
                    self.next_slot += 1;
                    let s = self.public.statement(slot, &self.weight, &r.root, &r.tokens, attempt);
                    let parts: Vec<_> = self
                        .accepted
                        .iter()
                        .enumerate()
                        .map(|(i, a)| kv::Segment {
                            root: &a.root,
                            profile: &self.public.ag,
                            bytes: self.public.profiles[i].bytes(),
                            model: self.weight.roots()[0],
                            quantization: s.quantization,
                            tokens: 150,
                            receipt: a.receipt,
                        })
                        .chain([kv::Segment {
                            root: &r.root,
                            profile: &self.public.ag,
                            bytes: self.public.profiles[slot].bytes(),
                            model: self.weight.roots()[0],
                            quantization: s.quantization,
                            tokens: 150,
                            receipt: [0; 32],
                        }])
                        .collect();
                    // Security §6's caller envelope is an operational stop here;
                    // this does not establish a native draw bound or runtime credit.
                    let mut fs = Fs::new(&header, 1usize << 42);
                    let receipt = self.public.profiles[slot]
                        .verify_body(
                            &s,
                            &self.public.tables[slot],
                            &parts,
                            &header,
                            &r.certificate,
                            delta,
                            &mut fs,
                            &mut rows,
                        )
                        .map_err(error)?;
                    Ok((
                        Acceptance { root: r.root.clone(), tokens: r.tokens, receipt },
                        Some(receipt),
                    ))
                })
                .map_err(|e| e.to_string())?;
            // Pool::attempt syncs the success journal before returning. This is
            // the only promotion path; no history/receipt is imported from P.
            self.accepted.push(acceptance);
            self.live = self.next_slot < 3;
            Ok::<_, String>(())
        }))
        .map_err(|_| "Stop".to_string())
        .and_then(|r| r);
        if result.is_err() {
            pool.stop();
        }
        result.map_err(|_| "Stop".into())
    }

    /// The caller authenticates and dedicates the transport to this session.
    /// Completion is emitted only after the verifier's durable acceptance.
    fn verify_authenticated(
        &mut self,
        prompt: &[u32],
        r: &Response,
        pool: &mut VerifierCapacity<'_, '_>,
        channel: &mut impl io::Write,
    ) -> Result<(), String> {
        let result = self.verify_response(prompt, r, pool);
        let completion = result.as_ref().ok().map(|_| {
            (*blake3::hash(&r.certificate).as_bytes(), self.accepted.last().unwrap().receipt)
        });
        if acceptance_transport::send(channel, completion).is_err() {
            self.live = false;
            pool.stop();
            return Err("Stop".into());
        }
        result
    }
}

/// Internal CPU composition. This is not GPU admission or a numerical
/// certificate. The dense component kernels still need a bounded device plan.
struct Prover<'a> {
    state: Registry<'a>,
    weights: Arc<Vec<i16>>,
    weight: b12::replay::ReplayModel,
    tables: Arc<calibration_input::Tables>,
    cache: Arc<ordered::Cache>,
    accepted: Vec<(Arc<ordered::Prepared>, b12::replay::ReplayModel)>,
    preparation_limit: usize,
}

impl<'a> Prover<'a> {
    fn new(
        public: Public<'a>,
        weights: Arc<Vec<i16>>,
        weight: b12::replay::ReplayModel,
        tables: Arc<calibration_input::Tables>,
        preparation_limit: usize,
        pool: &ProverCapacity<'_, '_>,
    ) -> Result<Self, String> {
        if weight.domain() != Domain::Flat(35)
            || weights.len()
                != public.profiles[0].plan.sources.iter().map(|s| s.rows * s.cols).sum::<usize>()
        {
            return Err("canonical W installation differs".into());
        }
        let identity = tables.with_slot(0, |t0| {
            tables.with_slot(1, |t1| {
                tables.with_slot(2, |t2| {
                    Public::from_shared(public.profiles.clone(), [*t0, *t1, *t2]).map(|p| p.digest)
                })
            })
        })????;
        if identity != public.digest {
            return Err("preparer public table identity differs".into());
        }
        let state = Registry::from_context(
            public,
            weight.root().clone(),
            pool.fixed_run_context().map_err(|e| e.to_string())?,
        )?;
        Ok(Self {
            state,
            weights,
            weight,
            tables,
            cache: Arc::default(),
            accepted: Vec::new(),
            preparation_limit,
        })
    }

    fn respond_authenticated(
        &mut self,
        prompt: &[u32; 100],
        nonce: [u8; 32],
        pool: &mut ProverCapacity<'_, '_>,
        exchange: impl FnOnce(&Response) -> Result<Vec<u8>, String>,
    ) -> Result<(), String> {
        if !self.state.live {
            pool.stop();
            return Err("Stop".into());
        }
        self.state.live = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.state.check_pool(pool.fixed_run_context().map_err(|e| e.to_string())?)?;
            let slot = self.state.next_slot;
            let required = self.state.public.required[slot];
            if nonce == [0; 32] || pool.remaining_fp3() < required {
                return Err("invalid nonce or capacity before preparation".into());
            }
            let p = self.state.public.profiles[slot].clone();
            let old: Vec<_> = self.accepted.iter().map(|(a, _)| a.clone()).collect();
            // Prepare receives no transcript, correlations, Delta or PCS coins.
            let snapshot = ordered::Prepared::prepare(
                p.clone(),
                self.tables.clone(),
                self.weights.clone(),
                &old,
                prompt,
                self.cache.clone(),
                self.preparation_limit,
            )?;
            let getter = snapshot.clone();
            let coins = fresh_pcs_coins()?;
            let current = b12::replay::ReplayModel::new(
                Domain::Flat(34),
                coins.seed,
                coins.salt_seed,
                Arc::new(move |i| {
                    E::from(Goldilocks::from_u64(u64::from(
                        getter.byte_at(i).expect("immutable canonical A"),
                    )))
                }),
                p.bytes().live,
            )?
            .retain_first_fold();
            let mut response = Response {
                root: current.root().clone(),
                tokens: snapshot.tokens(),
                nonce,
                certificate: Vec::new(),
            };
            let header = self.state.header(prompt, &response)?;
            let attempt = self.state.attempt(nonce);
            let acceptance = pool
                .attempt(required, |a, mut rows| {
                    let error = |e| io::Error::new(io::ErrorKind::InvalidData, e);
                    self.state.check_burn(&a).map_err(error)?;
                    self.state.cursor += 3 * required;
                    self.state.next_slot += 1;
                    let s = self.state.public.statement(
                        slot,
                        &self.state.weight,
                        &response.root,
                        &response.tokens,
                        attempt,
                    );
                    let parts: Vec<_> = self
                        .state
                        .accepted
                        .iter()
                        .enumerate()
                        .map(|(i, a)| kv::Segment {
                            root: &a.root,
                            profile: &self.state.public.ag,
                            bytes: self.state.public.profiles[i].bytes(),
                            model: self.state.weight.roots()[0],
                            quantization: s.quantization,
                            tokens: 150,
                            receipt: a.receipt,
                        })
                        .chain([kv::Segment {
                            root: &response.root,
                            profile: &self.state.public.ag,
                            bytes: p.bytes(),
                            model: self.state.weight.roots()[0],
                            quantization: s.quantization,
                            tokens: 150,
                            receipt: [0; 32],
                        }])
                        .collect();
                    let previous: Vec<_> =
                        self.accepted.iter().map(|(_, m)| SourceModel::Replay(m)).collect();
                    let mut fs = Fs::new(&header, 1usize << 42);
                    let (certificate, receipt) = p
                        .prove_body(
                            &s,
                            &self.state.public.tables[slot],
                            &parts,
                            &header,
                            SourceModel::Replay(&self.weight),
                            SourceModel::Replay(&current),
                            &previous,
                            |points| {
                                points
                                    .iter()
                                    .enumerate()
                                    .map(|(i, point)| {
                                        p.bytes().scalar.compact(
                                            &p.plan,
                                            i,
                                            point,
                                            |id, r, c| {
                                                snapshot
                                                    .weight(id, r, c)
                                                    .expect("immutable canonical W")
                                            },
                                            |id, r, c| {
                                                snapshot
                                                    .value(id, r, c)
                                                    .expect("immutable canonical A")
                                            },
                                        )
                                    })
                                    .collect()
                            },
                            |id, r, c, b| {
                                snapshot.byte(id, r, c, b).expect("immutable canonical A byte")
                            },
                            |id, r, c| {
                                snapshot.tail(id, r, c).expect("original canonical KV") as i16
                            },
                            &mut fs,
                            &mut rows,
                        )
                        .map_err(error)?;
                    response.certificate = certificate;
                    let completion = exchange(&response).map_err(error)?;
                    if completion.len() != acceptance_transport::BYTES {
                        return Err(error("completion length differs".to_string()));
                    }
                    acceptance_transport::receive(
                        &mut &completion[..],
                        *blake3::hash(&response.certificate).as_bytes(),
                        receipt,
                    )?;
                    Ok((
                        Acceptance {
                            root: response.root.clone(),
                            tokens: response.tokens,
                            receipt,
                        },
                        Some(receipt),
                    ))
                })
                .map_err(|e| e.to_string())?;
            // Durable success on both sides precedes promotion of numerical KV.
            self.state.accepted.push(acceptance);
            self.accepted.push((snapshot, current));
            self.state.live = self.state.next_slot < 3;
            Ok::<_, String>(())
        }))
        .map_err(|_| "Stop".to_string())
        .and_then(|r| r);
        if result.is_err() {
            pool.stop();
        }
        result.map_err(|_| "Stop".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_pcg::c71_lifetime::Lifetime;

    fn reject_shortage(
        public: Public<'_>,
        weight: C61Commitment,
        response: &Response,
        pool: &mut VerifierCapacity<'_, '_>,
    ) {
        let mut verifier = Verifier::new(public, weight, pool).unwrap();
        assert_eq!(verifier.verify_response(&[0; 100], response, pool), Err("Stop".into()));
        assert!(!verifier.live && verifier.accepted.is_empty());
        assert_eq!((verifier.next_slot, verifier.cursor), (0, 0));
        assert!(pool.fixed_run_context().is_err());
        assert!(pool.attempt::<()>(1, |_, _, _| panic!("reused stopped pool")).is_err());
        assert_eq!(verifier.verify_response(&[0; 100], response, pool), Err("Stop".into()));
    }

    #[test]
    fn c71_b12_native_registry_header_and_real_shortage_are_terminal() {
        let plan = crate::c71_matrix::gemma::compile().unwrap();
        let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
        let mut exponents: BTreeMap<_, _> =
            profile::Recipes::exponent_sources(&s, &o, &sm).into_iter().map(|id| (id, 0)).collect();
        for l in &sm.layers {
            exponents.insert(l.pi, -14);
            exponents.insert(l.score, 128);
        }
        // Public shape fixture only: no numerical profile or positive proof credit.
        let zeros = vec![0; 65535];
        let mut exp = vec![0; 65535];
        exp[0] = 1 << 30;
        let gelu: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I16(&zeros),
            })
            .collect();
        let exp30: Vec<_> = (0..60)
            .map(|profile| lookup::Table {
                profile,
                lower: -32767,
                outputs: lookup::Outputs::I32(&exp),
            })
            .collect();
        let cap =
            lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I16(&zeros) };
        let local = vec![vec![[1 << 30, 0]; 128]; 150];
        let global = vec![vec![[1 << 30, 0]; 64]; 150];
        let rope: [_; 3] = std::array::from_fn(|slot| {
            [
                kernel::rope::Table { position: 150 * slot, rows: &local },
                kernel::rope::Table { position: 150 * slot, rows: &global },
            ]
        });
        let tables = || {
            std::array::from_fn(|slot| profile::Tables {
                gelu: &gelu,
                exp30: &exp30,
                softcap: &cap,
                rope: &rope[slot],
            })
        };
        let public = Public::compile(&[0; 772], &exponents, tables()).unwrap();
        assert_ne!(public.digest, public.profiles[0].recipes.digest);
        assert!(public.required.windows(2).all(|r| r[0] < r[1]));
        let mut changed_values = zeros.clone();
        changed_values[123] = 1;
        let changed_cap = lookup::Table {
            profile: 0,
            lower: -32767,
            outputs: lookup::Outputs::I16(&changed_values),
        };
        let mut changed = tables();
        for t in &mut changed {
            t.softcap = &changed_cap;
        }
        let changed_public = Public::compile(&[0; 772], &exponents, changed).unwrap();
        assert_ne!(public.digest, changed_public.digest);
        assert_eq!(public.required, changed_public.required);
        let mut mixed = tables();
        mixed[1].softcap = &changed_cap;
        assert!(Public::compile(&[0; 772], &exponents, mixed).is_err());
        let weight = C61Commitment::new(vec![[1; 32]]);
        let binding = public.binding(&weight).unwrap();
        let mut v = Verifier {
            public,
            weight,
            session: [2; 32],
            seal: [3; 32],
            cursor: 0,
            next_slot: 0,
            accepted: Vec::new(),
            live: true,
        };
        let mut r = Response {
            root: C61Commitment::new(vec![[4; 32]]),
            tokens: [0; 150],
            nonce: [5; 32],
            certificate: Vec::new(),
        };
        let header = v.header(&[0; 100], &r).unwrap();
        assert!(header.starts_with(b"C71B12-Gemma-FixedRun-v1\0"));
        for fault in 0..10 {
            let mut model = binding;
            let mut session = v.session;
            let mut a = Attempt {
                capacity: v.seal,
                setup: 1,
                ordinal: 1,
                predecessor: [0; 32],
                first_base_row: 0,
            };
            match fault {
                0 => {}
                1 => model.anchor[0] ^= 1,
                2 => model.root[0] ^= 1,
                3 => model.semantics[0] ^= 1,
                4 => session[0] ^= 1,
                5 => a.capacity[0] ^= 1,
                6 => a.setup += 1,
                7 => a.ordinal += 1,
                8 => a.predecessor[0] ^= 1,
                _ => a.first_base_row += 3,
            }
            assert_eq!(v.check_pool((model, session, a)).is_ok(), fault == 0);
        }
        assert!(v.header(&[0; 99], &r).is_err());
        r.tokens[99] = 1;
        assert!(v.header(&[0; 100], &r).is_err());
        r.tokens[99] = 0;
        r.tokens[149] = 262144;
        assert!(v.header(&[0; 100], &r).is_err());
        r.tokens[149] = 1;
        assert_ne!(header, v.header(&[0; 100], &r).unwrap());
        r.tokens[149] = 0;
        r.nonce = [0; 32];
        assert!(v.header(&[0; 100], &r).is_err());
        r.nonce = [5; 32];
        // Synthetic history tests header binding only, never acceptance evidence.
        v.accepted.push(Acceptance { root: r.root.clone(), tokens: r.tokens, receipt: [6; 32] });
        v.next_slot = 1;
        v.cursor = 3 * v.public.required[0];
        assert!(v.header(&[0; 100], &r).is_err());
        r.root = C61Commitment::new(vec![[7; 32]]);
        let old = v.header(&[0; 100], &r).unwrap();
        v.accepted[0].tokens[149] = 1;
        assert_ne!(old, v.header(&[0; 100], &r).unwrap());
        v.accepted[0].tokens[149] = 0;
        v.accepted[0].receipt[0] ^= 1;
        assert_ne!(old, v.header(&[0; 100], &r).unwrap());
        #[cfg(feature = "c71-seed6-reference")]
        {
            let (_, _, counters, head) = super::super::super::protocol::pool::seed6_tests::pair(
                volta_pcg::c71_seed6::Geometry::new(2, 4, 2).unwrap(),
                binding,
                |_| (),
                |pool| {
                    reject_shortage(
                        Public::compile(&[0; 772], &exponents, tables()).unwrap(),
                        v.weight.clone(),
                        &r,
                        pool,
                    );
                },
            );
            assert_eq!(counters, (1, 0));
            assert_eq!(head, [0; 32]);
            println!("C71_CANONICAL_SEED6 shortage_before_decode=true canonical_acceptance=false");
        }
        // Fresh real pool; never import the diagnostic history above.
        let dir = std::env::temp_dir().join(format!(
            "c71-canonical-registry-{}-{}",
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
                let mut pool = store.prover_fixed_run(pc, [2; 32], [3; 32], 3).unwrap();
                pool.stop();
            });
            let mut store = Lifetime::install(&vp, binding).unwrap();
            {
                let mut pool = store.verifier_fixed_run(vc, [2; 32], [3; 32], 3).unwrap();
                reject_shortage(v.public, v.weight, &r, &mut VerifierCapacity::Dense(&mut pool));
                assert_eq!(pool.remaining_fp3(), 0);
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
