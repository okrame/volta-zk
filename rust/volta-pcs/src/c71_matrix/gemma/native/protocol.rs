//! One mandatory schedule, one FS, original endpoint batches, terminal failures.
use super::*;
use kernel::wire::{self, Wire};
use prepare::{Installed, Snapshot};
use std::sync::Arc;

#[path = "acceptance_transport.rs"]
pub(super) mod acceptance_transport;
#[path = "pool.rs"]
pub(super) mod pool;

#[cfg(test)]
#[path = "joint_inference.rs"]
mod joint_inference;
#[cfg(test)]
#[path = "joint_state.rs"]
mod joint_state;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

const MAGIC: &[u8] = b"C71B12-Gemma-FixedRun-v1/native-small-v1\0";
const END: &[u8] = b"C71B12-complete\0";

pub(super) struct Batch<T> {
    pub(super) forms: Vec<Vec<Cube>>,
    pub(super) targets: Vec<T>,
}
impl<T: Copy> Batch<T> {
    pub(super) fn new() -> Self {
        Self { forms: Vec::new(), targets: Vec::new() }
    }
    pub(super) fn add(&mut self, form: Vec<Cube>, target: T) {
        self.forms.push(form);
        self.targets.push(target);
    }
    pub(super) fn extend(
        &mut self,
        forms: Vec<Vec<Cube>>,
        bias: Vec<Fp3>,
        targets: Vec<T>,
        shift: impl Fn(T, Fp3) -> T,
    ) -> Result<(), String> {
        if forms.len() != bias.len() || forms.len() != targets.len() {
            return Err("original endpoint cardinality differs".into());
        }
        for ((f, b), t) in forms.into_iter().zip(bias).zip(targets) {
            self.add(f, shift(t, b));
        }
        Ok(())
    }
}
fn ashift(a: Auth, b: Fp3) -> Auth {
    Auth::new(a.x + b, a.m)
}

pub(super) struct Writer {
    bytes: Vec<u8>,
    count: u16,
    limit: usize,
}
impl Writer {
    fn new(header: &[u8]) -> Self {
        Self { bytes: header.to_vec(), count: 0, limit: wire::MAX_BYTES }
    }
    pub(super) fn canonical(header: &[u8]) -> Self {
        Self { bytes: header.to_vec(), count: 0, limit: wire::CANONICAL_MAX_BYTES }
    }
    pub(super) fn raw(&mut self, kind: u16, body: &[u8], fs: &mut Fs) -> Result<(), String> {
        if kind != self.count || self.bytes.len() + body.len() + 6 + END.len() + 10 > self.limit {
            return Err("composed certificate size/order".into());
        }
        let start = self.bytes.len();
        self.bytes.extend(kind.to_le_bytes());
        self.bytes.extend((body.len() as u32).to_le_bytes());
        self.bytes.extend(body);
        fs.set_phase(0x7f00);
        fs.record(0x7f00, &self.bytes[start..]);
        self.count += 1;
        Ok(())
    }
    pub(super) fn put<P: Wire>(&mut self, kind: u16, proof: &P, fs: &mut Fs) -> Result<(), String> {
        let mut bytes = Vec::new();
        proof.write(&mut bytes);
        self.raw(kind, &bytes, fs)
    }
    pub(super) fn finish(mut self, fs: &mut Fs) -> (Vec<u8>, [u8; 32]) {
        let mut end = END.to_vec();
        end.extend(self.count.to_le_bytes());
        end.extend((self.bytes.len() as u64).to_le_bytes());
        fs.set_phase(0x7fff);
        fs.record(0x7fff, &end);
        self.bytes.extend(end);
        (self.bytes, *fs.digest().as_bytes())
    }
}
pub(super) struct Reader<'a> {
    input: &'a [u8],
    consumed: usize,
    count: u16,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], header: &[u8]) -> Result<Self, String> {
        Self::with_limit(bytes, header, wire::MAX_BYTES)
    }
    pub(super) fn canonical(bytes: &'a [u8], header: &[u8]) -> Result<Self, String> {
        Self::with_limit(bytes, header, wire::CANONICAL_MAX_BYTES)
    }
    fn with_limit(bytes: &'a [u8], header: &[u8], limit: usize) -> Result<Self, String> {
        if bytes.len() > limit || !bytes.starts_with(header) {
            return Err("composed context/header mismatch".into());
        }
        Ok(Self { input: &bytes[header.len()..], consumed: header.len(), count: 0 })
    }
    pub(super) fn raw(&mut self, kind: u16) -> Result<(&'a [u8], &'a [u8]), String> {
        let initial = self.input;
        let encoded = u16::from_le_bytes(wire::take(&mut self.input, 2)?.try_into().unwrap());
        let n = u32::from_le_bytes(wire::take(&mut self.input, 4)?.try_into().unwrap()) as usize;
        if encoded != kind || kind != self.count {
            return Err("composed component order/cardinality mismatch".into());
        }
        let body = wire::take(&mut self.input, n)?;
        self.count += 1;
        self.consumed += n + 6;
        Ok((body, &initial[..n + 6]))
    }
    pub(super) fn get<P: Wire>(&mut self, kind: u16) -> Result<(P, &'a [u8]), String> {
        let (mut body, frame) = self.raw(kind)?;
        let p = P::read(&mut body)?;
        if !body.is_empty() {
            return Err("component trailing bytes".into());
        }
        Ok((p, frame))
    }
    pub(super) fn record(fs: &mut Fs, frame: &[u8]) {
        fs.set_phase(0x7f00);
        fs.record(0x7f00, frame);
    }
    pub(super) fn finish(mut self, fs: &mut Fs) -> Result<[u8; 32], String> {
        let mut end = END.to_vec();
        end.extend(self.count.to_le_bytes());
        end.extend((self.consumed as u64).to_le_bytes());
        if wire::take(&mut self.input, end.len())? != end || !self.input.is_empty() {
            return Err("composed completion framing mismatch".into());
        }
        fs.set_phase(0x7fff);
        fs.record(0x7fff, &end);
        Ok(*fs.digest().as_bytes())
    }
}

struct Accepted {
    root: C61Commitment,
    tokens: [u32; 2],
    receipt: [u8; 32],
}
struct State {
    profiles: Vec<Arc<Profile>>,
    weight: C61Commitment,
    session: [u8; 32],
    epoch: u64,
    seal: [u8; 32],
    cursor: usize,
    next_slot: usize,
    accepted: Vec<Accepted>,
    live: bool,
}
impl State {
    fn new(
        weight: C61Commitment,
        session: [u8; 32],
        epoch: u64,
        seal: [u8; 32],
    ) -> Result<Self, String> {
        if weight.num_roots() != 1 || [session, seal].contains(&[0; 32]) || epoch == 0 {
            return Err("invalid composed installation".into());
        }
        Ok(Self {
            profiles: (0..3)
                .map(|slot| Profile::small(slot).map(Arc::new))
                .collect::<Result<_, _>>()?,
            weight,
            session,
            epoch,
            seal,
            cursor: 0,
            next_slot: 0,
            accepted: Vec::new(),
            live: true,
        })
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
    fn header(
        &self,
        root: &C61Commitment,
        tokens: [u32; 2],
        nonce: [u8; 32],
        required: usize,
    ) -> Result<Vec<u8>, String> {
        if self.next_slot != self.accepted.len()
            || self.next_slot >= 3
            || tokens.iter().any(|&t| t >= 2)
            || nonce == [0; 32]
            || root.num_roots() != 1
            || root == &self.weight
            || self.accepted.iter().any(|a| &a.root == root)
        {
            return Err("invalid composed response context".into());
        }
        let p = &self.profiles[self.next_slot];
        let mut h = MAGIC.to_vec();
        h.extend(p.digest);
        h.extend(self.weight.roots()[0]);
        h.extend(self.session);
        h.extend(self.epoch.to_le_bytes());
        h.extend(self.seal);
        for n in [self.next_slot, self.cursor, 3 * required, self.accepted.len()] {
            h.extend((n as u64).to_le_bytes());
        }
        for (i, a) in self.accepted.iter().enumerate() {
            h.extend((i as u64).to_le_bytes());
            h.extend(((TOKENS * i) as u64).to_le_bytes());
            h.extend(a.root.roots()[0]);
            h.extend(self.profiles[i].bytes().layout_digest);
            for t in a.tokens {
                h.extend(t.to_le_bytes());
            }
            h.extend(a.receipt);
        }
        h.extend(root.roots()[0]);
        h.extend(p.bytes().layout_digest);
        h.extend(nonce);
        for g in [gamma(&DOMAIN_W.config()?), gamma(&DOMAIN_A.config()?)] {
            h.extend((g.len() as u64).to_le_bytes());
            h.extend(g);
        }
        h.extend(1u64.to_le_bytes());
        h.extend(tokens[0].to_le_bytes());
        h.extend(2u64.to_le_bytes());
        for t in tokens {
            h.extend(t.to_le_bytes());
        }
        Ok(h)
    }
    fn promote(&mut self, root: C61Commitment, tokens: [u32; 2], receipt: [u8; 32]) {
        self.accepted.push(Accepted { root, tokens, receipt });
        self.live = self.next_slot < 3;
    }
}

fn segments<'a>(
    state: &'a State,
    s: &'a caller::P0Statement<'a>,
    ag: &'a [u8],
) -> Vec<kv::Segment<'a>> {
    state
        .accepted
        .iter()
        .enumerate()
        .map(|(i, a)| kv::Segment {
            root: &a.root,
            profile: ag,
            bytes: state.profiles[i].bytes(),
            model: state.weight.roots()[0],
            quantization: state.profiles[i].digest,
            tokens: TOKENS,
            receipt: a.receipt,
        })
        .chain([kv::Segment {
            root: s.auxiliary,
            profile: ag,
            bytes: state.profiles[s.attempt.slot as usize].bytes(),
            model: state.weight.roots()[0],
            quantization: s.quantization,
            tokens: TOKENS,
            receipt: [0; 32],
        }])
        .collect()
}

struct Body<T, W> {
    fs: Fs,
    wire: W,
    bw: Batch<T>,
    ba: Batch<T>,
    openings: Vec<kv::Opening<T>>,
}

// The two source representations share the original numerical body and verifier.
// Replay owns only immutable getter state; it closes in the same original MACs.
pub(super) enum SourceModel<'a> {
    Dense(&'a Model),
    Replay(&'a b12::replay::ReplayModel),
}
impl SourceModel<'_> {
    pub(super) fn identity(&self) -> (Domain, &C61Commitment) {
        match self {
            Self::Dense(m) => (m.domain, &m.root),
            Self::Replay(m) => (m.domain(), m.root()),
        }
    }
    pub(super) fn byte(&self, index: usize) -> u8 {
        match self {
            Self::Dense(m) => m.weights.get(index).copied().unwrap_or(0) as u8,
            Self::Replay(m) => m.value(index).c0.value() as u8,
        }
    }
    pub(super) fn range(
        &self,
        attempt: AttemptContext,
        layout: [u8; 32],
        live: usize,
        alphabet: range::Alphabet,
        fs: &mut Fs,
        rows: &mut impl ExactSizeIterator<Item = Auth>,
    ) -> Result<(range::Proof, [Vec<Cube>; 2], [Auth; 2]), String> {
        match self {
            Self::Dense(m) => range::prove(m, attempt, layout, live, alphabet, fs, rows),
            Self::Replay(m) => range::prove_sourcewise(
                m.domain(),
                m.root(),
                attempt,
                layout,
                live,
                alphabet,
                &|i| m.value(i),
                fs,
                rows,
            ),
        }
    }
    pub(super) fn close(
        &self,
        attempt: AttemptContext,
        layout: [u8; 32],
        forms: &[Vec<Cube>],
        targets: &[Auth],
        fs: &mut Fs,
        rows: &mut impl ExactSizeIterator<Item = Auth>,
    ) -> Result<(MatrixProof, blake3::Hash), String> {
        match self {
            Self::Dense(m) => linear::prove(m, attempt, layout, forms, targets, fs, rows),
            Self::Replay(m) => {
                linear::prove_sourcewise(m, attempt, layout, forms, targets, fs, rows)
            }
        }
    }
}
trait Auxiliary: Sized {
    fn prepare(
        profile: Arc<Profile>,
        weights: Arc<Installed>,
        old: &[Self],
        prompt: u32,
    ) -> Result<Self, String>;
    fn root(&self) -> &C61Commitment;
    fn tokens(&self) -> [u32; 2];
    fn phase_end(&self, _phase: &str) {}
    fn value(&self, p: &Profile, id: usize, row: usize, col: usize) -> i64;
    fn model(&self) -> SourceModel<'_>;
    fn byte(&self, p: &Profile, id: usize, row: usize, col: usize, b: usize) -> u8 {
        let shape = &p.bytes().scalar.layout.sources[id];
        if row >= shape.rows || col >= shape.cols {
            return 0;
        }
        (self.value(p, id, row, col) as u64 >> (8 * b)) as u8
            ^ if b + 1 == p.bytes().widths[id] { 128 } else { 0 }
    }
    fn word6(&self, p: &Profile, id: usize, row: usize, col: usize) -> [u8; 6] {
        std::array::from_fn(|b| self.byte(p, id, row, col, b))
    }
    fn compact(
        &self,
        p: &Profile,
        w: &Installed,
        points: &[Vec<Fp3>],
    ) -> Result<Vec<caller::Compact>, String> {
        prepare::compact(p, w, points, |id, r, c| self.value(p, id, r, c))
    }
}
impl Auxiliary for Snapshot {
    fn prepare(
        profile: Arc<Profile>,
        weights: Arc<Installed>,
        old: &[Self],
        prompt: u32,
    ) -> Result<Self, String> {
        Snapshot::prepare(&profile, &weights, old, prompt)
    }
    fn root(&self) -> &C61Commitment {
        &self.source.root
    }
    fn tokens(&self) -> [u32; 2] {
        self.tokens
    }
    fn value(&self, p: &Profile, id: usize, row: usize, col: usize) -> i64 {
        Snapshot::value(self, p, id, row, col)
    }
    fn model(&self) -> SourceModel<'_> {
        SourceModel::Dense(&self.source)
    }
}

struct OrderedAux {
    reader: Arc<ordered::Reader>,
    source: b12::replay::ReplayModel,
}

fn ordered_work(_reader: &ordered::Reader, _phase: &str) {
    #[cfg(test)]
    eprintln!(
        "C71_INTEGRATED_GETTER {}",
        serde_json::json!({
            "phase":_phase,"work":_reader.take_work().unwrap(),
            "scope":"reduced original numerical source; CPU work, not HBM or H100 time"
        })
    );
}

impl Auxiliary for OrderedAux {
    fn prepare(
        profile: Arc<Profile>,
        weights: Arc<Installed>,
        old: &[Self],
        prompt: u32,
    ) -> Result<Self, String> {
        let previous = old.iter().map(|snapshot| snapshot.reader.clone()).collect::<Vec<_>>();
        let live = profile.bytes().live;
        let reader = ordered::Reader::prepare(profile, weights, &previous, prompt)?;
        ordered_work(&reader, "prepare_before_commit");
        let coins = fresh_pcs_coins()?;
        let getter = reader.clone();
        let source = b12::replay::ReplayModel::new(
            DOMAIN_A,
            coins.seed,
            coins.salt_seed,
            Arc::new(move |index| {
                E::from(Goldilocks::from_u64(u64::from(
                    getter.byte_at(index).expect("immutable validated A byte"),
                )))
            }),
            live,
        )?
        .retain_first_fold();
        let snapshot = Self { reader, source };
        snapshot.phase_end("initial_commit_A");
        Ok(snapshot)
    }
    fn root(&self) -> &C61Commitment {
        self.source.root()
    }
    fn tokens(&self) -> [u32; 2] {
        self.reader.tokens()
    }
    fn value(&self, _profile: &Profile, id: usize, row: usize, col: usize) -> i64 {
        self.reader.value(id, row, col).expect("immutable validated numerical reader")
    }
    fn model(&self) -> SourceModel<'_> {
        SourceModel::Replay(&self.source)
    }
    fn phase_end(&self, phase: &str) {
        ordered_work(&self.reader, phase);
    }
}

fn prove_schedule<S: Auxiliary>(
    state: &State,
    p: &Profile,
    w: &Installed,
    snapshot: &S,
    old: &[S],
    s: &caller::P0Statement<'_>,
    header: &[u8],
    rows: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let Body { mut fs, mut wire, bw, ba, openings } = prove_components(
        state,
        p,
        w,
        snapshot,
        old,
        s,
        header,
        rows,
        p.bytes().live,
        |requests, fs, rows| prove_originals(p, snapshot, s, requests, fs, rows),
        |requests, fs, rows| {
            let parts = segments(state, s, s.auxiliary_gamma);
            let ks = kv::Statement {
                model: state.weight.roots()[0],
                quantization: p.digest,
                attempt: s.attempt,
                segments: &parts,
            };
            let (proof, openings) =
                kv::prove(&ks, requests, |i, j| old[i].model().byte(j), fs, rows)?;
            let mut body = Vec::new();
            proof.write(&mut body);
            Ok((body, openings))
        },
    )?;
    if openings.len() != old.len() {
        return Err("native historical closure census differs".into());
    }
    let (proof, _) =
        w.source().close(s.attempt, p.plan.layout_digest, &bw.forms, &bw.targets, &mut fs, rows)?;
    wire.raw(15, &codec::encode_linear(DOMAIN_W, &proof).map_err(|e| e.to_string())?, &mut fs)?;
    for (i, o) in openings.into_iter().enumerate() {
        let (proof, _) = old[i].model().close(
            s.attempt,
            state.profiles[i].bytes().layout_digest,
            &[o.form],
            &[o.original],
            &mut fs,
            rows,
        )?;
        wire.raw(
            16 + i as u16,
            &codec::encode_linear(DOMAIN_A, &proof).map_err(|e| e.to_string())?,
            &mut fs,
        )?;
    }
    let (proof, _) = snapshot.model().close(
        s.attempt,
        p.bytes().layout_digest,
        &ba.forms,
        &ba.targets,
        &mut fs,
        rows,
    )?;
    wire.raw(
        16 + old.len() as u16,
        &codec::encode_linear(DOMAIN_A, &proof).map_err(|e| e.to_string())?,
        &mut fs,
    )?;
    snapshot.phase_end("linear_A_and_WHIR");
    if rows.len() != 0 {
        return Err("composed prover did not consume its exact reservation".into());
    }
    Ok(wire.finish(&mut fs))
}

fn prove_originals<S: Auxiliary>(
    p: &Profile,
    snapshot: &S,
    s: &caller::P0Statement<'_>,
    requests: Vec<(bytes::RneRequest<Auth>, i32)>,
    fs: &mut Fs,
    rows: &mut impl ExactSizeIterator<Item = Auth>,
) -> Result<(Vec<u8>, Batch<Auth>), String> {
    let mut ba = Batch::new();
    let mut proofs = Vec::new();
    for (r, shift) in requests {
        let rs = rne::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: r.view,
            attempt: s.attempt,
            output_point: &r.point,
            shape: r.shape,
            shift,
        };
        let (proof, point, original) = rne::prove(
            &rs,
            r.original,
            |j| {
                snapshot.word6(
                    p,
                    r.source,
                    j / r.shape[1].next_power_of_two(),
                    j % r.shape[1].next_power_of_two(),
                )
            },
            fs,
            rows,
        )?;
        ba.add(p.bytes().source_rne_form(r.source, &point)?, original);
        proofs.push(proof);
    }
    let mut body = Vec::new();
    proofs.write(&mut body);
    Ok((body, ba))
}

fn verify_originals(
    p: &Profile,
    s: &caller::P0Statement<'_>,
    requests: Vec<(bytes::RneRequest<Key>, i32)>,
    mut body: &[u8],
    delta: Fp3,
    fs: &mut Fs,
    rows: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<Batch<Key>, String> {
    let mut ba = Batch::new();
    let proofs = Vec::<rne::Proof>::read(&mut body)?;
    if !body.is_empty() {
        return Err("component trailing bytes".into());
    }
    if proofs.len() != requests.len() {
        return Err("original RNE certificate cardinality differs".into());
    }
    for ((r, rounding), proof) in requests.into_iter().zip(proofs) {
        let rs = rne::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: r.view,
            attempt: s.attempt,
            output_point: &r.point,
            shape: r.shape,
            shift: rounding,
        };
        let (point, original) = rne::verify(&rs, r.original, &proof, delta, fs, rows)?;
        ba.add(p.bytes().source_rne_form(r.source, &point)?, original);
    }
    Ok(ba)
}

// Both schedules run this exact numerical/GKR body. The test-only joint
// variant changes only original-RNE byte checks, KV closure and final PCS.
fn prove_components<S: Auxiliary, Rows: ExactSizeIterator<Item = Auth>>(
    state: &State,
    p: &Profile,
    w: &Installed,
    snapshot: &S,
    old: &[S],
    s: &caller::P0Statement<'_>,
    header: &[u8],
    rows: &mut Rows,
    auxiliary_live: usize,
    rne_hook: impl FnOnce(
        Vec<(bytes::RneRequest<Auth>, i32)>,
        &mut Fs,
        &mut Rows,
    ) -> Result<(Vec<u8>, Batch<Auth>), String>,
    kv_hook: impl FnOnce(
        &[kv::Request<Auth>],
        &mut Fs,
        &mut Rows,
    ) -> Result<(Vec<u8>, Vec<kv::Opening<Auth>>), String>,
) -> Result<Body<Auth, Writer>, String> {
    let mut fs = Fs::new(header, 1_000_000);
    let mut wire = Writer::new(header);
    let (mut bw, mut ba) = (Batch::new(), Batch::new());
    for (f, b) in p.public_forms(s, &mut fs)? {
        ba.add(f, Auth::new(b, Fp3::ZERO));
    }
    wire.raw(0, &[], &mut fs)?;
    let (proof, p0) = p.plan.prove_p0(s, |points| snapshot.compact(p, w, points), &mut fs, rows)?;
    wire.put(1, &proof, &mut fs)?;
    bw.forms = p0.weight_forms.clone();
    bw.targets = p0.weights.clone();
    let (f, b) = p.bytes().forms(&p.plan, &p0)?;
    ba.extend(
        f,
        b,
        p0.cuts.iter().map(|c| c.original).chain(p0.inputs.iter().map(|c| c.original)).collect(),
        ashift,
    )?;
    let read = |id, r, c, b| snapshot.byte(p, id, r, c, b);
    let (proof, norms) =
        p.rms.prove_rms(s, &vec![[0; 3]; p.rms.norms.len()], read, &mut fs, rows)?;
    wire.put(2, &proof, &mut fs)?;
    let (f, b, t) = p.rms.rms_forms(&norms)?;
    ba.extend(f, b, t, ashift)?;
    let (body, rne_batch) = rne_hook(p.originals(&p0, &norms)?, &mut fs, rows)?;
    let rne_sources = rne_batch.targets.len();
    ba.forms.extend(rne_batch.forms);
    ba.targets.extend(rne_batch.targets);
    wire.raw(3, &body, &mut fs)?;
    let pairs = p.table_pairs();
    let (proof, pending) = p.bytes().prove_table_rne(&p.plan, s, &pairs, read, &mut fs, rows)?;
    wire.put(4, &proof, &mut fs)?;
    let (f, b, t) = p.bytes().table_rne_forms(&p.plan, &pairs, &pending)?;
    ba.extend(f, b, t, ashift)?;
    let (proof, pending) = p.gelu.prove_lookup(
        p.bytes(),
        s,
        lookup::Table { profile: 0, lower: -2, outputs: lookup::Outputs::I16(&GELU) },
        read,
        &mut fs,
        rows,
    )?;
    wire.put(5, &proof, &mut fs)?;
    let (f, b) = p.gelu.forms(p.bytes(), &pending.point)?;
    ba.extend(f.into(), b.into(), pending.originals.into(), ashift)?;
    let (proof, pending) = gate_up::prove(
        &p.gate_statement(s),
        |i| {
            (
                snapshot.value(p, p.gate[2], i / 2, i % 2) as i16,
                snapshot.value(p, p.gate[3], i / 2, i % 2) as i16,
                snapshot.word6(p, p.gate[0], i / 2, i % 2),
            )
        },
        &mut fs,
        rows,
    )?;
    wire.put(6, &proof, &mut fs)?;
    for (id, point, t) in [
        (p.gate[0], &pending.raw_point, pending.originals[0]),
        (p.gate[2], &pending.input_point, pending.originals[1]),
        (p.gate[3], &pending.input_point, pending.originals[2]),
    ] {
        let (f, b) = p.word(id, point)?;
        ba.add(f, ashift(t, b));
    }
    let blocks = (0..2)
        .map(|_| kernel::rope::Block { rows: 2, heads: 1, width: 2, position: p.old, family: 0 })
        .collect::<Vec<_>>();
    let table = Q30[p.old..p.old + 2].iter().map(|x| vec![*x]).collect::<Vec<_>>();
    let tables = [kernel::rope::Table { position: p.old, rows: &table }];
    let rs = kernel::rope::Statement {
        root: s.auxiliary,
        profile: s.auxiliary_gamma,
        view: p.bytes().layout_digest,
        attempt: s.attempt,
        blocks: &blocks,
        tables: &tables,
    };
    let (proof, pending) = kernel::rope::prove(
        &rs,
        |i| {
            let r = p.rotations[i / 4];
            (
                snapshot.word6(p, r[0], i % 4 / 2, i % 2),
                snapshot.value(p, r[2], i % 4 / 2, i % 2) as i16,
            )
        },
        &mut fs,
        rows,
    )?;
    wire.put(7, &proof, &mut fs)?;
    let (f, b, t) = p.rope_forms(&pending)?;
    ba.extend(f, b, t, ashift)?;
    let tail = |source, t: usize, c| {
        if t < p.old {
            old[t / 2].value(&state.profiles[t / 2], source, t % 2, c) as i16
        } else {
            snapshot.value(p, source, t - p.old, c) as i16
        }
    };
    let (proof, q) = kernel::attention::prove_qk(
        &p.attn(s),
        |_, r, c| snapshot.word6(p, p.attention[0], r, c),
        |r, _, c| snapshot.value(p, p.rotations[0][1], r, c) as i16,
        |r, _, c| tail(p.rotations[1][1], r, c),
        &mut fs,
        rows,
    )?;
    wire.put(8, &proof, &mut fs)?;
    let value = p.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output;
    let (proof, v) = kernel::attention::prove_pv(
        &p.attn(s),
        |r, _, c| snapshot.word6(p, p.attention[1], r, c),
        |_, r, c| snapshot.value(p, p.softmax.layers[0].pi, r, c) as i16,
        |r, _, c| tail(value, r, c),
        &mut fs,
        rows,
    )?;
    wire.put(9, &proof, &mut fs)?;
    let requests = p.routes(&q, &v, &mut ba, ashift)?;
    let (body, mut openings) = kv_hook(&requests, &mut fs, rows)?;
    wire.raw(10, &body, &mut fs)?;
    let current = openings.pop().ok_or("missing current KV opening")?;
    ba.add(current.form, current.original);
    let (proof, pending) = p.output.prove_lookup(
        p.bytes(),
        s,
        lookup::Table { profile: 0, lower: -4, outputs: lookup::Outputs::I16(&SOFTCAP) },
        read,
        &mut fs,
        rows,
    )?;
    wire.put(11, &proof, &mut fs)?;
    let (f, b) = p.output.forms(p.bytes(), &pending.point)?;
    ba.extend(f.into(), b.into(), pending.originals.into(), ashift)?;
    let (proof, pending) = p.softmax.prove(
        p.bytes(),
        s,
        &[lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I32(&EXP30) }],
        read,
        &mut fs,
        rows,
    )?;
    wire.put(12, &proof, &mut fs)?;
    let (f, b, t) = p.softmax.forms(p.bytes(), &pending)?;
    ba.extend(f, b, t, ashift)?;
    let (proof, f, t) = w.source().range(
        s.attempt,
        p.plan.layout_digest,
        p.plan.live,
        range::Alphabet::Symmetric(32767),
        &mut fs,
        rows,
    )?;
    wire.put(13, &proof, &mut fs)?;
    for (f, t) in f.into_iter().zip(t) {
        bw.add(f, t);
    }
    snapshot.phase_end("producer_relations");
    let (proof, f, t) = snapshot.model().range(
        s.attempt,
        p.bytes().layout_digest,
        auxiliary_live,
        range::Alphabet::Byte,
        &mut fs,
        rows,
    )?;
    wire.put(14, &proof, &mut fs)?;
    for (f, t) in f.into_iter().zip(t) {
        ba.add(f, t);
    }
    snapshot.phase_end("range_A");
    if bw.targets.len() != 18 || ba.targets.len() != 103 + rne_sources {
        return Err(format!(
            "native closure census differs W={} A={}",
            bw.targets.len(),
            ba.targets.len()
        ));
    }
    Ok(Body { fs, wire, bw, ba, openings })
}

fn verify_schedule(
    state: &State,
    p: &Profile,
    s: &caller::P0Statement<'_>,
    header: &[u8],
    certificate: &[u8],
    delta: Fp3,
    rows: &mut impl ExactSizeIterator<Item = Key>,
) -> Result<[u8; 32], String> {
    let Body { mut fs, mut wire, bw, ba, openings } = verify_components(
        p,
        s,
        header,
        certificate,
        delta,
        rows,
        (DOMAIN_A, p.bytes().live),
        |requests, body, fs, rows| verify_originals(p, s, requests, body, delta, fs, rows),
        |requests, mut body, fs, rows| {
            let parts = segments(state, s, s.auxiliary_gamma);
            let ks = kv::Statement {
                model: state.weight.roots()[0],
                quantization: p.digest,
                attempt: s.attempt,
                segments: &parts,
            };
            let proof = kv::Proof::read(&mut body)?;
            if !body.is_empty() {
                return Err("component trailing bytes".into());
            }
            kv::verify(&ks, requests, &proof, delta, fs, rows)
        },
    )?;
    if openings.len() != state.accepted.len() {
        return Err("native historical closure census differs".into());
    }
    let (body, frame) = wire.raw(15)?;
    let proof = codec::decode_linear(DOMAIN_W, body).map_err(|e| e.to_string())?;
    linear::verify(
        DOMAIN_W,
        s.weights,
        s.attempt,
        p.plan.layout_digest,
        &bw.forms,
        &bw.targets,
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    for (i, o) in openings.into_iter().enumerate() {
        let (body, frame) = wire.raw(16 + i as u16)?;
        let proof = codec::decode_linear(DOMAIN_A, body).map_err(|e| e.to_string())?;
        linear::verify(
            DOMAIN_A,
            &state.accepted[i].root,
            s.attempt,
            state.profiles[i].bytes().layout_digest,
            &[o.form],
            &[o.original],
            &proof,
            delta,
            &mut fs,
            rows,
        )?;
        Reader::record(&mut fs, frame);
    }
    let (body, frame) = wire.raw(16 + state.accepted.len() as u16)?;
    let proof = codec::decode_linear(DOMAIN_A, body).map_err(|e| e.to_string())?;
    linear::verify(
        DOMAIN_A,
        s.auxiliary,
        s.attempt,
        p.bytes().layout_digest,
        &ba.forms,
        &ba.targets,
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    if rows.len() != 0 {
        return Err("composed verifier did not consume its exact reservation".into());
    }
    wire.finish(&mut fs)
}

fn verify_components<'a, Rows: ExactSizeIterator<Item = Key>>(
    p: &Profile,
    s: &caller::P0Statement<'_>,
    header: &[u8],
    certificate: &'a [u8],
    delta: Fp3,
    rows: &mut Rows,
    auxiliary_range: (Domain, usize),
    rne_hook: impl FnOnce(
        Vec<(bytes::RneRequest<Key>, i32)>,
        &[u8],
        &mut Fs,
        &mut Rows,
    ) -> Result<Batch<Key>, String>,
    kv_hook: impl FnOnce(
        &[kv::Request<Key>],
        &[u8],
        &mut Fs,
        &mut Rows,
    ) -> Result<Vec<kv::Opening<Key>>, String>,
) -> Result<Body<Key, Reader<'a>>, String> {
    let mut fs = Fs::new(header, 1_000_000);
    let mut wire = Reader::new(certificate, header)?;
    let shift = |t: Key, b: Fp3| Key::new(t.k + delta * b);
    let (mut bw, mut ba) = (Batch::new(), Batch::new());
    let (body, frame) = wire.raw(0)?;
    if !body.is_empty() {
        return Err("public targets have no prover payload".into());
    }
    for (f, b) in p.public_forms(s, &mut fs)? {
        ba.add(f, Key::new(delta * b));
    }
    Reader::record(&mut fs, frame);
    let (proof, frame) = wire.get(1)?;
    let p0 = p.plan.verify_p0(s, &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    bw.forms = p0.weight_forms.clone();
    bw.targets = p0.weights.clone();
    let (f, b) = p.bytes().forms(&p.plan, &p0)?;
    ba.extend(
        f,
        b,
        p0.cuts.iter().map(|c| c.original).chain(p0.inputs.iter().map(|c| c.original)).collect(),
        shift,
    )?;
    let (proof, frame) = wire.get(2)?;
    let norms =
        p.rms.verify_rms(s, &vec![[0; 3]; p.rms.norms.len()], &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let (f, b, t) = p.rms.rms_forms(&norms)?;
    ba.extend(f, b, t, shift)?;
    let (body, frame) = wire.raw(3)?;
    let rne_batch = rne_hook(p.originals(&p0, &norms)?, body, &mut fs, rows)?;
    let rne_sources = rne_batch.targets.len();
    ba.forms.extend(rne_batch.forms);
    ba.targets.extend(rne_batch.targets);
    Reader::record(&mut fs, frame);
    let pairs = p.table_pairs();
    let (proof, frame) = wire.get(4)?;
    let pending = p.bytes().verify_table_rne(&p.plan, s, &pairs, &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let (f, b, t) = p.bytes().table_rne_forms(&p.plan, &pairs, &pending)?;
    ba.extend(f, b, t, shift)?;
    let (proof, frame) = wire.get(5)?;
    let pending = p.gelu.verify_lookup(
        p.bytes(),
        s,
        lookup::Table { profile: 0, lower: -2, outputs: lookup::Outputs::I16(&GELU) },
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    let (f, b) = p.gelu.forms(p.bytes(), &pending.point)?;
    ba.extend(f.into(), b.into(), pending.originals.into(), shift)?;
    let (proof, frame) = wire.get(6)?;
    let pending = gate_up::verify(&p.gate_statement(s), &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    for (id, point, t) in [
        (p.gate[0], &pending.raw_point, pending.originals[0]),
        (p.gate[2], &pending.input_point, pending.originals[1]),
        (p.gate[3], &pending.input_point, pending.originals[2]),
    ] {
        let (f, b) = p.word(id, point)?;
        ba.add(f, shift(t, b));
    }
    let blocks = (0..2)
        .map(|_| kernel::rope::Block { rows: 2, heads: 1, width: 2, position: p.old, family: 0 })
        .collect::<Vec<_>>();
    let table = Q30[p.old..p.old + 2].iter().map(|x| vec![*x]).collect::<Vec<_>>();
    let tables = [kernel::rope::Table { position: p.old, rows: &table }];
    let rs = kernel::rope::Statement {
        root: s.auxiliary,
        profile: s.auxiliary_gamma,
        view: p.bytes().layout_digest,
        attempt: s.attempt,
        blocks: &blocks,
        tables: &tables,
    };
    let (proof, frame) = wire.get(7)?;
    let pending = kernel::rope::verify(&rs, &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let (f, b, t) = p.rope_forms(&pending)?;
    ba.extend(f, b, t, shift)?;
    let (proof, frame) = wire.get(8)?;
    let q = kernel::attention::verify_qk(&p.attn(s), &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let (proof, frame) = wire.get(9)?;
    let v = kernel::attention::verify_pv(&p.attn(s), &proof, delta, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let requests = p.routes(&q, &v, &mut ba, shift)?;
    let (body, frame) = wire.raw(10)?;
    let mut openings = kv_hook(&requests, body, &mut fs, rows)?;
    Reader::record(&mut fs, frame);
    let current = openings.pop().ok_or("missing current KV opening")?;
    ba.add(current.form, current.original);
    let (proof, frame) = wire.get(11)?;
    let pending = p.output.verify_lookup(
        p.bytes(),
        s,
        lookup::Table { profile: 0, lower: -4, outputs: lookup::Outputs::I16(&SOFTCAP) },
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    let (f, b) = p.output.forms(p.bytes(), &pending.point)?;
    ba.extend(f.into(), b.into(), pending.originals.into(), shift)?;
    let (proof, frame) = wire.get(12)?;
    let pending = p.softmax.verify(
        p.bytes(),
        s,
        &[lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I32(&EXP30) }],
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    let (f, b, t) = p.softmax.forms(p.bytes(), &pending)?;
    ba.extend(f, b, t, shift)?;
    let (proof, frame) = wire.get(13)?;
    let (f, t) = range::verify(
        DOMAIN_W,
        s.weights,
        s.attempt,
        p.plan.layout_digest,
        p.plan.live,
        32767,
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    for (f, t) in f.into_iter().zip(t) {
        bw.add(f, t);
    }
    let (proof, frame) = wire.get(14)?;
    let (f, t) = range::verify(
        auxiliary_range.0,
        s.auxiliary,
        s.attempt,
        p.bytes().layout_digest,
        auxiliary_range.1,
        range::Alphabet::Byte,
        &proof,
        delta,
        &mut fs,
        rows,
    )?;
    Reader::record(&mut fs, frame);
    for (f, t) in f.into_iter().zip(t) {
        ba.add(f, t);
    }
    if bw.targets.len() != 18 || ba.targets.len() != 103 + rne_sources {
        return Err("native endpoint closure census differs".into());
    }
    Ok(Body { fs, wire, bw, ba, openings })
}

#[cfg_attr(test, derive(Clone))]
struct Response {
    root: C61Commitment,
    tokens: [u32; 2],
    nonce: [u8; 32],
    certificate: Vec<u8>,
}
// Constructible only after VerifyResponse has closed the complete certificate.
struct Acceptance {
    root: C61Commitment,
    tokens: [u32; 2],
    receipt: [u8; 32],
    session: [u8; 32],
    epoch: u64,
    slot: usize,
}
struct Verifier {
    state: State,
    #[cfg(test)]
    delta: Fp3,
    #[cfg(test)]
    keys: std::vec::IntoIter<Key>,
}
struct Prover<S = Snapshot> {
    state: State,
    model: Arc<Installed>,
    #[cfg(test)]
    rows: std::vec::IntoIter<Auth>,
    accepted: Vec<S>,
    pending: Option<(S, [u8; 32])>,
}

impl Verifier {
    #[cfg(test)]
    fn verify_response(&mut self, prompt: u32, response: &Response) -> Result<Acceptance, String> {
        if !self.state.live {
            return Err("Stop".into());
        }
        self.state.live = false;
        // There is no retry, reopen or rollback API. Catch kernel/FS exhaustion
        // across infallible P3 APIs while keeping this run terminal.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let state = &mut self.state;
            if response.tokens[0] != prompt {
                return Err("prompt prefix differs".into());
            }
            let slot = state.next_slot;
            let p = state.profiles.get(slot).ok_or("no response slot")?;
            let (wg, ag) = (gamma(&DOMAIN_W.config()?), gamma(&DOMAIN_A.config()?));
            let attempt = state.attempt(response.nonce);
            let s = p.context(&state.weight, &response.root, &response.tokens, attempt, &wg, &ag);
            let required = p.required(&s)?;
            let header = state.header(&response.root, response.tokens, response.nonce, required)?;
            if self.keys.len() < required {
                return Err("capacity exhausted".into());
            }
            state.next_slot += 1;
            state.cursor += 3 * required;
            let mut rows = self.keys.by_ref().take(required).collect::<Vec<_>>().into_iter();
            let receipt = verify_schedule(
                state,
                p,
                &s,
                &header,
                &response.certificate,
                self.delta,
                &mut rows,
            )?;
            Ok(Acceptance {
                root: response.root.clone(),
                tokens: response.tokens,
                receipt,
                session: state.session,
                epoch: state.epoch,
                slot,
            })
        }));
        let acceptance = outcome.map_err(|_| "Stop".to_string())?.map_err(stop)?;
        self.state.promote(acceptance.root.clone(), acceptance.tokens, acceptance.receipt);
        Ok(acceptance)
    }
}

impl<S: Auxiliary> Prover<S> {
    #[cfg(test)]
    fn prepare_response(&mut self, prompt: u32, nonce: [u8; 32]) -> Result<Response, String> {
        if !self.state.live || self.pending.is_some() {
            return Err("Stop".into());
        }
        self.state.live = false;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let state = &mut self.state;
            let p = state.profiles.get(state.next_slot).ok_or("no response slot")?;
            let (wg, ag) = (gamma(&DOMAIN_W.config()?), gamma(&DOMAIN_A.config()?));
            let attempt = state.attempt(nonce);
            // The reservation is public and root-independent. Reject shortage
            // before private preparation; this placeholder grants no proof.
            let required = p.required(&p.context(
                &state.weight,
                &state.weight,
                &[prompt, 0],
                attempt,
                &wg,
                &ag,
            ))?;
            if self.rows.len() < required {
                return Err("capacity exhausted".into());
            }
            let snapshot = S::prepare(p.clone(), self.model.clone(), &self.accepted, prompt)?;
            let tokens = snapshot.tokens();
            let s = p.context(&state.weight, snapshot.root(), &tokens, attempt, &wg, &ag);
            let header = state.header(snapshot.root(), tokens, nonce, required)?;
            state.next_slot += 1;
            state.cursor += 3 * required;
            let mut rows = self.rows.by_ref().take(required);
            let (certificate, receipt) = prove_schedule(
                state,
                p,
                &self.model,
                &snapshot,
                &self.accepted,
                &s,
                &header,
                &mut rows,
            )?;
            let response = Response { root: snapshot.root().clone(), tokens, nonce, certificate };
            self.pending = Some((snapshot, receipt));
            Ok(response)
        }));
        outcome.map_err(|_| "Stop".to_string())?.map_err(stop)
    }
    fn check_acceptance(&self, accepted: &Acceptance) -> Result<(), String> {
        let (snapshot, receipt) = self.pending.as_ref().ok_or("Stop")?;
        if *receipt != accepted.receipt
            || snapshot.root() != &accepted.root
            || snapshot.tokens() != accepted.tokens
            || accepted.session != self.state.session
            || accepted.epoch != self.state.epoch
            || accepted.slot != self.accepted.len()
        {
            return Err("Stop".into());
        }
        Ok(())
    }
    fn promote(&mut self, accepted: Acceptance) -> Result<(), String> {
        self.state.live = false;
        if let Err(error) = self.check_acceptance(&accepted) {
            self.pending = None;
            return Err(error);
        }
        let (snapshot, receipt) = self.pending.take().ok_or("Stop")?;
        self.state.promote(accepted.root, accepted.tokens, receipt);
        self.accepted.push(snapshot);
        Ok(())
    }
    fn stop(&mut self) {
        self.state.live = false;
        self.pending = None;
    }
}

fn stop(_error: String) -> String {
    #[cfg(test)]
    eprintln!("native composed rejection: {_error}");
    "Stop".into()
}

impl Profile {
    fn context<'a>(
        &'a self,
        weight: &'a C61Commitment,
        root: &'a C61Commitment,
        tokens: &'a [u32],
        attempt: AttemptContext,
        wg: &'a [u8],
        ag: &'a [u8],
    ) -> caller::P0Statement<'a> {
        caller::P0Statement {
            weights: weight,
            auxiliary: root,
            weight_gamma: wg,
            auxiliary_gamma: ag,
            auxiliary_layout: &self.bytes().scalar,
            quantization: self.digest,
            tokens,
            attempt,
        }
    }
    fn table_pairs(&self) -> Vec<Pair> {
        self.matrix
            .iter()
            .filter(|p| [10, 11, 15].contains(&p.raw))
            .copied()
            .chain(self.rotations.iter().map(|r| Pair { raw: r[0], output: r[1], shift: 30 }))
            .chain([Pair {
                raw: self.attention[0],
                output: self.softmax.layers[0].score,
                shift: 0,
            }])
            .chain(self.residual.iter().copied())
            .collect()
    }
    fn originals<T: Copy>(
        &self,
        p0: &caller::PendingP0<T>,
        norms: &rms::caller::Pending<T>,
    ) -> Result<Vec<(bytes::RneRequest<T>, i32)>, String> {
        let mut r = self.bytes().rne_requests(&self.plan, p0)?;
        for v in self.rms.local_v_rne_requests(&self.plan, norms)? {
            r.push(bytes::RneRequest {
                consumer: v.norm,
                source: v.source,
                view: v.view,
                shape: v.shape,
                point: v.point,
                original: v.original,
            });
        }
        for (raw, consumer) in [(self.gate[0], 12), (self.attention[1], 7)] {
            let input = &p0.inputs[consumer - 1];
            let (view, shape) = self.bytes().source_rne_view(raw)?;
            r.push(bytes::RneRequest {
                consumer,
                source: raw,
                view,
                shape,
                point: input.point.clone(),
                original: input.original,
            });
        }
        if r.len() != 7 {
            return Err("native original RNE partition differs".into());
        }
        Ok(r.into_iter()
            .map(|r| {
                let shift = if r.source == self.attention[1] { 14 } else { 0 };
                (r, shift)
            })
            .collect())
    }
    fn attn<'a>(&self, s: &'a caller::P0Statement<'a>) -> kernel::attention::Statement<'a> {
        kernel::attention::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.bytes().layout_digest,
            attempt: s.attempt,
            layer: 0,
            old: self.old,
            prompt: 1,
            tokens: 2,
            groups: 1,
            repeats: 1,
            lanes: 2,
        }
    }
    fn gate_statement<'a>(&self, s: &'a caller::P0Statement<'a>) -> gate_up::Statement<'a> {
        gate_up::Statement {
            root: s.auxiliary,
            profile: s.auxiliary_gamma,
            view: self.bytes().layout_digest,
            attempt: s.attempt,
            cells: 4,
        }
    }
    fn required(&self, s: &caller::P0Statement<'_>) -> Result<usize, String> {
        let mut n = self.plan.p0_required()
            + self.rms.rms_required(s, &vec![[0; 3]; self.rms.norms.len()])?;
        let pairs = self.table_pairs();
        n += self.bytes().table_rne_required(&self.plan, &pairs)?;
        // Four direct P0 inputs, one V statistic input, gate/PV original inputs.
        for shift in [0, 0, 0, 0, 0, 0, 14] {
            n += rne::required(2, shift);
        }
        n += self.gelu.lookup_required(
            self.bytes(),
            s,
            &lookup::Table { profile: 0, lower: -2, outputs: lookup::Outputs::I16(&GELU) },
        )?;
        n += self.gate_statement(s).required()? + 3 * 3 + 2;
        n += self.attn(s).qk_required()? + self.attn(s).pv_required()? + self.old / TOKENS;
        n += self.output.lookup_required(
            self.bytes(),
            s,
            &lookup::Table { profile: 0, lower: -4, outputs: lookup::Outputs::I16(&SOFTCAP) },
        )?;
        n += self.softmax.required(
            self.bytes(),
            s,
            &[lookup::Table { profile: 0, lower: -32767, outputs: lookup::Outputs::I32(&EXP30) }],
        )?;
        n += range::required(10, 32767)
            + range::required(12, range::Alphabet::Byte)
            + 32
            + (self.old / TOKENS + 1) * 38;
        Ok(n)
    }
    fn public_forms(
        &self,
        s: &caller::P0Statement<'_>,
        fs: &mut Fs,
    ) -> Result<Vec<(Vec<Cube>, Fp3)>, String> {
        Ok(vec![
            self.bytes().affine_zero_form(&self.plan, s, &self.affine, fs)?,
            self.bytes().argmax_zero_form(
                &self.plan,
                s,
                self.output.output,
                self.output.slack,
                1,
                fs,
            )?,
            self.bytes().causal_zero_form(
                &self.plan,
                s,
                &[self.softmax.layers[0].pi],
                1,
                2,
                self.old,
                fs,
            )?,
            self.softmax.zero_form(self.bytes(), s, fs)?,
        ])
    }
    fn word(&self, id: usize, point: &[Fp3]) -> Result<(Vec<Cube>, Fp3), String> {
        let source = &self.bytes().scalar.layout.sources[id];
        let r = bits(source.rows);
        if point.len() != r + bits(source.cols) {
            return Err("native original point axes differ".into());
        }
        self.bytes().word_form(id, &point[..r], &point[r..], Fp3::ONE)
    }
    fn rope_forms<T: Copy>(
        &self,
        p: &kernel::rope::Pending<T>,
    ) -> Result<(Vec<Vec<Cube>>, Vec<Fp3>, Vec<T>), String> {
        let mut forms = Vec::new();
        let mut bias = Vec::new();
        for (point, field) in [(&p.raw_point, 0), (&p.input_point, 2)] {
            if point.len() != 3 {
                return Err("native joint RoPE point differs".into());
            }
            let (mut form, mut b) = (Vec::new(), Fp3::ZERO);
            for (j, r) in self.rotations.iter().enumerate() {
                let c = if j == 0 { Fp3::ONE - point[0] } else { point[0] };
                let (f, x) = self.bytes().word_form(r[field], &point[1..2], &point[2..], c)?;
                form.extend(f);
                b += x;
            }
            forms.push(form);
            bias.push(b);
        }
        Ok((forms, bias, p.originals.to_vec()))
    }
    fn routes<T: Copy>(
        &self,
        q: &kernel::attention::QkPending<T>,
        v: &kernel::attention::PvPending<T>,
        a: &mut Batch<T>,
        shift: impl Fn(T, Fp3) -> T,
    ) -> Result<Vec<kv::Request<T>>, String> {
        for (id, point, t) in [
            (self.attention[0], &q.raw_point, q.originals[0]),
            (self.rotations[0][1], &q.q_point, q.originals[1]),
            (self.attention[1], &v.raw_point, v.originals[0]),
            (self.softmax.layers[0].pi, &v.pi_point, v.originals[1]),
        ] {
            let (f, b) = self.word(id, point)?;
            a.add(f, shift(t, b));
        }
        let value = self.rms.norms.iter().find(|n| n.operation == "v_norm").unwrap().output;
        Ok(vec![
            kv::Request {
                source: self.rotations[1][1],
                point: q.k_point.clone(),
                original: q.originals[2],
            },
            kv::Request { source: value, point: v.v_point.clone(), original: v.originals[2] },
        ])
    }
}
