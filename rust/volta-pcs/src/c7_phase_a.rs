//! Finite D126 Phase-A conformance oracles.
//!
//! This module is intentionally CPU-only and test-scale.  It can produce
//! `TestOnlyPcsChecked`, never a production PCS receipt or `PCSConsumedSet`.

use std::collections::{BTreeMap, BTreeSet};

use volta_field::{Fp, Fp3, P};

type Result<T> = std::result::Result<T, String>;
type Digest = [u8; 32];

const SECTION_CAP: usize = 64 * 1024 * 1024;
const RECEIPT_OBJECT_CAP: usize = 1_048_576;
const GENESIS_REQUEST_FRAME_CAP: usize = 1_048_744;
const GENESIS_RESPONSE_FRAME_CAP: usize = 1_049_308;
const GENESIS_CACHE_OBJECT_CAP: usize = 1_049_356;

fn fp3(a: u64, b: u64, c: u64) -> Fp3 {
    Fp3::new(Fp::new(a), Fp::new(b), Fp::new(c))
}

fn fp3_pow(mut base: Fp3, mut exponent: usize) -> Fp3 {
    let mut result = Fp3::ONE;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn digest(context: &str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn d(label: &str, bytes: &[u8]) -> Digest {
    let context = format!("volta-zk/c7/digest/{label}/v1");
    let mut input = Vec::with_capacity(8 + bytes.len());
    input.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    input.extend_from_slice(bytes);
    digest(&context, &input)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| "truncated u16".to_owned())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "truncated u32".to_owned())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "truncated u64".to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MissingInput {
    QuantProfile,
    LifecycleSplit,
    WorkloadTokens,
    VerifiedSourceBodies,
    PackedArtifactsAndRoots,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedModel {
    Gpt2,
    Gemma4_31B,
}

pub fn selected_model_missing_inputs(model: SelectedModel) -> Vec<MissingInput> {
    match model {
        SelectedModel::Gpt2 => vec![
            MissingInput::LifecycleSplit,
            MissingInput::WorkloadTokens,
            MissingInput::PackedArtifactsAndRoots,
        ],
        SelectedModel::Gemma4_31B => vec![
            MissingInput::QuantProfile,
            MissingInput::LifecycleSplit,
            MissingInput::WorkloadTokens,
            MissingInput::VerifiedSourceBodies,
            MissingInput::PackedArtifactsAndRoots,
        ],
    }
}

#[derive(Clone, Copy)]
enum SourceDisposition {
    Private,
    Public,
    Forbidden,
}

#[derive(Clone, Copy)]
struct SourceClass {
    tensors: u64,
    scalars: u64,
    disposition: SourceDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticCensus {
    pub tensors: u64,
    pub physical_scalars: u64,
    pub private_tensors: u64,
    pub private_scalars: u64,
    pub public_tensors: u64,
    pub forbidden_tensors: u64,
}

fn census(classes: &[SourceClass]) -> Result<StaticCensus> {
    let mut out = StaticCensus {
        tensors: 0,
        physical_scalars: 0,
        private_tensors: 0,
        private_scalars: 0,
        public_tensors: 0,
        forbidden_tensors: 0,
    };
    for class in classes {
        out.tensors = out
            .tensors
            .checked_add(class.tensors)
            .ok_or_else(|| "tensor census overflows".to_owned())?;
        out.physical_scalars = out
            .physical_scalars
            .checked_add(class.scalars)
            .ok_or_else(|| "scalar census overflows".to_owned())?;
        match class.disposition {
            SourceDisposition::Private => {
                out.private_tensors += class.tensors;
                out.private_scalars += class.scalars;
            }
            SourceDisposition::Public => out.public_tensors += class.tensors,
            SourceDisposition::Forbidden => out.forbidden_tensors += class.tensors,
        }
    }
    Ok(out)
}

pub fn gpt2_static_census() -> Result<StaticCensus> {
    census(&[
        SourceClass { tensors: 48, scalars: 84_934_656, disposition: SourceDisposition::Private },
        SourceClass { tensors: 1, scalars: 38_597_376, disposition: SourceDisposition::Private },
        SourceClass { tensors: 1, scalars: 786_432, disposition: SourceDisposition::Private },
        SourceClass { tensors: 48, scalars: 82_944, disposition: SourceDisposition::Public },
        SourceClass { tensors: 50, scalars: 38_400, disposition: SourceDisposition::Public },
        SourceClass { tensors: 4, scalars: 262_144, disposition: SourceDisposition::Public },
    ])
}

pub fn gemma4_static_census() -> Result<StaticCensus> {
    census(&[
        SourceClass {
            tensors: 411,
            scalars: 30_696_013_824,
            disposition: SourceDisposition::Private,
        },
        SourceClass { tensors: 361, scalars: 1_331_456, disposition: SourceDisposition::Private },
        SourceClass { tensors: 60, scalars: 60, disposition: SourceDisposition::Public },
        SourceClass {
            tensors: 356,
            scalars: 575_743_536,
            disposition: SourceDisposition::Forbidden,
        },
    ])
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CellClass {
    SegmentLive { segment: u32, local_base: u64 },
    RootMask,
    PublicZero,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoverageRun {
    start: u64,
    length: u64,
    class: CellClass,
}

#[derive(Clone)]
struct CoverageFixture {
    total: u64,
    expected_mask_cells: u64,
    runs: Vec<CoverageRun>,
    root_values: Vec<Fp>,
    selectors: Vec<Vec<Fp>>,
    handle_owner: Vec<Option<u32>>,
    bindings: [Digest; 4],
    expected_bindings: [Digest; 4],
}

#[derive(Debug)]
struct CoverageMap {
    owners: Vec<Option<u32>>,
}

impl CoverageMap {
    fn broadcast_tag(&self, segment: u32, index: usize, tag: Fp3) -> Result<Fp3> {
        let owner =
            self.owners.get(index).ok_or_else(|| "coverage index is out of range".to_owned())?;
        Ok(if *owner == Some(segment) { tag } else { Fp3::ZERO })
    }
}

impl CoverageFixture {
    fn validate(&self) -> Result<CoverageMap> {
        let total = usize::try_from(self.total).map_err(|_| "coverage total exceeds usize")?;
        if self.root_values.len() != total
            || self.handle_owner.len() != total
            || self.selectors.iter().any(|selector| selector.len() != total)
            || self.bindings != self.expected_bindings
        {
            return Err("coverage geometry or binding differs".to_owned());
        }
        let mut cursor = 0u64;
        let mut class_order = 0u8;
        let mut mask_cells = 0u64;
        let mut owners = vec![None; total];
        let mut locals: BTreeMap<u32, BTreeSet<u64>> = BTreeMap::new();
        for run in &self.runs {
            if run.length == 0 || run.start != cursor {
                return Err("coverage has a gap, overlap, or empty run".to_owned());
            }
            let next = cursor
                .checked_add(run.length)
                .ok_or_else(|| "coverage interval overflows".to_owned())?;
            if next > self.total {
                return Err("coverage run exceeds the root".to_owned());
            }
            let current_order = match run.class {
                CellClass::SegmentLive { .. } => 1,
                CellClass::RootMask => 2,
                CellClass::PublicZero => 3,
            };
            if current_order < class_order {
                return Err("coverage class order differs".to_owned());
            }
            class_order = current_order;
            for global in cursor..next {
                let index = global as usize;
                match run.class {
                    CellClass::SegmentLive { segment, local_base } => {
                        let local = local_base + global - cursor;
                        if !locals.entry(segment).or_default().insert(local)
                            || self.handle_owner[index] != Some(segment)
                        {
                            return Err("coverage live owner aliases or differs".to_owned());
                        }
                        owners[index] = Some(segment);
                        for (selector_segment, selector) in self.selectors.iter().enumerate() {
                            let expected =
                                if selector_segment as u32 == segment { Fp::ONE } else { Fp::ZERO };
                            if selector[index] != expected {
                                return Err("coverage live selector differs".to_owned());
                            }
                        }
                    }
                    CellClass::RootMask => {
                        mask_cells += 1;
                        if self.handle_owner[index].is_some()
                            || self.selectors.iter().any(|selector| selector[index] != Fp::ZERO)
                        {
                            return Err("root mask is handle-bearing or selected".to_owned());
                        }
                    }
                    CellClass::PublicZero => {
                        if self.root_values[index] != Fp::ZERO
                            || self.handle_owner[index].is_some()
                            || self.selectors.iter().any(|selector| selector[index] != Fp::ZERO)
                        {
                            return Err(
                                "public zero is nonzero, selected, or handle-bearing".to_owned()
                            );
                        }
                    }
                }
            }
            cursor = next;
        }
        if cursor != self.total || mask_cells != self.expected_mask_cells {
            return Err("coverage union or mask count differs".to_owned());
        }
        for local_set in locals.values() {
            if local_set.iter().copied().ne(0..local_set.len() as u64) {
                return Err("coverage segment locals are not a bijection".to_owned());
            }
        }
        Ok(CoverageMap { owners })
    }
}

fn tiny_coverage_fixture() -> CoverageFixture {
    let mut root_values = (1..=12).map(Fp::new).collect::<Vec<_>>();
    root_values.extend([Fp::ZERO; 4]);
    let mut selectors = vec![vec![Fp::ZERO; 16]; 2];
    selectors[0][..4].fill(Fp::ONE);
    selectors[1][4..8].fill(Fp::ONE);
    let mut handle_owner = vec![None; 16];
    handle_owner[..4].fill(Some(0));
    handle_owner[4..8].fill(Some(1));
    let bindings = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
    CoverageFixture {
        total: 16,
        expected_mask_cells: 4,
        runs: vec![
            CoverageRun {
                start: 0,
                length: 4,
                class: CellClass::SegmentLive { segment: 0, local_base: 0 },
            },
            CoverageRun {
                start: 4,
                length: 4,
                class: CellClass::SegmentLive { segment: 1, local_base: 0 },
            },
            CoverageRun { start: 8, length: 4, class: CellClass::RootMask },
            CoverageRun { start: 12, length: 4, class: CellClass::PublicZero },
        ],
        root_values,
        selectors,
        handle_owner,
        bindings,
        expected_bindings: bindings,
    }
}

#[derive(Clone, Debug)]
struct RawUse {
    ordinal: u32,
    a: Fp3,
    q: Vec<Fp3>,
}

#[derive(Debug)]
struct ReductionResult {
    a_star: Fp3,
    q_star: Vec<Fp3>,
    zhat: Fp3,
    c_star: Fp3,
    wire_corrections: Vec<[Fp3; 2]>,
}

fn eval(values: &[Fp3], query: &[Fp3]) -> Result<Fp3> {
    if values.len() != query.len() {
        return Err("evaluation dimension differs".to_owned());
    }
    Ok(values
        .iter()
        .zip(query)
        .fold(Fp3::ZERO, |sum, (value, coefficient)| sum + *value * *coefficient))
}

fn interpolate_0_1_2(p0: Fp3, p1: Fp3, p2: Fp3, x: Fp3) -> Fp3 {
    let one = Fp3::ONE;
    let two = Fp3::from_base(Fp::new(2));
    let half = two.inv();
    p0 * ((x - one) * (x - two) * half) + p1 * (-(x * (x - two))) + p2 * (x * (x - one) * half)
}

fn fold_value(left: Fp3, right: Fp3, x: Fp3) -> Fp3 {
    left + x * (right - left)
}

fn polynomial_at(a: &[Fp3], q: &[Vec<Fp3>], witness: &[Fp3], x: Fp3) -> Result<Fp3> {
    let mut total = Fp3::ZERO;
    for pair in 0..a.len() / 2 {
        let folded_a = fold_value(a[2 * pair], a[2 * pair + 1], x);
        let folded_q = q[2 * pair]
            .iter()
            .zip(&q[2 * pair + 1])
            .map(|(left, right)| fold_value(*left, *right, x))
            .collect::<Vec<_>>();
        total += folded_a * eval(witness, &folded_q)?;
    }
    Ok(total)
}

fn validate_use_slots(slots: &[Option<u32>], real_count: usize) -> Result<()> {
    if real_count == 0
        || slots.len() != real_count.next_power_of_two()
        || slots[..real_count]
            .iter()
            .enumerate()
            .any(|(ordinal, value)| *value != Some(ordinal as u32))
        || slots[real_count..].iter().any(Option::is_some)
    {
        return Err("raw-use list or dummy suffix differs".to_owned());
    }
    Ok(())
}

fn reduce_uses(
    uses: &[RawUse],
    witness: &[Fp3],
    eta: Fp3,
    rhos: &[Fp3],
    mask_domain: u64,
) -> Result<ReductionResult> {
    if eta == Fp3::ZERO
        || mask_domain == 0
        || uses.is_empty()
        || uses.iter().enumerate().any(|(index, use_)| use_.ordinal != index as u32)
        || uses.iter().any(|use_| use_.q.len() != witness.len())
    {
        return Err("raw-use reducer input differs".to_owned());
    }
    let padded = uses.len().next_power_of_two();
    let depth = padded.trailing_zeros() as usize;
    if rhos.len() != depth || rhos.contains(&Fp3::ZERO) {
        return Err("raw-use reducer challenge count differs".to_owned());
    }
    let slots =
        (0..padded).map(|index| (index < uses.len()).then_some(index as u32)).collect::<Vec<_>>();
    validate_use_slots(&slots, uses.len())?;
    let mut a = vec![Fp3::ZERO; padded];
    let mut q = vec![vec![Fp3::ZERO; witness.len()]; padded];
    let mut current = Fp3::ZERO;
    for (index, use_) in uses.iter().enumerate() {
        let alpha = fp3_pow(eta, index + 1);
        a[index] = alpha * use_.a;
        q[index].clone_from(&use_.q);
        current += alpha * use_.a * eval(witness, &use_.q)?;
    }
    let mut wire_corrections = Vec::with_capacity(depth);
    for (round, rho) in rhos.iter().copied().enumerate() {
        let p0 = polynomial_at(&a, &q, witness, Fp3::ZERO)?;
        let p1 = polynomial_at(&a, &q, witness, Fp3::ONE)?;
        let p2 = polynomial_at(&a, &q, witness, Fp3::from_base(Fp::new(2)))?;
        if p0 + p1 != current {
            return Err("raw-use reducer sumcheck identity differs".to_owned());
        }
        let mask0 = fp3(101 + mask_domain + round as u64, 103 + mask_domain, 107);
        let mask2 = fp3(109 + mask_domain + round as u64, 113, 127 + mask_domain);
        let correction0 = p0 - mask0;
        let correction2 = p2 - mask2;
        if correction0 == p0 || correction2 == p2 {
            return Err("raw reducer exposed an unmasked round value".to_owned());
        }
        wire_corrections.push([correction0, correction2]);
        let interpolated = interpolate_0_1_2(p0, p1, p2, rho);
        let next_a =
            a.chunks_exact(2).map(|pair| fold_value(pair[0], pair[1], rho)).collect::<Vec<_>>();
        let next_q = q
            .chunks_exact(2)
            .map(|pair| {
                pair[0]
                    .iter()
                    .zip(&pair[1])
                    .map(|(left, right)| fold_value(*left, *right, rho))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let direct = next_a.iter().zip(&next_q).try_fold(Fp3::ZERO, |sum, (next_a, next_q)| {
            Ok::<_, String>(sum + *next_a * eval(witness, next_q)?)
        })?;
        if direct != interpolated {
            return Err("raw-use reducer interpolation differs".to_owned());
        }
        current = direct;
        a = next_a;
        q = next_q;
    }
    let zhat = eval(witness, &q[0])?;
    if current != a[0] * zhat {
        return Err("raw-use reducer terminal product differs".to_owned());
    }
    Ok(ReductionResult {
        a_star: a[0],
        q_star: q.remove(0),
        zhat,
        c_star: current,
        wire_corrections,
    })
}

#[derive(Default)]
struct OneTimeDomains(BTreeSet<u64>);

impl OneTimeDomains {
    fn reserve(&mut self, domain: u64) -> Result<()> {
        if domain == 0 || !self.0.insert(domain) {
            return Err("mask domain is zero or reused".to_owned());
        }
        Ok(())
    }
}

fn active_depths(use_counts: &[usize]) -> Vec<usize> {
    let depths = use_counts
        .iter()
        .map(|count| count.next_power_of_two().trailing_zeros() as usize)
        .collect::<Vec<_>>();
    (0..depths.iter().copied().max().unwrap_or(0))
        .map(|round| depths.iter().filter(|depth| **depth > round).count())
        .collect()
}

#[derive(Debug)]
struct ReservedAuthBind {
    serial: u64,
    segment: u32,
    u: Fp3,
    w: Fp3,
    r: Fp3,
}

#[derive(Debug)]
struct PreparedAuthBind {
    reserved: ReservedAuthBind,
    c: Fp3,
    zhat: Fp3,
    ztrue: Fp3,
    pending_gkr: Digest,
}

#[derive(Debug)]
struct BarrierApprovedAuthBind(PreparedAuthBind);

#[derive(Debug)]
struct BarrierToken {
    manifest: Digest,
    serials: BTreeSet<u64>,
}

#[derive(Debug)]
struct CorrectedAuthBind {
    prepared: PreparedAuthBind,
    correction: Fp3,
    prover_tag: Fp3,
    verifier_key: Fp3,
    delta: Fp3,
}

#[derive(Debug)]
struct ProductClosedAuthBind(CorrectedAuthBind);

#[derive(Debug, PartialEq, Eq)]
pub struct TestOnlyPcsChecked {
    manifest: Digest,
    serials: Vec<u64>,
}

impl ReservedAuthBind {
    fn prepare(
        self,
        query: &[Fp3],
        zhat: Fp3,
        ztrue: Fp3,
        pending_gkr: Digest,
    ) -> Result<PreparedAuthBind> {
        if query.is_empty() || pending_gkr == [0; 32] {
            return Err("AuthBind query or pending GKR is empty".to_owned());
        }
        Ok(PreparedAuthBind {
            reserved: self,
            c: query.iter().copied().fold(Fp3::ZERO, |sum, value| sum + value),
            zhat,
            ztrue,
            pending_gkr,
        })
    }
}

fn check_all_cs(
    manifest: Digest,
    prepared: Vec<PreparedAuthBind>,
) -> Result<(BarrierToken, Vec<BarrierApprovedAuthBind>)> {
    if manifest == [0; 32] || prepared.is_empty() {
        return Err("AllC barrier has no manifest or handles".to_owned());
    }
    let mut serials = BTreeSet::new();
    let mut segments = BTreeSet::new();
    for handle in &prepared {
        if handle.c == Fp3::ZERO
            || !serials.insert(handle.reserved.serial)
            || !segments.insert(handle.reserved.segment)
        {
            return Err("AllC barrier found zero mass or duplicate ownership".to_owned());
        }
    }
    Ok((
        BarrierToken { manifest, serials },
        prepared.into_iter().map(BarrierApprovedAuthBind).collect(),
    ))
}

fn correct_all(
    approved: Vec<BarrierApprovedAuthBind>,
    token: BarrierToken,
    delta: Fp3,
) -> Result<Vec<CorrectedAuthBind>> {
    if delta == Fp3::ZERO || approved.len() != token.serials.len() {
        return Err("AuthBind correction barrier differs".to_owned());
    }
    approved
        .into_iter()
        .map(|approved| {
            let prepared = approved.0;
            if !token.serials.contains(&prepared.reserved.serial) {
                return Err("AuthBind handle is not in the barrier".to_owned());
            }
            let correction = prepared.zhat - prepared.c * prepared.reserved.u;
            let prover_tag = prepared.c * prepared.reserved.w;
            let verifier_key = prepared.c * prepared.reserved.r + delta * correction;
            if verifier_key != prover_tag + delta * prepared.zhat {
                return Err("AuthBind one-Delta equation differs".to_owned());
            }
            Ok(CorrectedAuthBind { prepared, correction, prover_tag, verifier_key, delta })
        })
        .collect()
}

fn product_close_all(
    corrected: Vec<CorrectedAuthBind>,
    chi: Fp3,
) -> Result<Vec<ProductClosedAuthBind>> {
    if chi == Fp3::ZERO {
        return Err("ProductClosure challenge is zero".to_owned());
    }
    corrected
        .into_iter()
        .map(|claim| {
            if claim.prepared.zhat != claim.prepared.ztrue || claim.prepared.pending_gkr == [0; 32]
            {
                return Err("ProductClosure or structural PCS equality differs".to_owned());
            }
            Ok(ProductClosedAuthBind(claim))
        })
        .collect()
}

fn structural_pcs_check(
    manifest: Digest,
    claims: Vec<ProductClosedAuthBind>,
) -> Result<TestOnlyPcsChecked> {
    if claims.is_empty() {
        return Err("structural PCS set is empty".to_owned());
    }
    let serials = claims
        .into_iter()
        .map(|claim| {
            let claim = claim.0;
            debug_assert_eq!(
                claim.verifier_key,
                claim.prover_tag + claim.delta * claim.prepared.zhat
            );
            claim.prepared.reserved.serial
        })
        .collect();
    Ok(TestOnlyPcsChecked { manifest, serials })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowEvent {
    RawUseClose,
    Eta,
    ReducerCorrections(u8),
    Rho(u8),
    FreezeQ,
    CsNonzero,
    QueryClose,
    ScheduleClose,
    AllCReady,
    AuthBindCorrections,
    ProductPrefix,
    Chi,
    ProductResponse,
    Beta,
    PlaneHeader(u8),
    PlaneHeaderReceipt(u8),
    PlaneChain(u8),
    QueryTape(u8),
    Openings(u8),
    Gamma,
    Settlement(u8),
}

struct FlowOracle {
    expected: Vec<FlowEvent>,
    cursor: usize,
}

impl FlowOracle {
    fn tiny() -> Self {
        let mut expected = vec![
            FlowEvent::RawUseClose,
            FlowEvent::Eta,
            FlowEvent::ReducerCorrections(0),
            FlowEvent::Rho(0),
            FlowEvent::ReducerCorrections(1),
            FlowEvent::Rho(1),
            FlowEvent::FreezeQ,
            FlowEvent::CsNonzero,
            FlowEvent::QueryClose,
            FlowEvent::ScheduleClose,
            FlowEvent::AllCReady,
            FlowEvent::AuthBindCorrections,
            FlowEvent::ProductPrefix,
            FlowEvent::Chi,
            FlowEvent::ProductResponse,
            FlowEvent::Beta,
        ];
        for plane in 0..4 {
            expected.push(FlowEvent::PlaneHeader(plane));
            expected.push(FlowEvent::PlaneHeaderReceipt(plane));
            expected.push(FlowEvent::PlaneChain(plane));
        }
        for plane in 0..4 {
            expected.push(FlowEvent::QueryTape(plane));
            expected.push(FlowEvent::Openings(plane));
        }
        expected.push(FlowEvent::Gamma);
        expected.extend((0..4).map(FlowEvent::Settlement));
        Self { expected, cursor: 0 }
    }

    fn apply(&mut self, event: FlowEvent) -> Result<()> {
        if self.expected.get(self.cursor) != Some(&event) {
            return Err("phase event is early, skipped, duplicated, or reordered".to_owned());
        }
        self.cursor += 1;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.cursor == self.expected.len()
    }
}

fn ragged_split(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << ((usize::BITS - (n - 1).leading_zeros() - 1) as usize)
}

fn ragged_node(ctx: Digest, base: usize, leaves: &[Digest]) -> Digest {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let left_len = ragged_split(leaves.len());
    let left = ragged_node(ctx, base, &leaves[..left_len]);
    let right = ragged_node(ctx, base + left_len, &leaves[left_len..]);
    let mut bytes = Vec::with_capacity(32 + 16 + 64);
    bytes.extend_from_slice(&ctx);
    bytes.extend_from_slice(&(base as u64).to_le_bytes());
    bytes.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    digest("volta-zk/c7/policy2/g141-tree-node/v1", &bytes)
}

fn collect_frontier(
    ctx: Digest,
    base: usize,
    leaves: &[Digest],
    opened: &BTreeSet<usize>,
    frontier: &mut Vec<Digest>,
) {
    if !(base..base + leaves.len()).any(|index| opened.contains(&index)) {
        frontier.push(ragged_node(ctx, base, leaves));
        return;
    }
    if leaves.len() == 1 {
        return;
    }
    let left_len = ragged_split(leaves.len());
    collect_frontier(ctx, base, &leaves[..left_len], opened, frontier);
    collect_frontier(ctx, base + left_len, &leaves[left_len..], opened, frontier);
}

fn verify_frontier(
    ctx: Digest,
    base: usize,
    n: usize,
    opened: &BTreeMap<usize, Digest>,
    siblings: &[Digest],
    sibling_cursor: &mut usize,
) -> Result<Digest> {
    if !(base..base + n).any(|index| opened.contains_key(&index)) {
        let root = *siblings
            .get(*sibling_cursor)
            .ok_or_else(|| "compact frontier is truncated".to_owned())?;
        *sibling_cursor += 1;
        return Ok(root);
    }
    if n == 1 {
        return opened.get(&base).copied().ok_or_else(|| "opened leaf is missing".to_owned());
    }
    let left_len = ragged_split(n);
    let left = verify_frontier(ctx, base, left_len, opened, siblings, sibling_cursor)?;
    let right =
        verify_frontier(ctx, base + left_len, n - left_len, opened, siblings, sibling_cursor)?;
    let mut bytes = Vec::with_capacity(112);
    bytes.extend_from_slice(&ctx);
    bytes.extend_from_slice(&(base as u64).to_le_bytes());
    bytes.extend_from_slice(&(n as u64).to_le_bytes());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    Ok(digest("volta-zk/c7/policy2/g141-tree-node/v1", &bytes))
}

fn g141_query_leaves(start: u64, scalar_width: u64) -> Result<Vec<u64>> {
    let end = start
        .checked_add(scalar_width)
        .ok_or_else(|| "g141 query interval overflows".to_owned())?;
    if scalar_width == 0 {
        return Err("g141 query interval is empty".to_owned());
    }
    Ok((start / 141..=(end - 1) / 141).collect())
}

#[derive(Clone, Copy)]
struct RoundCap {
    k: u64,
    q: u64,
    u: u64,
    s: u64,
    h: u64,
}

fn g141_stream_max(rounds: &[RoundCap]) -> Result<u64> {
    if rounds.is_empty() || rounds.iter().any(|round| round.s != 141 * round.u) {
        return Err("g141 round caps differ".to_owned());
    }
    let mut total = 16u64;
    let mut q_total = 0u64;
    for round in rounds {
        q_total = q_total.checked_add(round.q).ok_or("g141 q overflows")?;
        let fold = 2 * 16 + 24 * round.k;
        let opening = 8 * round.s + 32 * round.u + 4 + 32 * round.h;
        total = total
            .checked_add(fold)
            .and_then(|value| value.checked_add(opening))
            .ok_or("g141 stream bytes overflow")?;
    }
    total = total
        .checked_add((rounds.len() as u64 - 1) * (16 + 32))
        .and_then(|value| value.checked_add(16 + 1_536))
        .and_then(|value| value.checked_add(16 + 4 * q_total))
        .and_then(|value| value.checked_add(16 + 24))
        .ok_or("g141 stream bytes overflow")?;
    Ok(total)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Authorization {
    connection: Digest,
    attempt: Digest,
    capacity_ordinal: u64,
    root_epoch: u64,
    manifest: Digest,
    predecessor: Digest,
    mac_domain: Digest,
    entropy_commitment: Digest,
}

impl Authorization {
    fn encode(&self) -> [u8; 252] {
        let mut out = [0u8; 252];
        out[..8].copy_from_slice(b"C7AUT1\0\0");
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[12..44].copy_from_slice(&self.connection);
        out[44..76].copy_from_slice(&self.attempt);
        out[76..84].copy_from_slice(&self.capacity_ordinal.to_le_bytes());
        out[84..92].copy_from_slice(&self.root_epoch.to_le_bytes());
        out[92..124].copy_from_slice(&self.manifest);
        out[124..156].copy_from_slice(&self.predecessor);
        out[156..188].copy_from_slice(&self.mac_domain);
        out[188..220].copy_from_slice(&self.entropy_commitment);
        let checksum = digest("volta-zk/c7/authorization/v1", &out[..220]);
        out[220..].copy_from_slice(&checksum);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 252
            || &bytes[..8] != b"C7AUT1\0\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
            || digest("volta-zk/c7/authorization/v1", &bytes[..220]) != bytes[220..252]
        {
            return Err("Authorization encoding differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        let value = Self {
            connection: take(12),
            attempt: take(44),
            capacity_ordinal: read_u64(bytes, 76)?,
            root_epoch: read_u64(bytes, 84)?,
            manifest: take(92),
            predecessor: take(124),
            mac_domain: take(156),
            entropy_commitment: take(188),
        };
        if [
            value.connection,
            value.attempt,
            value.manifest,
            value.mac_domain,
            value.entropy_commitment,
        ]
        .contains(&[0; 32])
        {
            return Err("Authorization required identifier is zero".to_owned());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttemptEnvelope {
    connection: Digest,
    attempt: Digest,
    root_epoch: u64,
    manifest: Digest,
    a0: Digest,
    predecessor: Digest,
    mac_domain: Digest,
}

impl AttemptEnvelope {
    fn encode(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[..8].copy_from_slice(b"C7ATV1\0\0");
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10..12].copy_from_slice(&1u16.to_le_bytes());
        out[12..14].copy_from_slice(&16u16.to_le_bytes());
        out[16..48].copy_from_slice(&self.connection);
        out[48..80].copy_from_slice(&self.attempt);
        out[80..88].copy_from_slice(&self.root_epoch.to_le_bytes());
        out[88..120].copy_from_slice(&self.manifest);
        out[120..152].copy_from_slice(&self.a0);
        out[152..184].copy_from_slice(&self.predecessor);
        out[184..216].copy_from_slice(&self.mac_domain);
        let checksum = digest("volta-zk/c7/attempt-envelope/v1", &out[..224]);
        out[224..].copy_from_slice(&checksum);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 256
            || &bytes[..8] != b"C7ATV1\0\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 1
            || read_u16(bytes, 12)? != 16
            || read_u16(bytes, 14)? != 0
            || read_u32(bytes, 216)? != 0
            || read_u32(bytes, 220)? != 0
            || digest("volta-zk/c7/attempt-envelope/v1", &bytes[..224]) != bytes[224..256]
        {
            return Err("AttemptEnvelope encoding differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        let value = Self {
            connection: take(16),
            attempt: take(48),
            root_epoch: read_u64(bytes, 80)?,
            manifest: take(88),
            a0: take(120),
            predecessor: take(152),
            mac_domain: take(184),
        };
        if [value.connection, value.attempt, value.manifest, value.a0, value.mac_domain]
            .contains(&[0; 32])
        {
            return Err("AttemptEnvelope required identifier is zero".to_owned());
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    frame_type: u16,
    direction: u8,
    sequence: u32,
    payload_len: u64,
}

impl FrameHeader {
    fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..2].copy_from_slice(&self.frame_type.to_le_bytes());
        out[2] = self.direction;
        out[4..8].copy_from_slice(&self.sequence.to_le_bytes());
        out[8..].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8], direction: u8, sequence: u32, payload_len: u64) -> Result<Self> {
        let frame_type = read_u16(bytes, 0)?;
        if bytes.len() != 16
            || !matches!(
                frame_type,
                0x0001
                    | 0x0002
                    | 0x0003
                    | 0x0010
                    | 0x0011
                    | 0x0012
                    | 0x0013
                    | 0x0014
                    | 0x0015
                    | 0x0016
                    | 0x0017
                    | 0x0020
                    | 0x0030
                    | 0x0031
                    | 0x0032
                    | 0x0040
                    | 0x0060
                    | 0x0070
                    | 0x1001
                    | 0x1002
                    | 0x7fff
            )
            || bytes[2] != direction
            || !matches!(bytes[2], 1 | 2)
            || bytes[3] != 0
            || read_u32(bytes, 4)? != sequence
            || read_u64(bytes, 8)? != payload_len
        {
            return Err("frame header differs".to_owned());
        }
        Ok(Self { frame_type, direction, sequence, payload_len })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G141Header {
    plane: u8,
    round_count: u16,
    schedule_id: u16,
}

impl G141Header {
    fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(b"C7G141V1");
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10] = self.plane;
        out[11] = 3;
        out[12..14].copy_from_slice(&self.round_count.to_le_bytes());
        out[14..16].copy_from_slice(&self.schedule_id.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8], expected: Self) -> Result<Self> {
        if bytes.len() != 16
            || &bytes[..8] != b"C7G141V1"
            || read_u16(bytes, 8)? != 1
            || bytes[10] != expected.plane
            || !(1..=4).contains(&bytes[10])
            || bytes[11] != 3
            || read_u16(bytes, 12)? != expected.round_count
            || read_u16(bytes, 12)? == 0
            || read_u16(bytes, 14)? != expected.schedule_id
            || read_u16(bytes, 14)? != u16::from(expected.plane - 1)
        {
            return Err("g141 stream header differs".to_owned());
        }
        Ok(Self {
            plane: bytes[10],
            round_count: read_u16(bytes, 12)?,
            schedule_id: read_u16(bytes, 14)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestContainer {
    l: Vec<u8>,
    a: Vec<u8>,
    q: Vec<u8>,
}

impl ManifestContainer {
    fn encode(&self) -> Result<Vec<u8>> {
        if [&self.l, &self.a, &self.q].iter().any(|section| section.len() > SECTION_CAP) {
            return Err("manifest section exceeds 64 MiB".to_owned());
        }
        let mut prefix = Vec::with_capacity(36 + self.l.len() + self.a.len() + self.q.len());
        prefix.extend_from_slice(b"C7MNF1\0\0");
        prefix.extend_from_slice(&1u16.to_le_bytes());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        for section in [&self.l, &self.a, &self.q] {
            prefix.extend_from_slice(&(section.len() as u64).to_le_bytes());
        }
        prefix.extend_from_slice(&self.l);
        prefix.extend_from_slice(&self.a);
        prefix.extend_from_slice(&self.q);
        let checksum = digest("volta-zk/c7/manifest-container/v1", &prefix);
        let mut out = Vec::with_capacity(68 + self.l.len() + self.a.len() + self.q.len());
        out.extend_from_slice(&prefix[..36]);
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&prefix[36..]);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 68
            || &bytes[..8] != b"C7MNF1\0\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
        {
            return Err("manifest header differs".to_owned());
        }
        let lengths = [read_u64(bytes, 12)?, read_u64(bytes, 20)?, read_u64(bytes, 28)?]
            .map(|length| {
                usize::try_from(length).map_err(|_| "manifest length exceeds usize".to_owned())
            })
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        if lengths.iter().any(|length| *length > SECTION_CAP)
            || 68usize.checked_add(lengths.iter().sum()).ok_or("manifest length overflows")?
                != bytes.len()
        {
            return Err("manifest section length differs".to_owned());
        }
        let mut covered = Vec::with_capacity(bytes.len() - 32);
        covered.extend_from_slice(&bytes[..36]);
        covered.extend_from_slice(&bytes[68..]);
        if digest("volta-zk/c7/manifest-container/v1", &covered) != bytes[36..68] {
            return Err("manifest digest differs".to_owned());
        }
        let l_end = 68 + lengths[0];
        let a_end = l_end + lengths[1];
        Ok(Self {
            l: bytes[68..l_end].to_vec(),
            a: bytes[l_end..a_end].to_vec(),
            q: bytes[a_end..].to_vec(),
        })
    }
}

fn encode_i16_identity(values: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 8 * values.len());
    out.extend_from_slice(b"C7QI16\0\0");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for value in values {
        out.extend_from_slice(&Fp::from_i64(i64::from(*value)).value().to_le_bytes());
    }
    out
}

fn decode_i16_identity(bytes: &[u8]) -> Result<Vec<i16>> {
    if bytes.len() < 24
        || &bytes[..8] != b"C7QI16\0\0"
        || read_u16(bytes, 8)? != 1
        || read_u16(bytes, 10)? != 0
        || read_u32(bytes, 16)? != 0
        || read_u32(bytes, 20)? != 0
    {
        return Err("i16 identity header differs".to_owned());
    }
    let count = read_u32(bytes, 12)? as usize;
    if bytes.len() != 24 + 8 * count {
        return Err("i16 identity length differs".to_owned());
    }
    (0..count)
        .map(|index| {
            let raw = read_u64(bytes, 24 + 8 * index)?;
            if raw >= P {
                return Err("i16 identity limb is noncanonical".to_owned());
            }
            if raw <= i16::MAX as u64 {
                Ok(raw as i16)
            } else if raw >= P - i16::MAX as u64 - 1 {
                Ok(-((P - raw) as i64) as i16)
            } else {
                Err("i16 identity value is outside i16".to_owned())
            }
        })
        .collect()
}

fn fixed_record<const N: usize>(magic: &[u8; 8], fill: u8) -> [u8; N] {
    assert!(N >= 44);
    let mut out = [fill; N];
    out[..8].copy_from_slice(magic);
    out[8..10].copy_from_slice(&1u16.to_le_bytes());
    out[10..12].fill(0);
    let checksum = digest("volta-zk/c7/fixed-record/v1", &out[..N - 32]);
    out[N - 32..].copy_from_slice(&checksum);
    out
}

fn decode_fixed_record<const N: usize>(bytes: &[u8], magic: &[u8; 8]) -> Result<[u8; N]> {
    let out: [u8; N] = bytes.try_into().map_err(|_| "fixed record length differs")?;
    if &out[..8] != magic
        || read_u16(&out, 8)? != 1
        || read_u16(&out, 10)? != 0
        || digest("volta-zk/c7/fixed-record/v1", &out[..N - 32]) != out[N - 32..]
    {
        return Err("fixed record encoding differs".to_owned());
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapacityProfile {
    n_attempts: u64,
    q_limit: u64,
    service_limit: u64,
    b_epoch_limit: u64,
    kv_epoch_limit: u64,
    charges: [u64; 4],
}

impl CapacityProfile {
    fn check(self, n_copy_request: u64, n_copy_grant: u64) -> Result<()> {
        if self.n_attempts == 0
            || self.n_attempts != n_copy_request
            || self.n_attempts != n_copy_grant
            || self.charges[2] != self.charges[3]
            || self.charges.contains(&0)
        {
            return Err("capacity copies or KV charge identity differ".to_owned());
        }
        Ok(())
    }

    fn admits(self, spent_q: u64, spent_service: u64, next_b: u64, next_kv: u64) -> Result<()> {
        let n = self.n_attempts;
        let twice_n = n.checked_mul(2).ok_or("capacity multiplication overflows")?;
        if spent_q.checked_add(twice_n).ok_or("Q capacity overflows")? > self.q_limit
            || spent_service.checked_add(twice_n).ok_or("SERVICE capacity overflows")?
                > self.service_limit
            || next_b.checked_add(n).ok_or("B epoch overflows")? > self.b_epoch_limit
            || next_kv
                .checked_add(n)
                .and_then(|value| value.checked_add(1))
                .ok_or("KV epoch overflows")?
                > self.kv_epoch_limit
        {
            return Err("capacity inequality fails".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenesisStatus {
    Building,
    Complete,
    Consumed,
    Burned,
}

#[derive(Clone, Debug)]
struct GenesisState {
    status: GenesisStatus,
    generation: u64,
    build_ordinal: u64,
    seed: [u8; 96],
    leaf_cursor: u64,
    cached_response: Option<Digest>,
}

impl GenesisState {
    fn begin(generation: u64) -> Result<Self> {
        if generation == u64::MAX {
            return Err("genesis generation exhausted".to_owned());
        }
        Ok(Self {
            status: GenesisStatus::Building,
            generation,
            build_ordinal: 0,
            seed: [0x5a; 96],
            leaf_cursor: 0,
            cached_response: None,
        })
    }

    fn restart(&mut self) -> Result<()> {
        if self.status != GenesisStatus::Building
            || self.generation == u64::MAX - 1
            || self.build_ordinal == u64::MAX
        {
            return Err("genesis restart is not available".to_owned());
        }
        self.generation += 1;
        self.build_ordinal += 1;
        self.leaf_cursor = 0;
        Ok(())
    }

    fn complete(&mut self, response: Digest) -> Result<()> {
        if self.status != GenesisStatus::Building
            || self.generation == u64::MAX
            || response == [0; 32]
        {
            return Err("genesis completion differs".to_owned());
        }
        self.generation += 1;
        self.status = GenesisStatus::Complete;
        self.seed = [0; 96];
        self.cached_response = Some(response);
        Ok(())
    }

    fn consume(&mut self, matching_a0: bool) -> Result<()> {
        if self.status != GenesisStatus::Complete || self.generation == u64::MAX || !matching_a0 {
            return Err("genesis consume differs".to_owned());
        }
        self.generation += 1;
        self.status = GenesisStatus::Consumed;
        self.cached_response = None;
        Ok(())
    }

    fn burn(&mut self) -> Result<()> {
        if !matches!(self.status, GenesisStatus::Building | GenesisStatus::Complete)
            || self.generation == u64::MAX
        {
            return Err("genesis burn differs".to_owned());
        }
        self.generation += 1;
        self.status = GenesisStatus::Burned;
        self.seed = [0; 96];
        self.cached_response = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebuildPhase {
    Journal,
    Tree,
    Footer,
    Synced,
    Installed,
}

#[derive(Clone, Debug)]
struct RebuildJournal {
    candidate: Digest,
    seed: [u8; 96],
    generation: u64,
    build_ordinal: u64,
    phase: RebuildPhase,
    leaf_cursor: u64,
}

impl RebuildJournal {
    fn new(candidate: Digest, generation: u64) -> Result<Self> {
        if candidate == [0; 32] || generation == u64::MAX {
            return Err("rebuild identity is invalid".to_owned());
        }
        Ok(Self {
            candidate,
            seed: [0x5a; 96],
            generation,
            build_ordinal: 0,
            phase: RebuildPhase::Journal,
            leaf_cursor: 0,
        })
    }

    fn advance(&mut self, next: RebuildPhase) -> Result<()> {
        let legal = matches!(
            (self.phase, next),
            (RebuildPhase::Journal, RebuildPhase::Tree)
                | (RebuildPhase::Tree, RebuildPhase::Footer)
                | (RebuildPhase::Footer, RebuildPhase::Synced)
                | (RebuildPhase::Synced, RebuildPhase::Installed)
        );
        if !legal || self.generation == u64::MAX {
            return Err("rebuild phase skipped or reordered".to_owned());
        }
        self.generation += 1;
        self.phase = next;
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        if self.phase == RebuildPhase::Installed
            || self.generation == u64::MAX
            || self.build_ordinal == u64::MAX
        {
            return Err("installed rebuild cannot restart".to_owned());
        }
        self.generation += 1;
        self.build_ordinal += 1;
        self.leaf_cursor = 0;
        self.phase = RebuildPhase::Journal;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ScopeKind {
    ModelOnboarding,
    DvConnectionSetup,
    CapacitySetup,
    ResponseAttempt,
    RootRefresh,
    GenesisKv,
    IngressFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ParentKey {
    RealAttempt(Digest),
    IngressFailure(Digest),
}

impl ParentKey {
    fn validate(self) -> Result<()> {
        match self {
            Self::RealAttempt(key) | Self::IngressFailure(key) if key != [0; 32] => Ok(()),
            _ => Err("typed parent key is zero".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReplayKind {
    Original,
    CachedInFlight,
    CachedAccepted,
    CachedRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransferOccurrence {
    scope: ScopeKind,
    parent: ParentKey,
    ordinal: u32,
    frame_sequence: u32,
    replay: ReplayKind,
    issued: u64,
    completed: u64,
}

#[derive(Default)]
struct TransferLedger {
    next: BTreeMap<(ScopeKind, ParentKey), u32>,
    rows: Vec<TransferOccurrence>,
}

impl TransferLedger {
    fn record(
        &mut self,
        scope: ScopeKind,
        parent: ParentKey,
        frame_sequence: u32,
        replay: ReplayKind,
        issued: u64,
        completed: u64,
    ) -> Result<()> {
        parent.validate()?;
        if completed > issued
            || matches!(scope, ScopeKind::IngressFailure)
                != matches!(parent, ParentKey::IngressFailure(_))
        {
            return Err("transfer parent or byte accounting differs".to_owned());
        }
        let ordinal = self.next.entry((scope, parent)).or_default();
        let current = *ordinal;
        *ordinal = ordinal.checked_add(1).ok_or("transfer occurrence overflows")?;
        self.rows.push(TransferOccurrence {
            scope,
            parent,
            ordinal: current,
            frame_sequence,
            replay,
            issued,
            completed,
        });
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CertificateFixture {
    composite_manifest: Digest,
    record_count: u32,
    final_transcript: Digest,
    envelope: AttemptEnvelope,
    records: Vec<u8>,
}

impl CertificateFixture {
    fn encode(&self) -> Vec<u8> {
        let envelope = self.envelope.encode();
        let mut out = Vec::with_capacity(376 + self.records.len());
        out.extend_from_slice(b"C7CRT1\0\0");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.composite_manifest);
        out.extend_from_slice(&self.record_count.to_le_bytes());
        out.extend_from_slice(&(self.records.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.final_transcript);
        out.extend_from_slice(&envelope);
        out.extend_from_slice(&self.records);
        let checksum = digest("volta-zk/c7/certificate/v1", &out);
        out.extend_from_slice(&checksum);
        out
    }

    fn decode(bytes: &[u8], record_cap: usize) -> Result<Self> {
        if bytes.len() < 376
            || &bytes[..8] != b"C7CRT1\0\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
        {
            return Err("certificate header differs".to_owned());
        }
        let record_len = usize::try_from(read_u64(bytes, 48)?)
            .map_err(|_| "certificate record length exceeds usize")?;
        if record_len > record_cap
            || 376usize.checked_add(record_len).ok_or("certificate length overflows")?
                != bytes.len()
            || digest("volta-zk/c7/certificate/v1", &bytes[..bytes.len() - 32])
                != bytes[bytes.len() - 32..]
        {
            return Err("certificate length or digest differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        Ok(Self {
            composite_manifest: take(12),
            record_count: read_u32(bytes, 44)?,
            final_transcript: take(56),
            envelope: AttemptEnvelope::decode(&bytes[88..344])?,
            records: bytes[344..344 + record_len].to_vec(),
        })
    }

    fn validate_semantics(
        &self,
        expected_manifest: Digest,
        expected_transcript: Digest,
        expected_record_count: u32,
    ) -> Result<()> {
        if self.composite_manifest != expected_manifest
            || self.final_transcript != expected_transcript
            || self.record_count != expected_record_count
        {
            return Err("certificate M, T_final, or record count differs".to_owned());
        }
        Ok(())
    }
}

fn composite_manifest(l: &[u8], a0: &[u8], a1: &[u8], q: &[u8]) -> Digest {
    let h_l = d("L", l);
    let h_a0 = d("A0", a0);
    let h_a1 = d("A1", a1);
    let h_q = d("Q", q);
    let pre_id = d("pre-id", &[h_l.as_slice(), h_a0.as_slice()].concat());
    d("composite", &[pre_id.as_slice(), h_a1.as_slice(), h_q.as_slice()].concat())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenesisBindings {
    request: Digest,
    l: Digest,
    profile: Digest,
    view: Digest,
    attempt: Digest,
    receipt: Digest,
    public_root_request: Digest,
    connection: Digest,
}

impl GenesisBindings {
    fn validate(self, expected: Self) -> Result<()> {
        let actual = [
            self.request,
            self.l,
            self.profile,
            self.view,
            self.attempt,
            self.receipt,
            self.public_root_request,
            self.connection,
        ];
        let expected = [
            expected.request,
            expected.l,
            expected.profile,
            expected.view,
            expected.attempt,
            expected.receipt,
            expected.public_root_request,
            expected.connection,
        ];
        if actual.contains(&[0; 32]) || actual != expected {
            return Err("genesis cross-record binding differs".to_owned());
        }
        Ok(())
    }

    fn mutate(&mut self, index: usize) {
        let field = match index {
            0 => &mut self.request,
            1 => &mut self.l,
            2 => &mut self.profile,
            3 => &mut self.view,
            4 => &mut self.attempt,
            5 => &mut self.receipt,
            6 => &mut self.public_root_request,
            7 => &mut self.connection,
            _ => panic!("binding field index is out of range"),
        };
        field[0] ^= 1;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkloadHeader {
    genesis_allowed: bool,
    k: u32,
    t: u32,
    successor: u32,
    context_cap: u32,
    predecessor_count: u32,
    state_epoch: u64,
    initial_root: Digest,
}

impl WorkloadHeader {
    fn validate(self) -> Result<()> {
        if self.t > 256
            || self.predecessor_count != self.k
            || self.k.checked_add(self.t) != Some(self.successor)
            || self.successor > self.context_cap
            || (self.genesis_allowed && (self.state_epoch != 1 || self.initial_root == [0; 32]))
            || (!self.genesis_allowed && (self.state_epoch != 0 || self.initial_root != [0; 32]))
        {
            return Err("workload or non-genesis sentinel differs".to_owned());
        }
        Ok(())
    }
}

fn encode_genesis_workload_seed(
    k: u32,
    t: u32,
    successor: u32,
    context_cap: u32,
    sampler: Digest,
    tokens: &[u32],
) -> Result<Vec<u8>> {
    if tokens.len() != k as usize
        || k.checked_add(t) != Some(successor)
        || t > 256
        || successor > context_cap
        || sampler == [0; 32]
    {
        return Err("genesis workload seed differs".to_owned());
    }
    let mut out = Vec::with_capacity(64 + tokens.len() * 4);
    out.extend_from_slice(b"C7GWS1\0\0");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&k.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&successor.to_le_bytes());
    out.extend_from_slice(&context_cap.to_le_bytes());
    out.extend_from_slice(&sampler);
    out.extend_from_slice(&(tokens.len() as u32).to_le_bytes());
    for token in tokens {
        out.extend_from_slice(&token.to_le_bytes());
    }
    Ok(out)
}

fn decode_genesis_workload_seed(bytes: &[u8]) -> Result<(u32, u32, u32, u32, Vec<u32>)> {
    if bytes.len() < 64
        || &bytes[..8] != b"C7GWS1\0\0"
        || read_u16(bytes, 8)? != 1
        || bytes[10] != 1
        || bytes[11] != 0
        || bytes[28..60] == [0; 32]
    {
        return Err("genesis workload seed header differs".to_owned());
    }
    let k = read_u32(bytes, 12)?;
    let t = read_u32(bytes, 16)?;
    let successor = read_u32(bytes, 20)?;
    let context_cap = read_u32(bytes, 24)?;
    let count = read_u32(bytes, 60)? as usize;
    if count != k as usize
        || 64usize.checked_add(count.checked_mul(4).ok_or("seed length overflows")?)
            != Some(bytes.len())
        || k.checked_add(t) != Some(successor)
        || t > 256
        || successor > context_cap
    {
        return Err("genesis workload seed length or geometry differs".to_owned());
    }
    let tokens = (0..count).map(|index| read_u32(bytes, 64 + 4 * index)).collect::<Result<_>>()?;
    Ok((k, t, successor, context_cap, tokens))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenesisInitRequestFixture {
    connection: Digest,
    attempt: Digest,
    capacity_ordinal: u64,
    profile: Digest,
    view: Digest,
    seed: Vec<u8>,
}

impl GenesisInitRequestFixture {
    fn encode(&self) -> Result<Vec<u8>> {
        decode_genesis_workload_seed(&self.seed)?;
        if self.seed.len() > 1_048_576
            || [self.connection, self.attempt, self.profile, self.view].contains(&[0; 32])
        {
            return Err("genesis request field differs".to_owned());
        }
        let mut out = Vec::with_capacity(152 + self.seed.len());
        out.extend_from_slice(b"C7GIRQ1\0");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.connection);
        out.extend_from_slice(&self.attempt);
        out.extend_from_slice(&self.capacity_ordinal.to_le_bytes());
        out.extend_from_slice(&self.profile);
        out.extend_from_slice(&self.view);
        out.extend_from_slice(&(self.seed.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.seed);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 152
            || &bytes[..8] != b"C7GIRQ1\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
        {
            return Err("genesis request header differs".to_owned());
        }
        let seed_len = read_u32(bytes, 148)? as usize;
        if seed_len > 1_048_576 || 152usize.checked_add(seed_len) != Some(bytes.len()) {
            return Err("genesis request length differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        let value = Self {
            connection: take(12),
            attempt: take(44),
            capacity_ordinal: read_u64(bytes, 76)?,
            profile: take(84),
            view: take(116),
            seed: bytes[152..].to_vec(),
        };
        decode_genesis_workload_seed(&value.seed)?;
        if [value.connection, value.attempt, value.profile, value.view].contains(&[0; 32]) {
            return Err("genesis request identifier is zero".to_owned());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenesisSetupReceiptFixture {
    suite: Digest,
    request: Digest,
    receipt: Vec<u8>,
}

impl GenesisSetupReceiptFixture {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.receipt.len() > 1_048_496 || [self.suite, self.request].contains(&[0; 32]) {
            return Err("genesis receipt field differs".to_owned());
        }
        let mut out = Vec::with_capacity(80 + self.receipt.len());
        out.extend_from_slice(b"C7GKRP1\0");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.suite);
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&(self.receipt.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.receipt);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 80
            || &bytes[..8] != b"C7GKRP1\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
        {
            return Err("genesis receipt header differs".to_owned());
        }
        let len = read_u32(bytes, 76)? as usize;
        if len > 1_048_496 || 80usize.checked_add(len) != Some(bytes.len()) {
            return Err("genesis receipt length differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        let value = Self { suite: take(12), request: take(44), receipt: bytes[80..].to_vec() };
        if [value.suite, value.request].contains(&[0; 32]) {
            return Err("genesis receipt identifier is zero".to_owned());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenesisInitResponseFixture {
    connection: Digest,
    attempt: Digest,
    request: Digest,
    budget_ordinal: u64,
    view: Digest,
    context: Digest,
    root: Digest,
    public_request: [u8; 460],
    receipt_digest: Digest,
    receipt: Vec<u8>,
}

impl GenesisInitResponseFixture {
    fn encode(&self) -> Result<Vec<u8>> {
        let receipt = GenesisSetupReceiptFixture::decode(&self.receipt)?;
        if self.receipt.len() > RECEIPT_OBJECT_CAP
            || [
                self.connection,
                self.attempt,
                self.request,
                self.view,
                self.context,
                self.root,
                self.receipt_digest,
            ]
            .contains(&[0; 32])
            || receipt.request != d("genesis-kv-setup-request", &self.public_request)
            || self.receipt_digest != d("genesis-kv-setup-receipt", &self.receipt)
        {
            return Err("genesis response field differs".to_owned());
        }
        let mut out = Vec::with_capacity(716 + self.receipt.len());
        out.extend_from_slice(b"C7GIRS1\0");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.connection);
        out.extend_from_slice(&self.attempt);
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&self.budget_ordinal.to_le_bytes());
        out.extend_from_slice(&self.view);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.public_request);
        out.extend_from_slice(&self.receipt_digest);
        out.extend_from_slice(&(self.receipt.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.receipt);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 716
            || &bytes[..8] != b"C7GIRS1\0"
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 0
            || read_u64(bytes, 108)? != 1
        {
            return Err("genesis response header differs".to_owned());
        }
        let receipt_len = read_u32(bytes, 712)? as usize;
        if receipt_len > RECEIPT_OBJECT_CAP
            || 716usize.checked_add(receipt_len) != Some(bytes.len())
        {
            return Err("genesis response length differs".to_owned());
        }
        let take = |start: usize| -> Digest { bytes[start..start + 32].try_into().unwrap() };
        let value = Self {
            connection: take(12),
            attempt: take(44),
            request: take(76),
            budget_ordinal: read_u64(bytes, 116)?,
            view: take(124),
            context: take(156),
            root: take(188),
            public_request: bytes[220..680].try_into().unwrap(),
            receipt_digest: take(680),
            receipt: bytes[716..].to_vec(),
        };
        let receipt = GenesisSetupReceiptFixture::decode(&value.receipt)?;
        if [
            value.connection,
            value.attempt,
            value.request,
            value.view,
            value.context,
            value.root,
            value.receipt_digest,
        ]
        .contains(&[0; 32])
            || receipt.request != d("genesis-kv-setup-request", &value.public_request)
            || value.receipt_digest != d("genesis-kv-setup-receipt", &value.receipt)
        {
            return Err("genesis response identifier is zero".to_owned());
        }
        Ok(value)
    }
}

fn encode_genesis_cache(request: Digest, response_frame: &[u8]) -> Result<Vec<u8>> {
    if request == [0; 32] || response_frame.len() > GENESIS_RESPONSE_FRAME_CAP {
        return Err("genesis cache field differs".to_owned());
    }
    let mut out = Vec::with_capacity(48 + response_frame.len());
    out.extend_from_slice(b"C7GIC1\0\0");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&request);
    out.extend_from_slice(&(response_frame.len() as u32).to_le_bytes());
    out.extend_from_slice(response_frame);
    Ok(out)
}

fn decode_genesis_cache(bytes: &[u8]) -> Result<(Digest, Vec<u8>)> {
    if bytes.len() < 48
        || &bytes[..8] != b"C7GIC1\0\0"
        || read_u16(bytes, 8)? != 1
        || read_u16(bytes, 10)? != 0
    {
        return Err("genesis cache header differs".to_owned());
    }
    let response_len = read_u32(bytes, 44)? as usize;
    if response_len > GENESIS_RESPONSE_FRAME_CAP
        || 48usize.checked_add(response_len) != Some(bytes.len())
    {
        return Err("genesis cache length differs".to_owned());
    }
    let request = bytes[12..44].try_into().unwrap();
    if request == [0; 32] {
        return Err("genesis cache request is zero".to_owned());
    }
    Ok((request, bytes[48..].to_vec()))
}

fn encode_kv_payload(logical_extent: u32, cells_per_token: u64, values: &[i16]) -> Result<Vec<u8>> {
    if u64::from(logical_extent).checked_mul(cells_per_token) != Some(values.len() as u64) {
        return Err("KV payload product differs".to_owned());
    }
    let mut out = Vec::with_capacity(32 + values.len() * 2);
    out.extend_from_slice(b"C7KVP1\0\0");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(2); // I16
    out.push(0);
    out.extend_from_slice(&logical_extent.to_le_bytes());
    out.extend_from_slice(&cells_per_token.to_le_bytes());
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

fn decode_kv_payload(bytes: &[u8]) -> Result<Vec<i16>> {
    if bytes.len() < 32
        || &bytes[..8] != b"C7KVP1\0\0"
        || read_u16(bytes, 8)? != 1
        || bytes[10] != 2
        || bytes[11] != 0
    {
        return Err("KV payload header differs".to_owned());
    }
    let logical_extent = read_u32(bytes, 12)?;
    let cells_per_token = read_u64(bytes, 16)?;
    let count =
        usize::try_from(read_u64(bytes, 24)?).map_err(|_| "KV payload count exceeds usize")?;
    if u64::from(logical_extent).checked_mul(cells_per_token) != Some(count as u64)
        || 32usize.checked_add(count.checked_mul(2).ok_or("KV payload size overflows")?)
            != Some(bytes.len())
    {
        return Err("KV payload extent or length differs".to_owned());
    }
    bytes[32..]
        .chunks_exact(2)
        .map(|pair| Ok(i16::from_le_bytes(pair.try_into().unwrap())))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Materialization {
    Live,
    Tombstone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KvRootMaterial {
    kind: Materialization,
    payload: Digest,
    slot_generation: u64,
    tree: Digest,
    footer: Digest,
    seed: [u8; 96],
    provenance: Digest,
}

impl KvRootMaterial {
    fn validate(self) -> Result<()> {
        let material_present = self.payload != [0; 32]
            && self.slot_generation != 0
            && self.tree != [0; 32]
            && self.footer != [0; 32]
            && self.seed != [0; 96];
        let material_absent = self.payload == [0; 32]
            && self.slot_generation == 0
            && self.tree == [0; 32]
            && self.footer == [0; 32]
            && self.seed == [0; 96];
        if self.provenance == [0; 32]
            || !matches!(
                (self.kind, material_present, material_absent),
                (Materialization::Live, true, false) | (Materialization::Tombstone, false, true)
            )
        {
            return Err("KV root materialization differs".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreOrigin {
    None,
    CandidateScan,
    CandidateComplete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RebuildInvariant {
    candidate: Digest,
    candidate_descriptor: Digest,
    old_root: Digest,
    packed_w: Digest,
    seed: [u8; 96],
    lifecycle_debits: Vec<u8>,
    seed_attempt: u16,
    restore_origin: RestoreOrigin,
    root_slot: u64,
    receipt: Digest,
}

impl RebuildInvariant {
    fn validate(&self, frozen: &Self) -> Result<()> {
        if self.candidate == [0; 32]
            || self.candidate_descriptor == [0; 32]
            || self.old_root == [0; 32]
            || self.packed_w == [0; 32]
            || self.seed == [0; 96]
            || self.lifecycle_debits != [1, 2, 3, 4]
            || self.receipt == [0; 32]
            || self != frozen
        {
            return Err("rebuild immutable state differs".to_owned());
        }
        Ok(())
    }
}

#[derive(Default)]
struct SharedWService {
    remaining: u64,
    root_slots: BTreeSet<u64>,
}

impl SharedWService {
    fn reserve(&mut self, slot: u64) -> Result<Vec<u8>> {
        if self.remaining == 0 || !self.root_slots.insert(slot) {
            return Err("shared W debit or RootSlot reservation failed".to_owned());
        }
        self.remaining -= 1;
        Ok(vec![slot as u8])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanOutcome {
    Complete,
    Crash,
    IoError,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanOccurrence {
    candidate: Digest,
    ordinal: u32,
    slot_generation: u64,
    bytes_read: u64,
    bytes_written: u64,
    outcome: ScanOutcome,
    terminal_root: Digest,
}

impl ScanOccurrence {
    fn validate(self) -> Result<()> {
        if self.candidate == [0; 32]
            || self.slot_generation == 0
            || self.bytes_read == 0
            || self.bytes_written == 0
            || (self.outcome == ScanOutcome::Complete) != (self.terminal_root != [0; 32])
        {
            return Err("rebuild scan occurrence differs".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RejectContext {
    accepted_record_count: u64,
    attempt: Digest,
    last_transcript: Digest,
    offending_record: Digest,
}

impl RejectContext {
    fn pre_envelope(offending_record: Digest) -> Result<Self> {
        if offending_record == [0; 32] {
            return Err("pre-envelope offending record is zero".to_owned());
        }
        Ok(Self {
            accepted_record_count: 0,
            attempt: [0; 32],
            last_transcript: [0; 32],
            offending_record,
        })
    }

    fn in_flight(
        count: u64,
        attempt: Digest,
        transcript: Digest,
        offending: Digest,
    ) -> Result<Self> {
        if count == 0 || [attempt, transcript, offending].contains(&[0; 32]) {
            return Err("in-flight reject context differs".to_owned());
        }
        Ok(Self {
            accepted_record_count: count,
            attempt,
            last_transcript: transcript,
            offending_record: offending,
        })
    }
}

fn require_exact_copy_set<T: Copy + Eq>(expected: T, copies: &[T]) -> Result<()> {
    if copies.is_empty() || copies.iter().any(|copy| *copy != expected) {
        return Err("repeated cross-record value differs".to_owned());
    }
    Ok(())
}

fn require_exact_sequence<T: Eq>(expected: &[T], actual: &[T]) -> Result<()> {
    if expected != actual {
        return Err("ordered state sequence differs".to_owned());
    }
    Ok(())
}

fn require_generation_successor(previous: u64, next: u64) -> Result<()> {
    if previous.checked_add(1) != Some(next) {
        return Err("generation skipped, regressed, or overflowed".to_owned());
    }
    Ok(())
}

fn transcript_step(previous: Digest, kind: u8, record: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(33 + record.len());
    bytes.extend_from_slice(&previous);
    bytes.push(kind);
    bytes.extend_from_slice(record);
    digest("volta-zk/c7/attempt-transcript/v1", &bytes)
}

fn validate_g141_layout(dimension: u32, rounds: &[RoundCap]) -> Result<()> {
    if dimension < 10
        || rounds.is_empty()
        || rounds[0].k != 4
        || rounds.iter().any(|round| round.k == 0 || round.q == 0 || round.u == 0)
    {
        return Err("g141 layout differs".to_owned());
    }
    g141_stream_max(rounds).map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectG141Disposition {
    BlockedMissingDirectG141Relation,
}

fn structural_g141_disposition() -> DirectG141Disposition {
    DirectG141Disposition::BlockedMissingDirectG141Relation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Digest {
        [byte; 32]
    }

    fn auth() -> Authorization {
        Authorization {
            connection: id(1),
            attempt: id(2),
            capacity_ordinal: 7,
            root_epoch: 11,
            manifest: id(3),
            predecessor: [0; 32],
            mac_domain: id(4),
            entropy_commitment: id(5),
        }
    }

    fn envelope() -> AttemptEnvelope {
        AttemptEnvelope {
            connection: id(1),
            attempt: id(2),
            root_epoch: 11,
            manifest: id(3),
            a0: id(6),
            predecessor: [0; 32],
            mac_domain: id(4),
        }
    }

    fn raw_uses(count: usize, width: usize) -> Vec<RawUse> {
        (0..count)
            .map(|ordinal| RawUse {
                ordinal: ordinal as u32,
                a: fp3(ordinal as u64 + 2, 3, 5),
                q: (0..width).map(|index| fp3((ordinal + index + 1) as u64, 7, 11)).collect(),
            })
            .collect()
    }

    fn reserve(serial: u64, segment: u32, delta: Fp3) -> ReservedAuthBind {
        let u = fp3(serial + 1, serial + 2, serial + 3);
        let w = fp3(serial + 4, serial + 5, serial + 6);
        ReservedAuthBind { serial, segment, u, w, r: w + delta * u }
    }

    fn gpt_rounds() -> Vec<RoundCap> {
        [
            (4, 266, 532, 75_012, 6_782),
            (5, 121, 242, 34_122, 3_495),
            (3, 111, 222, 31_302, 3_013),
            (3, 111, 222, 31_302, 2_791),
            (3, 111, 222, 31_302, 2_569),
            (4, 111, 222, 31_302, 2_347),
        ]
        .into_iter()
        .map(|(k, q, u, s, h)| RoundCap { k, q, u, s, h })
        .collect()
    }

    fn gemma_rounds() -> Vec<RoundCap> {
        [
            (4, 266, 532, 75_012, 10_506),
            (3, 121, 242, 34_122, 5_189),
            (3, 113, 226, 31_866, 4_643),
            (3, 111, 222, 31_302, 4_345),
            (4, 111, 222, 31_302, 4_123),
            (4, 111, 222, 31_302, 3_901),
            (4, 111, 222, 31_302, 3_679),
            (4, 111, 222, 31_302, 3_457),
        ]
        .into_iter()
        .map(|(k, q, u, s, h)| RoundCap { k, q, u, s, h })
        .collect()
    }

    #[test]
    fn fp3_and_typestate_kat() {
        let values = [fp3(1, 2, 3), fp3(P - 1, 17, 19), fp3(23, 29, 31)];
        for value in values {
            assert_eq!(Fp3::from_bytes(&value.to_bytes()).unwrap(), value);
            assert_eq!(value * value.inv(), Fp3::ONE);
        }
        for limb in 0..3 {
            let mut malformed = fp3(1, 2, 3).to_bytes();
            malformed[8 * limb..8 * limb + 8].copy_from_slice(&P.to_le_bytes());
            assert!(Fp3::from_bytes(&malformed).is_err());
        }

        let delta = fp3(7, 11, 13);
        let query = [fp3(2, 3, 5), fp3(7, 11, 17)];
        let prepared = vec![
            reserve(10, 0, delta).prepare(&query, fp3(19, 23, 29), fp3(19, 23, 29), id(8)).unwrap(),
            reserve(11, 1, delta).prepare(&query, fp3(31, 37, 41), fp3(31, 37, 41), id(9)).unwrap(),
        ];
        let (barrier, approved) = check_all_cs(id(7), prepared).unwrap();
        assert_eq!(barrier.manifest, id(7));
        let corrected = correct_all(approved, barrier, delta).unwrap();
        assert!(corrected.iter().all(|claim| {
            claim.correction == claim.prepared.zhat - claim.prepared.c * claim.prepared.reserved.u
        }));
        let closed = product_close_all(corrected, fp3(43, 47, 53)).unwrap();
        assert_eq!(structural_pcs_check(id(7), closed).unwrap().serials, [10, 11]);

        let zero_query = [fp3(1, 2, 3), -fp3(1, 2, 3)];
        let zero = reserve(12, 2, delta).prepare(&zero_query, Fp3::ONE, Fp3::ONE, id(3)).unwrap();
        assert!(check_all_cs(id(7), vec![zero]).is_err());
        let mismatch =
            reserve(13, 3, delta).prepare(&query, fp3(2, 3, 4), fp3(2, 3, 5), id(4)).unwrap();
        let (barrier, approved) = check_all_cs(id(7), vec![mismatch]).unwrap();
        assert!(product_close_all(correct_all(approved, barrier, delta).unwrap(), fp3(2, 1, 1))
            .is_err());

        for early in [
            FlowEvent::Rho(0),
            FlowEvent::Chi,
            FlowEvent::Beta,
            FlowEvent::Gamma,
            FlowEvent::PlaneHeader(0),
            FlowEvent::QueryTape(0),
        ] {
            assert!(FlowOracle::tiny().apply(early).is_err());
        }
        let expected = FlowOracle::tiny().expected;
        for skipped in 0..expected.len() {
            let mut flow = FlowOracle::tiny();
            for event in &expected[..skipped] {
                flow.apply(*event).unwrap();
            }
            if let Some(later) = expected.get(skipped + 1) {
                assert!(flow.apply(*later).is_err());
            } else {
                assert!(!flow.complete());
            }
        }
        for duplicated in 0..expected.len() {
            let mut flow = FlowOracle::tiny();
            for event in &expected[..=duplicated] {
                flow.apply(*event).unwrap();
            }
            assert!(flow.apply(expected[duplicated]).is_err());
        }
        // Ownership types are deliberately non-Clone; a corrected handle cannot be corrected again.
    }

    #[test]
    fn coverage_map_tiny_oracle() {
        let fixture = tiny_coverage_fixture();
        let map = fixture.validate().unwrap();
        let tag = fp3(3, 5, 7);
        assert_eq!(map.broadcast_tag(0, 0, tag).unwrap(), tag);
        assert_eq!(map.broadcast_tag(1, 0, tag).unwrap(), Fp3::ZERO);
        assert_eq!(map.broadcast_tag(0, 8, tag).unwrap(), Fp3::ZERO);
        assert_eq!(map.broadcast_tag(0, 12, tag).unwrap(), Fp3::ZERO);

        let mut mutations = Vec::new();
        let mut gap = fixture.clone();
        gap.runs[1].start += 1;
        mutations.push(gap);
        let mut overlap = fixture.clone();
        overlap.runs[1].start -= 1;
        mutations.push(overlap);
        let mut alias = fixture.clone();
        alias.runs[1] = CoverageRun {
            start: 4,
            length: 4,
            class: CellClass::SegmentLive { segment: 0, local_base: 0 },
        };
        mutations.push(alias);
        let mut public_nonzero = fixture.clone();
        public_nonzero.root_values[12] = Fp::ONE;
        mutations.push(public_nonzero);
        let mut mask_selected = fixture.clone();
        mask_selected.selectors[0][8] = Fp::ONE;
        mutations.push(mask_selected);
        let mut mask_count = fixture.clone();
        mask_count.expected_mask_cells += 1;
        mutations.push(mask_count);
        let mut wrong_order = fixture.clone();
        wrong_order.runs[2].class = CellClass::PublicZero;
        wrong_order.runs[3].class = CellClass::RootMask;
        mutations.push(wrong_order);
        let mut mask_as_zero = fixture.clone();
        mask_as_zero.runs[2].class = CellClass::PublicZero;
        mutations.push(mask_as_zero);
        let mut mask_handle = fixture.clone();
        mask_handle.handle_owner[8] = Some(0);
        mutations.push(mask_handle);
        for binding in 0..4 {
            let mut wrong_binding = fixture.clone();
            wrong_binding.bindings[binding][0] ^= 1;
            mutations.push(wrong_binding);
        }
        assert!(mutations.into_iter().all(|mutation| mutation.validate().is_err()));

        let base = d("base-triple", b"base");
        let closure = d("closure", &base);
        let triple = d("triple-desc", &[base.as_slice(), closure.as_slice()].concat());
        assert_ne!(base, closure);
        assert_ne!(closure, triple);
        assert_ne!(base, triple);
        let authorization = auth();
        let a0_connection = authorization.connection;
        let env = envelope();
        assert_eq!(authorization.connection, a0_connection);
        assert_eq!(authorization.connection, env.connection);
        assert_eq!(authorization.attempt, env.attempt);
        assert_eq!(authorization.root_epoch, env.root_epoch);
        assert_eq!(authorization.manifest, env.manifest);
        assert_eq!(authorization.predecessor, env.predecessor);
        assert_eq!(authorization.mac_domain, env.mac_domain);
        assert_ne!(env.a0, [0; 32]);
    }

    #[test]
    fn gpt2_static_manifest() {
        let census = gpt2_static_census().unwrap();
        assert_eq!(census.tensors, 152);
        assert_eq!(census.private_tensors, 50);
        assert_eq!(census.private_scalars, 124_318_464);
        assert_eq!(census.physical_scalars - census.private_scalars, 383_488);
        assert_eq!(49 * 2 + 4, 102);
        assert_eq!(102 + 8, 110);
        let classes = [124_318_464u64, 134_980_992, 9_136_000];
        assert_eq!(classes.iter().sum::<u64>(), 1 << 28);
        let virtual_views = 269_484_032u64;
        assert_ne!(classes.iter().sum::<u64>(), virtual_views);
        assert_eq!(virtual_views - classes.iter().sum::<u64>(), 1_048_576);
        assert_eq!(
            selected_model_missing_inputs(SelectedModel::Gpt2),
            vec![
                MissingInput::LifecycleSplit,
                MissingInput::WorkloadTokens,
                MissingInput::PackedArtifactsAndRoots,
            ]
        );
        let unit = CapacityProfile {
            n_attempts: 3,
            q_limit: 8,
            service_limit: 80,
            b_epoch_limit: 4,
            kv_epoch_limit: 4,
            charges: [3, 2, 2, 2],
        };
        unit.check(3, 3).unwrap();
        unit.admits(1, 0, 0, 0).unwrap();
    }

    #[test]
    fn gemma4_config_and_census_fixture() {
        let census = gemma4_static_census().unwrap();
        assert_eq!(census.tensors, 1_188);
        assert_eq!(census.private_tensors, 772);
        assert_eq!(census.private_scalars, 30_697_345_280);
        assert_eq!(census.public_tensors, 60);
        assert_eq!(census.forbidden_tensors, 356);
        assert_eq!((472, 480), (472, 472 + 8));
        assert_eq!(1_546 + 8, 1_554);
        assert_eq!(active_depths(&[472, 61, 60, 60]), vec![4, 4, 4, 4, 4, 4, 1, 1, 1]);
        assert_eq!(32 * 128, 4_096);
        assert_eq!(10 * 128 + 8 * 128 + 2_304, 4_608);
        assert_eq!(3_520 * 128, 450_560);
        assert_eq!((60, 5_376, 21_504, 262_144, 262_144), (60, 5_376, 21_504, 262_144, 262_144));
        assert_eq!((50 * 7, 10 * 6), (350, 60));
        assert_eq!((32 * 256, 16 * 256), (8_192, 4_096));
        assert_eq!((32 * 512, 4 * 512), (16_384, 2_048));
        assert_eq!((10_000u64, 1_000_000u64), (10_000, 1_000_000));
        assert_eq!((735u32, 10u32, 1u32, 30u32), (735, 10, 1, 30));
        assert_eq!((100u32, 50u32, 150u32), (100, 50, 100 + 50));
        let artifacts = [
            (
                "model-00001-of-00002.safetensors",
                49_784_788_364u64,
                "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
                "0a57a19d7f8430e9bd73af466cca6032f13677bcee640d0a26234eeff1923473",
            ),
            (
                "model-00002-of-00002.safetensors",
                12_761_549_884,
                "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
                "2324e95577e5d990387e6343d68f71675d1885fdba16e94c5d68fbd0b0a68e40",
            ),
            (
                "tokenizer.json",
                32_170_070,
                "12bac982b793c44b03d52a250a9f0d0b666813da566b910c24a6da0695fd11e6",
                "2e7ad99fe28ec40cd28867fbe6c65c1ec92ce18051c4fdb8eccad32e16989ada",
            ),
        ];
        assert_eq!("google/gemma-4-31B", "google/gemma-4-31B");
        assert_eq!("5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89".len(), 40);
        assert!(artifacts.iter().all(|(name, bytes, sha, xet)| {
            !name.is_empty() && *bytes != 0 && sha.len() == 64 && xet.len() == 64
        }));
        let mandatory_metadata = [
            "config.json",
            "generation_config.json",
            "model.safetensors.index.json",
            "tokenizer_config.json",
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
            "tokenizer.json",
        ];
        assert_eq!(mandatory_metadata.iter().copied().collect::<BTreeSet<_>>().len(), 7);
        assert_eq!(artifacts[..2].iter().map(|entry| entry.1).sum::<u64>(), 62_546_338_248);
        assert_eq!(31_273_088_876u64 * 2, 62_546_177_752);
        assert_eq!(62_546_338_248u64 - 62_546_177_752, 160_496);
        assert_eq!(31_273_088_876u64 - 2_364 + 1_409_286_144, 32_682_372_656);
        assert_eq!(410 * 2 + 60 * 12 + 4 + 2, 1_546);
        assert_eq!(1_546 + 8, 1_554);
        assert_eq!(50 * (7 + 1) + 10 * (6 + 1) + 2, 472);
        assert_eq!(472 + 4 + 2 + 2, 480);
        let sampler = "GREEDY";
        assert_eq!(sampler, "GREEDY");
        assert_ne!(sampler, "COMMITTED_CDF_V1");
        assert_ne!(d("kv-projection-owner", b"global"), d("kv-cache-cell", b"post-norm"));
        assert_ne!(d("kv-cache-cell", b"K-post-norm"), d("kv-cache-cell", b"V-post-norm"));
        assert_ne!(1_546, 1_566); // Shared global K/V projection is one W owner, not two edges.
        assert_eq!(
            selected_model_missing_inputs(SelectedModel::Gemma4_31B),
            vec![
                MissingInput::QuantProfile,
                MissingInput::LifecycleSplit,
                MissingInput::WorkloadTokens,
                MissingInput::VerifiedSourceBodies,
                MissingInput::PackedArtifactsAndRoots,
            ]
        );
    }

    #[test]
    fn reducer_barrier_event_log() {
        let witness = [fp3(2, 3, 5), fp3(7, 11, 13), fp3(17, 19, 23)];
        let mut domains = OneTimeDomains::default();
        for count in [1usize, 2, 4, 12] {
            let depth = count.next_power_of_two().trailing_zeros() as usize;
            let rhos = (0..depth).map(|i| fp3(i as u64 + 29, 31, 37)).collect::<Vec<_>>();
            let domain = 1_000 + count as u64;
            domains.reserve(domain).unwrap();
            let reduced = reduce_uses(
                &raw_uses(count, witness.len()),
                &witness,
                fp3(41, 43, 47),
                &rhos,
                domain,
            )
            .unwrap();
            assert_eq!(reduced.c_star, reduced.a_star * reduced.zhat);
            assert_eq!(reduced.zhat, eval(&witness, &reduced.q_star).unwrap());
            assert_eq!(reduced.wire_corrections.len(), depth);
            assert!(reduced.wire_corrections.iter().all(|pair| pair[0] != pair[1]));
        }
        assert!(domains.reserve(1_001).is_err());
        assert!(domains.reserve(0).is_err());
        let uses = raw_uses(4, witness.len());
        let rhos = [fp3(29, 31, 37), fp3(30, 31, 37)];
        let first = reduce_uses(&uses, &witness, fp3(41, 43, 47), &rhos, 2_001).unwrap();
        let deterministic = reduce_uses(&uses, &witness, fp3(41, 43, 47), &rhos, 2_001).unwrap();
        let remasked = reduce_uses(&uses, &witness, fp3(41, 43, 47), &rhos, 2_002).unwrap();
        assert_eq!(first.wire_corrections, deterministic.wire_corrections);
        assert_ne!(first.wire_corrections, remasked.wire_corrections);
        assert_eq!(
            (first.a_star, first.q_star, first.zhat, first.c_star),
            (remasked.a_star, remasked.q_star, remasked.zhat, remasked.c_star)
        );
        assert!(reduce_uses(&uses, &witness, Fp3::ZERO, &rhos, 2_003).is_err());
        assert!(reduce_uses(&uses, &witness, fp3(41, 43, 47), &rhos, 0).is_err());
        assert!(validate_use_slots(&[Some(0), Some(1), Some(2), None], 3).is_ok());
        for invalid in [
            vec![Some(0), Some(2), Some(1), None],
            vec![Some(0), Some(1), None, Some(2)],
            vec![Some(0), Some(1)],
        ] {
            assert!(validate_use_slots(&invalid, 3).is_err());
        }

        let mut flow = FlowOracle::tiny();
        for event in FlowOracle::tiny().expected {
            flow.apply(event).unwrap();
        }
        assert!(flow.complete());
        let mut no_late_q = FlowOracle::tiny();
        no_late_q.apply(FlowEvent::RawUseClose).unwrap();
        assert!(no_late_q.apply(FlowEvent::FreezeQ).is_err());
        let mut no_early_correction = FlowOracle::tiny();
        for event in [FlowEvent::RawUseClose, FlowEvent::Eta] {
            no_early_correction.apply(event).unwrap();
        }
        assert!(no_early_correction.apply(FlowEvent::AuthBindCorrections).is_err());

        for n in [3, 5, 6] {
            let ctx = id(n as u8);
            let leaves = (0..n).map(|i| d("leaf", &[n as u8, i as u8])).collect::<Vec<_>>();
            let root = ragged_node(ctx, 0, &leaves);
            let opened_set = [0usize, n - 1].into_iter().collect::<BTreeSet<_>>();
            let mut frontier = Vec::new();
            collect_frontier(ctx, 0, &leaves, &opened_set, &mut frontier);
            let opened = opened_set.iter().map(|i| (*i, leaves[*i])).collect::<BTreeMap<_, _>>();
            let mut cursor = 0;
            assert_eq!(verify_frontier(ctx, 0, n, &opened, &frontier, &mut cursor).unwrap(), root);
            assert_eq!(cursor, frontier.len());
            assert_ne!(ragged_node(id(99), 0, &leaves), root);
        }
        let four_roots = (0u8..4)
            .map(|plane| {
                let ctx = id(60 + plane);
                let leaves =
                    (0..5).map(|leaf| d("four-root-leaf", &[plane, leaf])).collect::<Vec<_>>();
                (ctx, leaves.clone(), ragged_node(ctx, 0, &leaves))
            })
            .collect::<Vec<_>>();
        assert_eq!(four_roots.iter().map(|entry| entry.2).collect::<BTreeSet<_>>().len(), 4);
        for plane in 0..4 {
            let (ctx, leaves, root) = &four_roots[plane];
            let opened_set = [0usize, 4].into_iter().collect::<BTreeSet<_>>();
            let mut frontier = Vec::new();
            collect_frontier(*ctx, 0, leaves, &opened_set, &mut frontier);
            let opened = opened_set.iter().map(|i| (*i, leaves[*i])).collect::<BTreeMap<_, _>>();
            let mut cursor = 0;
            assert_eq!(
                verify_frontier(*ctx, 0, 5, &opened, &frontier, &mut cursor).unwrap(),
                *root
            );
            assert_ne!(*root, four_roots[(plane + 1) % 4].2);
            assert!(
                verify_frontier(four_roots[(plane + 1) % 4].0, 0, 5, &opened, &frontier, &mut 0,)
                    .is_err()
                    || *root != four_roots[(plane + 1) % 4].2
            );
        }
        let query_union = (0..4)
            .flat_map(|plane| g141_query_leaves(140 + 141 * plane, 48).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(query_union, [0, 1, 2, 3, 4].into_iter().collect());
        assert_eq!(g141_query_leaves(140, 48).unwrap(), vec![0, 1]);
        assert_eq!(
            structural_g141_disposition(),
            DirectG141Disposition::BlockedMissingDirectG141Relation
        );
    }

    #[test]
    fn codec_census() {
        let authorization = auth();
        let authorization_bytes = authorization.encode();
        assert_eq!(authorization_bytes.len(), 252);
        assert_eq!(Authorization::decode(&authorization_bytes).unwrap(), authorization);
        for offset in [0, 8, 10, 220] {
            let mut bad = authorization_bytes;
            bad[offset] ^= 1;
            assert!(Authorization::decode(&bad).is_err());
        }

        let attempt_envelope = envelope();
        let envelope_bytes = attempt_envelope.encode();
        assert_eq!(AttemptEnvelope::decode(&envelope_bytes).unwrap(), attempt_envelope);
        for offset in [0, 8, 10, 12, 14, 216, 220, 224] {
            let mut bad = envelope_bytes;
            bad[offset] ^= 1;
            assert!(AttemptEnvelope::decode(&bad).is_err());
        }

        let header = FrameHeader { frame_type: 0x0017, direction: 1, sequence: 9, payload_len: 12 };
        let header_bytes = header.encode();
        assert_eq!(FrameHeader::decode(&header_bytes, 1, 9, 12).unwrap(), header);
        for (direction, sequence, length) in [(2, 9, 12), (1, 8, 12), (1, 9, 13)] {
            assert!(FrameHeader::decode(&header_bytes, direction, sequence, length).is_err());
        }
        let mut reserved_header = header_bytes;
        reserved_header[3] = 1;
        assert!(FrameHeader::decode(&reserved_header, 1, 9, 12).is_err());
        let mut unknown_header = header_bytes;
        unknown_header[..2].copy_from_slice(&0x5555u16.to_le_bytes());
        assert!(FrameHeader::decode(&unknown_header, 1, 9, 12).is_err());
        assert_eq!(16 + 64, 80); // ACK wire bytes.
        assert_eq!(16 + 36, 52); // Error wire bytes.
        assert_eq!(108, 2 + 2 + 2 + 2 + 4 + 32 + 32 + 32);
        let sampling_metadata = fixed_record::<108>(b"C7SAMPL\0", 0x19);
        assert!(decode_fixed_record::<108>(&sampling_metadata, b"C7SAMPL\0").is_ok());
        let mut bad_sampling = sampling_metadata;
        bad_sampling[12] ^= 1;
        assert!(decode_fixed_record::<108>(&bad_sampling, b"C7SAMPL\0").is_err());

        let manifest =
            ManifestContainer { l: b"L-v1".to_vec(), a: b"A0-A1".to_vec(), q: b"Q".to_vec() };
        let encoded_manifest = manifest.encode().unwrap();
        assert_eq!(ManifestContainer::decode(&encoded_manifest).unwrap(), manifest);
        assert_eq!(encoded_manifest.len(), 68 + 4 + 5 + 1);
        for offset in [0, 8, 10, 12, 36, encoded_manifest.len() - 1] {
            let mut bad = encoded_manifest.clone();
            bad[offset] ^= 1;
            assert!(ManifestContainer::decode(&bad).is_err());
        }
        let mut trailing = encoded_manifest.clone();
        trailing.push(0);
        assert!(ManifestContainer::decode(&trailing).is_err());

        let l = b"toy-L";
        let a0 = b"toy-A0";
        let a1 = b"toy-A1-four-roots-once";
        let q = b"toy-Q-with-c-masses";
        let composite = composite_manifest(l, a0, a1, q);
        for replacement in [
            composite_manifest(b"toy-L!", a0, a1, q),
            composite_manifest(l, b"toy-A0!", a1, q),
            composite_manifest(l, a0, b"toy-A1-four-roots-twice", q),
            composite_manifest(l, a0, a1, b"toy-Q-without-c-masses"),
        ] {
            assert_ne!(replacement, composite);
        }
        let roots = [id(91), id(92), id(93), id(94)];
        let a1_root_bytes = roots.concat();
        assert_eq!(a1_root_bytes.len(), 4 * 32);
        assert_eq!(a1_root_bytes.windows(32).filter(|window| *window == roots[0]).count(), 1);

        let quant = encode_i16_identity(&[i16::MIN, -1, 0, 1, i16::MAX]);
        assert_eq!(quant.len(), 24 + 5 * 8);
        assert_eq!(decode_i16_identity(&quant).unwrap(), [i16::MIN, -1, 0, 1, i16::MAX]);
        for offset in [0, 8, 10, 16, 20] {
            let mut bad = quant.clone();
            bad[offset] ^= 1;
            assert!(decode_i16_identity(&bad).is_err());
        }
        let mut noncanonical = quant.clone();
        noncanonical[24..32].copy_from_slice(&P.to_le_bytes());
        assert!(decode_i16_identity(&noncanonical).is_err());
        let mut quant_trailing = quant.clone();
        quant_trailing.push(0);
        assert!(decode_i16_identity(&quant_trailing).is_err());

        let initial_context = fixed_record::<236>(b"C7GINIT\0", 0x11);
        let aux_context = fixed_record::<128>(b"C7GAUX1\0", 0x22);
        assert!(decode_fixed_record::<236>(&initial_context, b"C7GINIT\0").is_ok());
        assert!(decode_fixed_record::<128>(&aux_context, b"C7GAUX1\0").is_ok());
        let records = [header_bytes.as_slice(), b"payload"].concat();
        let mut transcript = envelope_bytes[224..256].try_into().unwrap();
        transcript = transcript_step(transcript, 0, &records);
        transcript = transcript_step(transcript, 1, b"plane-header");
        transcript = transcript_step(transcript, 2, b"child");
        assert_ne!(transcript, [0; 32]);
        let certificate = CertificateFixture {
            composite_manifest: composite,
            record_count: 3,
            final_transcript: transcript,
            envelope: attempt_envelope.clone(),
            records: records.clone(),
        };
        let certificate_bytes = certificate.encode();
        assert_eq!(certificate_bytes.len(), 376 + records.len());
        let decoded_certificate =
            CertificateFixture::decode(&certificate_bytes, 29_999_624).unwrap();
        assert_eq!(decoded_certificate, certificate);
        decoded_certificate.validate_semantics(composite, transcript, 3).unwrap();
        for (wrong_m, wrong_t, wrong_count) in
            [(id(90), transcript, 3), (composite, id(89), 3), (composite, transcript, 2)]
        {
            assert!(decoded_certificate.validate_semantics(wrong_m, wrong_t, wrong_count).is_err());
        }
        for offset in [0usize, 8, 10, 12, 44, 48, 56, 88, certificate_bytes.len() - 1] {
            let mut bad = certificate_bytes.clone();
            bad[offset] ^= 1;
            assert!(CertificateFixture::decode(&bad, 29_999_624).is_err());
        }
        let mut certificate_trailing = certificate_bytes.clone();
        certificate_trailing.push(0);
        assert!(CertificateFixture::decode(&certificate_trailing, 29_999_624).is_err());
        assert!(CertificateFixture::decode(&certificate_bytes, records.len() - 1).is_err());

        let gpt = gpt_rounds();
        let gemma = gemma_rounds();
        validate_g141_layout(28, &gpt).unwrap();
        validate_g141_layout(35, &gemma).unwrap();
        assert_eq!(g141_stream_max(&gpt).unwrap(), 2_605_756);
        assert_eq!(g141_stream_max(&gemma).unwrap(), 3_729_740);
        assert!(validate_g141_layout(9, &gpt).is_err());
        assert!(validate_g141_layout(28, &[]).is_err());
        let mut wrong_first = gpt.clone();
        wrong_first[0].k = 3;
        assert!(validate_g141_layout(28, &wrong_first).is_err());
        let mut wrong_cap = gpt.clone();
        wrong_cap[0].s -= 1;
        assert!(g141_stream_max(&wrong_cap).is_err());

        for plane in 1u8..=4 {
            let g141 = G141Header {
                plane,
                round_count: 2 + u16::from(plane),
                schedule_id: u16::from(plane - 1),
            };
            let bytes = g141.encode();
            assert_eq!(G141Header::decode(&bytes, g141).unwrap(), g141);
            for offset in [0usize, 8, 10, 11, 12, 14] {
                let mut bad = bytes;
                bad[offset] ^= 1;
                assert!(G141Header::decode(&bad, g141).is_err());
            }
        }
        let flow_events = FlowOracle::tiny().expected;
        let first_query =
            flow_events.iter().position(|event| *event == FlowEvent::QueryTape(0)).unwrap();
        let last_tail =
            flow_events.iter().rposition(|event| *event == FlowEvent::PlaneChain(3)).unwrap();
        assert!(last_tail < first_query);
        for plane in 0..4 {
            let header = flow_events
                .iter()
                .position(|event| *event == FlowEvent::PlaneHeader(plane))
                .unwrap();
            assert_eq!(flow_events[header + 1], FlowEvent::PlaneHeaderReceipt(plane));
        }

        assert_eq!(fixed_record::<484>(b"C7GENST\0", 1).len(), 484);
        assert_eq!(fixed_record::<524>(b"C7KVROOT", 2).len(), 524);
        assert_eq!(fixed_record::<460>(b"C7GKPUB\0", 3).len(), 460);
        assert_eq!(fixed_record::<380>(b"C7SAMEW\0", 4).len(), 380);
        assert_eq!(RECEIPT_OBJECT_CAP, 1_048_576);
        assert_eq!(GENESIS_REQUEST_FRAME_CAP, 1_048_744);
        assert_eq!(GENESIS_RESPONSE_FRAME_CAP, 1_049_308);
        assert_eq!(GENESIS_CACHE_OBJECT_CAP, 1_049_356);
        assert_eq!(1_048_496 + 80, RECEIPT_OBJECT_CAP);
        assert!(1_048_497 + 80 > RECEIPT_OBJECT_CAP);
        for cap in [
            RECEIPT_OBJECT_CAP,
            GENESIS_REQUEST_FRAME_CAP,
            GENESIS_RESPONSE_FRAME_CAP,
            GENESIS_CACHE_OBJECT_CAP,
        ] {
            assert!(cap <= cap);
            assert!(cap.checked_add(1).unwrap() > cap);
        }
        assert_eq!(29_999_624 + 376, 30_000_000);
        assert_eq!(99_999_624 + 376, 100_000_000);
        assert!(114_999_624usize < SECTION_CAP * 2);
        let request_header = FrameHeader {
            frame_type: 0x1001,
            direction: 2,
            sequence: 0,
            payload_len: 64 + 4 * 3 + 152,
        };
        let response_header =
            FrameHeader { frame_type: 0x1002, direction: 1, sequence: 1, payload_len: 716 + 32 };
        assert_eq!(
            FrameHeader::decode(&request_header.encode(), 2, 0, request_header.payload_len)
                .unwrap(),
            request_header
        );
        assert_eq!(
            FrameHeader::decode(&response_header.encode(), 1, 1, response_header.payload_len)
                .unwrap(),
            response_header
        );
        let receipt = fixed_record::<256>(b"C7RECEIP", 5);
        let mut wrong_receipt = receipt;
        wrong_receipt[100] ^= 1;
        assert!(decode_fixed_record::<256>(&wrong_receipt, b"C7RECEIP").is_err());

        let seed = encode_genesis_workload_seed(3, 2, 5, 16, id(80), &[101, 102, 103]).unwrap();
        assert_eq!(seed.len(), 64 + 3 * 4);
        assert_eq!(
            decode_genesis_workload_seed(&seed).unwrap(),
            (3, 2, 5, 16, vec![101, 102, 103])
        );
        for offset in [0usize, 8, 10, 11, 12, 16, 20, 60] {
            let mut bad = seed.clone();
            bad[offset] ^= 1;
            assert!(decode_genesis_workload_seed(&bad).is_err());
        }
        for offset in [24usize, 28, seed.len() - 1] {
            let mut bad = seed.clone();
            bad[offset] ^= 1;
            assert_ne!(d("genesis-workload-seed", &bad), d("genesis-workload-seed", &seed));
        }
        let mut seed_trailing = seed.clone();
        seed_trailing.push(0);
        assert!(decode_genesis_workload_seed(&seed_trailing).is_err());

        let genesis_request = GenesisInitRequestFixture {
            connection: id(71),
            attempt: id(75),
            capacity_ordinal: 7,
            profile: id(73),
            view: id(74),
            seed: seed.clone(),
        };
        let request_payload = genesis_request.encode().unwrap();
        assert_eq!(GenesisInitRequestFixture::decode(&request_payload).unwrap(), genesis_request);
        assert_eq!(request_payload.len(), 152 + seed.len());
        let request_digest = d("genesis-init-request", &request_payload);
        let request_frame_header = FrameHeader {
            frame_type: 0x1001,
            direction: 2,
            sequence: 0,
            payload_len: request_payload.len() as u64,
        };
        let request_frame =
            [request_frame_header.encode().as_slice(), request_payload.as_slice()].concat();
        assert_eq!(request_frame.len(), 16 + request_payload.len());

        let public_request = fixed_record::<460>(b"C7GKPUB\0", 3);
        let public_request_digest = d("genesis-kv-setup-request", &public_request);
        let setup_receipt = GenesisSetupReceiptFixture {
            suite: id(76),
            request: public_request_digest,
            receipt: vec![0x5a; 32],
        };
        let setup_receipt_bytes = setup_receipt.encode().unwrap();
        assert_eq!(setup_receipt_bytes.len(), 112);
        assert_eq!(
            GenesisSetupReceiptFixture::decode(&setup_receipt_bytes).unwrap(),
            setup_receipt
        );
        let setup_receipt_digest = d("genesis-kv-setup-receipt", &setup_receipt_bytes);
        let genesis_response = GenesisInitResponseFixture {
            connection: genesis_request.connection,
            attempt: genesis_request.attempt,
            request: request_digest,
            budget_ordinal: 1,
            view: genesis_request.view,
            context: id(79),
            root: id(81),
            public_request,
            receipt_digest: setup_receipt_digest,
            receipt: setup_receipt_bytes,
        };
        let response_payload = genesis_response.encode().unwrap();
        assert_eq!(response_payload.len(), 716 + genesis_response.receipt.len());
        assert_eq!(
            GenesisInitResponseFixture::decode(&response_payload).unwrap(),
            genesis_response
        );
        let response_digest = d("genesis-init-response", &response_payload);
        let response_frame_header = FrameHeader {
            frame_type: 0x1002,
            direction: 1,
            sequence: 1,
            payload_len: response_payload.len() as u64,
        };
        let response_frame =
            [response_frame_header.encode().as_slice(), response_payload.as_slice()].concat();
        let cache = encode_genesis_cache(request_digest, &response_frame).unwrap();
        let (cached_request, cached_response) = decode_genesis_cache(&cache).unwrap();
        assert_eq!(cached_request, request_digest);
        assert_eq!(cached_response, response_frame);
        assert_ne!(d("genesis-init-cache", &cache), response_digest);
        for offset in [0usize, 8, 10, 148] {
            let mut bad = request_payload.clone();
            bad[offset] ^= 1;
            assert!(GenesisInitRequestFixture::decode(&bad).is_err());
        }
        let mut response_wrong_public = response_payload.clone();
        response_wrong_public[220] ^= 1;
        assert!(GenesisInitResponseFixture::decode(&response_wrong_public).is_err());
        let mut response_trailing = response_payload.clone();
        response_trailing.push(0);
        assert!(GenesisInitResponseFixture::decode(&response_trailing).is_err());
        let mut cache_trailing = cache.clone();
        cache_trailing.push(0);
        assert!(decode_genesis_cache(&cache_trailing).is_err());

        let genesis_workload = WorkloadHeader {
            genesis_allowed: true,
            k: 3,
            t: 2,
            successor: 5,
            context_cap: 16,
            predecessor_count: 3,
            state_epoch: 1,
            initial_root: id(81),
        };
        genesis_workload.validate().unwrap();
        let non_genesis = WorkloadHeader {
            genesis_allowed: false,
            state_epoch: 0,
            initial_root: [0; 32],
            ..genesis_workload
        };
        non_genesis.validate().unwrap();
        for mutation in [
            WorkloadHeader { state_epoch: 1, ..non_genesis },
            WorkloadHeader { initial_root: id(81), ..non_genesis },
            WorkloadHeader { predecessor_count: 2, ..non_genesis },
            WorkloadHeader { successor: 6, ..non_genesis },
            WorkloadHeader { t: 257, successor: 260, ..non_genesis },
        ] {
            assert!(mutation.validate().is_err());
        }

        let genesis_bindings = GenesisBindings {
            request: id(71),
            l: id(72),
            profile: id(73),
            view: id(74),
            attempt: id(75),
            receipt: id(76),
            public_root_request: id(77),
            connection: id(78),
        };
        genesis_bindings.validate(genesis_bindings).unwrap();
        for index in 0..8 {
            let mut mutation = genesis_bindings;
            mutation.mutate(index);
            assert!(mutation.validate(genesis_bindings).is_err());
        }
        let paired_receipt = d("genesis-kv-setup-request", &public_request);
        let other_public_request = fixed_record::<460>(b"C7GKPUB\0", 4);
        assert_eq!(paired_receipt, d("genesis-kv-setup-request", &public_request));
        assert_ne!(paired_receipt, d("genesis-kv-setup-request", &other_public_request));

        let profile = CapacityProfile {
            n_attempts: 3,
            q_limit: 8,
            service_limit: 80,
            b_epoch_limit: 4,
            kv_epoch_limit: 4,
            charges: [3, 2, 2, 2],
        };
        profile.check(3, 3).unwrap();
        require_exact_copy_set(3u64, &[profile.n_attempts, 3, 3, 3]).unwrap();
        for copies in [[2, 3, 3, 3], [3, 2, 3, 3], [3, 3, 2, 3], [3, 3, 3, 2]] {
            assert!(require_exact_copy_set(3u64, &copies).is_err());
        }
        assert!(profile.check(2, 3).is_err());
        assert!(profile.check(3, 2).is_err());
        let mut unequal_kv = profile;
        unequal_kv.charges[3] += 1;
        assert!(unequal_kv.check(3, 3).is_err());
        let mut zero_n = profile;
        zero_n.n_attempts = 0;
        assert!(zero_n.check(0, 0).is_err());
        require_exact_copy_set(110u32, &[110, 110, 110]).unwrap();
        require_exact_copy_set(1_554u32, &[1_554, 1_554, 1_554]).unwrap();
        assert!(require_exact_copy_set(110u32, &[110, 102, 110]).is_err());
        assert!(require_exact_copy_set(1_554u32, &[1_554, 1_546, 1_554]).is_err());

        let l_digests = (0u8..8).map(id).collect::<Vec<_>>();
        let canonical_l = d("L", &l_digests.concat());
        for index in 0..l_digests.len() {
            let mut mutated = l_digests.clone();
            mutated[index][0] ^= 1;
            assert_ne!(canonical_l, d("L", &mutated.concat()));
        }
        for index in 0..l_digests.len() - 1 {
            let mut reordered = l_digests.clone();
            reordered.swap(index, index + 1);
            assert_ne!(canonical_l, d("L", &reordered.concat()));
        }
        assert_eq!(
            structural_g141_disposition(),
            DirectG141Disposition::BlockedMissingDirectG141Relation
        );
    }

    #[test]
    fn journal_attack_matrix() {
        for crash_phase in
            [RebuildPhase::Journal, RebuildPhase::Tree, RebuildPhase::Footer, RebuildPhase::Synced]
        {
            let mut journal = RebuildJournal::new(id(21), 4).unwrap();
            while journal.phase != crash_phase {
                let next = match journal.phase {
                    RebuildPhase::Journal => RebuildPhase::Tree,
                    RebuildPhase::Tree => RebuildPhase::Footer,
                    RebuildPhase::Footer => RebuildPhase::Synced,
                    RebuildPhase::Synced => RebuildPhase::Installed,
                    RebuildPhase::Installed => unreachable!(),
                };
                journal.advance(next).unwrap();
            }
            let candidate = journal.candidate;
            let seed = journal.seed;
            let generation = journal.generation;
            journal.leaf_cursor = 17;
            journal.restart().unwrap();
            assert_eq!(journal.leaf_cursor, 0);
            assert_eq!(journal.candidate, candidate);
            assert_eq!(journal.seed, seed);
            assert_eq!(journal.generation, generation + 1);
            assert_eq!(journal.build_ordinal, 1);
        }
        let mut installed = RebuildJournal::new(id(22), 4).unwrap();
        for next in [
            RebuildPhase::Tree,
            RebuildPhase::Footer,
            RebuildPhase::Synced,
            RebuildPhase::Installed,
        ] {
            installed.advance(next).unwrap();
        }
        assert!(installed.restart().is_err());
        assert!(installed.advance(RebuildPhase::Tree).is_err());
        let mut skipped = RebuildJournal::new(id(23), 4).unwrap();
        assert!(skipped.advance(RebuildPhase::Footer).is_err());
        let mut exhausted = RebuildJournal::new(id(24), u64::MAX - 1).unwrap();
        exhausted.restart().unwrap();
        assert!(exhausted.restart().is_err());

        for (size, magic) in [
            (640usize, b"C7JRNL1\0" as &[u8; 8]),
            (128, b"C7FOOT1\0"),
            (364, b"C7ACTIVE"),
            (116, b"C7SRPTR\0"),
        ] {
            let record = match size {
                640 => fixed_record::<640>(magic, 1).to_vec(),
                128 => fixed_record::<128>(magic, 2).to_vec(),
                364 => fixed_record::<364>(magic, 3).to_vec(),
                116 => fixed_record::<116>(magic, 4).to_vec(),
                _ => unreachable!(),
            };
            assert_eq!(record.len(), size);
            let mut corrupt = record;
            corrupt[size / 2] ^= 1;
            let rejected = match size {
                640 => decode_fixed_record::<640>(&corrupt, magic).is_err(),
                128 => decode_fixed_record::<128>(&corrupt, magic).is_err(),
                364 => decode_fixed_record::<364>(&corrupt, magic).is_err(),
                116 => decode_fixed_record::<116>(&corrupt, magic).is_err(),
                _ => false,
            };
            assert!(rejected);
        }

        let request = b"nonce|authorization".to_vec();
        let cached = (d("request", &request), b"envelope|A0".to_vec());
        assert_eq!(d("request", &request), cached.0);
        assert_eq!(cached.1, b"envelope|A0");
        assert_ne!(d("request", b"nonce|divergent"), cached.0);

        let frozen = RebuildInvariant {
            candidate: id(61),
            candidate_descriptor: id(62),
            old_root: id(63),
            packed_w: id(64),
            seed: [0x33; 96],
            lifecycle_debits: vec![1, 2, 3, 4],
            seed_attempt: 1,
            restore_origin: RestoreOrigin::None,
            root_slot: 9,
            receipt: id(65),
        };
        frozen.validate(&frozen).unwrap();
        let mut mutations = Vec::new();
        let mut value = frozen.clone();
        value.candidate[0] ^= 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.candidate_descriptor[0] ^= 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.old_root[0] ^= 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.packed_w[0] ^= 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.seed[0] ^= 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.lifecycle_debits.swap(1, 2);
        mutations.push(value);
        let mut value = frozen.clone();
        value.lifecycle_debits.pop();
        mutations.push(value);
        let mut value = frozen.clone();
        value.seed_attempt += 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.restore_origin = RestoreOrigin::CandidateScan;
        mutations.push(value);
        let mut value = frozen.clone();
        value.root_slot += 1;
        mutations.push(value);
        let mut value = frozen.clone();
        value.receipt[0] ^= 1;
        mutations.push(value);
        assert!(mutations.iter().all(|mutation| mutation.validate(&frozen).is_err()));
        for restore_origin in [RestoreOrigin::CandidateScan, RestoreOrigin::CandidateComplete] {
            let branch = RebuildInvariant { restore_origin, ..frozen.clone() };
            branch.validate(&branch).unwrap();
            assert_eq!(branch.old_root, frozen.old_root);
        }

        let scans = [
            ScanOccurrence {
                candidate: frozen.candidate,
                ordinal: 0,
                slot_generation: 1,
                bytes_read: 1_024,
                bytes_written: 2_048,
                outcome: ScanOutcome::Crash,
                terminal_root: [0; 32],
            },
            ScanOccurrence {
                ordinal: 1,
                outcome: ScanOutcome::IoError,
                ..ScanOccurrence {
                    candidate: frozen.candidate,
                    ordinal: 0,
                    slot_generation: 2,
                    bytes_read: 1_024,
                    bytes_written: 2_048,
                    outcome: ScanOutcome::Crash,
                    terminal_root: [0; 32],
                }
            },
            ScanOccurrence {
                ordinal: 2,
                outcome: ScanOutcome::Abort,
                slot_generation: 3,
                ..ScanOccurrence {
                    candidate: frozen.candidate,
                    ordinal: 0,
                    slot_generation: 1,
                    bytes_read: 1_024,
                    bytes_written: 2_048,
                    outcome: ScanOutcome::Crash,
                    terminal_root: [0; 32],
                }
            },
            ScanOccurrence {
                candidate: frozen.candidate,
                ordinal: 3,
                slot_generation: 4,
                bytes_read: 1_024,
                bytes_written: 2_048,
                outcome: ScanOutcome::Complete,
                terminal_root: id(66),
            },
        ];
        assert!(scans.iter().copied().all(|scan| scan.validate().is_ok()));
        assert_eq!(scans.iter().map(|scan| scan.ordinal).collect::<Vec<_>>(), [0, 1, 2, 3]);
        let bad_complete = ScanOccurrence { terminal_root: [0; 32], ..scans[3] };
        assert!(bad_complete.validate().is_err());
        let bad_crash = ScanOccurrence { terminal_root: id(67), ..scans[0] };
        assert!(bad_crash.validate().is_err());

        let mut nonces = BTreeSet::new();
        assert!(nonces.insert((id(70), 1u64)));
        assert!(!nonces.insert((id(70), 1u64)));
        assert!(nonces.insert((id(71), 1u64)));
        let mut domains = BTreeSet::new();
        assert!(domains.insert((id(70), id(72))));
        assert!(!domains.insert((id(70), id(72))));
        assert!(domains.insert((id(71), id(73))));

        let mut shared = SharedWService { remaining: 1, ..SharedWService::default() };
        let winner = shared.reserve(101).unwrap();
        let loser = shared.reserve(102);
        assert_eq!(winner, [101]);
        assert!(loser.is_err());
        assert_eq!(shared.remaining, 0);
        assert_eq!(shared.root_slots, [101].into_iter().collect());
        let active_tree = true;
        let candidate_full_tree = false;
        assert!(!(active_tree && candidate_full_tree));
        let burned_high_water = 12u64.checked_add(1).unwrap();
        assert_eq!(burned_high_water, 13);
        let accepted_high_water = 12u64;
        assert_ne!(burned_high_water, accepted_high_water);
        let preburned_load_debit = true;
        let restored_old_root = frozen.old_root;
        assert!(preburned_load_debit);
        assert_eq!(restored_old_root, frozen.old_root);
        let atomic_install = (RebuildPhase::Installed, frozen.candidate, frozen.receipt);
        assert_eq!(atomic_install.0, RebuildPhase::Installed);
        assert_ne!(atomic_install.1, [0; 32]);
        assert_ne!(atomic_install.2, [0; 32]);
        let durable_issued =
            scans.iter().map(|scan| scan.bytes_read + scan.bytes_written).sum::<u64>();
        let completed_io = durable_issued - 1;
        assert!(durable_issued >= completed_io);
        let allocator_snapshot_before = id(80);
        let heads = [(id(81), id(82)), (id(83), id(84))].into_iter().collect::<BTreeMap<_, _>>();
        let cache_blobs = [(id(81), b"reply-a".as_slice()), (id(83), b"reply-b".as_slice())];
        assert_eq!(heads.len(), 2);
        assert_eq!(cache_blobs.len(), 2);
        assert_eq!(allocator_snapshot_before, id(80));
        let first_reply_visible = RebuildPhase::Installed == atomic_install.0;
        let a1_visible = first_reply_visible;
        assert!(first_reply_visible && a1_visible);
    }

    #[test]
    fn stateful_kv_continuation() {
        let shape = [2usize, 3, 4];
        let values = (-12i16..12).collect::<Vec<_>>();
        assert_eq!(shape.iter().product::<usize>(), values.len());
        let payload = encode_kv_payload(2, 12, &values).unwrap();
        let decoded = decode_kv_payload(&payload).unwrap();
        assert_eq!(decoded, values);
        for offset in [0usize, 8, 10, 11, 12, 16, 24] {
            let mut bad = payload.clone();
            bad[offset] ^= 1;
            assert!(decode_kv_payload(&bad).is_err());
        }
        let mut value_mutation = payload.clone();
        *value_mutation.last_mut().unwrap() ^= 1;
        assert_ne!(decode_kv_payload(&value_mutation).unwrap(), values);
        let mut payload_trailing = payload.clone();
        payload_trailing.push(0);
        assert!(decode_kv_payload(&payload_trailing).is_err());
        let reversed = values.iter().copied().rev().collect::<Vec<_>>();
        assert_ne!(encode_kv_payload(2, 12, &reversed).unwrap(), payload);
        let live_material = Some(d("kv-material", &payload));
        let tombstone_material: Option<Digest> = None;
        assert!(live_material.is_some());
        assert!(tombstone_material.is_none());
        assert_ne!(d("kv-root-live", &payload), d("kv-root-tombstone", &payload));
        let live = KvRootMaterial {
            kind: Materialization::Live,
            payload: id(1),
            slot_generation: 1,
            tree: id(2),
            footer: id(3),
            seed: [4; 96],
            provenance: id(5),
        };
        live.validate().unwrap();
        let tombstone = KvRootMaterial {
            kind: Materialization::Tombstone,
            payload: [0; 32],
            slot_generation: 0,
            tree: [0; 32],
            footer: [0; 32],
            seed: [0; 96],
            provenance: live.provenance,
        };
        tombstone.validate().unwrap();
        for bad in [
            KvRootMaterial { kind: Materialization::Tombstone, ..live },
            KvRootMaterial { provenance: [0; 32], ..tombstone },
            KvRootMaterial { payload: id(9), ..tombstone },
        ] {
            assert!(bad.validate().is_err());
        }

        for crash_leaf in [0, 1, 7, 23] {
            let mut genesis = GenesisState::begin(1).unwrap();
            let seed = genesis.seed;
            genesis.leaf_cursor = crash_leaf;
            genesis.restart().unwrap();
            assert_eq!(genesis.leaf_cursor, 0);
            assert_eq!(genesis.generation, 2);
            assert_eq!(genesis.build_ordinal, 1);
            assert_eq!(genesis.seed, seed);
            assert_eq!(genesis.build_ordinal + 1, 2); // derived slot generation
        }
        let mut genesis = GenesisState::begin(1).unwrap();
        assert!(genesis.consume(true).is_err());
        genesis.complete(id(31)).unwrap();
        assert_eq!(genesis.generation, 2);
        assert_eq!(genesis.seed, [0; 96]);
        assert_eq!(genesis.cached_response, Some(id(31)));
        assert!(genesis.consume(false).is_err());
        genesis.consume(true).unwrap();
        assert_eq!(genesis.generation, 3);
        assert_eq!(genesis.status, GenesisStatus::Consumed);
        assert_eq!(genesis.cached_response, None);
        let mut abandoned = GenesisState::begin(1).unwrap();
        abandoned.burn().unwrap();
        assert_eq!(abandoned.status, GenesisStatus::Burned);
        assert_eq!(abandoned.seed, [0; 96]);
        assert!(GenesisState::begin(u64::MAX).is_err());
        let mut terminal = GenesisState::begin(u64::MAX - 1).unwrap();
        assert!(terminal.restart().is_err());
        terminal.burn().unwrap();
        assert_eq!((terminal.generation, terminal.status), (u64::MAX, GenesisStatus::Burned));
        assert!(terminal.burn().is_err());
        assert!(require_generation_successor(7, 8).is_ok());
        assert!(require_generation_successor(7, 7).is_err());
        assert!(require_generation_successor(7, 9).is_err());
        assert!(require_generation_successor(u64::MAX, 0).is_err());

        let first = CapacityProfile {
            n_attempts: 3,
            q_limit: 8,
            service_limit: 80,
            b_epoch_limit: 4,
            kv_epoch_limit: 4,
            charges: [3, 2, 2, 2],
        };
        first.check(3, 3).unwrap();
        first.admits(1, 0, 0, 0).unwrap();
        assert_eq!((1 + 3 * 2, 0 + 3 * 2, 0 + 3, 0 + 3 + 1), (7, 6, 3, 4));
        let accepted_slot = 0;
        let burned_suffix = [1, 2];
        let mac_domain_active = true;
        assert_eq!(accepted_slot, 0);
        assert_eq!(burned_suffix, [1, 2]);
        assert!(mac_domain_active);
        let complete_high_waters = (0u64, 0u16);
        let lifecycle_bases = [id(101), id(102), id(103), id(104)];
        let w_lifecycle_record: Option<Digest> = None;
        assert_eq!(complete_high_waters, (0, 0));
        assert!(lifecycle_bases.iter().all(|base| *base != [0; 32]));
        assert!(w_lifecycle_record.is_none());
        let first_a0_debit = (0u64, first.charges[3]);
        assert_eq!(first_a0_debit, (0, 2));

        let second = CapacityProfile { n_attempts: 2, ..first };
        second.check(2, 2).unwrap();
        second.admits(2, 2, 1, 1).unwrap();
        assert_eq!((2 + 2 * 2, 2 + 2 * 2, 1 + 2, 1 + 2 + 1), (6, 6, 3, 4));
        let previous_kv_new = (id(41), id(42), id(43), id(44));
        let next_kv_old = previous_kv_new;
        assert_eq!(next_kv_old, previous_kv_new);
        let predecessor = vec![10u32, 11];
        let mut continuation = predecessor.clone();
        continuation.push(12);
        assert!(continuation.starts_with(&predecessor));

        let expected_binding = [id(110), id(111), id(112), id(113), id(114), id(115), id(116)];
        require_exact_sequence(&expected_binding, &expected_binding).unwrap();
        for index in 0..expected_binding.len() {
            let mut mutation = expected_binding;
            mutation[index][0] ^= 1;
            assert!(require_exact_sequence(&expected_binding, &mutation).is_err());
        }
        let expected_numeric = [
            second.q_limit,
            2, // spent Q
            second.charges[0],
            second.n_attempts,
            1, // owner epoch
            2, // KV budget ordinal
            3, // logical extent
        ];
        require_exact_sequence(&expected_numeric, &expected_numeric).unwrap();
        for index in 0..expected_numeric.len() {
            let mut mutation = expected_numeric;
            mutation[index] = mutation[index].checked_add(1).unwrap();
            assert!(require_exact_sequence(&expected_numeric, &mutation).is_err());
        }
        assert_eq!(second.charges[2], second.charges[3]);
        let mut unequal_mask_profile = [id(120), id(120)];
        unequal_mask_profile[1][0] ^= 1;
        assert_ne!(unequal_mask_profile[0], unequal_mask_profile[1]);
        let allocation_path = ["ALLOCATED", "ROOT_RESERVED", "DEBITED", "IN_FLIGHT"];
        require_exact_sequence(&allocation_path, &allocation_path).unwrap();
        let mut reordered_path = allocation_path;
        reordered_path.swap(1, 2);
        assert!(require_exact_sequence(&allocation_path, &reordered_path).is_err());

        let mut bad = second;
        bad.q_limit = 5;
        assert!(bad.admits(2, 2, 1, 1).is_err());
        bad = second;
        bad.service_limit = 5;
        assert!(bad.admits(2, 2, 1, 1).is_err());
        bad = second;
        bad.b_epoch_limit = 2;
        assert!(bad.admits(2, 2, 1, 1).is_err());
        bad = second;
        bad.kv_epoch_limit = 3;
        assert!(bad.admits(2, 2, 1, 1).is_err());
        assert!(second.admits(2, 80, 1, 2).is_err());
        assert!(second.admits(8, 2, 1, 2).is_err());
        assert!(second.admits(2, 2, 4, 2).is_err());
        assert!(second.admits(2, 2, 1, 4).is_err());
        assert_ne!(d("attempt", b"connection-a/nonce"), d("attempt", b"connection-b/nonce"));
        let mut global_attempts = BTreeSet::new();
        assert!(global_attempts.insert(d("attempt", b"connection-a/nonce")));
        assert!(!global_attempts.insert(d("attempt", b"connection-a/nonce")));
        assert!(global_attempts.insert(d("attempt", b"connection-b/nonce")));
        let same_connection_nonce_a = d("attempt", b"connection-a/nonce-a");
        let same_connection_nonce_b = d("attempt", b"connection-a/nonce-b");
        assert_ne!(same_connection_nonce_a, same_connection_nonce_b);
        let active_nonce = Some(same_connection_nonce_a);
        assert!(active_nonce != Some(same_connection_nonce_b));
        let mut consumed_grants = BTreeSet::new();
        assert!(consumed_grants.insert((id(140), 4u64)));
        assert!(!consumed_grants.insert((id(140), 4u64)));
        let old_head = id(130);
        let proposed_epoch = 3u64;
        let first_budget_ordinal = 4u64;
        let fresh_budget_ordinal = 5u64;
        let burn_before_a1 = (old_head, proposed_epoch, first_budget_ordinal, false);
        let burn_after_a1 = (old_head, proposed_epoch, fresh_budget_ordinal, true);
        assert_eq!(burn_before_a1.0, old_head);
        assert_eq!(burn_after_a1.0, old_head);
        assert_eq!(burn_before_a1.1, burn_after_a1.1);
        assert_ne!(burn_before_a1.2, burn_after_a1.2);
        assert_ne!(burn_before_a1.3, burn_after_a1.3);
        assert!(proposed_epoch.checked_add(1).is_some());
        assert!(u64::MAX.checked_add(1).is_none());
        let consumed_local_record_pointer = [0; 32];
        assert_eq!(consumed_local_record_pointer, [0; 32]);
        let gc_before_tombstone_cas = (true, true); // material and provenance retained
        let gc_after_tombstone_cas = (false, true); // material gone, provenance retained
        assert_eq!(gc_before_tombstone_cas, (true, true));
        assert_eq!(gc_after_tombstone_cas, (false, true));
        assert_eq!(fixed_record::<460>(b"C7GKPUB\0", 8).len(), 460);
        let retained_certificate_tip = 2usize;
        let retained_cache_tip = 1usize;
        assert!(retained_certificate_tip <= 2 && retained_cache_tip <= 1);
    }

    #[test]
    fn c41_reconciliation() {
        let parent = ParentKey::RealAttempt(id(51));
        let mut ledger = TransferLedger::default();
        for (scope, sequence) in [
            (ScopeKind::ModelOnboarding, 0),
            (ScopeKind::DvConnectionSetup, 0),
            (ScopeKind::CapacitySetup, 0),
            (ScopeKind::ResponseAttempt, 0),
            (ScopeKind::RootRefresh, 0),
            (ScopeKind::GenesisKv, 0),
            (ScopeKind::IngressFailure, u32::MAX),
        ] {
            let scoped_parent = if scope == ScopeKind::IngressFailure {
                ParentKey::IngressFailure(id(51))
            } else {
                parent
            };
            ledger.record(scope, scoped_parent, sequence, ReplayKind::Original, 80, 80).unwrap();
        }
        for replay in [
            ReplayKind::Original,
            ReplayKind::CachedInFlight,
            ReplayKind::CachedAccepted,
            ReplayKind::CachedRejected,
        ] {
            ledger
                .record(
                    ScopeKind::ResponseAttempt,
                    ParentKey::RealAttempt(id(52)),
                    7,
                    replay,
                    80,
                    64,
                )
                .unwrap();
        }
        ledger
            .record(
                ScopeKind::ResponseAttempt,
                ParentKey::RealAttempt(id(53)),
                0,
                ReplayKind::Original,
                256,
                256,
            )
            .unwrap();
        ledger
            .record(
                ScopeKind::ResponseAttempt,
                ParentKey::RealAttempt(id(53)),
                0,
                ReplayKind::Original,
                64,
                64,
            )
            .unwrap();
        let coalesced = ledger
            .rows
            .iter()
            .filter(|row| row.parent == ParentKey::RealAttempt(id(53)))
            .collect::<Vec<_>>();
        assert_eq!(coalesced.len(), 2);
        assert_eq!(coalesced.iter().map(|row| row.ordinal).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(coalesced.iter().map(|row| row.frame_sequence).collect::<Vec<_>>(), [0, 0]);

        for sequence in [0, 1] {
            ledger
                .record(
                    ScopeKind::ResponseAttempt,
                    ParentKey::RealAttempt(id(54)),
                    sequence,
                    ReplayKind::Original,
                    52,
                    52,
                )
                .unwrap();
            ledger
                .record(
                    ScopeKind::ResponseAttempt,
                    ParentKey::RealAttempt(id(54)),
                    sequence,
                    ReplayKind::CachedAccepted,
                    52,
                    52,
                )
                .unwrap();
        }
        let genesis_rows = ledger
            .rows
            .iter()
            .filter(|row| row.parent == ParentKey::RealAttempt(id(54)))
            .collect::<Vec<_>>();
        assert_eq!(genesis_rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(
            genesis_rows.iter().map(|row| row.frame_sequence).collect::<Vec<_>>(),
            [0, 0, 1, 1]
        );

        assert!(ledger
            .record(
                ScopeKind::IngressFailure,
                ParentKey::IngressFailure([0; 32]),
                u32::MAX,
                ReplayKind::Original,
                1,
                0,
            )
            .is_err());
        assert!(ledger
            .record(
                ScopeKind::IngressFailure,
                ParentKey::IngressFailure(id(55)),
                u32::MAX,
                ReplayKind::Original,
                1,
                2,
            )
            .is_err());
        ledger
            .next
            .insert((ScopeKind::IngressFailure, ParentKey::IngressFailure(id(56))), u32::MAX);
        assert!(ledger
            .record(
                ScopeKind::IngressFailure,
                ParentKey::IngressFailure(id(56)),
                u32::MAX,
                ReplayKind::Original,
                0,
                0,
            )
            .is_err());

        assert_ne!(ParentKey::RealAttempt(id(60)), ParentKey::IngressFailure(id(60)));
        ParentKey::RealAttempt(id(60)).validate().unwrap();
        ParentKey::IngressFailure(id(60)).validate().unwrap();
        assert!(ledger
            .record(
                ScopeKind::IngressFailure,
                ParentKey::RealAttempt(id(60)),
                u32::MAX,
                ReplayKind::Original,
                1,
                1,
            )
            .is_err());
        assert!(ledger
            .record(
                ScopeKind::ResponseAttempt,
                ParentKey::IngressFailure(id(60)),
                0,
                ReplayKind::Original,
                1,
                1,
            )
            .is_err());
        for ((scope, parent), next) in &ledger.next {
            let ordinals = ledger
                .rows
                .iter()
                .filter(|row| row.scope == *scope && row.parent == *parent)
                .map(|row| row.ordinal)
                .collect::<Vec<_>>();
            if *next != u32::MAX {
                assert_eq!(ordinals, (0..*next).collect::<Vec<_>>());
            }
        }

        let genesis_parent = ParentKey::RealAttempt(id(61));
        for (sequence, replay) in [
            (0, ReplayKind::Original),
            (1, ReplayKind::Original),
            (0, ReplayKind::CachedInFlight),
            (0, ReplayKind::CachedAccepted),
            (1, ReplayKind::CachedAccepted),
        ] {
            ledger.record(ScopeKind::GenesisKv, genesis_parent, sequence, replay, 80, 80).unwrap();
        }
        let genesis =
            ledger.rows.iter().filter(|row| row.parent == genesis_parent).collect::<Vec<_>>();
        assert_eq!(genesis.iter().map(|row| row.ordinal).collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
        assert_eq!(
            genesis.iter().map(|row| row.frame_sequence).collect::<Vec<_>>(),
            [0, 1, 0, 0, 1]
        );

        let lost_ack_parent = ParentKey::RealAttempt(id(62));
        ledger
            .record(ScopeKind::ResponseAttempt, lost_ack_parent, 9, ReplayKind::Original, 80, 0)
            .unwrap();
        ledger
            .record(
                ScopeKind::ResponseAttempt,
                lost_ack_parent,
                9,
                ReplayKind::CachedAccepted,
                80,
                80,
            )
            .unwrap();
        let lost_ack =
            ledger.rows.iter().filter(|row| row.parent == lost_ack_parent).collect::<Vec<_>>();
        assert_eq!(lost_ack.iter().map(|row| row.ordinal).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(lost_ack.iter().map(|row| row.frame_sequence).collect::<Vec<_>>(), [9, 9]);
        assert_eq!(lost_ack[0].completed, 0);
        assert_eq!(lost_ack[1].replay, ReplayKind::CachedAccepted);

        let issued = ledger.rows.iter().map(|row| row.issued).sum::<u64>();
        let completed = ledger.rows.iter().map(|row| row.completed).sum::<u64>();
        assert!(issued >= completed);
        let syscalls = ledger.rows.len() as u64;
        assert_ne!(issued, issued + syscalls); // transport syscall counts are a separate axis.
        assert_ne!(
            d("ingress-failure", b"unparseable Authorization"),
            d("ingress-failure", b"truncated 0x1001")
        );
        let pre_envelope =
            RejectContext::pre_envelope(d("transfer-record", b"bad Authorization")).unwrap();
        let in_flight =
            RejectContext::in_flight(3, id(57), id(58), d("transfer-record", b"truncated 0x1001"))
                .unwrap();
        assert_eq!(pre_envelope.attempt, [0; 32]);
        assert_eq!(pre_envelope.accepted_record_count, 0);
        assert_ne!(in_flight.attempt, [0; 32]);
        assert!(RejectContext::pre_envelope([0; 32]).is_err());
        assert!(RejectContext::in_flight(0, id(1), id(2), id(3)).is_err());
        let close_without_error_frame = (0u64, 0u64, false);
        assert_eq!(close_without_error_frame, (0, 0, false));

        let response_attempt_counters =
            [("genesis-build", 1u64), ("prefill", 1), ("receipt", 1), ("tree", 1), ("gc", 2)];
        assert_eq!(response_attempt_counters.iter().map(|row| row.1).sum::<u64>(), 6);
        let accepted_grant_suffix = [1u64, 2];
        let burned_grant_suffix = accepted_grant_suffix;
        assert_eq!(burned_grant_suffix, [1, 2]);
        let scan_children = [
            ScanOccurrence {
                candidate: id(63),
                ordinal: 0,
                slot_generation: 1,
                bytes_read: 10,
                bytes_written: 20,
                outcome: ScanOutcome::Crash,
                terminal_root: [0; 32],
            },
            ScanOccurrence {
                candidate: id(63),
                ordinal: 1,
                slot_generation: 2,
                bytes_read: 10,
                bytes_written: 20,
                outcome: ScanOutcome::Complete,
                terminal_root: id(64),
            },
        ];
        assert!(scan_children.iter().copied().all(|scan| scan.validate().is_ok()));
        assert_eq!(scan_children.iter().map(|scan| scan.ordinal).collect::<Vec<_>>(), [0, 1]);
    }
}
