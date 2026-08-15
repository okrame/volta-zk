//! Reference-only private-entropy transport for C6AWP1.
//!
//! The provider endpoint owns only a synchronous channel.  Verifier entropy,
//! its transcript state, and any replay checkpoint stay in the broker thread.
//! A disconnected attempt can be replayed deterministically to a recorded
//! frontier: every provider move must match byte-for-byte before its old
//! challenge is released, after which the broker continues with fresh draws.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::point::Point;
use p3_symmetric::MerkleCap;
use volta_field::P;
use volta_mac::{
    Transcript, TranscriptChallengeChannel, TranscriptChallengeRequest, TranscriptChallengeResponse,
};
use volta_proto::c6::{C6ClientAttempt, C6ClientState, C6Digest, C6_MAC_COORDINATES};

use crate::c61_whir_reference::{
    C61Commitment, C61P3Fp2, C61WhirInteractionStats, C61WhirReferenceError, ReferenceResult,
    C61_WHIRA1_DIGEST_BYTES, C61_WHIRA1_FP_BYTES,
};

const C61_PRIVATE_MESSAGE_LABEL: &str = "c61.native.interactive_message";
const C61_PRIVATE_FINAL_LABEL: &str = "c61.native.final_payload";
const C61_INTERACTIVE_CHECKPOINT_MAGIC: [u8; 8] = *b"C6ICT1\0\0";
const C61_INTERACTIVE_CHECKPOINT_VERSION: u16 = 1;
const C61_INTERACTIVE_CHECKPOINT_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4 + 32;
const C61_INTERACTIVE_CHECKPOINT_MAX_BYTES: usize = 1_000_000;
const C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS: usize = 100_000;
const C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES: usize = 1_000_000;
const C61_INTERACTIVE_TAPE_MAGIC: [u8; 8] = *b"C6ICT2\0\0";
const C61_INTERACTIVE_TAPE_VERSION: u16 = 2;
const C61_INTERACTIVE_TAPE_HEADER_BYTES: usize = 104;
const C61_INTERACTIVE_TAPE_DIGEST_BYTES: usize = 32;
const C61_INTERACTIVE_TAPE_MAX_BYTES: usize = 2_100_000;
pub const C61_INTERACTIVE_TAPE_LANES: usize = 7;
const C61_INTERACTIVE_BUNDLE_TAPE_COUNT: usize = C61_INTERACTIVE_TAPE_LANES + 1;
const C61_INTERACTIVE_BUNDLE_MAGIC: [u8; 8] = *b"C6ICB3\0\0";
const C61_INTERACTIVE_BUNDLE_VERSION: u16 = 2;
const C61_INTERACTIVE_BUNDLE_HEADER_BYTES: usize = 80;
const C61_INTERACTIVE_BUNDLE_LANE_HEADER_BYTES: usize = 36;
const C61_INTERACTIVE_BUNDLE_DIGEST_BYTES: usize = 32;
const C61_INTERACTIVE_BUNDLE_MAX_BYTES: usize = C61_INTERACTIVE_BUNDLE_HEADER_BYTES
    + C61_INTERACTIVE_BUNDLE_TAPE_COUNT
        * (C61_INTERACTIVE_BUNDLE_LANE_HEADER_BYTES + C61_INTERACTIVE_TAPE_MAX_BYTES)
    + C61_INTERACTIVE_BUNDLE_DIGEST_BYTES;
const C61_DURABLE_JOURNAL_MAGIC: [u8; 8] = *b"C6ICJ1\0\0";
const C61_DURABLE_JOURNAL_VERSION: u16 = 1;
const C61_DURABLE_JOURNAL_MAX_MASK_EVENTS: usize = 16;
const C61_DURABLE_RECORD_CHALLENGE: u8 = 1;
const C61_DURABLE_RECORD_MASK_FRONTIER: u8 = 2;
const C61_DURABLE_RECORD_FINISH: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
enum C61ChallengeKind {
    Fp,
    Fp2,
    Query { bits: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum C61ChallengeValue {
    Fp(u64),
    Fp2([u64; 2]),
    Query(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C61ChallengeRecord {
    provider_move: Vec<u8>,
    kind: C61ChallengeKind,
    value: C61ChallengeValue,
}

impl C61ChallengeRecord {
    fn encode_body(&self) -> ReferenceResult<Vec<u8>> {
        let (kind, bits, value, extension) = match (&self.kind, &self.value) {
            (C61ChallengeKind::Fp, C61ChallengeValue::Fp(value)) => (0u8, 0u8, *value, None),
            (C61ChallengeKind::Fp2, C61ChallengeValue::Fp2([c0, c1])) => (2u8, 0u8, *c0, Some(*c1)),
            (C61ChallengeKind::Query { bits }, C61ChallengeValue::Query(value)) => {
                (1u8, *bits, u64::from(*value), None)
            }
            _ => return Err(C61WhirReferenceError::new("C6ICT1 challenge tag mismatch")),
        };
        if self.provider_move.len() > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES {
            return Err(C61WhirReferenceError::new("C6ICT1 provider move exceeds cap"));
        }
        let mut bytes =
            Vec::with_capacity(16 + extension.map_or(0, |_| 8) + self.provider_move.len());
        bytes.push(kind);
        bytes.push(bits);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.provider_move.len())
                .map_err(|_| C61WhirReferenceError::new("C6ICT1 move length exceeds u32"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&value.to_le_bytes());
        if let Some(extension) = extension {
            bytes.extend_from_slice(&extension.to_le_bytes());
        }
        bytes.extend_from_slice(&self.provider_move);
        Ok(bytes)
    }

    fn decode_body(bytes: &[u8]) -> ReferenceResult<Self> {
        let mut reader = C61CheckpointReader::new(bytes);
        let kind_tag = reader.u8()?;
        let bits = reader.u8()?;
        if reader.u16()? != 0 {
            return Err(C61WhirReferenceError::new("C6ICT1 record reserved field is nonzero"));
        }
        let move_len = reader.u32()?;
        if move_len > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES {
            return Err(C61WhirReferenceError::new("C6ICT1 provider move exceeds cap"));
        }
        let raw_value = reader.u64()?;
        let (kind, value) = match kind_tag {
            0 if bits == 0 && raw_value < P => {
                (C61ChallengeKind::Fp, C61ChallengeValue::Fp(raw_value))
            }
            1 if (1..=32).contains(&bits) && raw_value < (1u64 << bits) => (
                C61ChallengeKind::Query { bits },
                C61ChallengeValue::Query(
                    u32::try_from(raw_value)
                        .map_err(|_| C61WhirReferenceError::new("C6ICT1 query exceeds u32"))?,
                ),
            ),
            2 if bits == 0 && raw_value < P => {
                let c1 = reader.u64()?;
                if c1 >= P {
                    return Err(C61WhirReferenceError::new("C6ICT2 noncanonical Fp2 challenge"));
                }
                (C61ChallengeKind::Fp2, C61ChallengeValue::Fp2([raw_value, c1]))
            }
            _ => return Err(C61WhirReferenceError::new("C6ICT1 noncanonical challenge")),
        };
        let provider_move = reader.take(move_len)?.to_vec();
        reader.finish()?;
        Ok(Self { provider_move, kind, value })
    }
}

/// Verifier-local resumable prefix.  It contains already released public
/// challenges and exact provider moves, but never the verifier entropy seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C61InteractiveCheckpoint {
    num_variables: u8,
    context_digest: [u8; 32],
    records: Vec<C61ChallengeRecord>,
}

impl C61InteractiveCheckpoint {
    pub(crate) fn empty(num_variables: usize, context_digest: [u8; 32]) -> ReferenceResult<Self> {
        let num_variables = u8::try_from(num_variables)
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 dimension exceeds u8"))?;
        Ok(Self { num_variables, context_digest, records: Vec::new() })
    }

    pub(crate) fn challenge_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn encode(&self) -> ReferenceResult<Vec<u8>> {
        if self.records.len() > C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS {
            return Err(C61WhirReferenceError::new("C6ICT1 record count exceeds cap"));
        }
        let mut bytes = Vec::with_capacity(C61_INTERACTIVE_CHECKPOINT_HEADER_BYTES);
        bytes.extend_from_slice(&C61_INTERACTIVE_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&C61_INTERACTIVE_CHECKPOINT_VERSION.to_le_bytes());
        bytes.push(self.num_variables);
        bytes.push(0);
        bytes.extend_from_slice(
            &u32::try_from(self.records.len())
                .map_err(|_| C61WhirReferenceError::new("C6ICT1 record count exceeds u32"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.context_digest);
        for record in &self.records {
            bytes.extend_from_slice(&record.encode_body()?);
            if bytes.len() > C61_INTERACTIVE_CHECKPOINT_MAX_BYTES {
                return Err(C61WhirReferenceError::new("C6ICT1 payload exceeds cap"));
            }
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> ReferenceResult<Self> {
        if bytes.len() > C61_INTERACTIVE_CHECKPOINT_MAX_BYTES {
            return Err(C61WhirReferenceError::new("C6ICT1 payload exceeds cap"));
        }
        let mut reader = C61CheckpointReader::new(bytes);
        if reader.take(8)? != C61_INTERACTIVE_CHECKPOINT_MAGIC {
            return Err(C61WhirReferenceError::new("C6ICT1 magic mismatch"));
        }
        if reader.u16()? != C61_INTERACTIVE_CHECKPOINT_VERSION {
            return Err(C61WhirReferenceError::new("C6ICT1 version mismatch"));
        }
        let num_variables = reader.u8()?;
        if reader.u8()? != 0 {
            return Err(C61WhirReferenceError::new("C6ICT1 reserved byte is nonzero"));
        }
        let count = reader.u32()?;
        if count > C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS {
            return Err(C61WhirReferenceError::new("C6ICT1 record count exceeds cap"));
        }
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(reader.take(32)?);
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let start = reader.offset;
            let kind = reader.u8()?;
            let _bits = reader.u8()?;
            let _reserved = reader.u16()?;
            let move_len = reader.u32()?;
            let _value = reader.u64()?;
            if kind == 2 {
                let _extension_value = reader.u64()?;
            }
            reader.take(move_len)?;
            records.push(C61ChallengeRecord::decode_body(&bytes[start..reader.offset])?);
        }
        reader.finish()?;
        Ok(Self { num_variables, context_digest, records })
    }

    pub(crate) fn mutate_first_move_for_test(&mut self) {
        if let Some(byte) =
            self.records.first_mut().and_then(|record| record.provider_move.first_mut())
        {
            *byte ^= 1;
        }
    }
}

struct C61CheckpointReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> C61CheckpointReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> ReferenceResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C61WhirReferenceError::new("C6ICT1 cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(C61WhirReferenceError::new("truncated C6ICT1 payload"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> ReferenceResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> ReferenceResult<u16> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> ReferenceResult<usize> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw) as usize)
    }

    fn u64(&mut self) -> ReferenceResult<u64> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn finish(self) -> ReferenceResult<()> {
        if self.offset != self.bytes.len() {
            return Err(C61WhirReferenceError::new("trailing bytes in C6ICT1 payload"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C61DurableBinding {
    digest: C6Digest,
    slot: u32,
    raw_counts: [u64; C6_MAC_COORDINATES],
    raw_ends: [u64; C6_MAC_COORDINATES],
}

impl C61DurableBinding {
    pub(crate) fn from_reserved_attempt(
        state: C6ClientState,
        attempt: C6ClientAttempt,
        num_variables: usize,
        context_digest: [u8; 32],
    ) -> ReferenceResult<Self> {
        state.validate().map_err(|error| {
            C61WhirReferenceError::new(format!("invalid C6 client state: {error}"))
        })?;
        if state.pending_attempt != Some(attempt) {
            return Err(C61WhirReferenceError::new(
                "C6ICT1 durable binding requires the current reserved attempt",
            ));
        }
        let mut raw_counts = [0u64; C6_MAC_COORDINATES];
        let mut raw_ends = [0u64; C6_MAC_COORDINATES];
        for coordinate in 0..C6_MAC_COORDINATES {
            let range = attempt.correlation_ranges.coordinates[coordinate];
            raw_counts[coordinate] = range.count;
            raw_ends[coordinate] = range
                .start
                .checked_add(range.count)
                .ok_or_else(|| C61WhirReferenceError::new("C6ICT1 raw range overflows"))?;
            if raw_ends[coordinate] != state.raw_high_water[coordinate] {
                return Err(C61WhirReferenceError::new(
                    "C6ICT1 durable binding does not end at client high-water",
                ));
            }
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"volta-zk/c61/durable-interaction-binding/v1");
        hasher.update(&state.connection_id);
        hasher.update(&state.setup_manifest_digest);
        hasher.update(&attempt.slot.to_le_bytes());
        hasher.update(&attempt.nonce);
        hasher.update(&attempt.old_head_digest);
        hasher.update(&attempt.predecessor_certificate_digest);
        hasher.update(&(num_variables as u64).to_le_bytes());
        hasher.update(&context_digest);
        for range in attempt.correlation_ranges.coordinates {
            hasher.update(&range.stage.to_le_bytes());
            hasher.update(&range.start.to_le_bytes());
            hasher.update(&range.count.to_le_bytes());
        }
        Ok(Self { digest: *hasher.finalize().as_bytes(), slot: attempt.slot, raw_counts, raw_ends })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C61DurableResume {
    checkpoint: C61InteractiveCheckpoint,
    mask_events: Vec<(usize, u32, [u8; 32])>,
    final_seal: Option<(usize, usize, [u8; 32])>,
}

#[derive(Debug)]
pub(crate) struct C61DurableJournal {
    file: File,
    binding: C61DurableBinding,
    resume: C61DurableResume,
    sequence: u32,
    last_checksum: [u8; 32],
}

fn c61_durable_header(
    binding: C61DurableBinding,
    num_variables: u8,
    context_digest: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&C61_DURABLE_JOURNAL_MAGIC);
    body.extend_from_slice(&C61_DURABLE_JOURNAL_VERSION.to_le_bytes());
    body.push(num_variables);
    body.push(0);
    body.extend_from_slice(&context_digest);
    body.extend_from_slice(&binding.digest);
    body.extend_from_slice(&binding.slot.to_le_bytes());
    for count in binding.raw_counts {
        body.extend_from_slice(&count.to_le_bytes());
    }
    for end in binding.raw_ends {
        body.extend_from_slice(&end.to_le_bytes());
    }
    let checksum = blake3::derive_key("volta-zk/c61/durable-header/v1", &body);
    body.extend_from_slice(&checksum);
    body
}

fn c61_durable_record(
    binding_digest: [u8; 32],
    previous_checksum: [u8; 32],
    sequence: u32,
    tag: u8,
    payload: &[u8],
) -> ReferenceResult<(Vec<u8>, [u8; 32])> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| C61WhirReferenceError::new("C6ICJ1 record exceeds u32"))?;
    let mut body = Vec::with_capacity(12 + payload.len());
    body.push(tag);
    body.extend_from_slice(&[0; 3]);
    body.extend_from_slice(&sequence.to_le_bytes());
    body.extend_from_slice(&payload_len.to_le_bytes());
    body.extend_from_slice(payload);
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c61/durable-record/v1");
    hasher.update(&binding_digest);
    hasher.update(&previous_checksum);
    hasher.update(&body);
    let checksum = *hasher.finalize().as_bytes();
    body.extend_from_slice(&checksum);
    Ok((body, checksum))
}

fn c61_parent(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn c61_sync_directory(path: &Path) -> ReferenceResult<()> {
    File::open(path).and_then(|directory| directory.sync_all()).map_err(|error| {
        C61WhirReferenceError::new(format!("cannot sync C6ICJ1 directory: {error}"))
    })
}

#[cfg(unix)]
fn c61_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn c61_private_file(_options: &mut OpenOptions) {}

impl C61DurableJournal {
    pub(crate) fn create(
        path: impl AsRef<Path>,
        binding: C61DurableBinding,
        checkpoint: C61InteractiveCheckpoint,
    ) -> ReferenceResult<Self> {
        if checkpoint.challenge_count() != 0 {
            return Err(C61WhirReferenceError::new("new C6ICJ1 journal must start empty"));
        }
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(c61_parent(&path)).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot create C6ICJ1 directory: {error}"))
        })?;
        let header =
            c61_durable_header(binding, checkpoint.num_variables, checkpoint.context_digest);
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(true);
        c61_private_file(&mut options);
        let mut file = options.open(&path).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot create C6ICJ1 journal: {error}"))
        })?;
        file.write_all(&header).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot write C6ICJ1 header: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            C61WhirReferenceError::new(format!("cannot sync C6ICJ1 header: {error}"))
        })?;
        c61_sync_directory(c61_parent(&path))?;
        let last_checksum: [u8; 32] = header[header.len() - 32..].try_into().expect("header seal");
        Ok(Self {
            file,
            binding,
            resume: C61DurableResume { checkpoint, mask_events: Vec::new(), final_seal: None },
            sequence: 0,
            last_checksum,
        })
    }

    pub(crate) fn open(
        path: impl AsRef<Path>,
        expected_binding: C61DurableBinding,
    ) -> ReferenceResult<Self> {
        let path = path.as_ref().to_path_buf();
        let bytes = fs::read(&path).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot read C6ICJ1 journal: {error}"))
        })?;
        let (binding, resume, sequence, last_checksum) = Self::parse(&bytes, expected_binding)?;
        let mut options = OpenOptions::new();
        options.read(true).append(true);
        let file = options.open(&path).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot reopen C6ICJ1 journal: {error}"))
        })?;
        Ok(Self { file, binding, resume, sequence, last_checksum })
    }

    fn parse(
        bytes: &[u8],
        expected_binding: C61DurableBinding,
    ) -> ReferenceResult<(C61DurableBinding, C61DurableResume, u32, [u8; 32])> {
        let mut reader = C61CheckpointReader::new(bytes);
        if reader.take(8)? != C61_DURABLE_JOURNAL_MAGIC {
            return Err(C61WhirReferenceError::new("C6ICJ1 magic mismatch"));
        }
        if reader.u16()? != C61_DURABLE_JOURNAL_VERSION {
            return Err(C61WhirReferenceError::new("C6ICJ1 version mismatch"));
        }
        let num_variables = reader.u8()?;
        if reader.u8()? != 0 {
            return Err(C61WhirReferenceError::new("C6ICJ1 header reserved byte is nonzero"));
        }
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(reader.take(32)?);
        let mut binding_digest = [0u8; 32];
        binding_digest.copy_from_slice(reader.take(32)?);
        let slot = reader.u32()? as u32;
        let raw_counts = [reader.u64()?, reader.u64()?];
        let raw_ends = [reader.u64()?, reader.u64()?];
        let header_body_end = reader.offset;
        let mut header_checksum = [0u8; 32];
        header_checksum.copy_from_slice(reader.take(32)?);
        if blake3::derive_key("volta-zk/c61/durable-header/v1", &bytes[..header_body_end])
            != header_checksum
        {
            return Err(C61WhirReferenceError::new("C6ICJ1 header checksum mismatch"));
        }
        let binding = C61DurableBinding { digest: binding_digest, slot, raw_counts, raw_ends };
        if binding != expected_binding {
            return Err(C61WhirReferenceError::new("C6ICJ1 reserved-attempt binding mismatch"));
        }
        let mut resume = C61DurableResume {
            checkpoint: C61InteractiveCheckpoint {
                num_variables,
                context_digest,
                records: Vec::new(),
            },
            mask_events: Vec::new(),
            final_seal: None,
        };
        let mut sequence = 0u32;
        let mut last_checksum = header_checksum;
        while reader.offset != bytes.len() {
            let tag = reader.u8()?;
            if reader.take(3)? != [0; 3] {
                return Err(C61WhirReferenceError::new("C6ICJ1 record reserved bytes are nonzero"));
            }
            let record_sequence = reader.u32()? as u32;
            let payload_len = reader.u32()?;
            let payload = reader.take(payload_len)?;
            let mut checksum = [0u8; 32];
            checksum.copy_from_slice(reader.take(32)?);
            if record_sequence
                != sequence
                    .checked_add(1)
                    .ok_or_else(|| C61WhirReferenceError::new("C6ICJ1 sequence overflows"))?
            {
                return Err(C61WhirReferenceError::new("C6ICJ1 non-sequential record"));
            }
            let (_, expected_checksum) =
                c61_durable_record(binding.digest, last_checksum, record_sequence, tag, payload)?;
            if checksum != expected_checksum {
                return Err(C61WhirReferenceError::new("C6ICJ1 record checksum mismatch"));
            }
            match tag {
                C61_DURABLE_RECORD_CHALLENGE if resume.final_seal.is_none() => {
                    if resume.checkpoint.records.len() >= C61_INTERACTIVE_CHECKPOINT_MAX_RECORDS {
                        return Err(C61WhirReferenceError::new("C6ICJ1 challenge cap exceeded"));
                    }
                    resume.checkpoint.records.push(C61ChallengeRecord::decode_body(payload)?);
                }
                C61_DURABLE_RECORD_MASK_FRONTIER if resume.final_seal.is_none() => {
                    let mut event = C61CheckpointReader::new(payload);
                    let challenge_index = event.u32()?;
                    let frontier = event.u32()? as u32;
                    let mut provider_move_digest = [0u8; 32];
                    provider_move_digest.copy_from_slice(event.take(32)?);
                    event.finish()?;
                    let previous = resume.mask_events.last().map_or(0, |(_, value, _)| *value);
                    if challenge_index != resume.checkpoint.records.len()
                        || frontier <= previous
                        || resume.mask_events.len() >= C61_DURABLE_JOURNAL_MAX_MASK_EVENTS
                        || u64::from(frontier) > binding.raw_counts[0]
                        || u64::from(frontier) > binding.raw_counts[1]
                    {
                        return Err(C61WhirReferenceError::new("invalid C6ICJ1 mask frontier"));
                    }
                    resume.mask_events.push((challenge_index, frontier, provider_move_digest));
                }
                C61_DURABLE_RECORD_FINISH if resume.final_seal.is_none() => {
                    let mut seal = C61CheckpointReader::new(payload);
                    let challenge_index = seal.u32()?;
                    let payload_bytes = usize::try_from(seal.u64()?).map_err(|_| {
                        C61WhirReferenceError::new("C6ICJ1 final payload exceeds usize")
                    })?;
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(seal.take(32)?);
                    seal.finish()?;
                    if challenge_index != resume.checkpoint.records.len() || payload_bytes == 0 {
                        return Err(C61WhirReferenceError::new("invalid C6ICJ1 final seal"));
                    }
                    resume.final_seal = Some((challenge_index, payload_bytes, digest));
                }
                _ => return Err(C61WhirReferenceError::new("illegal C6ICJ1 record transition")),
            }
            sequence = record_sequence;
            last_checksum = checksum;
        }
        Ok((binding, resume, sequence, last_checksum))
    }

    fn append(&mut self, tag: u8, payload: &[u8]) -> ReferenceResult<()> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| C61WhirReferenceError::new("C6ICJ1 sequence overflows"))?;
        let (record, checksum) =
            c61_durable_record(self.binding.digest, self.last_checksum, sequence, tag, payload)?;
        self.file.write_all(&record).map_err(|error| {
            C61WhirReferenceError::new(format!("cannot append C6ICJ1 record: {error}"))
        })?;
        self.file.sync_all().map_err(|error| {
            C61WhirReferenceError::new(format!("cannot sync C6ICJ1 record: {error}"))
        })?;
        self.sequence = sequence;
        self.last_checksum = checksum;
        Ok(())
    }

    fn append_challenge(&mut self, record: C61ChallengeRecord) -> ReferenceResult<()> {
        if self.resume.final_seal.is_some() {
            return Err(C61WhirReferenceError::new("C6ICJ1 is already sealed"));
        }
        self.append(C61_DURABLE_RECORD_CHALLENGE, &record.encode_body()?)?;
        self.resume.checkpoint.records.push(record);
        Ok(())
    }

    fn append_mask_frontier(
        &mut self,
        frontier: u32,
        provider_move_digest: [u8; 32],
    ) -> ReferenceResult<()> {
        let previous = self.resume.mask_events.last().map_or(0, |(_, value, _)| *value);
        if self.resume.final_seal.is_some()
            || frontier <= previous
            || self.resume.mask_events.len() >= C61_DURABLE_JOURNAL_MAX_MASK_EVENTS
            || u64::from(frontier) > self.binding.raw_counts[0]
            || u64::from(frontier) > self.binding.raw_counts[1]
        {
            return Err(C61WhirReferenceError::new("invalid C6ICJ1 mask frontier"));
        }
        let challenge_index = self.resume.checkpoint.records.len();
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&(challenge_index as u32).to_le_bytes());
        payload.extend_from_slice(&frontier.to_le_bytes());
        payload.extend_from_slice(&provider_move_digest);
        self.append(C61_DURABLE_RECORD_MASK_FRONTIER, &payload)?;
        self.resume.mask_events.push((challenge_index, frontier, provider_move_digest));
        Ok(())
    }

    fn append_finish(&mut self, payload_bytes: usize, digest: [u8; 32]) -> ReferenceResult<()> {
        if self.resume.final_seal.is_some() || payload_bytes == 0 {
            return Err(C61WhirReferenceError::new("invalid C6ICJ1 final seal"));
        }
        let challenge_index = self.resume.checkpoint.records.len();
        let mut payload = Vec::with_capacity(44);
        payload.extend_from_slice(&(challenge_index as u32).to_le_bytes());
        payload.extend_from_slice(&(payload_bytes as u64).to_le_bytes());
        payload.extend_from_slice(&digest);
        self.append(C61_DURABLE_RECORD_FINISH, &payload)?;
        self.resume.final_seal = Some((challenge_index, payload_bytes, digest));
        Ok(())
    }

    pub(crate) fn resume(&self) -> C61DurableResume {
        self.resume.clone()
    }
}

pub(crate) fn create_c61_durable_checkpoint_prefix(
    path: impl AsRef<Path>,
    state: C6ClientState,
    attempt: C6ClientAttempt,
    checkpoint: C61InteractiveCheckpoint,
    mask_events: &[(usize, u32, [u8; 32])],
) -> ReferenceResult<C61DurableJournal> {
    let binding = C61DurableBinding::from_reserved_attempt(
        state,
        attempt,
        checkpoint.num_variables as usize,
        checkpoint.context_digest,
    )?;
    let empty = C61InteractiveCheckpoint::empty(
        checkpoint.num_variables as usize,
        checkpoint.context_digest,
    )?;
    let mut journal = C61DurableJournal::create(path, binding, empty)?;
    let mut next_mask_event = 0usize;
    for challenge_index in 0..=checkpoint.records.len() {
        while mask_events
            .get(next_mask_event)
            .is_some_and(|(index, _, _)| *index == challenge_index)
        {
            journal.append_mask_frontier(
                mask_events[next_mask_event].1,
                mask_events[next_mask_event].2,
            )?;
            next_mask_event += 1;
        }
        if let Some(record) = checkpoint.records.get(challenge_index) {
            journal.append_challenge(record.clone())?;
        }
    }
    if next_mask_event != mask_events.len() {
        return Err(C61WhirReferenceError::new(
            "C6ICJ1 mask event lies beyond checkpoint frontier",
        ));
    }
    Ok(journal)
}

pub(crate) fn open_c61_durable_checkpoint(
    path: impl AsRef<Path>,
    state: C6ClientState,
    attempt: C6ClientAttempt,
    num_variables: usize,
    context_digest: [u8; 32],
) -> ReferenceResult<C61DurableJournal> {
    let binding =
        C61DurableBinding::from_reserved_attempt(state, attempt, num_variables, context_digest)?;
    C61DurableJournal::open(path, binding)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61InteractiveTape {
    checkpoint: C61InteractiveCheckpoint,
    final_payload_bytes: usize,
    final_payload_blake3: [u8; 32],
    final_semantic_bytes: usize,
    final_pending_provider_move: Vec<u8>,
}

impl C61InteractiveTape {
    pub fn challenge_count(&self) -> usize {
        self.checkpoint.records.len()
    }

    pub fn context_digest(&self) -> [u8; 32] {
        self.checkpoint.context_digest
    }

    pub fn encoded_len(&self) -> usize {
        C61_INTERACTIVE_TAPE_HEADER_BYTES
            + self.checkpoint.encode().map_or(0, |bytes| bytes.len())
            + self.final_pending_provider_move.len()
            + C61_INTERACTIVE_TAPE_DIGEST_BYTES
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let checkpoint = self.checkpoint.encode().map_err(|error| error.to_string())?;
        if self.final_payload_bytes == 0
            || self.final_semantic_bytes > self.final_payload_bytes
            || self.final_pending_provider_move.len() > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES
        {
            return Err("C6ICT2 tape final seal is noncanonical".to_owned());
        }
        let encoded_len = C61_INTERACTIVE_TAPE_HEADER_BYTES
            .checked_add(checkpoint.len())
            .and_then(|value| value.checked_add(self.final_pending_provider_move.len()))
            .and_then(|value| value.checked_add(C61_INTERACTIVE_TAPE_DIGEST_BYTES))
            .ok_or_else(|| "C6ICT2 tape length overflows".to_owned())?;
        if encoded_len > C61_INTERACTIVE_TAPE_MAX_BYTES {
            return Err("C6ICT2 tape exceeds private-state cap".to_owned());
        }
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&C61_INTERACTIVE_TAPE_MAGIC);
        bytes.extend_from_slice(&C61_INTERACTIVE_TAPE_VERSION.to_le_bytes());
        bytes.push(self.checkpoint.num_variables);
        bytes.push(0);
        bytes.extend_from_slice(&self.checkpoint.context_digest);
        bytes.extend_from_slice(&(self.challenge_count() as u32).to_le_bytes());
        bytes.extend_from_slice(&(checkpoint.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.final_payload_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&self.final_payload_blake3);
        bytes.extend_from_slice(&(self.final_semantic_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.final_pending_provider_move.len() as u32).to_le_bytes());
        debug_assert_eq!(bytes.len(), C61_INTERACTIVE_TAPE_HEADER_BYTES);
        bytes.extend_from_slice(&checkpoint);
        bytes.extend_from_slice(&self.final_pending_provider_move);
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < C61_INTERACTIVE_TAPE_HEADER_BYTES + C61_INTERACTIVE_TAPE_DIGEST_BYTES
            || bytes.len() > C61_INTERACTIVE_TAPE_MAX_BYTES
            || bytes[..8] != C61_INTERACTIVE_TAPE_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed C6ICT2 version"))
                != C61_INTERACTIVE_TAPE_VERSION
            || bytes[11] != 0
        {
            return Err("C6ICT2 tape header/version/length mismatch".to_owned());
        }
        let digest_offset = bytes.len() - C61_INTERACTIVE_TAPE_DIGEST_BYTES;
        if blake3::hash(&bytes[..digest_offset]).as_bytes() != &bytes[digest_offset..] {
            return Err("C6ICT2 tape digest mismatch".to_owned());
        }
        let num_variables = bytes[10];
        let context_digest: [u8; 32] = bytes[12..44].try_into().expect("fixed C6ICT2 context");
        let challenge_count =
            u32::from_le_bytes(bytes[44..48].try_into().expect("fixed C6ICT2 count")) as usize;
        let checkpoint_len =
            u32::from_le_bytes(bytes[48..52].try_into().expect("fixed C6ICT2 checkpoint length"))
                as usize;
        let final_payload_bytes = usize::try_from(u64::from_le_bytes(
            bytes[52..60].try_into().expect("fixed C6ICT2 payload length"),
        ))
        .map_err(|_| "C6ICT2 payload length exceeds usize".to_owned())?;
        let final_payload_blake3 = bytes[60..92].try_into().expect("fixed C6ICT2 payload digest");
        let final_semantic_bytes = usize::try_from(u64::from_le_bytes(
            bytes[92..100].try_into().expect("fixed C6ICT2 semantic length"),
        ))
        .map_err(|_| "C6ICT2 semantic length exceeds usize".to_owned())?;
        let pending_len =
            u32::from_le_bytes(bytes[100..104].try_into().expect("fixed C6ICT2 pending length"))
                as usize;
        let pending_offset = C61_INTERACTIVE_TAPE_HEADER_BYTES
            .checked_add(checkpoint_len)
            .ok_or_else(|| "C6ICT2 checkpoint end overflows".to_owned())?;
        if pending_len > C61_INTERACTIVE_CHECKPOINT_MAX_MOVE_BYTES
            || pending_offset.checked_add(pending_len) != Some(digest_offset)
            || final_payload_bytes == 0
            || final_semantic_bytes > final_payload_bytes
        {
            return Err("C6ICT2 tape body census mismatch".to_owned());
        }
        let checkpoint = C61InteractiveCheckpoint::decode(
            &bytes[C61_INTERACTIVE_TAPE_HEADER_BYTES..pending_offset],
        )
        .map_err(|error| error.to_string())?;
        if checkpoint.num_variables != num_variables
            || checkpoint.context_digest != context_digest
            || checkpoint.records.len() != challenge_count
        {
            return Err("C6ICT2 tape repeats a different checkpoint binding".to_owned());
        }
        let tape = Self {
            checkpoint,
            final_payload_bytes,
            final_payload_blake3,
            final_semantic_bytes,
            final_pending_provider_move: bytes[pending_offset..digest_offset].to_vec(),
        };
        if tape.encode()? != bytes {
            return Err("noncanonical C6ICT2 tape".to_owned());
        }
        Ok(tape)
    }

    pub(crate) fn checkpoint(&self, count: usize) -> ReferenceResult<C61InteractiveCheckpoint> {
        if count > self.checkpoint.records.len() {
            return Err(C61WhirReferenceError::new("C6ICT1 checkpoint frontier exceeds tape"));
        }
        Ok(C61InteractiveCheckpoint {
            num_variables: self.checkpoint.num_variables,
            context_digest: self.checkpoint.context_digest,
            records: self.checkpoint.records[..count].to_vec(),
        })
    }

    pub(crate) fn checkpoint_bytes(&self, count: usize) -> ReferenceResult<Vec<u8>> {
        self.checkpoint(count)?.encode()
    }

    /// Construct a seedless transcript that releases only this tape's
    /// recorded challenges after exact provider-move replay.
    pub fn replay_transcript(
        &self,
        num_variables: usize,
        context_digest: [u8; 32],
    ) -> Result<Transcript, String> {
        let endpoint = C61PrivateEntropyTranscriptReplayEndpoint::new(
            self.clone(),
            num_variables,
            context_digest,
        )
        .map_err(|error| error.to_string())?;
        Ok(Transcript::new_interactive(Box::new(endpoint)))
    }
}

fn c61_interactive_attempt_digest(attempt: C6ClientAttempt) -> Result<[u8; 32], String> {
    attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
    attempt.workload.validate().map_err(|error| error.to_string())?;
    if attempt.setup_manifest_digest == [0; 32]
        || attempt.nonce == [0; 32]
        || attempt.old_head_digest == [0; 32]
    {
        return Err("C6ICT2 tape bundle attempt is noncanonical".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/interactive-attempt/v1");
    hasher.update(&attempt.slot.to_le_bytes());
    hasher.update(&attempt.nonce);
    hasher.update(&attempt.setup_manifest_digest);
    hasher.update(&attempt.old_head_digest);
    hasher.update(&attempt.predecessor_certificate_digest);
    for range in attempt.correlation_ranges.coordinates {
        hasher.update(&range.stage.to_le_bytes());
        hasher.update(&range.start.to_le_bytes());
        hasher.update(&range.count.to_le_bytes());
    }
    hasher.update(&attempt.workload.digest());
    Ok(*hasher.finalize().as_bytes())
}

/// Model-independent context for the global response transcript. The final
/// certificate is bound by the enclosing bundle after proof construction.
pub fn c61_response_transcript_context_digest(
    attempt: C6ClientAttempt,
    statement_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if statement_digest == [0; 32] {
        return Err("C6ICT3 response statement digest is zero".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/response-transcript/v1");
    hasher.update(&c61_interactive_attempt_digest(attempt)?);
    hasher.update(&statement_digest);
    Ok(*hasher.finalize().as_bytes())
}

/// Canonical verifier-private replay object for the six production chains,
/// the post-body joint bridge and the separate global response transcript.
/// It is certificate-bound but never provider wire or setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61InteractiveTapeBundle {
    attempt_digest: [u8; 32],
    certificate_digest: [u8; 32],
    tapes: [C61InteractiveTape; C61_INTERACTIVE_TAPE_LANES],
    response_tape: C61InteractiveTape,
}

impl C61InteractiveTapeBundle {
    pub fn from_completed_attempt(
        attempt: C6ClientAttempt,
        certificate_digest: [u8; 32],
        tapes: [C61InteractiveTape; C61_INTERACTIVE_TAPE_LANES],
        response_tape: C61InteractiveTape,
        expected_contexts: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
        expected_response_context: [u8; 32],
    ) -> Result<Self, String> {
        let bundle = Self {
            attempt_digest: c61_interactive_attempt_digest(attempt)?,
            certificate_digest,
            tapes,
            response_tape,
        };
        bundle.validate_contexts(
            certificate_digest,
            expected_contexts,
            expected_response_context,
        )?;
        Ok(bundle)
    }

    fn validate_internal_contexts(&self) -> Result<(), String> {
        let mut contexts =
            self.tapes.iter().map(C61InteractiveTape::context_digest).collect::<Vec<_>>();
        contexts.push(self.response_tape.context_digest());
        if contexts.contains(&[0; 32])
            || (0..contexts.len()).any(|index| contexts[..index].contains(&contexts[index]))
        {
            return Err("C6ICT3 tape context is zero or duplicated".to_owned());
        }
        Ok(())
    }

    fn validate_contexts(
        &self,
        certificate_digest: [u8; 32],
        expected_contexts: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
        expected_response_context: [u8; 32],
    ) -> Result<(), String> {
        self.validate_internal_contexts()?;
        if certificate_digest == [0; 32]
            || self.certificate_digest != certificate_digest
            || expected_contexts.iter().any(|digest| *digest == [0; 32])
            || expected_response_context == [0; 32]
        {
            return Err("C6ICT3 tape bundle binding is empty or mismatched".to_owned());
        }
        for index in 0..C61_INTERACTIVE_TAPE_LANES {
            if self.tapes[index].context_digest() != expected_contexts[index]
                || expected_contexts[..index].contains(&expected_contexts[index])
            {
                return Err("C6ICT2 tape lane is moved, duplicated or misbound".to_owned());
            }
        }
        if self.response_tape.context_digest() != expected_response_context
            || expected_contexts.contains(&expected_response_context)
        {
            return Err("C6ICT3 response tape is moved, duplicated or misbound".to_owned());
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        attempt: C6ClientAttempt,
        certificate_digest: [u8; 32],
        expected_contexts: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
        expected_response_context: [u8; 32],
    ) -> Result<(), String> {
        if self.attempt_digest != c61_interactive_attempt_digest(attempt)? {
            return Err("C6ICT2 tape bundle belongs to another reserved attempt".to_owned());
        }
        self.validate_contexts(certificate_digest, expected_contexts, expected_response_context)
    }

    pub fn validate_attempt(
        &self,
        attempt: C6ClientAttempt,
        certificate_digest: [u8; 32],
    ) -> Result<(), String> {
        self.validate_internal_contexts()?;
        if self.attempt_digest != c61_interactive_attempt_digest(attempt)?
            || self.certificate_digest != certificate_digest
            || certificate_digest == [0; 32]
        {
            return Err("C6ICT2 tape bundle attempt/certificate binding mismatch".to_owned());
        }
        Ok(())
    }

    pub fn tapes(&self) -> &[C61InteractiveTape; C61_INTERACTIVE_TAPE_LANES] {
        &self.tapes
    }

    pub fn response_tape(&self) -> &C61InteractiveTape {
        &self.response_tape
    }

    pub fn into_tapes(
        self,
    ) -> ([C61InteractiveTape; C61_INTERACTIVE_TAPE_LANES], C61InteractiveTape) {
        (self.tapes, self.response_tape)
    }

    pub fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    pub fn encoded_len(&self) -> usize {
        C61_INTERACTIVE_BUNDLE_HEADER_BYTES
            + C61_INTERACTIVE_BUNDLE_LANE_HEADER_BYTES * C61_INTERACTIVE_BUNDLE_TAPE_COUNT
            + self.tapes.iter().map(C61InteractiveTape::encoded_len).sum::<usize>()
            + self.response_tape.encoded_len()
            + C61_INTERACTIVE_BUNDLE_DIGEST_BYTES
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_internal_contexts()?;
        let encoded_len = self.encoded_len();
        if encoded_len > C61_INTERACTIVE_BUNDLE_MAX_BYTES {
            return Err("C6ICT2 tape bundle exceeds private-state cap".to_owned());
        }
        let encoded_tapes = self
            .tapes
            .iter()
            .chain(std::iter::once(&self.response_tape))
            .map(C61InteractiveTape::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&C61_INTERACTIVE_BUNDLE_MAGIC);
        bytes.extend_from_slice(&C61_INTERACTIVE_BUNDLE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C61_INTERACTIVE_BUNDLE_TAPE_COUNT as u16).to_le_bytes());
        bytes.extend_from_slice(&self.attempt_digest);
        bytes.extend_from_slice(&self.certificate_digest);
        bytes.extend_from_slice(
            &u32::try_from(encoded_len)
                .map_err(|_| "C6ICT2 tape bundle length exceeds u32".to_owned())?
                .to_le_bytes(),
        );
        debug_assert_eq!(bytes.len(), C61_INTERACTIVE_BUNDLE_HEADER_BYTES);
        for (tape, encoded) in
            self.tapes.iter().chain(std::iter::once(&self.response_tape)).zip(&encoded_tapes)
        {
            bytes.extend_from_slice(&tape.context_digest());
            bytes.extend_from_slice(
                &u32::try_from(encoded.len())
                    .map_err(|_| "C6ICT2 tape lane length exceeds u32".to_owned())?
                    .to_le_bytes(),
            );
        }
        for encoded in encoded_tapes {
            bytes.extend_from_slice(&encoded);
        }
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        if bytes.len() != encoded_len {
            return Err("C6ICT2 tape bundle byte census diverged".to_owned());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let minimum = C61_INTERACTIVE_BUNDLE_HEADER_BYTES
            + C61_INTERACTIVE_BUNDLE_LANE_HEADER_BYTES * C61_INTERACTIVE_BUNDLE_TAPE_COUNT
            + C61_INTERACTIVE_BUNDLE_DIGEST_BYTES;
        if bytes.len() < minimum
            || bytes.len() > C61_INTERACTIVE_BUNDLE_MAX_BYTES
            || bytes[..8] != C61_INTERACTIVE_BUNDLE_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed bundle version"))
                != C61_INTERACTIVE_BUNDLE_VERSION
            || u16::from_le_bytes(bytes[10..12].try_into().expect("fixed bundle census"))
                != C61_INTERACTIVE_BUNDLE_TAPE_COUNT as u16
            || u32::from_le_bytes(bytes[76..80].try_into().expect("fixed bundle length")) as usize
                != bytes.len()
        {
            return Err("C6ICT2 tape bundle header/version/length mismatch".to_owned());
        }
        let digest_offset = bytes.len() - C61_INTERACTIVE_BUNDLE_DIGEST_BYTES;
        if blake3::hash(&bytes[..digest_offset]).as_bytes() != &bytes[digest_offset..] {
            return Err("C6ICT2 tape bundle digest mismatch".to_owned());
        }
        let attempt_digest = bytes[12..44].try_into().expect("fixed bundle attempt");
        let certificate_digest = bytes[44..76].try_into().expect("fixed bundle certificate");
        let mut contexts = [[0u8; 32]; C61_INTERACTIVE_BUNDLE_TAPE_COUNT];
        let mut lengths = [0usize; C61_INTERACTIVE_BUNDLE_TAPE_COUNT];
        let mut offset = C61_INTERACTIVE_BUNDLE_HEADER_BYTES;
        for index in 0..C61_INTERACTIVE_BUNDLE_TAPE_COUNT {
            contexts[index].copy_from_slice(&bytes[offset..offset + 32]);
            lengths[index] = u32::from_le_bytes(
                bytes[offset + 32..offset + 36].try_into().expect("fixed lane length"),
            ) as usize;
            offset += C61_INTERACTIVE_BUNDLE_LANE_HEADER_BYTES;
        }
        let mut tapes = Vec::with_capacity(C61_INTERACTIVE_BUNDLE_TAPE_COUNT);
        for index in 0..C61_INTERACTIVE_BUNDLE_TAPE_COUNT {
            let end = offset
                .checked_add(lengths[index])
                .filter(|end| *end <= digest_offset)
                .ok_or_else(|| "truncated C6ICT2 tape bundle lane".to_owned())?;
            let tape = C61InteractiveTape::decode(&bytes[offset..end])?;
            if tape.context_digest() != contexts[index] {
                return Err("C6ICT2 tape bundle repeats a different lane context".to_owned());
            }
            tapes.push(tape);
            offset = end;
        }
        if offset != digest_offset || certificate_digest == [0; 32] {
            return Err("C6ICT2 tape bundle lane census mismatch".to_owned());
        }
        let response_tape =
            tapes.pop().ok_or_else(|| "C6ICT3 tape bundle omits response tape".to_owned())?;
        let tapes = tapes
            .try_into()
            .map_err(|_| "C6ICT2 native tape bundle lane count mismatch".to_owned())?;
        let bundle = Self { attempt_digest, certificate_digest, tapes, response_tape };
        if bundle.encode()? != bytes {
            return Err("noncanonical C6ICT2 tape bundle".to_owned());
        }
        Ok(bundle)
    }
}

#[derive(Debug)]
pub(crate) struct C61PrivateEntropyBrokerOutput {
    pub(crate) tape: C61InteractiveTape,
    pub(crate) interaction: C61WhirInteractionStats,
    pub(crate) transcript_bytes: u64,
    pub(crate) ledger: BTreeMap<&'static str, u64>,
    pub(crate) replayed_challenges: usize,
    pub(crate) replayed_mask_events: usize,
    pub(crate) mask_frontier: u32,
    pub(crate) mask_events: Vec<(usize, u32, [u8; 32])>,
    pub(crate) durable_record_count: u32,
}

enum C61BrokerResponse {
    Fp(u64),
    Fp2([u64; 2]),
    Query(u32),
    Ack,
}

enum C61BrokerRequest {
    Challenge {
        provider_move: Vec<u8>,
        semantic_bytes: usize,
        kind: C61ChallengeKind,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
    MaskFrontier {
        frontier: u32,
        provider_move_digest: [u8; 32],
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
    Finish {
        pending_provider_move: Vec<u8>,
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
    ReplayChallenge {
        provider_move: Vec<u8>,
        semantic_bytes: usize,
        kind: C61ChallengeKind,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
    ReplayFinish {
        pending_provider_move: Vec<u8>,
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
        response: mpsc::SyncSender<ReferenceResult<C61BrokerResponse>>,
    },
}

/// The only object crossing into the provider role.  Its fields contain no
/// entropy seed, verifier transcript, or resumable checkpoint.
#[derive(Clone)]
struct C61ProviderEndpoint {
    sender: mpsc::SyncSender<C61BrokerRequest>,
}

/// Seedless exact-move endpoint for production protocol code that uses the
/// generic VOLTA transcript rather than the P3 challenger interface.
pub struct C61PrivateEntropyEndpoint {
    endpoint: C61ProviderEndpoint,
}

impl TranscriptChallengeChannel for C61PrivateEntropyEndpoint {
    fn challenge(
        &mut self,
        provider_move: Vec<u8>,
        provider_semantic_bytes: usize,
        request: TranscriptChallengeRequest,
    ) -> Result<TranscriptChallengeResponse, String> {
        let kind = match request {
            TranscriptChallengeRequest::Fp => C61ChallengeKind::Fp,
            TranscriptChallengeRequest::Fp2 => C61ChallengeKind::Fp2,
            TranscriptChallengeRequest::Bits(bits) if (1..=32).contains(&bits) => {
                C61ChallengeKind::Query { bits }
            }
            TranscriptChallengeRequest::Bits(_) => {
                return Err("C6ICT2 transcript query width exceeds u32".to_owned())
            }
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.endpoint
            .sender
            .send(C61BrokerRequest::Challenge {
                provider_move,
                semantic_bytes: provider_semantic_bytes,
                kind,
                response: response_sender,
            })
            .map_err(|_| "C6ICT2 verifier broker disconnected".to_owned())?;
        let response = response_receiver
            .recv()
            .map_err(|_| "C6ICT2 verifier response disconnected".to_owned())?
            .map_err(|error| error.to_string())?;
        match response {
            C61BrokerResponse::Fp(value) => Ok(TranscriptChallengeResponse::Fp(value)),
            C61BrokerResponse::Fp2(value) => Ok(TranscriptChallengeResponse::Fp2(value)),
            C61BrokerResponse::Query(value) => {
                Ok(TranscriptChallengeResponse::Bits(u64::from(value)))
            }
            C61BrokerResponse::Ack => Err("C6ICT2 transcript received an ACK challenge".to_owned()),
        }
    }

    fn finish(
        &mut self,
        pending_provider_move: Vec<u8>,
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
    ) -> Result<(), String> {
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.endpoint
            .sender
            .send(C61BrokerRequest::Finish {
                pending_provider_move,
                payload_bytes,
                payload_blake3,
                semantic_bytes,
                response: response_sender,
            })
            .map_err(|_| "C6ICT2 verifier broker disconnected at finish".to_owned())?;
        match response_receiver
            .recv()
            .map_err(|_| "C6ICT2 verifier finish response disconnected".to_owned())?
            .map_err(|error| error.to_string())?
        {
            C61BrokerResponse::Ack => Ok(()),
            _ => Err("C6ICT2 transcript finish response is not an ACK".to_owned()),
        }
    }
}

/// Client-side live mirror for a duplex response transcript. It contains no
/// entropy or checkpoint and can release only a challenge the broker already
/// released to the provider after the same canonical move.
pub struct C61PrivateEntropyLiveReplayEndpoint {
    endpoint: C61ProviderEndpoint,
}

impl TranscriptChallengeChannel for C61PrivateEntropyLiveReplayEndpoint {
    fn challenge(
        &mut self,
        provider_move: Vec<u8>,
        provider_semantic_bytes: usize,
        request: TranscriptChallengeRequest,
    ) -> Result<TranscriptChallengeResponse, String> {
        let kind = match request {
            TranscriptChallengeRequest::Fp => C61ChallengeKind::Fp,
            TranscriptChallengeRequest::Fp2 => C61ChallengeKind::Fp2,
            TranscriptChallengeRequest::Bits(bits) if (1..=32).contains(&bits) => {
                C61ChallengeKind::Query { bits }
            }
            TranscriptChallengeRequest::Bits(_) => {
                return Err("C6ICT3 live replay query width exceeds u32".to_owned())
            }
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.endpoint
            .sender
            .send(C61BrokerRequest::ReplayChallenge {
                provider_move,
                semantic_bytes: provider_semantic_bytes,
                kind,
                response: response_sender,
            })
            .map_err(|_| "C6ICT3 duplex broker disconnected".to_owned())?;
        let response = response_receiver
            .recv()
            .map_err(|_| "C6ICT3 duplex replay response disconnected".to_owned())?
            .map_err(|error| error.to_string())?;
        match response {
            C61BrokerResponse::Fp(value) => Ok(TranscriptChallengeResponse::Fp(value)),
            C61BrokerResponse::Fp2(value) => Ok(TranscriptChallengeResponse::Fp2(value)),
            C61BrokerResponse::Query(value) => {
                Ok(TranscriptChallengeResponse::Bits(u64::from(value)))
            }
            C61BrokerResponse::Ack => {
                Err("C6ICT3 live replay received an ACK challenge".to_owned())
            }
        }
    }

    fn finish(
        &mut self,
        pending_provider_move: Vec<u8>,
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
    ) -> Result<(), String> {
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.endpoint
            .sender
            .send(C61BrokerRequest::ReplayFinish {
                pending_provider_move,
                payload_bytes,
                payload_blake3,
                semantic_bytes,
                response: response_sender,
            })
            .map_err(|_| "C6ICT3 duplex broker disconnected at replay finish".to_owned())?;
        match response_receiver
            .recv()
            .map_err(|_| "C6ICT3 duplex replay finish disconnected".to_owned())?
            .map_err(|error| error.to_string())?
        {
            C61BrokerResponse::Ack => Ok(()),
            _ => Err("C6ICT3 live replay finish response is not an ACK".to_owned()),
        }
    }
}

struct C61ProviderState {
    endpoint: C61ProviderEndpoint,
    initial_root_seen: bool,
    public_statement_bound: bool,
    num_variables: usize,
    pending_provider_move: Vec<u8>,
    semantic_bytes: usize,
    failure: Option<C61WhirReferenceError>,
    fallback_query: u32,
}

/// Provider-side challenger backed only by the typed synchronous endpoint.
pub(crate) struct C61PrivateEntropyProverChallenger {
    state: Arc<Mutex<C61ProviderState>>,
}

impl Clone for C61PrivateEntropyProverChallenger {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

impl C61PrivateEntropyProverChallenger {
    fn new(endpoint: C61ProviderEndpoint, num_variables: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(C61ProviderState {
                endpoint,
                initial_root_seen: false,
                public_statement_bound: false,
                num_variables,
                pending_provider_move: Vec::new(),
                semantic_bytes: 0,
                failure: None,
                fallback_query: 0,
            })),
        }
    }

    pub(crate) fn observe_public_point(&mut self, point: &Point<C61P3Fp2>) -> ReferenceResult<()> {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        if !state.initial_root_seen || state.public_statement_bound {
            return Err(C61WhirReferenceError::new("C6ICT1 public-point order mismatch"));
        }
        if point.num_variables() != state.num_variables {
            return Err(C61WhirReferenceError::new("C6ICT1 public-point arity mismatch"));
        }
        state.public_statement_bound = true;
        Ok(())
    }

    fn request(&self, kind: C61ChallengeKind) -> ReferenceResult<C61BrokerResponse> {
        let (endpoint, provider_move) = {
            let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            if !state.public_statement_bound {
                return Err(C61WhirReferenceError::new(
                    "C6ICT1 challenge requested before public statement",
                ));
            }
            (state.endpoint.clone(), std::mem::take(&mut state.pending_provider_move))
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        endpoint
            .sender
            .send(C61BrokerRequest::Challenge {
                semantic_bytes: provider_move.len(),
                provider_move,
                kind,
                response: response_sender,
            })
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier broker disconnected"))?;
        let result = response_receiver
            .recv()
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier response disconnected"))?;
        if let Err(error) = &result {
            self.state.lock().expect("C6ICT1 provider mutex poisoned").failure =
                Some(error.clone());
        }
        result
    }

    fn record_failure(&self, message: &'static str) {
        self.state.lock().expect("C6ICT1 provider mutex poisoned").failure =
            Some(C61WhirReferenceError::new(message));
    }

    fn next_fallback_query(&self, bits: u8) -> usize {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        let mask = if bits == 32 { u32::MAX } else { (1u32 << bits) - 1 };
        let value = state.fallback_query & mask;
        state.fallback_query = state.fallback_query.wrapping_add(1);
        value as usize
    }

    pub(crate) fn note_mask_frontier(&self, frontier: u32) -> ReferenceResult<()> {
        let (endpoint, provider_move_digest) = {
            let state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            (state.endpoint.clone(), *blake3::hash(&state.pending_provider_move).as_bytes())
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        endpoint
            .sender
            .send(C61BrokerRequest::MaskFrontier {
                frontier,
                provider_move_digest,
                response: response_sender,
            })
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier broker disconnected"))?;
        let result = response_receiver
            .recv()
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier response disconnected"))?;
        if let Err(error) = &result {
            self.state.lock().expect("C6ICT1 provider mutex poisoned").failure =
                Some(error.clone());
        }
        match result? {
            C61BrokerResponse::Ack => Ok(()),
            _ => Err(C61WhirReferenceError::new("C6ICT1 mask ACK tag mismatch")),
        }
    }

    pub(crate) fn finish(&self, payload: &[u8]) -> ReferenceResult<()> {
        let (endpoint, semantic_bytes, pending_empty) = {
            let state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            (state.endpoint.clone(), state.semantic_bytes, state.pending_provider_move.is_empty())
        };
        if !pending_empty {
            return Err(C61WhirReferenceError::new(
                "C6ICT1 final provider move lacks a challenge boundary",
            ));
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        endpoint
            .sender
            .send(C61BrokerRequest::Finish {
                pending_provider_move: Vec::new(),
                payload_bytes: payload.len(),
                payload_blake3: *blake3::hash(payload).as_bytes(),
                semantic_bytes,
                response: response_sender,
            })
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier broker disconnected"))?;
        match response_receiver
            .recv()
            .map_err(|_| C61WhirReferenceError::new("C6ICT1 verifier response disconnected"))??
        {
            C61BrokerResponse::Ack => Ok(()),
            _ => Err(C61WhirReferenceError::new("C6ICT1 finish response tag mismatch")),
        }
    }
}

impl CanObserve<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn observe(&mut self, value: Goldilocks) {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        state.pending_provider_move.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        state.semantic_bytes += C61_WHIRA1_FP_BYTES;
    }
}

impl CanObserve<C61Commitment> for C61PrivateEntropyProverChallenger {
    fn observe(&mut self, value: C61Commitment) {
        let mut state = self.state.lock().expect("C6ICT1 provider mutex poisoned");
        assert_eq!(value.num_roots(), 1, "C6ICT1 requires cap height zero");
        state.initial_root_seen = true;
        state.pending_provider_move.extend_from_slice(&value.roots()[0]);
        state.semantic_bytes += C61_WHIRA1_DIGEST_BYTES;
    }
}

impl CanSample<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn sample(&mut self) -> Goldilocks {
        match self.request(C61ChallengeKind::Fp) {
            Err(_) => Goldilocks::ONE,
            Ok(C61BrokerResponse::Fp(value)) => Goldilocks::new(value),
            Ok(_) => {
                self.record_failure("C6ICT1 field response tag mismatch");
                Goldilocks::ONE
            }
        }
    }
}

impl CanSampleBits<usize> for C61PrivateEntropyProverChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C6ICT1 query width must fit u32");
        let bits = u8::try_from(bits).expect("validated C6ICT1 query width");
        match self.request(C61ChallengeKind::Query { bits }) {
            Ok(C61BrokerResponse::Query(value)) => value as usize,
            Err(_) => self.next_fallback_query(bits),
            Ok(_) => {
                self.record_failure("C6ICT1 query response tag mismatch");
                self.next_fallback_query(bits)
            }
        }
    }
}

impl CanSampleUniformBits<Goldilocks> for C61PrivateEntropyProverChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61PrivateEntropyProverChallenger {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6ICT1 proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61PrivateEntropyProverChallenger {}

fn derive_challenge(transcript: &mut Transcript, kind: &C61ChallengeKind) -> C61ChallengeValue {
    match kind {
        C61ChallengeKind::Fp => C61ChallengeValue::Fp(transcript.challenge_fp().value()),
        C61ChallengeKind::Fp2 => {
            let value = transcript.challenge_fp2();
            C61ChallengeValue::Fp2([value.c0.value(), value.c1.value()])
        }
        C61ChallengeKind::Query { bits } => {
            C61ChallengeValue::Query(transcript.challenge_bits(*bits) as u32)
        }
    }
}

fn broker_loop(
    receiver: mpsc::Receiver<C61BrokerRequest>,
    verifier_seed: [u8; 32],
    checkpoint: C61InteractiveCheckpoint,
    mut durable: Option<C61DurableJournal>,
    require_live_replay: bool,
) -> ReferenceResult<C61PrivateEntropyBrokerOutput> {
    let durable_resume = durable.as_ref().map(C61DurableJournal::resume);
    if durable_resume.as_ref().is_some_and(|resume| resume.checkpoint != checkpoint) {
        return Err(C61WhirReferenceError::new(
            "C6ICJ1 durable checkpoint disagrees with broker checkpoint",
        ));
    }
    let mut transcript = Transcript::new(verifier_seed);
    let mut records = Vec::new();
    let mut interaction = C61WhirInteractionStats::default();
    let mut replayed_challenges = 0usize;
    let mut replayed_mask_events = 0usize;
    let mut mask_frontier = 0u32;
    let mut mask_events = Vec::new();
    let mut live_replay_cursor = 0usize;
    let mut live_replay_semantic_bytes = 0usize;
    let mut pending_duplex_output = None;

    while let Ok(request) = receiver.recv() {
        match request {
            C61BrokerRequest::Challenge { provider_move, semantic_bytes, kind, response } => {
                if pending_duplex_output.is_some() {
                    let error = C61WhirReferenceError::new(
                        "C6ICT3 provider challenged after its final seal",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if durable_resume.as_ref().is_some_and(|resume| {
                    resume
                        .mask_events
                        .get(replayed_mask_events)
                        .is_some_and(|(index, _, _)| *index == records.len())
                }) {
                    let error = C61WhirReferenceError::new(
                        "C6ICT1 replay skipped a durable mask-frontier event",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if !provider_move.is_empty() {
                    transcript.append(
                        C61_PRIVATE_MESSAGE_LABEL,
                        u64::try_from(semantic_bytes).map_err(|_| {
                            C61WhirReferenceError::new("C6ICT2 semantic move exceeds u64")
                        })?,
                    );
                    interaction.provider_messages += 1;
                    interaction.provider_semantic_bytes += semantic_bytes as u64;
                }
                let value = derive_challenge(&mut transcript, &kind);
                let record = C61ChallengeRecord { provider_move, kind, value };
                let result = if records.len() < checkpoint.records.len() {
                    if record != checkpoint.records[records.len()] {
                        Err(C61WhirReferenceError::new(
                            "C6ICT1 replay diverged before the recorded frontier",
                        ))
                    } else {
                        replayed_challenges += 1;
                        Ok(())
                    }
                } else {
                    Ok(())
                };
                if let Err(error) = result {
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if records.len() >= checkpoint.records.len() {
                    if let Some(journal) = durable.as_mut() {
                        journal.append_challenge(record.clone())?;
                    }
                }
                interaction.client_challenge_payload_bytes += match record.kind {
                    C61ChallengeKind::Fp => {
                        interaction.client_fp_challenges += 1;
                        C61_WHIRA1_FP_BYTES as u64
                    }
                    C61ChallengeKind::Fp2 => {
                        interaction.client_fp_challenges += 2;
                        16
                    }
                    C61ChallengeKind::Query { .. } => {
                        interaction.client_query_challenges += 1;
                        4
                    }
                };
                let broker_response = match record.value {
                    C61ChallengeValue::Fp(value) => C61BrokerResponse::Fp(value),
                    C61ChallengeValue::Fp2(value) => C61BrokerResponse::Fp2(value),
                    C61ChallengeValue::Query(value) => C61BrokerResponse::Query(value),
                };
                records.push(record);
                if response.send(Ok(broker_response)).is_err() {
                    return Err(C61WhirReferenceError::new(
                        "C6ICT1 provider dropped a challenge response",
                    ));
                }
            }
            C61BrokerRequest::ReplayChallenge { provider_move, semantic_bytes, kind, response } => {
                let result = if !require_live_replay {
                    Err(C61WhirReferenceError::new(
                        "C6ICT3 live replay used on a provider-only broker",
                    ))
                } else if let Some(record) = records.get(live_replay_cursor) {
                    if record.provider_move != provider_move || record.kind != kind {
                        Err(C61WhirReferenceError::new(
                            "C6ICT3 live replay provider move or kind diverged",
                        ))
                    } else {
                        live_replay_semantic_bytes = live_replay_semantic_bytes
                            .checked_add(semantic_bytes)
                            .ok_or_else(|| {
                                C61WhirReferenceError::new(
                                    "C6ICT3 live replay semantic-byte count overflows",
                                )
                            })?;
                        live_replay_cursor += 1;
                        Ok(match record.value {
                            C61ChallengeValue::Fp(value) => C61BrokerResponse::Fp(value),
                            C61ChallengeValue::Fp2(value) => C61BrokerResponse::Fp2(value),
                            C61ChallengeValue::Query(value) => C61BrokerResponse::Query(value),
                        })
                    }
                } else {
                    Err(C61WhirReferenceError::new(
                        "C6ICT3 live replay advanced beyond the provider frontier",
                    ))
                };
                match result {
                    Ok(value) => response.send(Ok(value)).map_err(|_| {
                        C61WhirReferenceError::new("C6ICT3 live replay dropped its response")
                    })?,
                    Err(error) => {
                        let _ = response.send(Err(error.clone()));
                        return Err(error);
                    }
                }
            }
            C61BrokerRequest::MaskFrontier { frontier, provider_move_digest, response } => {
                if frontier <= mask_frontier {
                    let error =
                        C61WhirReferenceError::new("C6ICT1 mask frontier is not strictly monotone");
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                let challenge_index = records.len();
                let replayed = if let Some((
                    expected_index,
                    expected_frontier,
                    expected_provider_move_digest,
                )) = durable_resume
                    .as_ref()
                    .and_then(|resume| resume.mask_events.get(replayed_mask_events))
                {
                    if *expected_index != challenge_index
                        || *expected_frontier != frontier
                        || *expected_provider_move_digest != provider_move_digest
                    {
                        let error = C61WhirReferenceError::new(
                            "C6ICT1 mask frontier diverged before durable checkpoint",
                        );
                        let _ = response.send(Err(error.clone()));
                        return Err(error);
                    }
                    replayed_mask_events += 1;
                    true
                } else {
                    false
                };
                if !replayed {
                    if let Some(journal) = durable.as_mut() {
                        journal.append_mask_frontier(frontier, provider_move_digest)?;
                    }
                }
                mask_frontier = frontier;
                mask_events.push((challenge_index, frontier, provider_move_digest));
                response
                    .send(Ok(C61BrokerResponse::Ack))
                    .map_err(|_| C61WhirReferenceError::new("C6ICT1 provider dropped mask ACK"))?;
            }
            C61BrokerRequest::Finish {
                pending_provider_move,
                payload_bytes,
                payload_blake3,
                semantic_bytes,
                response,
            } => {
                if pending_duplex_output.is_some() {
                    let error = C61WhirReferenceError::new(
                        "C6ICT3 provider supplied more than one final seal",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if records.len() < checkpoint.records.len() {
                    let error = C61WhirReferenceError::new(
                        "C6ICT1 provider finished before the replay frontier",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if require_live_replay && live_replay_cursor != records.len() {
                    let error = C61WhirReferenceError::new(
                        "C6ICT3 provider finished before live replay reached its frontier",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                if durable_resume
                    .as_ref()
                    .is_some_and(|resume| replayed_mask_events != resume.mask_events.len())
                {
                    let error = C61WhirReferenceError::new(
                        "C6ICT1 provider finished before durable mask replay completed",
                    );
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                let observed_semantic = interaction.provider_semantic_bytes as usize;
                if semantic_bytes < observed_semantic || semantic_bytes > payload_bytes {
                    let error = C61WhirReferenceError::new("C6ICT1 semantic-byte census mismatch");
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                let terminal_semantic = semantic_bytes - observed_semantic;
                if terminal_semantic > 0 {
                    transcript.append(C61_PRIVATE_MESSAGE_LABEL, terminal_semantic as u64);
                    interaction.provider_messages += 1;
                    interaction.provider_semantic_bytes = semantic_bytes as u64;
                }
                let residual = payload_bytes - semantic_bytes;
                if residual > 0 {
                    transcript.append(C61_PRIVATE_FINAL_LABEL, residual as u64);
                    interaction.provider_messages += 1;
                }
                interaction.provider_payload_bytes = payload_bytes as u64;
                let tape = C61InteractiveTape {
                    checkpoint: C61InteractiveCheckpoint {
                        num_variables: checkpoint.num_variables,
                        context_digest: checkpoint.context_digest,
                        records: std::mem::take(&mut records),
                    },
                    final_payload_bytes: payload_bytes,
                    final_payload_blake3: payload_blake3,
                    final_semantic_bytes: semantic_bytes,
                    final_pending_provider_move: pending_provider_move,
                };
                if let Some(resume) = &durable_resume {
                    if let Some((expected_count, expected_bytes, expected_digest)) =
                        resume.final_seal
                    {
                        if expected_count != tape.checkpoint.challenge_count()
                            || expected_bytes != payload_bytes
                            || expected_digest != payload_blake3
                        {
                            let error = C61WhirReferenceError::new(
                                "C6ICT1 final payload diverged from durable seal",
                            );
                            let _ = response.send(Err(error.clone()));
                            return Err(error);
                        }
                    } else if let Some(journal) = durable.as_mut() {
                        journal.append_finish(payload_bytes, payload_blake3)?;
                    }
                } else if let Some(journal) = durable.as_mut() {
                    journal.append_finish(payload_bytes, payload_blake3)?;
                }
                response
                    .send(Ok(C61BrokerResponse::Ack))
                    .map_err(|_| C61WhirReferenceError::new("C6ICT1 finish ACK disconnected"))?;
                let output = C61PrivateEntropyBrokerOutput {
                    tape,
                    interaction: std::mem::take(&mut interaction),
                    transcript_bytes: transcript.total_bytes(),
                    ledger: transcript.ledger().clone(),
                    replayed_challenges,
                    replayed_mask_events,
                    mask_frontier,
                    mask_events: std::mem::take(&mut mask_events),
                    durable_record_count: durable.as_ref().map_or(0, |journal| journal.sequence),
                };
                if require_live_replay {
                    pending_duplex_output = Some(output);
                } else {
                    return Ok(output);
                }
            }
            C61BrokerRequest::ReplayFinish {
                pending_provider_move,
                payload_bytes,
                payload_blake3,
                semantic_bytes,
                response,
            } => {
                let result = pending_duplex_output.as_ref().ok_or_else(|| {
                    C61WhirReferenceError::new(
                        "C6ICT3 live replay finished before the provider final seal",
                    )
                });
                let result = result.and_then(|output| {
                    let tape = &output.tape;
                    if !require_live_replay
                        || live_replay_cursor != tape.challenge_count()
                        || pending_provider_move != tape.final_pending_provider_move
                        || payload_bytes != tape.final_payload_bytes
                        || payload_blake3 != tape.final_payload_blake3
                        || semantic_bytes != tape.final_semantic_bytes
                        || live_replay_semantic_bytes > semantic_bytes
                    {
                        Err(C61WhirReferenceError::new("C6ICT3 live replay final seal diverged"))
                    } else {
                        Ok(())
                    }
                });
                if let Err(error) = result {
                    let _ = response.send(Err(error.clone()));
                    return Err(error);
                }
                response.send(Ok(C61BrokerResponse::Ack)).map_err(|_| {
                    C61WhirReferenceError::new("C6ICT3 live replay final ACK disconnected")
                })?;
                return pending_duplex_output.take().ok_or_else(|| {
                    C61WhirReferenceError::new("C6ICT3 duplex output disappeared after validation")
                });
            }
        }
    }
    Err(C61WhirReferenceError::new("C6ICT1 provider disconnected before finish"))
}

pub(crate) fn spawn_c61_private_entropy_broker(
    verifier_seed: [u8; 32],
    num_variables: usize,
    context_digest: [u8; 32],
    checkpoint: C61InteractiveCheckpoint,
) -> ReferenceResult<(
    C61PrivateEntropyProverChallenger,
    JoinHandle<ReferenceResult<C61PrivateEntropyBrokerOutput>>,
)> {
    if checkpoint.num_variables as usize != num_variables
        || checkpoint.context_digest != context_digest
    {
        return Err(C61WhirReferenceError::new("C6ICT1 checkpoint context mismatch"));
    }
    let (sender, receiver) = mpsc::sync_channel(0);
    let endpoint = C61ProviderEndpoint { sender };
    let challenger = C61PrivateEntropyProverChallenger::new(endpoint, num_variables);
    let handle =
        thread::spawn(move || broker_loop(receiver, verifier_seed, checkpoint, None, false));
    Ok((challenger, handle))
}

pub struct C61PrivateEntropyBrokerHandle {
    handle: JoinHandle<ReferenceResult<C61PrivateEntropyBrokerOutput>>,
}

impl C61PrivateEntropyBrokerHandle {
    pub(crate) fn finish_output(self) -> ReferenceResult<C61PrivateEntropyBrokerOutput> {
        self.handle
            .join()
            .map_err(|_| C61WhirReferenceError::new("C6ICT2 verifier broker panicked"))?
    }

    pub fn finish(self) -> Result<C61InteractiveTape, String> {
        self.finish_output().map(|output| output.tape).map_err(|error| error.to_string())
    }
}

pub fn spawn_c61_private_entropy_transcript_broker(
    verifier_seed: [u8; 32],
    num_variables: usize,
    context_digest: [u8; 32],
) -> ReferenceResult<(C61PrivateEntropyEndpoint, C61PrivateEntropyBrokerHandle)> {
    let checkpoint = C61InteractiveCheckpoint::empty(num_variables, context_digest)?;
    let (sender, receiver) = mpsc::sync_channel(0);
    let endpoint = C61ProviderEndpoint { sender };
    let handle =
        thread::spawn(move || broker_loop(receiver, verifier_seed, checkpoint, None, false));
    Ok((C61PrivateEntropyEndpoint { endpoint }, C61PrivateEntropyBrokerHandle { handle }))
}

/// Start one client-owned response channel with separate seedless provider
/// and live-replay endpoints. The replay endpoint can observe only records
/// already released to the provider and both roles must seal the same payload.
pub fn spawn_c61_private_entropy_duplex_transcript_broker(
    verifier_seed: [u8; 32],
    num_variables: usize,
    context_digest: [u8; 32],
) -> ReferenceResult<(
    C61PrivateEntropyEndpoint,
    C61PrivateEntropyLiveReplayEndpoint,
    C61PrivateEntropyBrokerHandle,
)> {
    let checkpoint = C61InteractiveCheckpoint::empty(num_variables, context_digest)?;
    let (sender, receiver) = mpsc::sync_channel(0);
    let provider = C61ProviderEndpoint { sender: sender.clone() };
    let replay = C61ProviderEndpoint { sender };
    let handle =
        thread::spawn(move || broker_loop(receiver, verifier_seed, checkpoint, None, true));
    Ok((
        C61PrivateEntropyEndpoint { endpoint: provider },
        C61PrivateEntropyLiveReplayEndpoint { endpoint: replay },
        C61PrivateEntropyBrokerHandle { handle },
    ))
}

/// Seedless verifier endpoint for the generic VOLTA transcript. It releases
/// only the values already recorded by the client-owned tape and checks every
/// canonical provider move, challenge kind, terminal move and payload seal.
pub(crate) struct C61PrivateEntropyTranscriptReplayEndpoint {
    tape: C61InteractiveTape,
    next_record: usize,
    semantic_bytes: usize,
    finished: bool,
}

impl C61PrivateEntropyTranscriptReplayEndpoint {
    pub(crate) fn new(
        tape: C61InteractiveTape,
        num_variables: usize,
        context_digest: [u8; 32],
    ) -> ReferenceResult<Self> {
        if tape.checkpoint.num_variables as usize != num_variables
            || tape.checkpoint.context_digest != context_digest
        {
            return Err(C61WhirReferenceError::new(
                "C6ICT2 transcript replay tape context mismatch",
            ));
        }
        Ok(Self { tape, next_record: 0, semantic_bytes: 0, finished: false })
    }

    fn request_kind(request: TranscriptChallengeRequest) -> Result<C61ChallengeKind, String> {
        match request {
            TranscriptChallengeRequest::Fp => Ok(C61ChallengeKind::Fp),
            TranscriptChallengeRequest::Fp2 => Ok(C61ChallengeKind::Fp2),
            TranscriptChallengeRequest::Bits(bits) if (1..=32).contains(&bits) => {
                Ok(C61ChallengeKind::Query { bits })
            }
            TranscriptChallengeRequest::Bits(_) => {
                Err("C6ICT2 transcript replay query width exceeds u32".to_owned())
            }
        }
    }
}

impl TranscriptChallengeChannel for C61PrivateEntropyTranscriptReplayEndpoint {
    fn challenge(
        &mut self,
        provider_move: Vec<u8>,
        provider_semantic_bytes: usize,
        request: TranscriptChallengeRequest,
    ) -> Result<TranscriptChallengeResponse, String> {
        if self.finished {
            return Err("C6ICT2 transcript replay challenged after finish".to_owned());
        }
        let expected_kind = Self::request_kind(request)?;
        let record = self
            .tape
            .checkpoint
            .records
            .get(self.next_record)
            .ok_or_else(|| "C6ICT2 transcript replay exhausted challenge tape".to_owned())?;
        if record.provider_move != provider_move || record.kind != expected_kind {
            return Err("C6ICT2 transcript replay provider move or kind diverged".to_owned());
        }
        self.semantic_bytes = self
            .semantic_bytes
            .checked_add(provider_semantic_bytes)
            .ok_or_else(|| "C6ICT2 transcript replay semantic-byte count overflows".to_owned())?;
        self.next_record += 1;
        match record.value {
            C61ChallengeValue::Fp(value) => Ok(TranscriptChallengeResponse::Fp(value)),
            C61ChallengeValue::Fp2(value) => Ok(TranscriptChallengeResponse::Fp2(value)),
            C61ChallengeValue::Query(value) => {
                Ok(TranscriptChallengeResponse::Bits(u64::from(value)))
            }
        }
    }

    fn finish(
        &mut self,
        pending_provider_move: Vec<u8>,
        payload_bytes: usize,
        payload_blake3: [u8; 32],
        semantic_bytes: usize,
    ) -> Result<(), String> {
        if self.finished
            || self.next_record != self.tape.checkpoint.records.len()
            || pending_provider_move != self.tape.final_pending_provider_move
            || payload_bytes != self.tape.final_payload_bytes
            || payload_blake3 != self.tape.final_payload_blake3
            || semantic_bytes != self.tape.final_semantic_bytes
            || self.semantic_bytes > semantic_bytes
        {
            return Err("C6ICT2 transcript replay final seal diverged".to_owned());
        }
        self.finished = true;
        Ok(())
    }
}

pub(crate) fn spawn_c61_durable_private_entropy_broker(
    verifier_seed: [u8; 32],
    num_variables: usize,
    context_digest: [u8; 32],
    journal: C61DurableJournal,
) -> ReferenceResult<(
    C61PrivateEntropyProverChallenger,
    JoinHandle<ReferenceResult<C61PrivateEntropyBrokerOutput>>,
)> {
    let checkpoint = journal.resume.checkpoint.clone();
    if checkpoint.num_variables as usize != num_variables
        || checkpoint.context_digest != context_digest
    {
        return Err(C61WhirReferenceError::new("C6ICJ1 checkpoint context mismatch"));
    }
    let (sender, receiver) = mpsc::sync_channel(0);
    let endpoint = C61ProviderEndpoint { sender };
    let challenger = C61PrivateEntropyProverChallenger::new(endpoint, num_variables);
    let handle = thread::spawn(move || {
        broker_loop(receiver, verifier_seed, checkpoint, Some(journal), false)
    });
    Ok((challenger, handle))
}

struct C61ReplayState {
    tape: C61InteractiveTape,
    next_record: usize,
    initial_root_seen: bool,
    public_statement_bound: bool,
    num_variables: usize,
    pending_provider_move: Vec<u8>,
    interaction: C61WhirInteractionStats,
}

/// Verifier challenger that consumes the broker's typed tape.  It has no seed
/// and rejects any proof observation or challenge-kind divergence.
pub(crate) struct C61PrivateEntropyReplayChallenger {
    state: Arc<Mutex<C61ReplayState>>,
}

impl Clone for C61PrivateEntropyReplayChallenger {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

impl C61PrivateEntropyReplayChallenger {
    pub(crate) fn new(
        tape: C61InteractiveTape,
        num_variables: usize,
        context_digest: [u8; 32],
    ) -> ReferenceResult<Self> {
        if tape.checkpoint.num_variables as usize != num_variables
            || tape.checkpoint.context_digest != context_digest
        {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier tape context mismatch"));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(C61ReplayState {
                tape,
                next_record: 0,
                initial_root_seen: false,
                public_statement_bound: false,
                num_variables,
                pending_provider_move: Vec::new(),
                interaction: C61WhirInteractionStats::default(),
            })),
        })
    }

    pub(crate) fn observe_public_point(&mut self, point: &Point<C61P3Fp2>) -> ReferenceResult<()> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.initial_root_seen || state.public_statement_bound {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier public-point order mismatch"));
        }
        if point.num_variables() != state.num_variables {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier public-point arity mismatch"));
        }
        state.public_statement_bound = true;
        Ok(())
    }

    fn replay(&self, kind: C61ChallengeKind) -> ReferenceResult<C61ChallengeValue> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.public_statement_bound {
            return Err(C61WhirReferenceError::new(
                "C6ICT1 verifier challenge before public statement",
            ));
        }
        let index = state.next_record;
        let provider_move = std::mem::take(&mut state.pending_provider_move);
        let record = state
            .tape
            .checkpoint
            .records
            .get(index)
            .ok_or_else(|| C61WhirReferenceError::new("C6ICT1 verifier exhausted challenge tape"))?
            .clone();
        if record.provider_move != provider_move || record.kind != kind {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier tape divergence"));
        }
        if !record.provider_move.is_empty() {
            state.interaction.provider_messages += 1;
            state.interaction.provider_semantic_bytes += record.provider_move.len() as u64;
        }
        state.next_record += 1;
        state.interaction.client_challenge_payload_bytes += match record.kind {
            C61ChallengeKind::Fp => {
                state.interaction.client_fp_challenges += 1;
                C61_WHIRA1_FP_BYTES as u64
            }
            C61ChallengeKind::Fp2 => {
                state.interaction.client_fp_challenges += 2;
                16
            }
            C61ChallengeKind::Query { .. } => {
                state.interaction.client_query_challenges += 1;
                4
            }
        };
        Ok(record.value)
    }

    pub(crate) fn finish(&self, payload: &[u8]) -> ReferenceResult<C61WhirInteractionStats> {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        if !state.pending_provider_move.is_empty()
            || state.next_record != state.tape.checkpoint.records.len()
        {
            return Err(C61WhirReferenceError::new("C6ICT1 verifier did not consume exact tape"));
        }
        if payload.len() != state.tape.final_payload_bytes
            || *blake3::hash(payload).as_bytes() != state.tape.final_payload_blake3
            || state.interaction.provider_semantic_bytes as usize > payload.len()
        {
            return Err(C61WhirReferenceError::new("C6ICT1 final artifact seal mismatch"));
        }
        if state.interaction.provider_semantic_bytes < payload.len() as u64 {
            state.interaction.provider_messages += 1;
        }
        state.interaction.provider_payload_bytes = payload.len() as u64;
        Ok(state.interaction)
    }
}

impl CanObserve<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn observe(&mut self, value: Goldilocks) {
        self.state
            .lock()
            .expect("C6ICT1 replay mutex poisoned")
            .pending_provider_move
            .extend_from_slice(&value.as_canonical_u64().to_le_bytes());
    }
}

impl CanObserve<MerkleCap<Goldilocks, [u8; 32]>> for C61PrivateEntropyReplayChallenger {
    fn observe(&mut self, value: MerkleCap<Goldilocks, [u8; 32]>) {
        let mut state = self.state.lock().expect("C6ICT1 replay mutex poisoned");
        assert_eq!(value.num_roots(), 1, "C6ICT1 replay requires cap height zero");
        state.initial_root_seen = true;
        state.pending_provider_move.extend_from_slice(&value.roots()[0]);
    }
}

impl CanSample<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn sample(&mut self) -> Goldilocks {
        match self.replay(C61ChallengeKind::Fp).unwrap_or_else(|error| panic!("{error}")) {
            C61ChallengeValue::Fp(value) => Goldilocks::new(value),
            _ => panic!("C6ICT1 replay field tag mismatch"),
        }
    }
}

impl CanSampleBits<usize> for C61PrivateEntropyReplayChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C6ICT1 replay query width must fit u32");
        match self
            .replay(C61ChallengeKind::Query { bits: bits as u8 })
            .unwrap_or_else(|error| panic!("{error}"))
        {
            C61ChallengeValue::Query(value) => value as usize,
            _ => panic!("C6ICT1 replay query tag mismatch"),
        }
    }
}

impl CanSampleUniformBits<Goldilocks> for C61PrivateEntropyReplayChallenger {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61PrivateEntropyReplayChallenger {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6ICT1 replay proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61PrivateEntropyReplayChallenger {}

impl fmt::Debug for C61PrivateEntropyProverChallenger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("C61PrivateEntropyProverChallenger(endpoint-only)")
    }
}

#[cfg(test)]
mod tests {
    use volta_field::{Fp, Fp2};

    use super::*;

    #[test]
    fn transcript_broker_carries_exact_fp_fp2_and_bit_challenges() {
        let context_digest = [0xC2; 32];
        let (endpoint, handle) =
            spawn_c61_private_entropy_transcript_broker([0x71; 32], 28, context_digest).unwrap();
        let mut transcript = Transcript::new_interactive(Box::new(endpoint));
        transcript.append_message("first", &[1, 2, 3, 4]);
        assert_ne!(transcript.challenge_fp(), Fp::ZERO);
        transcript.append_message("second", &[5; 16]);
        assert_ne!(transcript.challenge_fp2(), Fp2::ZERO);
        transcript.append_message_digest("third", 4096, [0xA5; 32]);
        assert!(transcript.challenge_bits(20) < (1 << 20));
        transcript.append("terminal", 32);
        let payload = vec![0x5A; 8192];
        transcript.finish_interactive(&payload).unwrap();

        let output = handle.finish_output().unwrap();
        assert_eq!(output.tape.challenge_count(), 3);
        assert_eq!(output.interaction.client_fp_challenges, 3);
        assert_eq!(output.interaction.client_query_challenges, 1);
        assert_eq!(output.interaction.provider_semantic_bytes, 4148);
        assert_eq!(output.interaction.provider_payload_bytes, payload.len() as u64);
        assert_eq!(output.transcript_bytes, payload.len() as u64);
        let encoded = output.tape.checkpoint_bytes(3).unwrap();
        let decoded = C61InteractiveCheckpoint::decode(&encoded).unwrap();
        assert_eq!(decoded, output.tape.checkpoint);
        let tape_bytes = output.tape.encode().unwrap();
        assert_eq!(tape_bytes.len(), output.tape.encoded_len());
        assert_eq!(C61InteractiveTape::decode(&tape_bytes).unwrap(), output.tape);
        let mut changed_tape_bytes = tape_bytes.clone();
        changed_tape_bytes[12] ^= 1;
        assert!(C61InteractiveTape::decode(&changed_tape_bytes).is_err());
        let mut changed_tape_digest = tape_bytes.clone();
        *changed_tape_digest.last_mut().unwrap() ^= 1;
        assert!(C61InteractiveTape::decode(&changed_tape_digest).is_err());
        assert!(C61InteractiveTape::decode(&tape_bytes[..tape_bytes.len() - 1]).is_err());

        let mut replay_transcript = output.tape.replay_transcript(28, context_digest).unwrap();
        replay_transcript.append_message("first", &[1, 2, 3, 4]);
        assert_ne!(replay_transcript.challenge_fp(), Fp::ZERO);
        replay_transcript.append_message("second", &[5; 16]);
        assert_ne!(replay_transcript.challenge_fp2(), Fp2::ZERO);
        replay_transcript.append_message_digest("third", 4096, [0xA5; 32]);
        assert!(replay_transcript.challenge_bits(20) < (1 << 20));
        replay_transcript.append("terminal", 32);
        replay_transcript.finish_interactive(&payload).unwrap();

        let changed =
            C61PrivateEntropyTranscriptReplayEndpoint::new(output.tape, 28, context_digest)
                .unwrap();
        let mut changed_transcript = Transcript::new_interactive(Box::new(changed));
        changed_transcript.append_message("first", &[1, 2, 3, 5]);
        assert_eq!(changed_transcript.challenge_fp(), Fp::ONE);
        assert!(changed_transcript
            .interactive_error()
            .is_some_and(|error| error.contains("provider move or kind diverged")));
    }

    #[test]
    fn duplex_transcript_releases_only_past_challenges_and_seals_both_roles() {
        let context = [0xD3; 32];
        let (provider, replay, handle) =
            spawn_c61_private_entropy_duplex_transcript_broker([0x91; 32], 0, context).unwrap();
        let mut provider_tx = Transcript::new_interactive(Box::new(provider));
        let mut replay_tx = Transcript::new_interactive(Box::new(replay));

        provider_tx.append_message("round-0", &[1, 2, 3]);
        let first = provider_tx.challenge_fp2();
        replay_tx.append_message("round-0", &[1, 2, 3]);
        assert_eq!(replay_tx.challenge_fp2(), first);
        provider_tx.append_message_digest("round-1", 4096, [0xA5; 32]);
        let second = provider_tx.challenge_fp();
        replay_tx.append_message_digest("round-1", 4096, [0xA5; 32]);
        assert_eq!(replay_tx.challenge_fp(), second);

        let payload = [0xC6; 8192];
        provider_tx.finish_interactive(&payload).unwrap();
        replay_tx.finish_interactive(&payload).unwrap();
        let tape = handle.finish().unwrap();
        assert_eq!(tape.challenge_count(), 2);

        let mut disk_tx = tape.replay_transcript(0, context).unwrap();
        disk_tx.append_message("round-0", &[1, 2, 3]);
        assert_eq!(disk_tx.challenge_fp2(), first);
        disk_tx.append_message_digest("round-1", 4096, [0xA5; 32]);
        assert_eq!(disk_tx.challenge_fp(), second);
        disk_tx.finish_interactive(&payload).unwrap();
    }

    #[test]
    fn duplex_transcript_rejects_frontier_move_and_payload_mutations() {
        let context = [0xD4; 32];
        let (provider, replay, handle) =
            spawn_c61_private_entropy_duplex_transcript_broker([0x92; 32], 0, context).unwrap();
        let mut provider_tx = Transcript::new_interactive(Box::new(provider));
        let mut replay_tx = Transcript::new_interactive(Box::new(replay));
        provider_tx.append_message("round", &[7]);
        let _ = provider_tx.challenge_fp2();
        replay_tx.append_message("round", &[8]);
        assert_eq!(replay_tx.challenge_fp2(), Fp2::ONE);
        assert!(replay_tx.interactive_error().is_some());
        assert!(handle.finish().is_err());

        let (provider, replay, handle) =
            spawn_c61_private_entropy_duplex_transcript_broker([0x93; 32], 0, context).unwrap();
        let mut provider_tx = Transcript::new_interactive(Box::new(provider));
        let mut replay_tx = Transcript::new_interactive(Box::new(replay));
        provider_tx.append_message("round", &[9]);
        let challenge = provider_tx.challenge_fp();
        replay_tx.append_message("round", &[9]);
        assert_eq!(replay_tx.challenge_fp(), challenge);
        provider_tx.finish_interactive(&[0x11; 64]).unwrap();
        assert!(replay_tx.finish_interactive(&[0x12; 64]).is_err());
        assert!(handle.finish().is_err());

        let (provider, _replay, handle) =
            spawn_c61_private_entropy_duplex_transcript_broker([0x94; 32], 0, context).unwrap();
        let mut provider_tx = Transcript::new_interactive(Box::new(provider));
        provider_tx.append_message("round", &[10]);
        let _ = provider_tx.challenge_fp();
        assert!(provider_tx.finish_interactive(&[0x13; 64]).is_err());
        assert!(handle.finish().is_err());
    }

    #[test]
    fn seven_native_lanes_and_response_tape_are_canonical_bound_and_ordered() {
        let contexts: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES] =
            std::array::from_fn(|index| [0x30 + index as u8; 32]);
        let mut tapes = Vec::with_capacity(C61_INTERACTIVE_TAPE_LANES);
        for (index, context) in contexts.iter().copied().enumerate() {
            let (endpoint, handle) =
                spawn_c61_private_entropy_transcript_broker([0x70 + index as u8; 32], 0, context)
                    .unwrap();
            let mut transcript = Transcript::new_interactive(Box::new(endpoint));
            transcript.append_message("lane", &[index as u8]);
            let _ = transcript.challenge_fp2();
            transcript.finish_interactive(&[0xA0 + index as u8; 64]).unwrap();
            tapes.push(handle.finish().unwrap());
        }
        let tapes: [C61InteractiveTape; C61_INTERACTIVE_TAPE_LANES] = tapes.try_into().unwrap();
        let response_context = [0x3F; 32];
        let (response_endpoint, response_handle) =
            spawn_c61_private_entropy_transcript_broker([0x7F; 32], 0, response_context).unwrap();
        let mut response_transcript = Transcript::new_interactive(Box::new(response_endpoint));
        response_transcript.append_message("response", &[0xF0]);
        let _ = response_transcript.challenge_fp2();
        response_transcript.finish_interactive(&[0xF1; 64]).unwrap();
        let response_tape = response_handle.finish().unwrap();
        let certificate_digest = [0xC6; 32];
        let bundle = C61InteractiveTapeBundle {
            attempt_digest: [0xA7; 32],
            certificate_digest,
            tapes,
            response_tape,
        };
        bundle.validate_contexts(certificate_digest, contexts, response_context).unwrap();
        let encoded = bundle.encode().unwrap();
        assert_eq!(encoded.len(), bundle.encoded_len());
        assert_eq!(C61InteractiveTapeBundle::decode(&encoded).unwrap(), bundle);

        let mut moved = bundle.clone();
        moved.tapes.swap(0, 1);
        assert!(moved.validate_contexts(certificate_digest, contexts, response_context).is_err());
        assert!(bundle.validate_contexts([0xC7; 32], contexts, response_context).is_err());

        let mut duplicated = bundle.clone();
        duplicated.response_tape = duplicated.tapes[0].clone();
        assert!(duplicated.encode().is_err());

        let mut corrupted = encoded.clone();
        corrupted[44] ^= 1;
        assert!(C61InteractiveTapeBundle::decode(&corrupted).is_err());
        assert!(C61InteractiveTapeBundle::decode(&encoded[..encoded.len() - 1]).is_err());
    }
}
