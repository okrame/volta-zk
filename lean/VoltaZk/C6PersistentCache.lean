import Mathlib.Data.List.Basic
import Mathlib.Tactic

/-!
# C6 persistent committed cache and abort/rollback state

This is the new cross-certificate seam.  It does not alter frozen M4's
within-response authenticated write log.  Instead it specifies the compact
state accepted between certificates:

* a certificate consumes exactly the currently accepted predecessor head;
* a binding commitment identifies the old cache and an append transition;
* acceptance advances epoch/head atomically;
* abort burns only the attempt slot and leaves the accepted client state
  unchanged;
* a produced slot permits only byte-identical retransmission;
* replay of an already accepted certificate is impossible without rolling
  back the durable client state.

Concrete commitment collision resistance is an explicit `Function.Injective`
hypothesis.  No hash-binding axiom is introduced.
-/

namespace VoltaZk

/-- Compact cache state retained by the client. -/
structure C6CacheHead (Digest : Type*) where
  epoch : ℕ
  cacheLen : ℕ
  root : Digest
  predecessorCertificate : Digest
deriving DecidableEq

/-- Durable single-client state in C6 V1. -/
structure C6ClientState (Digest : Type*) where
  connectionId : Digest
  head : C6CacheHead Digest
  acceptedCertificate : Digest
deriving DecidableEq

/-- State-binding fields of one final C6 certificate. -/
structure C6Certificate (Digest Nonce : Type*) where
  oldHead : C6CacheHead Digest
  newHead : C6CacheHead Digest
  predecessorCertificate : Digest
  nonce : Nonce
  slot : ℕ
  digest : Digest
deriving DecidableEq

namespace C6Certificate

variable {Digest Nonce : Type*}

/-- Checks performed before a certificate may be atomically committed. -/
def Admissible (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce) : Prop :=
  certificate.oldHead = state.head
    ∧ certificate.predecessorCertificate = state.acceptedCertificate
    ∧ certificate.newHead.epoch = certificate.oldHead.epoch + 1
    ∧ certificate.oldHead.cacheLen ≤ certificate.newHead.cacheLen

/-- The only durable state produced by successful acceptance. -/
def advance (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce) : C6ClientState Digest :=
  {
    state with
    head := certificate.newHead
    acceptedCertificate := certificate.digest
  }

/-- Successful acceptance changes only the head/certificate pair; connection
identity remains fixed. -/
theorem advance_connectionId (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce) :
    (advance state certificate).connectionId = state.connectionId := rfl

theorem advance_head (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce) :
    (advance state certificate).head = certificate.newHead := rfl

theorem advance_digest (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce) :
    (advance state certificate).acceptedCertificate = certificate.digest := rfl

/-- **Anti-replay.**  After one admissible certificate advances the durable
head, the same certificate cannot be admissible again. -/
theorem accepted_certificate_not_replayable (state : C6ClientState Digest)
    (certificate : C6Certificate Digest Nonce)
    (h : certificate.Admissible state) :
    ¬ certificate.Admissible (advance state certificate) := by
  intro replay
  have holdNew : certificate.oldHead = certificate.newHead := by
    calc
      certificate.oldHead = (advance state certificate).head := replay.1
      _ = certificate.newHead := rfl
  have hepoch := h.2.2.1
  rw [holdNew] at hepoch
  omega

end C6Certificate

/-- Abstract fixed-capacity cache transition.  `newSlab` is appended to the
accepted predecessor cache; paths and values are wrapper witness, not wire. -/
structure C6CacheTransition (Value : Type*) where
  oldCache : List Value
  newSlab : List Value
  newCache : List Value

namespace C6CacheTransition

variable {Value Digest : Type*}

/-- Commitment/root and append conditions proved by the wrapper. -/
def Valid (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value) : Prop :=
  commit transition.oldCache = oldHead.root
    ∧ transition.newCache = transition.oldCache ++ transition.newSlab
    ∧ commit transition.newCache = newHead.root
    ∧ oldHead.cacheLen = transition.oldCache.length
    ∧ newHead.cacheLen = transition.newCache.length

/-- Binding is an explicit premise: two witnesses for one accepted old root
must be the same old cache. -/
theorem old_cache_unique (commit : List Value → Digest)
    (hbind : Function.Injective commit)
    (oldHead newHead₁ newHead₂ : C6CacheHead Digest)
    (transition₁ transition₂ : C6CacheTransition Value)
    (h₁ : transition₁.Valid commit oldHead newHead₁)
    (h₂ : transition₂.Valid commit oldHead newHead₂) :
    transition₁.oldCache = transition₂.oldCache := by
  apply hbind
  rw [h₁.1, h₂.1]

/-- A valid transition is append-only at the concrete value level. -/
theorem append_only (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value)
    (h : transition.Valid commit oldHead newHead) :
    transition.newCache = transition.oldCache ++ transition.newSlab :=
  h.2.1

/-- Cache length cannot decrease under the append transition. -/
theorem cache_length_monotone (commit : List Value → Digest)
    (oldHead newHead : C6CacheHead Digest)
    (transition : C6CacheTransition Value)
    (h : transition.Valid commit oldHead newHead) :
    oldHead.cacheLen ≤ newHead.cacheLen := by
  rw [h.2.2.2.1, h.2.2.2.2, h.2.1, List.length_append]
  omega

end C6CacheTransition

/-- Durable lifecycle of one response slot. -/
inductive C6SlotStatus
  | available
  | reserved
  | inFlight
  | produced
  | accepted
  | burned
deriving DecidableEq

/-- Slot identity and its unique produced certificate digest. -/
structure C6Slot (Digest Nonce : Type*) where
  id : ℕ
  rangeStart : ℕ
  rangeCount : ℕ
  nonce : Nonce
  predecessorHead : Digest
  status : C6SlotStatus
  producedCertificate : Option Digest
deriving DecidableEq

namespace C6Slot

variable {Digest Nonce : Type*}

/-- Abort is fail-closed for the individual range. -/
def burn (slot : C6Slot Digest Nonce) : C6Slot Digest Nonce :=
  { slot with status := .burned }

/-- ACK ambiguity permits only retransmission of the recorded digest. -/
def Retransmittable (slot : C6Slot Digest Nonce) (digest : Digest) : Prop :=
  (slot.status = .produced ∨ slot.status = .accepted)
    ∧ slot.producedCertificate = some digest

/-- A produced slot has at most one retransmittable certificate digest. -/
theorem retransmission_digest_unique (slot : C6Slot Digest Nonce)
    {digest₁ digest₂ : Digest}
    (h₁ : slot.Retransmittable digest₁)
    (h₂ : slot.Retransmittable digest₂) :
    digest₁ = digest₂ := by
  exact Option.some.inj (h₁.2.symm.trans h₂.2)

theorem burn_status (slot : C6Slot Digest Nonce) :
    slot.burn.status = .burned := rfl

/-- Burning never changes which one-time range was consumed. -/
theorem burn_preserves_range (slot : C6Slot Digest Nonce) :
    (slot.burn.rangeStart, slot.burn.rangeCount)
      = (slot.rangeStart, slot.rangeCount) := rfl

/-- Burning never changes the predecessor/nonce identity, so a retry cannot
reinterpret the old range under a new attempt. -/
theorem burn_preserves_attempt_identity (slot : C6Slot Digest Nonce) :
    (slot.burn.id, slot.burn.nonce, slot.burn.predecessorHead)
      = (slot.id, slot.nonce, slot.predecessorHead) := rfl

end C6Slot

/-- Abort updates only the provider slot journal. -/
def c6AbortAttempt {Digest Nonce : Type*}
    (state : C6ClientState Digest) (slot : C6Slot Digest Nonce) :
    C6ClientState Digest × C6Slot Digest Nonce :=
  (state, slot.burn)

/-- **Abort semantics.**  The last accepted client head and certificate stay
byte-for-byte unchanged. -/
theorem c6_abort_preserves_accepted_state {Digest Nonce : Type*}
    (state : C6ClientState Digest) (slot : C6Slot Digest Nonce) :
    (c6AbortAttempt state slot).1 = state := rfl

/-- Abstract crash result of the atomic client commit.  Durable recovery sees
either the complete old state or the complete new state, never a mixed head. -/
inductive C6AtomicOutcome {Digest Nonce : Type*}
    (old : C6ClientState Digest) (certificate : C6Certificate Digest Nonce)
  | oldState
  | newState

/-- Recovery interpretation of the two atomic outcomes. -/
def C6AtomicOutcome.state {Digest Nonce : Type*}
    {old : C6ClientState Digest} {certificate : C6Certificate Digest Nonce} :
    C6AtomicOutcome old certificate → C6ClientState Digest
  | .oldState => old
  | .newState => certificate.advance old

theorem c6_atomic_state_is_old_or_new {Digest Nonce : Type*}
    (old : C6ClientState Digest) (certificate : C6Certificate Digest Nonce)
    (outcome : C6AtomicOutcome old certificate) :
    outcome.state = old ∨ outcome.state = certificate.advance old := by
  cases outcome <;> simp [C6AtomicOutcome.state]

/-- Logical event cover for predecessor-conditional certificate soundness.
If the accepted predecessor and every named wrapper seam are good, the
transition is valid; hence a false transition must lie in a separately named
bad event. -/
theorem c6_false_transition_event_cover
    (predecessorValid wrapperGood residualGood commitmentGood transitionValid : Prop)
    (hrefine :
      predecessorValid → wrapperGood → residualGood → commitmentGood → transitionValid)
    (hfalse : ¬ transitionValid) :
    ¬ predecessorValid ∨ ¬ wrapperGood ∨ ¬ residualGood ∨ ¬ commitmentGood := by
  tauto

end VoltaZk
