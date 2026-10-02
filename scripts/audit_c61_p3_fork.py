#!/usr/bin/env python3
"""Fail-closed source provenance for the Plonky3 forks reused by C7.1."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "rust" / "third_party"
MANIFEST = THIRD_PARTY / "C61_P3_UPSTREAM_SHA256SUMS"
REVISION = "66e290615de1858f2f2f6a804158064c406cda1c"

# Initial C7.1 B2 review at 2d949dc; B12 common-pad and live salt-stream
# reviews: active specs and rust/volta-pcs/src/c71_matrix/b12/replay_tree.rs.
# Pin content, not just filenames: a later edit requires another explicit review.
REVIEWED_DELTAS = {
    "merkle-tree/src/hiding_mmcs.rs": "96b60d03788ed158d744aeffbdbf74c836e49f7b1bd1d76c197c296ce94d73a4",
    "merkle-tree/src/merkle_tree.rs": "fbf4e1a5d2a35056ea7c791ed51c732f1157f8c760cd3b86d0f95752fb9ec10d",
    "sumcheck/src/strategy.rs": "f57d565614913fd4c73150c56947e48219239c360d41cdc826702c10f6545199",
    "sumcheck/src/zk/data.rs": "d232f1849fcfeba844b54892bb225fddca665dd5f18347b950ea710262ecda9e",
    "sumcheck/src/zk/mod.rs": "da41b12bdebae2e7bda25a5c32b884c5628e8e55be68da2fb358f9a4a2cc3369",
    "sumcheck/src/zk/prover/mod.rs": "c940595342df9708fc78ea2d768c834fd992d5fa02625b3b70612fc1cd17b4ef",
    "sumcheck/src/zk/prover/residual.rs": "89ac6a1fff3525975c0bd91b3fbe3fd107176bf6774262eeb654cdce30fe6822",
    "sumcheck/src/zk/prover/zk_prover.rs": "549d68c03efc5cac081dac944c15a723282708629e29244376e808b78374e972",
    "sumcheck/src/zk/verifier.rs": "1b6e268b534f14077fa8e56941ca5e081d6d4481dbf7a918cb599a2d9c3537a7",
    "whir/src/fiat_shamir/domain_separator.rs": "0b6befed2c7800e01d740fc2ff77ddfcd1816f1cb7df26618b49a3118024c2c5",
    "whir/src/fiat_shamir/pattern.rs": "4f6cceca63afed5080da22c237e0ddb65bcb5601434b8f35f06961b7c7b7ca1f",
    "whir/src/lib.rs": "99de98e84fb910d2766b5658c5ad7adf69e93dea5d8ef481d63eff79eb6ee9ed",
    "whir/src/parameters/whir.rs": "69940e6e6d5e66d9b2d01fba329607fd59e25c0ed106f40abbe8324f4f6f381b",
    "whir/src/pcs/zk/base_case/mod.rs": "693ba0ec816cb0fca4960bb14a7c07f9c6be1d36f015cf1790c8d1ff211217ec",
    "whir/src/pcs/zk/base_case/prover.rs": "fe3b77c36c183a34925d4aeca4f3efb1acc219fb09f4873042bd76e1a7f1fd9c",
    "whir/src/pcs/zk/base_case/verifier.rs": "537e1950e9938174e4e95ea7ac3995a670c1ff2af855bf3f7c99cddd9d999094",
    "whir/src/pcs/zk/code_switch.rs": "62c939f65cab7e951e820b322c2491e38b342f7921b156a8ecd4c706cba0a0d4",
    "whir/src/pcs/zk/committer.rs": "4c7c86c4ff3236d0aeae88c36ad33262646693914d3f1ba712237d5fa33077e7",
    "whir/src/pcs/zk/config.rs": "fe4c304e367f99ae5d9bba28c5bf1d10d87706420bdfc2c41cf152bd7fc05320",
    "whir/src/pcs/zk/mod.rs": "13ec481db27c9db647ba2ec665ced70281cbe94d81aaeb49667b709bebb35e06",
    "whir/src/pcs/zk/proof.rs": "313dd6bb3b67e0504dc0d546c41c258be12a79d88a8af90f82700b0feb17c0a1",
    "whir/src/pcs/zk/prover/data.rs": "af84d5fcab44180ebcdb246f90a941e33ca50911ce5b0e408fbf3e938360ea6f",
    "whir/src/pcs/zk/prover/masks.rs": "dae258f8cd5e717d864b824daee062473b545b0be317e5df12ea831ad98488ba",
    "whir/src/pcs/zk/prover/mod.rs": "be3ab299a30e9d15b42e93b37a5859f64949deaa29608816238be8d1e27aac45",
    "whir/src/pcs/zk/verifier/masks.rs": "6e808029b7eee32ea9e51db75c441df5a89461ead6b827311ae227b9e5e4cb21",
    "whir/src/pcs/zk/verifier/mod.rs": "8dcbab319ba34669d713cacd72b1a5e98cae49d89d627c46bd879b8229e792bd",
}
ALLOWED_DELTAS = frozenset(REVIEWED_DELTAS)

# The historical 87-source manifest is immutable. These nine hashes extend
# the same upstream revision to the Merkle dependency actually selected by Cargo.
MERKLE_UPSTREAM = {
    "merkle-tree/src/hiding_mmcs.rs": "0293a2261f6b46c5e7ba585cce36fbf291717e02602725ca977aba8e696f921c",
    "merkle-tree/src/lib.rs": "04eac5d40e5f404ff2d3c6d171fbfa28f4fcb3af35da23088275073907fd9eff",
    "merkle-tree/src/merkle_tree.rs": "49e5391e1ec0b6e5cc0b3cd2f36249994804dc4297ee090a5276049754cc72a8",
    "merkle-tree/src/mmcs/batch.rs": "e91228643f1d5a48c683c94cfa5fc9d75212c6b64e64d9d93c51b6c7525d713a",
    "merkle-tree/src/mmcs/error.rs": "7bb85833e07d9bd881432695fecfcc185f69f26c748131f26c46bb1aa2ef81a2",
    "merkle-tree/src/mmcs/geometry.rs": "f629ce4a945c1289b1f214c6600febfbbc4795ac226380bad2ad64804c1678e5",
    "merkle-tree/src/mmcs/mod.rs": "c6af51fcae2dd8a2709f6b17cad2356b6f441203a9a06955d37cc5a5c2216db4",
    "merkle-tree/src/mmcs/pruned.rs": "e0d9c7876de92275dc59d7a27abaf4439577065ca392e1547c47035e8b3f9a76",
    "merkle-tree/src/pruning.rs": "acbad34851adaf33da0713fa158d345c035a4eefeec6995a384f6ac6c610d522",
}

CRATES = {
    "merkle-tree": THIRD_PARTY / "p3-merkle-tree-c61",
    "sumcheck": THIRD_PARTY / "p3-sumcheck-c61",
    "whir": THIRD_PARTY / "p3-whir-c61",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict[str, str]:
    records: dict[str, str] = {}
    for line_number, raw in enumerate(MANIFEST.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if (len(fields) != 2 or len(fields[0]) != 64
                or any(c not in "0123456789abcdef" for c in fields[0])):
            raise SystemExit(f"malformed upstream hash at line {line_number}")
        sha256, relative = fields
        if relative in records:
            raise SystemExit(f"duplicate upstream path: {relative}")
        records[relative] = sha256
    if len(records) != 87 or set(records) & MERKLE_UPSTREAM.keys():
        raise SystemExit("historical upstream source census changed")
    return records | MERKLE_UPSTREAM


def vendored_path(relative: str) -> Path:
    crate, inner = relative.split("/", 1)
    try:
        return CRATES[crate] / inner
    except KeyError as error:
        raise SystemExit(f"unknown manifest crate: {crate}") from error


def actual_sources() -> set[str]:
    paths: set[str] = set()
    for crate, root in CRATES.items():
        for path in (root / "src").rglob("*.rs"):
            paths.add(f"{crate}/{path.relative_to(root).as_posix()}")
    return paths


def require_source_guards() -> None:
    hiding_mmcs = (CRATES["merkle-tree"] / "src/hiding_mmcs.rs").read_text()
    replay_tree = (ROOT / "rust/volta-pcs/src/c71_matrix/b12/replay_tree.rs").read_text()
    private_rng_calls = sum(
        path.read_text().count(".with_private_rng(")
        for path in (ROOT / "rust/volta-pcs/src").rglob("*.rs")
    )
    if hiding_mmcs.count("pub fn with_private_rng") != 1 or private_rng_calls != 1:
        raise SystemExit("live salt-stream access must remain one reviewed replay-tree call")
    if replay_tree.count(".with_private_rng(") != 1:
        raise SystemExit("reviewed replay tree no longer owns the live salt-stream access")

    replay_data = (CRATES["whir"] / "src/pcs/zk/prover/data.rs").read_text()
    replay_prover = (CRATES["whir"] / "src/pcs/zk/prover/mod.rs").read_text()
    replay_backend = (ROOT / "rust/volta-pcs/src/c71_matrix/b12/replay.rs").read_text()
    if "pub struct ZkWhirReplayHandle(Box<dyn Any + Send + Sync>)" not in replay_data:
        raise SystemExit("WHIR replay handle is no longer opaque prover-local ownership")
    if replay_prover.count("oracle.release_replay(handle)?;") != 2:
        raise SystemExit("WHIR replay handles must be released after rounds and base case")
    for required in (
        "ZkRoundData::Replay(initial_handle)",
        "oracle.open_replay(handle, &stir_indexes, &batch.randomness)?",
        "oracle.open_replay(handle, positions, &batch.randomness)",
    ):
        if required not in replay_prover:
            raise SystemExit(f"WHIR replay lifecycle guard missing: {required}")
    for required in (
        "mmcs.bind(indices, &rows, &proof);",
        "drop(tree); // no opening callback survives when the generation is released",
        "lease.release()?;",
    ):
        if required not in replay_backend:
            raise SystemExit(f"native WHIR replay guard missing: {required}")

    proof = (CRATES["whir"] / "src/pcs/zk/proof.rs").read_text()
    prover = (CRATES["whir"] / "src/pcs/zk/prover/mod.rs").read_text()
    verifier = (CRATES["whir"] / "src/pcs/zk/verifier/mod.rs").read_text()
    residual = (CRATES["sumcheck"] / "src/zk/prover/residual.rs").read_text()
    if "pub evals:" in proof:
        raise SystemExit("claimless ZK proof regressed to a clear evaluation field")
    if prover.count("into_zk_sumcheck_claimless_with_residual(") != 2:
        raise SystemExit("claimless prover must use exactly two claimless sumcheck batches")
    if "claims.len() <= 128" not in prover or "claims[0]" in prover:
        raise SystemExit("claimless prover lost its bounded ordered multi-opening reduction")
    if "verify_affine_claim" not in verifier:
        raise SystemExit("claimless verifier no longer performs affine replay")
    if "points.len() > 128" not in verifier or "points[0]" in verifier:
        raise SystemExit("claimless verifier lost its bounded ordered multi-opening reduction")
    wrapper = residual.split("pub fn into_zk_sumcheck_claimless_with_residual", 1)
    if len(wrapper) != 2 or "aux_claim,\n        false," not in wrapper[1].split(
        "fn into_zk_sumcheck_with_residual", 1
    )[0]:
        raise SystemExit("sumcheck claimless entry point no longer disables clear binding")

    adapter = (ROOT / "rust/volta-pcs/src/c61_authenticated_whir_p3.rs").read_text()
    production_adapter = adapter.split("#[cfg(test)]", 1)[0]
    # Current call-site census, including C62's common executor/replay and
    # compact compiler replay. These are drift guards, not a security proof.
    if production_adapter.count("C61InteractiveChallenger::new_claimless(") != 8:
        raise SystemExit("claimless provider/verifier/simulator must use no-skip challenger mode")
    if production_adapter.count(".observe_public_point(") != 5:
        raise SystemExit(
            "claimless roles plus private-entropy provider/replay must explicitly bind the point"
        )
    if production_adapter.count(".observe_public_points(") != 11:
        raise SystemExit("claimless multi-opening roles must bind the complete ordered point batch")
    if production_adapter.count(".ensure_public_statement_bound()") != 5:
        raise SystemExit("claimless roles must fail closed on incomplete statements")
    if production_adapter.count("challenger.finish(") != 9:
        raise SystemExit("claimless roles must finalize strict wire accounting")
    if "proof.evals" in production_adapter:
        raise SystemExit("claimless adapter regressed to a clear evaluation codec field")
    if 'C61_AUTHENTICATED_P3_MAGIC: [u8; 8] = *b"C6AWP1\\0\\0"' not in production_adapter:
        raise SystemExit("claimless adapter strict codec identity changed")
    if 'C61_SHARED_MULTI_ORACLE_MAGIC: [u8; 8] = *b"C6SMO1\\0\\0"' not in production_adapter:
        raise SystemExit("shared-round multi-oracle strict codec identity changed")
    if production_adapter.count("c61_shared_round_pair(") != 3:
        raise SystemExit("shared-round provider and both verifier paths must use lockstep pairs")
    if production_adapter.count(".sample_postproof_fp2()") != 3:
        raise SystemExit("shared-round roles lost the fresh post-proof residual batch")
    if (
        '66e290615de1858f2f2f6a804158064c406cda1c+c61-claimless-affine-multi-v2'
        not in production_adapter
    ):
        raise SystemExit("claimless fork semantic revision is not pinned")
    if "decode_c61_authenticated_p3_artifact_inner" not in production_adapter:
        raise SystemExit("claimless verifier no longer consumes the strict codec")
    if "fn simulate_view_diagnostic(" not in production_adapter:
        raise SystemExit("designated-view simulator entry point is absent")
    simulator = production_adapter.split("fn simulate_view_diagnostic(", 1)[1].split(
        "fn verify_diagnostic(", 1
    )[0]
    if "target_key: VerifierKey" not in simulator:
        raise SystemExit("designated-view simulator lost its verifier target key")
    for forbidden in ("target_tag", "ProverAuthed", "CorrelationStream"):
        if forbidden in simulator:
            raise SystemExit(
                f"designated-view simulator reads forbidden provider state: {forbidden}"
            )
    if "simulate_c61_authenticated_whir_base_view(" not in simulator:
        raise SystemExit("designated-view simulator no longer derives the tag from verifier state")
    verifier_adapter = production_adapter.split("fn verify_diagnostic(", 1)[1].split(
        "/// Run one reference-only", 1
    )[0]
    if any(
        forbidden in verifier_adapter
        for forbidden in ("artifact.provider_", "artifact.point", "artifact.target_key")
    ):
        raise SystemExit("claimless verifier regained provider-local fixture metadata")

    driver = (ROOT / "rust/volta-pcs/src/c61_interactive_driver.rs").read_text()
    if 'C61_INTERACTIVE_CHECKPOINT_MAGIC: [u8; 8] = *b"C6ICT1\\0\\0"' not in driver:
        raise SystemExit("private-entropy checkpoint codec identity changed")
    if 'C61_DURABLE_JOURNAL_MAGIC: [u8; 8] = *b"C6ICJ1\\0\\0"' not in driver:
        raise SystemExit("durable private-entropy journal identity changed")
    endpoint = driver.split("struct C61ProviderEndpoint", 1)[1].split("}", 1)[0]
    if "SyncSender<C61BrokerRequest>" not in endpoint:
        raise SystemExit("private-entropy provider endpoint lost its typed broker channel")
    for forbidden in ("verifier_seed", "checkpoint", "Transcript"):
        if forbidden in endpoint:
            raise SystemExit(
                f"private-entropy provider endpoint reads verifier state: {forbidden}"
            )
    provider = production_adapter.split(
        "fn prove_private_entropy_provider_diagnostic(", 1
    )[1].split("fn prove_private_entropy_diagnostic(", 1)[0]
    for forbidden in ("verifier_seed", "checkpoint"):
        if forbidden in provider:
            raise SystemExit(
                f"private-entropy provider helper reads verifier state: {forbidden}"
            )
    for required in (
        "spawn_c61_private_entropy_broker",
        "spawn_c61_durable_private_entropy_broker",
        "C61PrivateEntropyReplayChallenger",
        "C61InteractiveCheckpoint::decode(",
        "state.pending_attempt != Some(attempt)",
        "journal.append_mask_frontier(frontier, provider_move_digest)?",
        "self.file.sync_all()",
    ):
        if required not in driver and required not in production_adapter:
            raise SystemExit(f"private-entropy driver guard missing: {required}")
    fresh_challenge = driver.split(
        "if records.len() >= checkpoint.records.len()", 1
    )[1].split("C61BrokerRequest::MaskFrontier", 1)[0]
    persist_at = fresh_challenge.find("journal.append_challenge(record.clone())?")
    release_at = fresh_challenge.find("response.send(Ok(broker_response))")
    if persist_at < 0 or release_at < 0 or persist_at > release_at:
        raise SystemExit("durable challenge is released before its journal fsync path")


def build_report() -> dict[str, object]:
    expected = load_manifest()
    actual = actual_sources()
    expected_paths = set(expected)
    missing = sorted(expected_paths - actual)
    extra = sorted(actual - expected_paths)
    if missing or extra:
        raise SystemExit(f"fork source census mismatch: missing={missing}, extra={extra}")
    if len(expected) != 96:
        raise SystemExit(f"upstream source census changed: expected 96, got {len(expected)}")
    if len(ALLOWED_DELTAS) != 26:
        raise SystemExit("reviewed C7.1 delta census must remain exactly 26 files")

    changed: list[str] = []
    for relative, upstream_hash in sorted(expected.items()):
        current_hash = digest(vendored_path(relative))
        if current_hash != upstream_hash:
            changed.append(relative)
            if relative not in ALLOWED_DELTAS:
                raise SystemExit(f"unregistered vendored source delta: {relative}")
            if current_hash != REVIEWED_DELTAS[relative]:
                raise SystemExit(f"reviewed vendored source content changed: {relative}")
    if set(changed) != ALLOWED_DELTAS:
        absent = sorted(ALLOWED_DELTAS - set(changed))
        raise SystemExit(f"registered C6.1 delta unexpectedly equals upstream: {absent}")

    for root in CRATES.values():
        if (root / "Cargo.lock").exists():
            raise SystemExit(f"generated library lockfile is forbidden: {root / 'Cargo.lock'}")
        if (root / "target").exists():
            raise SystemExit(f"crate-local Cargo target directory is forbidden: {root / 'target'}")
        cargo = (root / "Cargo.toml").read_text()
        provenance = "C61_FORK_PROVENANCE.md" if root == CRATES["merkle-tree"] else "UPSTREAM.md"
        upstream = (root / provenance).read_text()
        if REVISION not in cargo or REVISION not in upstream:
            raise SystemExit(f"fork identity is not pinned in {root}")

    require_source_guards()
    return {
        "profile": "C7.1-p3-fork-provenance-v3",
        "credit": False,
        "scope": "pinned source provenance and textual guards; not protocol security or native execution",
        "initial_reviewed_runtime_commit": "2d949dc",
        "subsequent_review": "B12 common switch-mask pad and live salt-stream replay; exact hashes in REVIEWED_DELTAS",
        "historical_manifest_source_files": 87,
        "merkle_dependency_source_files": 9,
        "reviewed_delta_content_pinned": True,
        "upstream_revision": REVISION,
        "upstream_source_files": len(expected),
        "allowed_modified_source_files": changed,
        "allowed_modified_source_file_count": len(changed),
        "all_other_source_files_byte_identical": True,
        "generated_library_lockfiles_absent": True,
        "crate_local_target_directories_absent": True,
        "claimless_source_guards": True,
        "claimless_adapter_statement_guards": True,
        "claimless_strict_codec_guards": True,
        "private_entropy_driver_source_guards": True,
        "durable_private_entropy_journal_source_guards": True,
        "live_salt_stream_single_caller_guard": True,
        "sourcewise_replay_lifecycle_guards": True,
        "verdict": "C71_PINNED_FORK_PROVENANCE_PASS",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["verdict"])
        print(f"upstream revision: {report['upstream_revision']}")
        print(f"upstream source files: {report['upstream_source_files']}")
        print(f"registered source deltas: {report['allowed_modified_source_file_count']}")
        print("all other source files: byte-identical")


if __name__ == "__main__":
    main()
