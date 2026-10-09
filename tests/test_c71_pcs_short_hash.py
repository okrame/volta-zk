"""Independent pinned BLAKE3 leaf/node/root and salts replay parity. No CUDA."""
import hashlib
import json
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = 0xFFFFFFFF00000001
CAP = 1 << 40
LEAF = b"volta-zk/c71/b12/merkle/leaf/v1\0"
NODE = b"volta-zk/c71/b12/merkle/node/v1\0"

# Link the same already-built, pinned dependency as the existing Rust salt
# fixture. No Cargo invocation, registry access or replacement hash oracle.
ORACLE = r'''
use std::io::{self, Read, Write};
fn n(input: &[u8], at: &mut usize, bytes: usize) -> u64 {
    let mut x = 0u64;
    for i in 0..bytes { x |= (input[*at+i] as u64) << (8*i); }
    *at += bytes; x
}
fn main() {
    let mut input = Vec::new(); io::stdin().read_to_end(&mut input).unwrap();
    let mut at = 0usize; let count = n(&input, &mut at, 4);
    let mut output = Vec::new();
    for _ in 0..count {
        match n(&input, &mut at, 1) {
            0 => {
                let len = n(&input, &mut at, 4) as usize;
                output.extend_from_slice(blake3::hash(&input[at..at+len]).as_bytes());
                at += len;
            }
            1 => {
                let seed = &input[at..at+32]; at += 32;
                let origin = n(&input, &mut at, 8);
                let leaves = n(&input, &mut at, 4);
                assert!(origin <= (1u64<<40) && leaves <= 65536);
                let mut hash = blake3::Hasher::new();
                hash.update(b"volta-zk/c71/b12/private-coins/v1\0"); hash.update(seed);
                let mut reader = hash.finalize_xof(); reader.set_position(origin);
                let mut positions = Vec::new(); positions.push(origin);
                for _ in 0..leaves {
                    let mut accepted = 0;
                    while accepted < 4 {
                        assert!(reader.position() <= (1u64<<40)-8);
                        let mut bytes = [0u8;8]; reader.fill(&mut bytes);
                        if u64::from_le_bytes(bytes) < 0xffffffff00000001 {
                            output.extend_from_slice(&bytes); accepted += 1;
                        }
                    }
                    positions.push(reader.position());
                }
                for position in positions { output.extend_from_slice(&position.to_le_bytes()); }
            }
            _ => panic!("unknown reference operation"),
        }
    }
    assert_eq!(at, input.len()); io::stdout().write_all(&output).unwrap();
}
'''


def _u32(value):
    return struct.pack("<I", value)


def _u64s(values):
    return struct.pack(f"<{len(values)}Q", *values)


def _build_oracle(tmp_path):
    deps = ROOT / "rust/target/debug/deps"
    libraries = sorted(deps.glob("libblake3-*.rlib"), key=lambda path: path.stat().st_mtime_ns)
    assert libraries, "Build the pinned repository Rust test dependencies first; no fetch/fallback."
    library = libraries[-1]
    source = tmp_path / "short-hash-reference.rs"
    source.write_text(ORACLE)
    binary = tmp_path / "short-hash-reference"
    subprocess.run(["rustc", "--edition=2021", "-O", str(source), "--crate-name",
                    "c71_short_hash_reference", "--extern", f"blake3={library}",
                    "-L", f"dependency={deps}", "-o", str(binary)], check=True, timeout=30)
    return binary, library


def _oracle(binary, requests):
    payload = _u32(len(requests)) + b"".join(requests)
    return subprocess.run([str(binary)], input=payload, capture_output=True,
                          check=True, timeout=20).stdout


def _hashes(binary, messages):
    result = _oracle(binary, [b"\0" + _u32(len(message)) + message for message in messages])
    assert len(result) == 32 * len(messages)
    return [result[i:i+32] for i in range(0, len(result), 32)]


def _values(rows, cosets, case):
    # Distinct PCS extension-column/limb/coset/row values exercise all
    # layout coordinates; edge limbs 0 and p-1 also remain canonical.
    output = []
    for col in range(12):
        for coset in range(cosets):
            for row in range(rows):
                index = ((col * cosets + coset) * rows + row)
                if (index + case) % 19 == 0:
                    output.append(0)
                elif (index + case) % 23 == 0:
                    output.append(P - 1)
                else:
                    output.append(((col+1) * 0x914C301BEC035541
                                   + (coset+3) * 0x41A938D24036737F
                                   + (row+7) * 0xB145839046839551 + case) % P)
    return output


def test_pcs_short_leaves_salts_bands_and_all_merkle_nodes(tmp_path):
    oracle, library = _build_oracle(tmp_path)
    shapes = [(1, 2, 1, 0), (2, 4, 3, 1), (8, 16, 7, 7),
              (32, 64, 63, 63), (128, 2, 257, 4095),
              (512, 16, 1023, (1 << 38) + 7),
              (1024, 2, 65536, CAP - 4*2048*8 - 128)]
    seeds = [bytes((17*case+3*i) % 256 for i in range(32)) for case in range(len(shapes))]
    raw_salts = _oracle(oracle, [b"\1" + seed + struct.pack("<Q", origin) + _u32(rows*cosets)
                               for seed, (rows, cosets, _, origin) in zip(seeds, shapes)])
    salt_cases, at = [], 0
    for rows, cosets, _, _ in shapes:
        height = rows*cosets
        salts = list(struct.unpack_from(f"<{4*height}Q", raw_salts, at)); at += 32*height
        positions = list(struct.unpack_from(f"<{height+1}Q", raw_salts, at)); at += 8*(height+1)
        salt_cases.append((salts, positions))
    assert at == len(raw_salts)
    payload = bytearray(_u32(len(shapes)))
    expected_leaf_total = expected_node_total = 0
    for case, ((rows, cosets, band, origin), seed, (salts, positions)) in enumerate(
            zip(shapes, seeds, salt_cases)):
        height = rows*cosets
        values = _values(rows, cosets, case)
        messages = []
        for coset in range(cosets):
            for row in range(rows):
                limb_values = [values[(col*cosets+coset)*rows+row] for col in range(12)]
                natural = row*cosets+coset
                messages.append(LEAF + _u64s(limb_values) + _u64s(salts[4*natural:4*natural+4]))
        leaves = _hashes(oracle, messages)
        levels, previous, width = [], leaves, cosets
        while width > 1:
            previous = _hashes(oracle, [NODE + previous[(2*col)*rows+row]
                                       + previous[(2*col+1)*rows+row]
                                       for col in range(width//2) for row in range(rows)])
            levels.append(previous); width //= 2
        row_nodes, roots = [], previous
        while len(roots) > 1:
            roots = _hashes(oracle, [NODE + roots[2*row] + roots[2*row+1]
                                    for row in range(len(roots)//2)])
            row_nodes.extend(roots)
        payload.extend(seed + struct.pack("<QIII", origin, rows, cosets, band))
        payload.extend(_u64s(values) + _u64s(salts) + _u64s(positions))
        payload.extend(b"".join(leaves))
        for level in levels:
            payload.extend(b"".join(level))
        payload.extend(b"".join(row_nodes) + roots[0])
        expected_leaf_total += height
        expected_node_total += height-1
        # The independent oracle is sensitive to limb order, canonical LE
        # word bytes, salts and the short final block's exact message size.
        first = messages[0]
        swapped = first[:32] + first[40:48] + first[32:40] + first[48:]
        assert _hashes(oracle, [first, swapped, first+b"\0"*32])[0] == leaves[0]
        if first[32:40] != first[40:48]:
            assert _hashes(oracle, [swapped])[0] != leaves[0]
        assert _hashes(oracle, [first+b"\0"*32])[0] != leaves[0]
    originals = [[0]*128, [P-1]*128, list(range(128)),
                 [(i*0x913747EF332A0441+0xFEDCBA9876543210) % P for i in range(128)]]
    original_salts = [0, 1, P-1, 0xEFCDAB8967452301]
    original_hashes = _hashes(oracle, [LEAF+_u64s(values)+_u64s(original_salts) for values in originals])
    payload.extend(_u32(len(originals)))
    for values, digest in zip(originals, original_hashes):
        payload.extend(_u64s(values)+_u64s(original_salts)+digest)
    binary = tmp_path / "pcs-short-hash-host"
    subprocess.run(["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(ROOT / "cuda"),
                    str(ROOT / "tests/c71_pcs_short_hash_host.cpp"), "-o", str(binary)],
                   check=True, timeout=30)
    result = subprocess.run([str(binary)], input=bytes(payload), capture_output=True, check=True, timeout=20)
    text = result.stdout.decode()
    report = json.loads(text.strip().removeprefix("C71_PCS_SHORT_HASH_HOST "))
    print(text.strip())
    print("C71_PCS_SHORT_HASH_REFERENCE " + json.dumps({
        "stdin_bytes": len(payload), "stdin_sha256": hashlib.sha256(payload).hexdigest(),
        "oracle": "pinned repository Rust blake3::hash and OutputReader",
        "oracle_rlib_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "cargo_lock_sha256": hashlib.sha256((ROOT / "rust/Cargo.lock").read_bytes()).hexdigest(),
        "cuda_compilation": False, "gpu_execution": False, "credit": False,
    }))
    assert report["cases"] == len(shapes)
    assert report["leaves"] == expected_leaf_total
    assert report["nodes"] == expected_node_total
    assert report["original128_cases"] == len(originals)
    assert report["span_guard_checks"] == 22
    assert report["large_row_replay_cases"] == 2
    assert report["canonical_rejections"] == 2*report["bands"]
    assert report["paired_leaves"] == expected_leaf_total
    assert report["paired_nodes"] == expected_leaf_total//2
    assert report["paired_bands"] > 0 and report["host_paired_fixture_seconds"] > 0
    assert report["replay_logical_bytes"] == sum(positions[-1]-origin
        for (_, _, _, origin), (_, positions) in zip(shapes, salt_cases))
    assert report["paired_replay_logical_bytes"] == report["replay_logical_bytes"]
    assert report["named_heap_peak_bytes"] < 16*1024**2
    assert report["short_leaf_bytes"] == 160 and report["short_leaf_compressions"] == 3
    assert all(report[key] > 0 for key in ("host_replay_seconds", "host_hash_fixture_seconds",
                                          "host_nodes_fixture_seconds"))
    assert not report["gpu_execution"] and not report["integrated"] and not report["credit"]
