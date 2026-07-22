use volta_field::{Fp, Fp2};
use volta_pcs::x4::{
    root_of_unity, CohortIdentityV4, CohortTreeV4, CohortVerifierConfigV4, Fp2NttPlan, OracleKindV4,
};

fn descriptor_pattern(slot: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = (slot.wrapping_mul(17).wrapping_add(index).wrapping_add(1)) as u8;
    }
    digest
}

fn print_digest(label: &str, digest: [u8; 32]) {
    print!("{label}=");
    for byte in digest {
        print!("{byte:02x}");
    }
    println!();
}

fn tree_root(
    structural_slots: usize,
    present_slots: usize,
    cohort_id: u32,
    oracle_kind: OracleKindV4,
    fold_round: u8,
) -> [u8; 32] {
    let outer_len = 32usize;
    let slot_descriptors = (0..structural_slots)
        .map(|slot| (slot < present_slots).then(|| descriptor_pattern(slot)))
        .collect::<Vec<_>>();
    let slot_symbols = (0..structural_slots)
        .map(|slot| {
            (slot < present_slots).then(|| {
                (0..outer_len)
                    .map(|coordinate| {
                        Fp2::new(
                            Fp::new((slot * 257 + coordinate * 17 + 3) as u64),
                            Fp::new((slot * 19 + coordinate * coordinate + 5) as u64),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    CohortTreeV4::build_flat(
        CohortVerifierConfigV4 {
            identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round },
            slot_descriptors,
            outer_len,
            expected_symbol_count: 1,
        },
        slot_symbols,
    )
    .expect("reference tree")
    .root()
}

fn main() {
    let mut payload = [0u8; 104];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index * 29 + 7) as u8;
    }
    for (label, context) in [
        ("derive_pcs_leaf", "volta-zk/x4/pcs-leaf/v4"),
        ("derive_pcs_node", "volta-zk/x4/pcs-node/v4"),
        ("derive_manifest_leaf", "volta-zk/x4/manifest-leaf/v4"),
        ("derive_manifest_node", "volta-zk/x4/manifest-node/v4"),
    ] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(&payload);
        print_digest(label, *hasher.finalize().as_bytes());
    }

    let root = root_of_unity(33).expect("2^33 root");
    println!("root_2_33={:016x}:{:016x}", root.c0.value(), root.c1.value());

    let coefficients = (0..11)
        .map(|index| Fp2::new(Fp::new(index * 17 + 3), Fp::new(index * index + 5)))
        .collect::<Vec<_>>();
    let encoded = Fp2NttPlan::new(32).expect("reference NTT").encode(&coefficients).unwrap();
    for (index, value) in encoded.iter().enumerate() {
        println!("ntt_{index:02}={:016x}:{:016x}", value.c0.value(), value.c1.value());
    }

    print_digest("root_m1_p1", tree_root(1, 1, 7, OracleKindV4::WeightExtension, 0));
    print_digest("root_m2_p1", tree_root(2, 1, 8, OracleKindV4::Auxiliary, 0));
    print_digest("root_m16_p13", tree_root(16, 13, 9, OracleKindV4::WeightExtension, 0));
    print_digest("root_m64_p49", tree_root(64, 49, 10, OracleKindV4::Auxiliary, 0));
    print_digest("root_fold", tree_root(1, 1, 11, OracleKindV4::GlobalFoldAggregate, 3));
}
