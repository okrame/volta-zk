//! Public-only capacity census. No witness, weights, device, PCG or admission.
use super::*;
use std::mem::{size_of, MaybeUninit};

fn heap<T>(make: impl FnOnce() -> T) -> (T, usize) {
    let start = kernel::census::host_layout_bytes();
    let value = make();
    (value, (kernel::census::host_layout_bytes() - start) as usize)
}

fn arc_bytes<T>() -> usize {
    let start = kernel::census::host_layout_bytes();
    let (value, bytes) = heap(|| Arc::new(MaybeUninit::<T>::uninit()));
    assert!(bytes >= size_of::<T>() + 2 * size_of::<usize>());
    drop(value);
    assert_eq!(kernel::census::host_layout_bytes(), start);
    bytes
}

// Rust BTree nodes have two layouts. At the first root split, the newly
// allocated leaf+branch is an upper for either node, including alignment.
fn node_bytes<K: Ord + Copy, V>(keys: [K; 12]) -> usize {
    let start = kernel::census::host_layout_bytes();
    let mut tree = BTreeMap::<K, MaybeUninit<V>>::new();
    tree.insert(keys[0], MaybeUninit::uninit());
    let leaf = kernel::census::host_layout_bytes() - start;
    for key in &keys[1..11] { tree.insert(*key, MaybeUninit::uninit()); }
    assert_eq!(kernel::census::host_layout_bytes() - start, leaf);
    tree.insert(keys[11], MaybeUninit::uninit());
    let split = kernel::census::host_layout_bytes() - start - leaf;
    assert!(split > leaf, "pinned std BTree root split changed");
    drop(tree);
    assert_eq!(kernel::census::host_layout_bytes(), start);
    split as usize
}

fn nodes(count: usize) -> usize {
    // Every nonempty node owns a key; allow an empty root and one unfinished
    // split per level while inserting. This also covers deletion/root collapse.
    count + 1 + if count == 0 { 0 } else { count.ilog2() as usize + 2 }
}

fn producer_metadata(profile: &Canonical) -> serde_json::Value {
    let sources = &profile.bytes().scalar.layout.sources;
    let count = sources.len();
    let kv: BTreeSet<_> = profile.sources.attention.layers.iter().flat_map(|l| [l.k,l.v]).collect();
    let cuts = profile.checkpoint_ids().unwrap().len();
    let mut ports = 0;
    let mut max_inputs = 0;
    let mut max_outputs = 0;
    let mut histogram_count = 0;
    let mut histogram_seen = 0;
    for (step, producer) in profile.steps.iter().enumerate() {
        let (input, output) = profile.ports(producer);
        ports += input.len();
        max_inputs = max_inputs.max(input.len()).max(input_keys(profile, step, 0).unwrap().len());
        max_outputs = max_outputs.max(output.len());
        if let Some((_, output, _)) = profile.native_lookup_sources(step) {
            histogram_count += 1;
            histogram_seen += sources[output].rows;
        }
    }
    assert_eq!((count, profile.steps.len(), cuts, histogram_count), (3471,2328,61,121));
    assert!(sources.iter().all(|s| s.rows <= 8192));
    assert!(max_inputs <= 32 && max_outputs <= 6 && kv.len() <= 120);
    let key = core::array::from_fn(|i| i);
    let row_node = node_bytes::<usize,Rows>(key);
    let live_node = node_bytes::<(usize,usize),Rows>(core::array::from_fn(|i| (i,0)));
    let tail_node = node_bytes::<usize,Tail>(key);
    let histogram_node = node_bytes::<usize,Histogram>(key);
    let seen_node = node_bytes::<usize,Vec<bool>>(key);
    let bitmap_node = node_bytes::<usize,Vec<u64>>(key);
    let scalar_node = node_bytes::<usize,usize>(key);
    let set_node = node_bytes::<usize,()>(key);
    let seen = sources.iter().map(|s| s.rows).sum::<usize>();
    let bitmap = sources.iter().map(|s| s.rows.div_ceil(64)*8).sum::<usize>();
    // Three promoted/accepted entries, one current generation. The additional
    // KV map exists during build/replay before it is moved or retired.
    let persistent = 3*nodes(kv.len())*tail_node + nodes(cuts)*row_node
        + nodes(histogram_count)*row_node + 4*size_of::<Entry>()
        + 3*size_of::<Arc<Canonical>>() + 2*60*size_of::<usize>();
    // A common-owner slot is required for each unique Engine.live Rows. Source
    // maps/bitmaps use actual full-source counts, not a small fixture's frontier.
    let replay = nodes(512)*live_node + nodes(histogram_count)*histogram_node
        + histogram_seen + nodes(kv.len())*tail_node
        + nodes(count)*seen_node + seen + nodes(count)*bitmap_node + bitmap
        + 6*nodes(count.max(profile.steps.len()))*set_node
        + nodes(cuts)*scalar_node
        + count*(size_of::<usize>()+size_of::<Option<usize>>())
        + profile.steps.len()*size_of::<Vec<usize>>() + 4*count*size_of::<usize>()
        + 2*(count+ports)*size_of::<usize>()
        + 512*size_of::<(usize,usize)>()
        + 2*max_inputs*size_of::<(usize,usize)>()
        + max_inputs*size_of::<&Rows>() + 2*max_outputs*size_of::<Rows>();
    serde_json::json!({"old_tokens":profile.sources.attention.rope.old,"source_count":count,
        "source_rows_sum":seen,"source_bitmap_bytes":bitmap,"producer_steps":profile.steps.len(),
        "ports_input_count":ports,"kv_source_count":kv.len(),"checkpoint_sources":cuts,
        "histogram_sources":histogram_count,"histogram_seen_bytes":histogram_seen,
        "node_upper_bytes":{"rows":row_node,"live_rows":live_node,"tails":tail_node,
            "histograms":histogram_node,"seen":seen_node,"bitmap":bitmap_node,
            "scalar":scalar_node,"set":set_node},
        "persistent_descriptor_heap_upper_bytes":persistent,
        "producer_descriptor_heap_upper_bytes":replay,
        "scope":"typed node/Vec upper; bitmap plus scanner may coexist; no numeric/device payload or row cache"})
}

#[test]
fn c71_canonical_public_metadata_capacity_pinned_no_private_inputs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let candidate = root.join("artifact/c7.1-pod/pilot-complete-20261007T133500Z/pilot-fp64-full/candidate.json");
    let admission = root.join("artifact/c7.1-pod/gamma-admission-20261007T155133Z/admission.json");
    let body = std::fs::read(&candidate).unwrap();
    assert!(body.len() <= 1<<20);
    let receipt: serde_json::Value = serde_json::from_slice(&std::fs::read(admission).unwrap()).unwrap();
    assert_eq!(receipt["gamma_admitted"], true);
    assert!(receipt["evidence"].as_array().unwrap().iter().any(|v|
        v["path"].as_str()==Some("artifact/c7.1-pod/pilot-complete-20261007T133500Z/pilot-fp64-full/candidate.json")
        && v["sha256"].as_str()==Some("8965d0c3dc170e41b304982b90409b0362e93de4d029b08bba3716ab64dbf95e")));
    let start = kernel::census::reset_host_layout_peak();
    let first: Vec<_> = calibration_input::profiles_capacity_only(&body).unwrap().into_iter().map(Arc::new).collect();
    let first_bytes = kernel::census::host_layout_bytes()-start;
    let second: Vec<_> = calibration_input::profiles_capacity_only(&body).unwrap().into_iter().map(Arc::new).collect();
    let six_bytes = kernel::census::host_layout_bytes()-start;
    let build_peak = kernel::census::host_layout_peak_bytes()-start;
    assert_eq!(six_bytes,2*first_bytes);
    let mut metadata = Vec::with_capacity(3);
    for slot in 0..3 {
        let p = &first[slot];
        assert_eq!(p.sources.attention.rope.old,150*slot);
        assert_eq!(p.recipes.digest,second[slot].recipes.digest);
        assert_eq!(blake3::Hash::from_bytes(p.recipes.digest).to_hex().as_str(),
            "d96b9350cfe9e47acda8cebaf02b895de66d55c525fa2c4463f20022dc3c1014");
        metadata.push(producer_metadata(p));
    }
    // from_bytes uses fixed-size exact iterators only: values cannot change
    // capacities. Zero public bytes exercise that allocation path, no table
    // certification or alternative Gamma admission is claimed.
    let table_body = vec![0; calibration_input::Tables::BYTES];
    let table_start = kernel::census::host_layout_bytes();
    let table_p = Arc::new(calibration_input::Tables::from_bytes(&table_body).unwrap());
    let table_v = calibration_input::Tables::from_bytes(&table_body).unwrap();
    let table_heap = (kernel::census::host_layout_bytes()-table_start) as usize;
    let declared = table_p.capacity_bytes()+table_v.capacity_bytes();
    assert_eq!(table_heap,declared+2*size_of::<usize>()-size_of::<calibration_input::Tables>());
    let table_metadata = table_heap-2*calibration_input::Tables::BYTES;
    let public_table_views = 6*120*size_of::<kernel::lookup::Table<'static>>();
    let (_gammas,gamma_heap) = heap(|| [
        gamma(&Domain::Flat(35).config().unwrap()),gamma(&Domain::Flat(34).config().unwrap()),
        gamma(&Domain::Flat(35).config().unwrap()),gamma(&Domain::Flat(34).config().unwrap())]);
    let session_arc = arc_bytes::<Session>();
    let runtime_arc = arc_bytes::<Mutex<Runtime>>();
    let prepared_arc = arc_bytes::<Prepared>();
    let buffer_arc = arc_bytes::<Buffer>();
    let fs_arc = arc_bytes::<Mutex<kernel::FsState>>();
    let fixed = session_arc+runtime_arc+3*prepared_arc+512*buffer_arc+arc_bytes::<()>()
        + arc_bytes::<Vec<i16>>() + arc_bytes::<super::super::ordered::Cache>() + 3*262144*8 + 18*4096 + 20*size_of::<String>() + 4*fs_arc;
    // Tree::open has at most 512 pruned subtrees. Only typed map nodes are
    // additional here; batch_indices and Vec<triple> payload belong to class 3.
    let path_node=node_bytes::<usize,Vec<(usize,usize,usize)>>(core::array::from_fn(|i|i));
    let path_nodes=nodes(512)*path_node;
    let weight_tiles=first[0].plan.pcs_weight_tiles();
    let pcs = kernel::b12::replay::public_metadata_descriptor_upper(weight_tiles.capacity());
    let before_drop=kernel::census::host_layout_bytes();
    drop((first,second));
    let retired_profiles=before_drop-kernel::census::host_layout_bytes();
    assert_eq!(retired_profiles,six_bytes);
    println!("C71_PUBLIC_METADATA_CAPACITY {}",serde_json::json!({
        "schema":"volta-c71-public-metadata-capacity-v1","credit":false,"admission":false,
        "private_inputs":false,"gpu_execution":false,"rms_temporary_validation_skipped":true,
        "candidate_blake3":blake3::hash(&body).to_hex().to_string(),
        "recipe_digest":"d96b9350cfe9e47acda8cebaf02b895de66d55c525fa2c4463f20022dc3c1014",
        "live_profile_slots":[[0,150,300],[0,150,300]],"profile_count":6,
        "three_profile_actual_heap_bytes":first_bytes,"six_profile_actual_heap_bytes":six_bytes,
        "profile_build_metadata_only_heap_peak_bytes":build_peak,"retired_profile_actual_heap_bytes":retired_profiles,"producer_metadata":metadata,
        "table_heap_actual_shape_bytes":table_heap,"table_payload_bytes":2*calibration_input::Tables::BYTES,
        "table_metadata_actual_shape_bytes":table_metadata,"borrowed_table_view_heap_upper_bytes":public_table_views,
        "public_gamma_encoding_heap_bytes":gamma_heap,"table_capacity_value_independent":true,
        "public_value_sizeof_bytes":size_of::<super::super::state::Public<'static>>(),
        "typed_arc_bytes":{"session":session_arc,"runtime":runtime_arc,"prepared":prepared_arc,
            "buffer":buffer_arc,"fs":fs_arc},"fixed_and_row_cache_heap_upper_bytes":fixed,
        "row_cache_heap_upper_bytes_already_named":3*262144*8,
        "fixed_descriptor_heap_upper_bytes":fixed-3*262144*8,
        "paths_upper_bytes":18*4096,
        "paths_bound_requires_run_manifest_argv_and_path_cap":4096,
        "pruned_path_btree_node_heap_upper_bytes":path_nodes,"pruned_path_subtree_count_upper":512,
        "pcs_metadata":pcs,
        "measurement":"global requested-layout delta includes nested Vec/String/BTree/Arc; input/output JSON excluded",
        "exclusions":"numeric/device/root/pad payloads are elsewhere; no full joint fit or physical peak claim"}));
}
