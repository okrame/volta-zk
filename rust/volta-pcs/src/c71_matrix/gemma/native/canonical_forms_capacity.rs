//! Class 8 public constructor upper bounds. No witness, polynomial, PCG or IO.
//! A coefficient zero can remove a cube, never increase these emission counts.
//! Source project emits at most popcount(rows)*popcount(cols) scalar tiles;
//! pullback emits popcount(codec width) byte planes per scalar tile. The view
//! count below also accounts both alignments of a split lane interval.
use super::*;
use core::mem::size_of;
use crate::c71_matrix::linear::{self, Cube};

#[derive(Clone, Copy)]
struct Constructor {
    name: &'static str,
    targets: usize,
    cubes: usize,
    scalar_temporary: usize,
}
fn scalar_tiles(s: &Source) -> usize {
    s.rows.count_ones() as usize * s.cols.count_ones() as usize
}
fn word(b: &bytes::Bytes, id: usize) -> usize {
    scalar_tiles(&b.scalar.layout.sources[id]) * b.widths[id].count_ones() as usize
}
fn view(b: &bytes::Bytes, id: usize, first: usize) -> usize {
    let mut pieces = 0;
    for (offset, width) in intervals(b.widths[id]) {
        let mut start = 0;
        while start < width {
            let mut size = (width - start).next_power_of_two();
            while start % size != 0 || (first + offset + start) % size != 0 { size /= 2; }
            pieces += 1;
            start += size;
        }
    }
    scalar_tiles(&b.scalar.layout.sources[id]) * pieces
}
// Same public alignment rule used by original selected-row and KV routes.
fn route_pieces(rows: usize, offset: usize) -> usize {
    let (mut local, mut pieces) = (0, 0);
    while local < rows {
        let mut size = (rows - local).next_power_of_two();
        while size > rows - local || local % size != 0 || (offset + local) % size != 0 {
            size /= 2;
        }
        local += size;
        pieces += 1;
    }
    pieces
}
fn constructor_bounds(p: &Canonical) -> Vec<Constructor> {
    let b = p.bytes();
    let a = &p.sources.attention;
    let rope = &a.rope;
    let gu = &rope.gate_up;
    let g = &gu.gelu;
    let rms = &g.rms;
    let mut result = Vec::new();
    let mut push = |name, targets, cubes, scalar_temporary| {
        result.push(Constructor { name, targets, cubes, scalar_temporary });
    };
    // Public-form constructors all complete before the first Batch::add.
    // For affine, both i16 inputs are charged even if this Gamma sets a zero
    // coefficient: the geometry bound remains valid for every allowed scale.
    let affine = p.recipes.affine.iter().map(|r| {
        4 * scalar_tiles(&b.scalar.layout.sources[r.raw])
    }).sum();
    push("public_affine", 1, affine, 0);
    let output = &b.scalar.layout.sources[p.output.output];
    // Each selected vocabulary vertex is in exactly one dyadic scalar tile.
    push("public_argmax", 1, word(b, p.output.output) + word(b, p.output.slack) + output.rows, 0);
    let forbidden = bytes::mask::forbidden_rectangles(150, rope.old).unwrap();
    let allowed = bytes::mask::allowed_rectangles(150, rope.old).unwrap();
    // mask.rs already establishes one cube per aligned head/key rectangle.
    push("public_causal", 1, forbidden.len() * a.layers.len(), 1);
    let zero = p.softmax.layers.iter().map(|s| {
        word(b, s.difference) + word(b, s.denominator)
        + allowed.len() * (word(b, s.maximum) + word(b, s.score) + word(b, s.exponential))
    }).sum();
    push("public_softmax_zero", 1, zero, 1);

    let mut p0 = 0;
    let mut p0_scalar = 0;
    for id in 0..p.plan.cohorts.len() {
        p0 += word(b, id);
        p0_scalar += scalar_tiles(&b.scalar.layout.sources[id]);
    }
    for (index, &id) in b.scalar.input_sources.iter().enumerate() {
        let route = p.plan.input_route(index + 1).unwrap();
        let pieces = if route.row_offset == 0 && route.selected_rows == route.rows {
            1
        } else { route_pieces(route.selected_rows, route.row_offset) };
        p0 += pieces * word(b, id);
        p0_scalar += pieces * scalar_tiles(&b.scalar.layout.sources[id]);
    }
    // bytes.forms first creates ALL scalar forms, then pulls them back one
    // at a time. Charge that old scalar collection, not only one source.
    push("P0_A_pullback", p.plan.cohorts.len() + b.scalar.input_sources.len(), p0, p0_scalar);
    let mut norm = 0;
    let mut joint = 0;
    let mut rms_scalar_max = 0;
    for n in &rms.norms {
        let tiles = n.rows.count_ones() as usize * n.columns.count_ones() as usize;
        norm += word(b, n.statistic) + 2 * tiles * word(b, n.input);
        let first = if n.cohort.is_some() { 4 } else { 2 };
        joint += tiles * (view(b, n.product, 0) + view(b, n.output, first + 6) + view(b, n.statistic, first));
        for id in [n.input, n.product, n.output, n.statistic] {
            rms_scalar_max = rms_scalar_max.max(scalar_tiles(&b.scalar.layout.sources[id]));
        }
    }
    push("RMS_originals_and_joint", 3 * rms.norms.len() + 1, norm + joint, rms_scalar_max);
    // The original/table RNE partition is the existing verifier-owned recipe.
    let fresh = p.recipes.table_pairs(&p.plan).unwrap();
    let originals = [&p.recipes.matrix, &p.recipes.gate_up, &p.recipes.rope,
        &p.recipes.score, &p.recipes.pv, &p.recipes.residual].into_iter().flatten()
        .filter(|q| !fresh.iter().any(|f| f.raw == q.raw)).collect::<Vec<_>>();
    assert_eq!(originals.len(), 410);
    push("original_RNE", originals.len(), originals.iter().map(|q| view(b, q.raw, 0)).sum(), 0);
    push("whole_table_RNE", 2 * fresh.len(), fresh.iter().map(|q| view(b, q.raw, 0) + word(b, q.output)).sum(), 1);

    let (mut gelu, mut gate) = (0, 0);
    for (i, q) in g.gelu.iter().enumerate() {
        let tiles = q.rows.count_ones() as usize * q.columns.count_ones() as usize;
        gelu += tiles * (word(b, q.input) + word(b, q.output));
        gelu += 65535usize.count_ones() as usize * word(b, q.histogram);
        gate += tiles * (word(b, gu.products[i].raw) + word(b, q.output) + word(b, gu.products[i].up));
    }
    push("GELU_lookup", 3, gelu, 16);
    push("gate_up", 3, gate, 1);
    let rotation = rope.rotations.iter().map(|r| {
        let tiles = r.rows.count_ones() as usize * (r.heads * r.width).count_ones() as usize;
        tiles * (word(b, r.raw) + word(b, rms.norms[r.norm].output))
    }).sum();
    push("RoPE", 2, rotation, 1);
    push("QK_PV_originals", 4 * a.layers.len(), a.layers.iter().map(|l| {
        word(b, l.raw_score) + word(b, l.q) + word(b, l.raw_output) + word(b, l.pi)
    }).sum(), 1);
    let mut kv_current = 0;
    for l in &a.layers {
        for id in [l.k, l.v] {
            kv_current += route_pieces(b.scalar.layout.sources[id].rows, rope.old) * word(b, id);
        }
    }
    push("KV_current", 1, kv_current, 1);
    let out_query = scalar_tiles(output) * (word(b, p.output.input) + word(b, p.output.output));
    push("softcap_lookup", 3, out_query + 65535usize.count_ones() as usize * word(b, p.output.histogram), 16);
    let mut sm = 0;
    for s in &p.softmax.layers {
        // The rectangle bound charges all source tiles; coefficient zero and
        // fixed rectangle prefixes only reduce this conservative emission count.
        sm += allowed.len() * (word(b, s.difference) + view(b, s.exponential, 0)
            + view(b, s.denominator, 4) + view(b, s.pi, 10));
        let tiles = scalar_tiles(&b.scalar.layout.sources[s.difference]);
        sm += tiles * (word(b, s.difference) + word(b, s.exponential));
        sm += 65535usize.count_ones() as usize * word(b, s.histogram);
    }
    push("softmax_originals", 5, sm, 16);
    // Full EQ contributes one cube; dyadic padding suffix contributes <=D.
    push("A_range", 2, 35, 0);
    let scalar_max = b.scalar.layout.sources.iter().map(scalar_tiles).max().unwrap();
    for r in &mut result { r.scalar_temporary = r.scalar_temporary.max(scalar_max); }
    result
}

#[test]
fn c71_canonical_forms_constructor_capacity_public_upper_bounds() {
    let plan = super::super::super::compile().unwrap();
    let (s, o, sm) = plan.softmax_sources_at(0).unwrap();
    let mut exponents: BTreeMap<_, _> = profile::Recipes::exponent_sources(&s, &o, &sm)
        .into_iter().map(|id| (id, 0)).collect();
    for layer in &sm.layers { exponents.insert(layer.pi, -14); }
    let cube = size_of::<Cube>();
    let fp3 = size_of::<Fp3>();
    assert_eq!((cube, fp3), (56, 24));
    // RawVec::grow_amortized in the pinned toolchain: max(2*old, required,
    // minimum). Each growth has old+new <=3*final+minimum descriptors.
    // This is named allocation payload, not malloc/RSS/physical H100 evidence.
    let construction = |c: usize, scalar: usize, d: usize, t: usize| {
        (3 * c + 4) * cube + c * (2 * d).max(4) * fp3
        + (3 * scalar + 4) * cube + scalar * (2 * d).max(4) * fp3
        + (3 * t + 4) * size_of::<Vec<Cube>>() + (3 * t + 4) * size_of::<Auth>()
        + d * fp3 // one old+new point during shrink_to_fit
    };
    for slot in 0..3 {
        let p = Canonical::compile(slot, &[0; 772], &exponents).unwrap();
        let records = constructor_bounds(&p);
        let targets: usize = records.iter().map(|r| r.targets).sum();
        assert_eq!(targets, 4446);
        let w_cubes = p.plan.cohorts.iter().map(|c| {
            if c.kind == Kind::Lookup {
                150 * p.plan.sources[c.tensor].cols.count_ones() as usize
            } else { scalar_tiles(&p.plan.sources[c.tensor]) }
        }).sum::<usize>() + 36;
        assert_eq!(p.plan.cohorts.len() + 2, 775);
        let a_upper: usize = records.iter().map(|r| r.cubes).sum();
        let mut constructor_max = 0;
        // public_forms keeps all four results before its first retention call.
        let public = records.iter().take(4).map(|r| r.cubes).sum();
        constructor_max = constructor_max.max(construction(public, 1, 34, 4));
        for r in &records {
            let bytes = construction(r.cubes, r.scalar_temporary, 34, r.targets);
            constructor_max = constructor_max.max(bytes);
            println!("C71_CLASS8_CONSTRUCTOR {{\"slot\":{slot},\"name\":\"{}\",\"targets\":{},\"cube_upper\":{},\"scalar_temporary_upper\":{},\"construction_payload_upper\":{bytes}}}", r.name, r.targets, r.cubes, r.scalar_temporary);
        }
        // Aggregate validation is at bind, AFTER earlier constructors retain
        // claims. Do not silently clamp the preceding phase to MAX_CUBES.
        let kept_w = w_cubes;
        let kept_a = a_upper;
        let retained = |c, d, t, target| {
            c * (cube + d * fp3) + (2 * t + 4) * (size_of::<Vec<Cube>>() + target)
        };
        // Old accepted A openings bypass Batch::add and keep their construction
        // capacities until each separate old-root PCS closes. They overlap W
        // and current A claims, including W bind; old+new roots are not ranges.
        let mut old_cubes = 0;
        for previous in 0..slot {
            let prior = Canonical::compile(previous, &[0; 772], &exponents).unwrap();
            for l in &p.sources.attention.layers {
                for id in [l.k, l.v] {
                    old_cubes += route_pieces(prior.bytes().scalar.layout.sources[id].rows, 150 * previous)
                        * word(prior.bytes(), id);
                }
            }
        }
        let old_openings = (2 * old_cubes + 4) * cube + old_cubes * 68 * fp3
            + (2 * slot + 4) * (size_of::<Vec<Cube>>() + size_of::<Auth>());
        let kv_current = records.iter().find(|r| r.name == "KV_current").unwrap().cubes;
        constructor_max = constructor_max.max(construction(kv_current + old_cubes, 1, 34, slot + 1));
        constructor_max = constructor_max.max(construction(w_cubes - 36, 0, 35, 773));
        let retained_p = retained(kept_w, 35, 775, size_of::<Auth>())
            + retained(kept_a, 34, targets, size_of::<Auth>());
        let retained_v = retained(kept_w, 35, 775, size_of::<Key>())
            + retained(kept_a, 34, targets, size_of::<Key>());
        let attempt = AttemptContext { session: [1; 32], capacity: [2; 32], slot: slot as u8,
            predecessor: [0; 32], nonce: [3; 32] };
        let record = |d, c, t| {
            let config = Domain::Flat(d).config().unwrap();
            linear::linear_record_length(gamma(&config).len(), attempt.encode().len(), &[]).unwrap()
                + 4 * t + c * (36 + fp3 * d)
        };
        let w_record = record(35, kept_w.min(linear::MAX_CUBES), 775);
        let a_record = record(34, kept_a.min(linear::MAX_CUBES), targets);
        // Pending originals remain through the RMS→original-RNE transition.
        // This upper also charges original request construction while pending
        // inputs still exist, and the later K/V request list (disjoint in time).
        // Point capacities use the root dimension; no witness values are read.
        let routes = (1..773).map(|i| p.plan.input_route(i).unwrap().producer.1.len()).sum::<usize>();
        let pending_upper = (2 * 773 + 4) * size_of::<caller::CutOpening<Auth>>()
            + (2 * 772 + 4) * size_of::<caller::InputOpening<Auth>>() + routes
            + (773 + 772) * 70 * fp3
            + (2 * p.sources.attention.rope.gate_up.gelu.rms.norms.len() + 4) * size_of::<crate::c71_matrix::rms::statistic::Pending<Auth>>()
            + p.sources.attention.rope.gate_up.gelu.rms.norms.len() * 2 * 68 * fp3 + 68 * fp3
            + (3 * 410 + 4) * (size_of::<bytes::RneRequest<Auth>>() + size_of::<i32>())
            + 2 * 410 * 68 * fp3
            + (3 * 120 + 4) * size_of::<bytes::kv::Request<Auth>>() + 120 * 68 * fp3;
        // Profile and attempt bytes coexist briefly with the exact record;
        // returned lambda coefficients may be allocated before that Vec drops.
        let w_bind_extra = 2 * gamma(&Domain::Flat(35).config().unwrap()).len() + 130 + (2 * 775 + 4) * fp3;
        let a_bind_extra = 2 * gamma(&Domain::Flat(34).config().unwrap()).len() + 130 + (2 * targets + 4) * fp3;
        println!("C71_CLASS8_FORMS {{\"slot\":{slot},\"W_targets\":775,\"A_targets\":{targets},\"W_cube_upper\":{w_cubes},\"A_constructor_cube_upper\":{a_upper},\"MAX_CUBES\":{},\"retained_P_payload_upper\":{retained_p},\"retained_V_payload_upper\":{retained_v},\"constructor_payload_upper\":{constructor_max},\"W_bind_record_payload_upper\":{w_record},\"A_bind_record_payload_upper\":{a_record},\"pending_original_payload_upper\":{pending_upper},\"old_KV_unshrunk_payload_upper\":{old_openings},\"W_bind_extra_payload_upper\":{w_bind_extra},\"A_bind_extra_payload_upper\":{a_bind_extra},\"P_constructor_phase_payload_upper\":{},\"P_W_bind_phase_payload_upper\":{},\"V_W_bind_phase_payload_upper\":{},\"P_A_bind_phase_payload_upper\":{},\"V_A_bind_phase_payload_upper\":{},\"credit\":false,\"physical_complete\":false,\"private_W_A_read\":false}}", linear::MAX_CUBES,
            retained_p + old_openings + pending_upper + constructor_max, retained_p + old_openings + w_record + w_bind_extra, retained_v + old_openings + w_record + w_bind_extra, retained(kept_a.min(linear::MAX_CUBES), 34, targets, size_of::<Auth>()) + a_record + a_bind_extra, retained(kept_a.min(linear::MAX_CUBES), 34, targets, size_of::<Key>()) + a_record + a_bind_extra);
    }
}
