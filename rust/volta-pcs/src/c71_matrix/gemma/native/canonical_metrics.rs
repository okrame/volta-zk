//! Local diagnostic measurements, outside the cryptographic transcript.
//! Nested wall intervals and process-wide RSS are not additive phase peaks.
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Default)]
pub(super) struct Traffic {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}

impl Traffic {
    pub(super) fn bytes(&self) -> (u64, u64) {
        (self.sent.load(Ordering::Relaxed), self.received.load(Ordering::Relaxed))
    }
}

pub(super) struct Counted<T> {
    pub(super) channel: T,
    pub(super) traffic: Traffic,
}
impl<T: Read> Read for Counted<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.channel.read(bytes)?;
        self.traffic.received.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}
impl<T: Write> Write for Counted<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.channel.write(bytes)?;
        self.traffic.sent.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

pub(super) struct Measurements {
    started: Instant,
    budget: Mutex<Option<crate::c71_matrix::census::Budget>>,
    phases: Mutex<Vec<serde_json::Value>>,
    channels: Mutex<Vec<(&'static str, Option<usize>, Traffic)>>,
    native: Mutex<Option<Arc<super::resident::Session>>>,
    resources: Mutex<Vec<serde_json::Value>>,
}

impl Measurements {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            budget: Mutex::default(),
            phases: Mutex::default(),
            channels: Mutex::default(),
            native: Mutex::default(),
            resources: Mutex::default(),
        }
    }

    pub(super) fn budget(&self, weights: &Arc<Vec<i16>>) -> Result<(), String> {
        *self.budget.lock().unwrap() = Some(crate::c71_matrix::census::Budget::new(weights)?);
        Ok(())
    }

    pub(super) fn release(self) -> Result<(), String> {
        let bytes = self.budget.lock().unwrap().as_ref().map(|b| b.weight_capacity_bytes());
        let before = bytes.map(|n| crate::c71_matrix::progress::resident_w("host", "retiring", n, None)).transpose();
        drop(self); // Release every retained Arc, not just the allocator's Budget.
        before?;
        if let Some(n) = bytes { crate::c71_matrix::progress::resident_w("host", "retired", n, None)?; }
        Ok(())
    }

    pub(super) fn native(&self, session: Arc<super::resident::Session>) {
        *self.native.lock().unwrap() = Some(session);
    }

    pub(super) fn resource(
        &self,
        name: &'static str,
        slot: Option<usize>,
        values: serde_json::Value,
    ) {
        let record = serde_json::json!({
            "phase": name, "slot": slot, "elapsed_ns": self.elapsed_ns(),
            "values": values, "simultaneous": self.sample()
        });
        let _ = crate::c71_matrix::progress::emit(
            serde_json::json!({"kind": "resources", "sample": record}),
        );
        self.resources.lock().unwrap().push(record);
    }

    fn sample(&self) -> serde_json::Value {
        serde_json::json!({"host_process": memory(),
            "joint_allocations": crate::c71_matrix::census::simultaneous(),
            "native": self.native.lock().unwrap().as_ref().map(|session| session.census())})
    }

    pub(super) fn close_native(
        &self,
        failed: bool,
    ) -> Result<Option<super::kernel::range::windowed::native::Stats>, String> {
        let native = self.native.lock().unwrap();
        let Some(session) = native.as_ref() else { return Ok(None) };
        if failed {
            session.stop();
        }
        session.close().map(Some)
    }

    pub(super) fn phase(
        &self,
        role: &'static str,
        slot: Option<usize>,
        name: &'static str,
    ) -> Phase<'_> {
        let start_resources = self.sample();
        let _ = crate::c71_matrix::progress::emit(serde_json::json!({
            "kind": "start", "role": role, "slot": slot, "phase": name,
            "resources": start_resources, "channels": self.traffic_snapshot()
        }));
        Phase {
            measurements: self,
            role,
            slot,
            name,
            start_ns: self.elapsed_ns(),
            complete: false,
            start_resources,
        }
    }

    fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).expect("measurement duration fits u64")
    }

    pub(super) fn channel(&self, name: &'static str, slot: Option<usize>) -> Traffic {
        let traffic = Traffic::default();
        self.channels.lock().unwrap().push((name, slot, traffic.clone()));
        traffic
    }

    fn traffic_snapshot(&self) -> Vec<serde_json::Value> {
        self.channels
            .lock()
            .unwrap()
            .iter()
            .map(|(name, slot, traffic)| {
                let (sent, received) = traffic.bytes();
                serde_json::json!({"phase": name, "slot": slot,
                "bytes_to_verifier": received, "bytes_from_verifier": sent})
            })
            .collect()
    }

    pub(super) fn report(&self) -> serde_json::Value {
        let mut phases = self.phases.lock().unwrap().clone();
        phases.sort_by_key(|p| p["start_ns"].as_u64());
        let mut to_verifier = 0;
        let mut from_verifier = 0;
        let mut charged = [(0u64, 0u64); 3];
        let mut attempted = [false; 3];
        let channels: Vec<_> = self
            .channels
            .lock()
            .unwrap()
            .iter()
            .map(|(name, slot, traffic)| {
                let (sent, received) = traffic.bytes();
                to_verifier += received;
                from_verifier += sent;
                // Initial public data, installation and Seed6 are charged once to
                // response 0, never amortized over future responses.
                let index = slot.unwrap_or(0);
                charged[index].0 += received;
                charged[index].1 += sent;
                if slot.is_some() {
                    attempted[index] = true;
                }
                serde_json::json!({"phase": name, "slot": slot,
                "bytes_to_verifier": received, "bytes_from_verifier": sent})
            })
            .collect();
        let response_charges: Vec<_> = charged
            .iter()
            .enumerate()
            .map(|(slot, &(to, from))| {
                serde_json::json!({"slot": slot, "response_channel_registered": attempted[slot],
                "observed_bytes_to_verifier": to, "observed_bytes_from_verifier": from,
                "observed_bytes_both_directions": to + from,
                "includes_initial_distribution_installation_and_setup": slot == 0})
            })
            .collect();
        serde_json::json!({
            "phases": phases, "channels": channels, "total_wall_ns": self.elapsed_ns(),
            "bytes_to_verifier": to_verifier, "bytes_from_verifier": from_verifier,
            "response_charges": response_charges,
            "timing_scope": "nested wall intervals; roles overlap, do not sum",
            "traffic_scope": "actual application bytes at verifier boundary, including public distribution; excludes OS framing and executable provisioning",
            "complete_physical_peak": false, "gpu_backend_selected": self.native.lock().unwrap().is_some(),
            "resource_samples": self.resources.lock().unwrap().clone(),
            "process_memory": memory(),
            "joint_allocations": crate::c71_matrix::census::simultaneous(),
            "memory_scope": "joint host allocator/native reservation counter covers both roles and realloc overlap; W packed alone is exempt; RSS/HWM and native phase samples remain diagnostics; physical runtime allowance requires external process/device measurement"
        })
    }
}

fn memory() -> Option<Vec<String>> {
    crate::c71_matrix::progress::host_process_memory()
}

pub(super) struct Phase<'a> {
    measurements: &'a Measurements,
    role: &'static str,
    slot: Option<usize>,
    name: &'static str,
    start_ns: u64,
    complete: bool,
    start_resources: serde_json::Value,
}

impl Phase<'_> {
    pub(super) fn finish(mut self) -> u64 {
        self.complete = true;
        self.measurements.elapsed_ns() - self.start_ns
    }
}

impl Drop for Phase<'_> {
    fn drop(&mut self) {
        let end_ns = self.measurements.elapsed_ns();
        let record = serde_json::json!({
            "role": self.role, "slot": self.slot, "phase": self.name,
            "start_ns": self.start_ns, "end_ns": end_ns,
            "wall_ns": end_ns - self.start_ns, "complete": self.complete,
            "start_resources": self.start_resources, "end_resources": self.measurements.sample()
        });
        let _ = crate::c71_matrix::progress::emit(serde_json::json!({
            "kind": "end", "phase_record": record, "channels": self.measurements.traffic_snapshot()
        }));
        self.measurements.phases.lock().unwrap().push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_canonical_public_metadata_telemetry_bounded_schema() {
        use std::mem::{size_of, MaybeUninit};
        use crate::c71_matrix::census::host_layout_bytes;
        let start = host_layout_bytes();
        let mut map = std::collections::BTreeMap::<String, MaybeUninit<serde_json::Value>>::new();
        // Empty keys have the same typed node layout and no String allocation.
        // Unique lengths distinguish them; subtract their exact payload.
        for i in 0..11 { map.insert("x".repeat(i), MaybeUninit::uninit()); }
        let leaf = host_layout_bytes()-start-(0..11).sum::<u64>();
        map.insert("x".repeat(11), MaybeUninit::uninit());
        let node = (host_layout_bytes()-start-(0..12).sum::<u64>()-leaf) as usize;
        assert!(node > leaf as usize);
        drop(map);
        assert_eq!(host_layout_bytes(),start);
        let stats = serde_json::to_value(super::super::kernel::range::windowed::native::Stats::default()).unwrap();
        let joint = crate::c71_matrix::census::simultaneous();
        assert_eq!(stats.as_object().unwrap().len(),19);
        assert_eq!(joint.as_object().unwrap().len(),13);
        let native = include_str!("canonical_device.rs");
        let body = native.split("\"sample_available\": true").nth(1).unwrap().split("})").next().unwrap();
        let pieces: Vec<_> = body.split('"').collect();
        assert_eq!(1+pieces.iter().enumerate().filter(|(i,_)|i%2==1)
            .filter(|(i,_)|pieces[i+1].trim_start().starts_with(':')).count(),12);
        // Every diagnostic String is a fixed literal <=512 bytes, or a Linux
        // u64 RSS/HWM line <=33 bytes. Paths are outside these JSON snapshots.
        assert!(native.lines().find(|l|l.contains("named payloads are subsets")).unwrap().len()<512);
        let record = |members:usize, objects:usize, slots:usize, strings:usize| {
            let depth = members.ilog2() as usize+2;
            (members+objects*(1+depth))*node + members*64 + strings*512
                + 2*slots*size_of::<serde_json::Value>()
        };
        // sample=3 root+13 joint+12 native+19 Stats fields; two memory strings.
        let sample = record(47,4,2,4);
        let phase = record(9+2*47,9,4,10);
        // Max resource: weight/current/two prior model census objects <=17
        // fields each; phase/slot/time/values/sample and three values keys.
        let resource = record(5+3+4*17+47,10,4,10);
        let progress = record(160,20,16,24);
        let stored = 44*phase+6*resource+64*size_of::<serde_json::Value>()
            +8*size_of::<serde_json::Value>()+8*size_of::<(&str,Option<usize>,Traffic)>();
        // 14 fixed phases plus 10 per response; seven live nesting scopes;
        // three public-distribution/setup/install and three response channels.
        let process_read = 3 * (crate::c71_matrix::progress::PROCESS_STATUS_MAX_BYTES + 1);
        // P/V diagnostics can overlap. A progress read runs on its emitting
        // role's thread, not a third diagnostic worker.
        let crypto = stored+7*sample+3*progress+12*(16+size_of::<AtomicU64>())+size_of::<Measurements>()+2*process_read;
        let report = 4*stored+3*progress+6*sample+2*process_read;
        println!("C71_PUBLIC_METADATA_TELEMETRY {}",serde_json::json!({
            "schema":"volta-c71-public-metadata-telemetry-v1","credit":false,"admission":false,
            "phase_count_upper":44,"resource_count_upper":6,"channel_count_upper":6,
            "active_phase_count_upper":7,"json_node_upper_bytes":node,
            "sample_heap_upper_bytes":sample,"phase_record_heap_upper_bytes":phase,
            "resource_record_heap_upper_bytes":resource,"progress_heap_upper_bytes":progress,
            "crypto_live_metadata_heap_upper_bytes":crypto,
            "diagnostic_status_read_moving_upper_bytes_per_role":process_read,
            "after_cleanup_report_metadata_heap_upper_bytes":report,
            "source":"canonical_runner/canonical_state call sites; current sample/Stats/Session JSON schema",
            "scope":"allocator payload upper; report clones occur after native cleanup; durable progress does not retain records"}));
    }

    #[test]
    fn c71_canonical_metrics_nested_failure_and_partial_io() {
        let m = Measurements::new();
        let whole = m.phase("prover", Some(1), "response_total");
        m.phase("prover", Some(1), "inference").finish();
        drop(m.phase("prover", Some(1), "commitment"));
        whole.finish();
        let traffic = m.channel("response", Some(1));
        let mut io = Counted { channel: io::Cursor::new([0; 3]), traffic: traffic.clone() };
        assert!(io.write_all(&[1, 2, 3, 4]).is_err());
        io.channel.set_position(0);
        assert!(io.read_exact(&mut [0; 4]).is_err());
        assert_eq!(traffic.bytes(), (3, 3));
        let r = m.report();
        assert_eq!(r["bytes_to_verifier"], 3);
        assert_eq!(r["bytes_from_verifier"], 3);
        assert_eq!(r["response_charges"][1]["observed_bytes_both_directions"], 6);
        let mut initial = Counted { channel: io::sink(), traffic: m.channel("seed6_setup", None) };
        initial.write_all(&[0; 7]).unwrap();
        let r = m.report();
        assert_eq!(r["response_charges"][0]["observed_bytes_both_directions"], 7);
        assert_eq!(r["response_charges"][1]["observed_bytes_both_directions"], 6);
        assert_eq!(r["response_charges"][2]["response_channel_registered"], false);
        let phases = r["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 3);
        assert_eq!(phases[2]["complete"], false);
        assert!(phases[0]["end_ns"].as_u64().unwrap() >= phases[2]["end_ns"].as_u64().unwrap());
        for p in phases {
            assert_eq!(
                p["wall_ns"].as_u64().unwrap(),
                p["end_ns"].as_u64().unwrap() - p["start_ns"].as_u64().unwrap()
            );
        }
        assert_eq!(r["complete_physical_peak"], false);
    }
}
