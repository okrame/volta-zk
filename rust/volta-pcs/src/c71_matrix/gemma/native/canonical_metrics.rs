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
    phases: Mutex<Vec<serde_json::Value>>,
    channels: Mutex<Vec<(&'static str, Option<usize>, Traffic)>>,
}

impl Measurements {
    pub(super) fn new() -> Self {
        Self { started: Instant::now(), phases: Mutex::default(), channels: Mutex::default() }
    }

    pub(super) fn phase(
        &self,
        role: &'static str,
        slot: Option<usize>,
        name: &'static str,
    ) -> Phase<'_> {
        Phase { measurements: self, role, slot, name, start_ns: self.elapsed_ns(), complete: false }
    }

    fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).expect("measurement duration fits u64")
    }

    pub(super) fn channel(&self, name: &'static str, slot: Option<usize>) -> Traffic {
        let traffic = Traffic::default();
        self.channels.lock().unwrap().push((name, slot, traffic.clone()));
        traffic
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
            "complete_physical_peak": false, "gpu_execution": false,
            "process_memory": memory(),
            "memory_scope": "process-wide host RSS/HWM, both roles; no per-role peak, retained-capacity census or HBM measurement"
        })
    }
}

fn memory() -> Option<Vec<String>> {
    std::fs::read_to_string("/proc/self/status").ok().map(|s| {
        s.lines()
            .filter(|l| l.starts_with("VmHWM:") || l.starts_with("VmRSS:"))
            .map(str::to_owned)
            .collect()
    })
}

pub(super) struct Phase<'a> {
    measurements: &'a Measurements,
    role: &'static str,
    slot: Option<usize>,
    name: &'static str,
    start_ns: u64,
    complete: bool,
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
        self.measurements.phases.lock().unwrap().push(serde_json::json!({
            "role": self.role, "slot": self.slot, "phase": self.name,
            "start_ns": self.start_ns, "end_ns": end_ns,
            "wall_ns": end_ns - self.start_ns, "complete": self.complete
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
