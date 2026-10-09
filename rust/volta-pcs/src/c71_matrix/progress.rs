//! Private, durable laboratory telemetry. Never part of FS, wire or resume state.
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Log {
    file: File,
    started: Instant,
    sequence: u64,
    error: Option<String>,
}
static LOG: Mutex<Option<Log>> = Mutex::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub(super) struct Recording;
impl Recording {
    pub(super) fn start(path: &Path) -> Result<Self, String> {
        let mut log = LOG.lock().map_err(|_| "progress lock poisoned")?;
        if log.is_some() {
            return Err("progress recording already active".into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
            .and_then(|directory| directory.sync_all())
            .map_err(|e| e.to_string())?;
        *log = Some(Log { file, started: Instant::now(), sequence: 0, error: None });
        ACTIVE.store(true, Ordering::Relaxed);
        Ok(Self)
    }
}
impl Drop for Recording {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Relaxed);
        LOG.lock().unwrap().take();
    }
}

pub(super) fn check() -> Result<(), String> {
    match LOG.lock().map_err(|_| "progress lock poisoned")?.as_ref().and_then(|l| l.error.clone()) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(super) const PROCESS_STATUS_MAX_BYTES: usize = 64 << 10;

// Diagnostics have a finite Rust allocation bound as well as bounded JSON.
// An unavailable or oversized status remains an unavailable RSS sample.
pub(super) fn host_process_memory() -> Option<Vec<String>> {
    let mut status = String::new();
    File::open("/proc/self/status").ok()?
        .take((PROCESS_STATUS_MAX_BYTES + 1) as u64)
        .read_to_string(&mut status).ok()?;
    if status.len() > PROCESS_STATUS_MAX_BYTES { return None; }
    Some(status.lines().filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .map(str::to_owned).collect())
}

fn process_start_ticks(stat: &str) -> Result<u64, String> {
    // comm may contain spaces and parentheses; field 22 follows its last ')'.
    stat.rsplit_once(')').and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok()).filter(|&ticks| ticks > 0)
        .ok_or_else(|| "invalid process identity for W residency".into())
}

/// Only the external canonical monitor needs private virtual addresses. This
/// durable lifecycle is diagnostic, outside wire/FS and unavailable for resume.
pub(in crate::c71_matrix) fn resident_w(
    space: &str, state: &str, bytes: u64, address: Option<u64>,
) -> Result<(), String> {
    match std::env::var_os("C71_CANONICAL_MONITOR") {
        None => return Ok(()),
        Some(value) if value == "1" => {},
        Some(_) => return Err("invalid canonical monitor switch".into()),
    }
    if !ACTIVE.load(Ordering::Relaxed) {
        return Err("canonical W monitor requires durable progress".into());
    }
    let mut stat = [0u8; 4096];
    let mut file = File::open("/proc/self/stat").map_err(|e| e.to_string())?;
    let count = file.read(&mut stat).map_err(|e| e.to_string())?;
    if count == stat.len() { return Err("oversized process identity".into()); }
    let ticks = process_start_ticks(std::str::from_utf8(&stat[..count]).map_err(|e| e.to_string())?)?;
    let mut event = json!({"kind": "resident_w", "space": space, "state": state,
        "bytes": bytes, "pid": std::process::id(), "process_start_ticks": ticks});
    if let Some(address) = address { event["address"] = json!(address); }
    emit(event)
}

pub(super) fn emit(event: Value) -> Result<(), String> {
    if !ACTIVE.load(Ordering::Relaxed) {
        return Ok(());
    }
    let mut guard = LOG.lock().map_err(|_| "progress lock poisoned")?;
    let Some(log) = guard.as_mut() else {
        return Ok(());
    };
    if let Some(error) = &log.error {
        return Err(error.clone());
    }
    let record = json!({"schema": "volta-c71-progress-v1", "credit": false,
        "sequence": log.sequence, "elapsed_ns": log.started.elapsed().as_nanos() as u64,
        "thread": format!("{:?}", std::thread::current().id()), "event": event,
        "joint_allocations": super::census::simultaneous(),
        "host_process": host_process_memory()});
    let result = (|| -> Result<(), String> {
        serde_json::to_writer(&mut log.file, &record).map_err(|e| e.to_string())?;
        log.file.write_all(b"\n").and_then(|_| log.file.sync_all()).map_err(|e| e.to_string())
    })();
    if let Err(error) = &result {
        log.error = Some(format!("durable progress failed: {error}"));
    }
    log.sequence += 1;
    result
}

/// One span per substantial phase, with throttled public work counters.
pub(super) struct Span {
    phase: &'static str,
    geometry: Value,
    started: Instant,
    last: Instant,
    finished: bool,
}
impl Span {
    pub(super) fn start(phase: &'static str, geometry: Value) -> Result<Self, String> {
        emit(json!({"kind": "start", "phase": phase, "geometry": geometry}))?;
        Ok(Self { phase, geometry, started: Instant::now(), last: Instant::now(), finished: false })
    }
    pub(super) fn checkpoint(&mut self, work: impl FnOnce() -> Value) -> Result<(), String> {
        if ACTIVE.load(Ordering::Relaxed) && self.last.elapsed() >= Duration::from_secs(1) {
            emit(json!({"kind": "progress", "phase": self.phase,
                "geometry": self.geometry, "work": work(), "wall_ns": self.started.elapsed().as_nanos() as u64}))?;
            self.last = Instant::now();
        }
        Ok(())
    }
    pub(super) fn finish(mut self, work: Value) -> Result<(), String> {
        emit(json!({"kind": "end", "phase": self.phase, "geometry": self.geometry,
            "complete": true, "work": work, "wall_ns": self.started.elapsed().as_nanos() as u64}))?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            let _ = emit(json!({"kind": "end", "phase": self.phase, "geometry": self.geometry,
                "complete": false, "wall_ns": self.started.elapsed().as_nanos() as u64}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c71_progress_process_identity_uses_last_parenthesis() {
        let fields = (3..=21).map(|_| "0").chain(std::iter::once("12345")).collect::<Vec<_>>().join(" ");
        assert_eq!(process_start_ticks(&format!("42 (worker ) name) {fields} 999")).unwrap(), 12345);
        for invalid in ["", "42 (bad) S 123", "42 no comm"] { assert!(process_start_ticks(invalid).is_err()); }
        assert!(process_start_ticks(&std::fs::read_to_string("/proc/self/stat").unwrap()).unwrap() > 0);
    }

    #[test]
    fn c71_progress_durable_prefix_no_overwrite_and_failure() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "c71-progress-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let recording = Recording::start(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let span = Span::start("salt_prescan", json!({"leaves": 16})).unwrap();
        // Read the durable prefix while the writer and unfinished span are live.
        let rows: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event"]["kind"], "start");
        drop(span);
        Span::start("fft", Value::Null).unwrap().finish(json!({"columns": 8})).unwrap();
        check().unwrap();
        drop(recording);
        assert!(Recording::start(&path).is_err());
        let rows: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1]["event"]["complete"], false);
        assert_eq!(rows[3]["event"]["work"]["columns"], 8);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row["sequence"], i);
        }
        std::fs::remove_file(path).unwrap();
        // A write failure cannot be turned into a successful measured run.
        *LOG.lock().unwrap() = Some(Log {
            file: OpenOptions::new().write(true).open("/dev/full").unwrap(),
            started: Instant::now(),
            sequence: 0,
            error: None,
        });
        ACTIVE.store(true, Ordering::Relaxed);
        let recording = Recording;
        assert!(emit(json!({"kind": "fixture"})).is_err());
        assert!(check().is_err());
        drop(recording);
    }
}
