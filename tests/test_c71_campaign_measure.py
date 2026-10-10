"""Campaign-controller fixtures only: no GPU, model, provider, or hardware credit."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import c71_campaign_measure as monitor


def record(sequence, event=None, **overrides):
    census = dict(payload_limit_bytes=monitor.PAYLOAD_LIMIT,
                  runtime_allowance_bytes=monitor.RUNTIME_ALLOWANCE,
                  temporary_payload_peak_bytes=1024, temporary_live_bytes=512,
                  denied_allocations=0, enforced=True)
    census.update(overrides)
    return dict(schema='volta-c71-progress-v1', sequence=sequence,
                joint_allocations=census, event=event or dict(kind='progress'))


def resident(space, state, **overrides):
    event = dict(kind='resident_w', space=space, state=state,
                 pid=os.getpid(), process_start_ticks=monitor.start_ticks(os.getpid()),
                 bytes=monitor.W_BYTES)
    if space == 'host' and state == 'live':
        event['address'] = 0x1101
    event.update(overrides)
    return event


def sample(**overrides):
    values = dict(mode='canonical', rss=1 << 30, swap=0,
                  gpu_used=1 << 30, gpu_total=80_000_000_000, gpu_free=78_000_000_000,
                  disk=30_000_000_000)
    values.update(overrides)
    return values


def test_process_sampling_skips_exited_processes_but_keeps_read_errors(monkeypatch):
    monkeypatch.setattr(Path, 'iterdir', lambda _path: iter(map(Path, ('/proc/1', '/proc/2', '/proc/3'))))
    def read(path):
        if path.parent.name == '1':
            raise FileNotFoundError('process exited before open')
        if path.parent.name == '2':
            raise ProcessLookupError('process exited during read')
        return 'PPid: 0\nVmRSS: 4 kB\nVmSwap: 0 kB\n'
    monkeypatch.setattr(Path, 'read_text', read)
    assert monitor.process_rows() == {3: (0, 4096, 0)}
    def denied(_path):
        raise PermissionError('metrics unavailable')
    monkeypatch.setattr(Path, 'read_text', denied)
    with pytest.raises(PermissionError):
        monitor.process_rows()


def test_orphaned_profiler_descendants_remain_accounted_only_with_matching_identity(monkeypatch):
    rows = {2: (1, 4096, 0), 3: (2, 8192, 0)}
    monkeypatch.setattr(monitor, 'process_rows', lambda: rows)
    monkeypatch.setattr(monitor.os, 'getsid', lambda _pid: 123)
    monkeypatch.setattr(monitor, 'start_ticks', lambda _pid: 100)
    assert monitor.host_tree(999, 999, {2: 100}) == rows
    assert monitor.host_tree(999, 999, {2: 101}) == {}


def test_W_owner_in_new_session_requires_root_ancestry_and_original_identity(tmp_path, monkeypatch):
    progress = monitor.Progress(tmp_path / 'none')
    progress.consume(record(0, resident('device', 'allocating')))
    progress.consume(record(1, resident('device', 'live')))
    pid = os.getpid()
    monkeypatch.setattr(monitor.os, 'getsid', lambda _pid: 123)
    rows = {pid: (999, 12288, 0), 999: (0, 4096, 0)}
    assert progress.exemptions(rows, 999) == (0, monitor.W_BYTES)
    with pytest.raises(ValueError, match='monitored process'):
        progress.exemptions({pid: (998, 12288, 0)}, 999)
    progress.process = (pid, progress.process[1] + 1)
    with pytest.raises(ValueError, match='monitored process'):
        progress.exemptions(rows, 999)


def test_stop_never_signals_reused_detached_PID(monkeypatch):
    delivered, closed = [], []
    monkeypatch.setattr(monitor, 'host_tree', lambda *_: {})
    monkeypatch.setattr(monitor.os, 'getsid', lambda pid: pid)
    monkeypatch.setattr(monitor, 'start_ticks', lambda _pid: 2)
    monkeypatch.setattr(monitor.os, 'pidfd_open', lambda _pid: 12)
    monkeypatch.setattr(monitor.signal, 'pidfd_send_signal', lambda *args: delivered.append(args))
    monkeypatch.setattr(monitor.os, 'close', lambda fd: closed.append(fd))
    monkeypatch.setattr(Path, 'iterdir', lambda _path: iter(()))
    monkeypatch.setattr(monitor.os, 'killpg', lambda *_: None)
    monitor.stop_session(999, {123: 1})
    assert delivered == [] and closed == [12]


def test_smaps_exempts_only_guaranteed_resident_whole_W_pages():
    smaps = ('1000-5000 rw-p 00000000 00:00 0\nRss: 12 kB\n'
             '9000-a000 r-xp 00000000 00:00 0\nRss: 4 kB\n')
    # W owns only pages [0x2000,0x4000), out of a four-page mapping.
    # Of its 12 KiB resident, at least 4 KiB must be W; the rest may be outside.
    assert monitor.host_w_residency(smaps, 0x1101, 0x3200, 4096) == (4096, 16384)
    # Partial mapping residency must never grant the nominal W size.
    assert monitor.host_w_residency(smaps.replace('12 kB', '4 kB'), 0x1101, 0x3200, 4096) == (0, 8192)
    with pytest.raises(ValueError, match='missing|noncontiguous'):
        monitor.host_w_residency(smaps, 0x4000, 0x6000, 4096)
    with pytest.raises(ValueError, match='inconsistent'):
        monitor.host_w_residency(smaps.replace('12 kB', '20 kB'), 0x1101, 0x3200, 4096)


def test_smaps_overlap_cannot_compensate_for_missing_W_pages():
    smaps = '1000-2000 rw-p 0 0:0 0\nRss: 4 kB\n' * 2
    with pytest.raises(monitor.SmapsCoverageError, match='noncontiguous'):
        monitor.host_w_residency(smaps, 0x1000, 8192, 4096)


@pytest.mark.parametrize('failures', [1, 2, 3])
def test_smaps_retries_preserve_failures_and_require_complete_coverage(tmp_path, monkeypatch, failures):
    monkeypatch.setattr(monitor, 'W_BYTES', 8192)
    progress = monitor.Progress(tmp_path / 'progress.jsonl')
    progress.consume(record(0, resident('host', 'live', address=0x1000)))
    missing = '9000-a000 rw-p 0 0:0 0\nRss: 4 kB\n'
    complete = '1000-3000 rw-p 0 0:0 0\nRss: 8 kB\n'
    snapshots = iter([missing] * failures + [complete])
    original_open = Path.open
    def read(path, *args, **kwargs):
        return io.StringIO(next(snapshots)) if path.name == 'smaps' else original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', read)
    rows = {os.getpid(): (os.getppid(), 12288, 0)}
    if failures < 3:
        assert progress.exemptions(rows, os.getsid(0)) == (8192, 0)
    else:
        with pytest.raises(monitor.SmapsCoverageError, match='missing'):
            progress.exemptions(rows, os.getsid(0))
    assert progress.smaps_read_failures == failures
    saved = sorted(tmp_path.glob('*.smaps-failed-*.txt'))
    assert len(saved) == failures
    assert all(p.read_text() == missing and p.stat().st_mode & 0o777 == 0o600 for p in saved)


def test_smaps_retry_retention_bound_is_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, 'W_BYTES', 8192)
    progress = monitor.Progress(tmp_path / 'progress.jsonl')
    progress.consume(record(0, resident('host', 'live', address=0x1000)))
    progress.smaps_read_failures = monitor.MAX_SMAPS_FAILURES - 1
    original_open = Path.open
    monkeypatch.setattr(Path, 'open', lambda path, *a, **kw:
        io.StringIO('9000-a000 rw-p 0 0:0 0\nRss: 4 kB\n') if path.name == 'smaps'
        else original_open(path, *a, **kw))
    with pytest.raises(monitor.SmapsCoverageError):
        progress.exemptions({os.getpid(): (os.getppid(), 12288, 0)}, os.getsid(0))
    assert progress.smaps_read_failures == monitor.MAX_SMAPS_FAILURES


def test_canonical_memory_couples_host_device_and_monitor_allowance():
    assert monitor.check_resources(**sample(rss=monitor.PHYSICAL_LIMIT - (1 << 30))) == monitor.PHYSICAL_LIMIT
    with pytest.raises(RuntimeError, match='simultaneous'):
        monitor.check_resources(**sample(rss=monitor.PHYSICAL_LIMIT - (1 << 30) + 1))
    assert monitor.check_resources(**sample(rss=monitor.W_BYTES + (1 << 30),
        gpu_used=monitor.W_BYTES + (1 << 30), gpu_free=10 << 30,
        host_w=monitor.W_BYTES, device_w=monitor.W_BYTES)) == 2 << 30
    with pytest.raises(ValueError, match='exceeds measured'):
        monitor.check_resources(**sample(host_w=monitor.W_BYTES))
    with pytest.raises(RuntimeError, match='simultaneous'):
        monitor.check_resources(**sample(rss=monitor.W_BYTES, gpu_used=monitor.W_BYTES, gpu_free=10 << 30))


def test_calibration_limits_are_separate_from_canonical():
    assert monitor.check_resources(**sample(mode='calibration', rss=96 << 30)) is None
    with pytest.raises(RuntimeError, match='96 GiB'):
        monitor.check_resources(**sample(mode='calibration', rss=(96 << 30) + 1))
    with pytest.raises(RuntimeError, match='simultaneous'):
        monitor.check_resources(**sample(mode='canonical', rss=96 << 30))


@pytest.mark.parametrize('changes', [dict(swap=1), dict(disk=monitor.DISK_MARGIN - 1),
    dict(gpu_used=monitor.GPU_LIMIT, gpu_total=90_000_000_000, gpu_free=2 << 30),
    dict(gpu_free=monitor.GPU_MARGIN - 1)])
def test_global_limits_also_apply_during_uncredited_transitions(changes):
    with pytest.raises(RuntimeError, match='resource stop'):
        monitor.check_resources(**sample(transition=True, **changes))
    assert monitor.check_resources(**sample(transition=True, rss=monitor.W_BYTES)) is None


def test_deadline_requires_explicit_closeout_reserve_and_reserves_it():
    env = dict(AUTHORIZED_END_EPOCH='1000', CLOSE_RESERVE_SECONDS='50')
    assert monitor.campaign_bounds(150, env, 800) == (1000, 50, 950)
    with pytest.raises(ValueError, match='reserve'):
        monitor.campaign_bounds(151, env, 800)
    for invalid in ('0', '-1'):
        with pytest.raises(ValueError):
            monitor.campaign_bounds(1, dict(env, CLOSE_RESERVE_SECONDS=invalid), 800)
    with pytest.raises(KeyError):
        monitor.campaign_bounds(1, dict(AUTHORIZED_END_EPOCH='1000'), 800)
    with pytest.raises(ValueError):
        monitor.campaign_bounds(1, dict(env, AUTHORIZED_END_EPOCH='nan'), 800)


def test_progress_records_lifecycle_and_refuses_phase_during_transition(tmp_path):
    progress = monitor.Progress(tmp_path / 'run.jsonl')
    progress.consume(record(0, resident('host', 'live')))
    progress.consume(record(1, resident('device', 'allocating')))
    assert progress.transition()
    with pytest.raises(ValueError, match='new phase'):
        progress.consume(record(2, dict(kind='start', phase='proof')))
    progress.consume(record(3, resident('device', 'live')))
    assert not progress.transition()
    progress.consume(record(4, resident('device', 'retiring')))
    progress.consume(record(5, resident('device', 'retired')))
    progress.consume(record(6, dict(kind='command_result', complete=True)))
    assert progress.enforced and progress.complete
    assert progress.live_spaces == {'host', 'device'}


@pytest.mark.parametrize('event', [resident('device', 'live'), resident('host', 'live', bytes=1),
    resident('host', 'live', address=0), resident('other', 'live'),
    resident('host', 'live', process_start_ticks=-1)])
def test_invalid_W_metadata_never_grants_an_exemption(tmp_path, event):
    with pytest.raises(ValueError):
        monitor.Progress(tmp_path / 'none').consume(record(0, event))


@pytest.mark.parametrize('census', [dict(temporary_live_bytes=monitor.PAYLOAD_LIMIT + 1),
    dict(temporary_payload_peak_bytes=monitor.PAYLOAD_LIMIT + 1), dict(denied_allocations=1),
    dict(payload_limit_bytes=monitor.PAYLOAD_LIMIT + 1), dict(enforced='true')])
def test_bad_allocator_census_fails_closed(tmp_path, census):
    with pytest.raises(ValueError):
        monitor.Progress(tmp_path / 'none').consume(record(0, **census))


def test_progress_reads_complete_records_rejects_truncation_permissions_and_sequence(tmp_path):
    path = tmp_path / 'progress.jsonl'
    with monitor.new_file(path) as sink:
        sink.write(json.dumps(record(0)) + '\n' + json.dumps(record(1))[:12])
    progress = monitor.Progress(path)
    progress.read()
    assert progress.sequence == 1
    with path.open('a') as sink:
        sink.write(json.dumps(record(1))[12:] + '\n')
    progress.read()
    assert progress.sequence == 2
    path.write_text('')
    with pytest.raises(ValueError, match='truncated'):
        progress.read()
    path.chmod(0o644)
    with pytest.raises(ValueError, match='private'):
        monitor.Progress(path).read()
    with pytest.raises(ValueError, match='sequence'):
        monitor.Progress(tmp_path / 'missing').consume(record(3))


def test_unresolved_transition_cannot_be_success(tmp_path):
    progress = monitor.Progress(tmp_path / 'unused')
    progress.consume(record(0, resident('device', 'allocating')))
    with pytest.raises(ValueError, match='unresolved'):
        progress.consume(record(1, dict(kind='command_result', complete=True)))


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    fake = tmp_path / 'nvidia-smi'
    fake.write_text('#!/bin/sh\nprintf "100, 80000, 79000\\n"\n')
    fake.chmod(0o700)
    time_binary = tmp_path / 'fake-time'
    time_binary.write_text('#!/bin/sh\n'
        'test "$1" = -v || exit 2\nshift\n'
        'test "$1" = -o || exit 2\nshift\n'
        'printf "time wrapper fixture\\n" > "$1"\nshift\nexec "$@"\n')
    time_binary.chmod(0o700)
    monkeypatch.setattr(monitor, 'TIME_BINARY', str(time_binary))
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    monkeypatch.setenv('CUDA_VISIBLE_DEVICES', 'GPU-01234567-89ab-cdef-0123-456789abcdef')
    monkeypatch.setenv('AUTHORIZED_END_EPOCH', str(time.time() + 60))
    monkeypatch.setenv('CLOSE_RESERVE_SECONDS', '10')
    # No actual disk-sized workload is needed by the controller fixture.
    monkeypatch.setattr(monitor, 'DISK_MARGIN', 0)
    cgroup = tmp_path / 'fake-cgroup'
    cgroup.mkdir()
    (cgroup / 'memory.current').write_text('1024\n')
    (cgroup / 'memory.events').write_text('oom 0\noom_kill 0\n')
    monkeypatch.setattr(monitor, 'CGROUP', cgroup)
    return argparse.Namespace(mode='calibration', progress=None, root=tmp_path,
                              label='fixture', seconds=2,
                              command=[sys.executable, '-c', 'import time; time.sleep(0.3)'])


def test_fake_GPU_process_success_private_outputs_and_no_overwrite(campaign):
    campaign.command = [sys.executable, '-c',
        'import os,time; print(os.environ["C71_DIAGNOSTIC_TIMEOUT_SECONDS"]); time.sleep(0.3)']
    before_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    assert monitor.run(campaign) == 0
    after_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    log = campaign.root / 'logs'
    report = json.loads((log / 'fixture.summary.json').read_text())
    assert report['samples'] > 0 and not report['physical_complete_peak']
    assert 'CLOCK_MONOTONIC' in report['sample_interval_clock']
    assert 'no GPU synchronization' in report['sample_interval_scope']
    with (log / 'fixture.memory.csv').open(newline='') as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == [
            'unix_seconds', 'sample_duration_seconds', 'host_tree_rss_bytes',
            'host_tree_swap_bytes', 'whole_gpu_used_bytes', 'whole_gpu_free_bytes',
            'resident_host_W_lower_bound_bytes', 'resident_device_W_bytes',
            'sampled_temporary_bytes', 'W_transition_incomplete',
            'cgroup_memory_current_bytes', 'disk_available_bytes', 'smaps_read_failures',
            'monotonic_sample_start_ns', 'monotonic_sample_end_ns',
        ]
        rows = list(reader)
    assert len(rows) == report['samples']
    previous_end_ns = before_ns
    for row in rows:
        start_ns, end_ns = (int(row[name]) for name in
                            ('monotonic_sample_start_ns', 'monotonic_sample_end_ns'))
        assert before_ns <= previous_end_ns <= start_ns < end_ns <= after_ns
        previous_end_ns = end_ns
    assert (log / 'fixture.stdout').read_text().strip() == '2'
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in log.iterdir())
    original = (log / 'fixture.summary.json').read_bytes()
    with pytest.raises(ValueError, match='no overwrite'):
        monitor.run(campaign)
    assert (log / 'fixture.summary.json').read_bytes() == original


@pytest.mark.parametrize('new_session', [False, True])
def test_runtime_deadline_kills_descendant_in_another_process_group(campaign, new_session):
    pid_path = campaign.root / 'descendant'
    campaign.seconds = 1
    campaign.command = [sys.executable, '-c',
        'import pathlib,subprocess,sys,time; '
        'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],**json.loads(sys.argv[2])); '
        'pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)', str(pid_path)]
    campaign.command[2] = 'import json; ' + campaign.command[2]
    campaign.command.append(json.dumps({'start_new_session': True} if new_session else {'process_group': 0}))
    assert monitor.run(campaign) != 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert 'deadline' in report['resource_failure']
    pid = int(pid_path.read_text())
    # A killed orphan may remain a zombie until the container's init reaps it.
    status = Path(f'/proc/{pid}/status')
    stop_wait = time.monotonic() + 1
    while status.exists() and 'State:\tZ' not in status.read_text() and time.monotonic() < stop_wait:
        time.sleep(0.01)
    assert not status.exists() or 'State:\tZ' in status.read_text()


def test_failed_GPU_sample_stops_command_and_cannot_be_success(campaign):
    (campaign.root / 'nvidia-smi').write_text('#!/bin/sh\nexit 3\n')
    assert monitor.run(campaign) != 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert report['samples'] == 0
    assert 'CalledProcessError' in report['resource_failure']


def test_recovered_smaps_read_does_not_skip_physical_cap(campaign, monkeypatch):
    campaign.mode = 'canonical'
    campaign.progress = campaign.root / 'canonical.progress.jsonl'
    def recovered(progress, _rows, _session):
        progress.smaps_read_failures += 1
        return 0, 0
    monkeypatch.setattr(monitor.Progress, 'exemptions', recovered)
    monkeypatch.setattr(monitor, 'host_tree', lambda *_:
                        {os.getpid(): (0, monitor.PHYSICAL_LIMIT, 0)})
    assert monitor.run(campaign) != 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert 'simultaneous' in report['resource_failure']
    assert report['smaps_read_failures'] == 1


def test_physical_stop_preserves_offending_sample_in_summary(campaign, monkeypatch):
    campaign.mode = 'canonical'
    campaign.progress = campaign.root / 'canonical.progress.jsonl'
    monkeypatch.setattr(monitor.Progress, 'exemptions', lambda *_: (0, 0))
    monkeypatch.setattr(monitor, 'host_tree', lambda *_:
                        {os.getpid(): (0, monitor.PHYSICAL_LIMIT, 0)})
    assert monitor.run(campaign) != 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert 'simultaneous' in report['resource_failure']
    assert report['samples'] == report['stable_samples'] == 1
    assert report['sampled_stable_temporary_peak_bytes'] == monitor.PHYSICAL_LIMIT + (100 << 20)


def test_missing_cgroup_metrics_fail_before_launch(campaign, monkeypatch):
    (monitor.CGROUP / 'memory.events').unlink()
    def forbidden(*_args, **_kwargs):
        pytest.fail('missing required metric must fail before launching')
    monkeypatch.setattr(monitor.subprocess, 'Popen', forbidden)
    with pytest.raises(FileNotFoundError):
        monitor.run(campaign)


def test_canonical_mode_requires_new_progress_path_before_launch(campaign):
    campaign.mode = 'canonical'
    with pytest.raises(ValueError, match='requires --progress'):
        monitor.run(campaign)
    campaign.progress = campaign.root / 'existing.jsonl'
    campaign.progress.touch(mode=0o600)
    with pytest.raises(ValueError, match='must be new'):
        monitor.run(campaign)
    assert not (campaign.root / 'logs').exists()


@pytest.mark.parametrize('new_session', [False, True])
def test_canonical_controller_reads_real_small_host_mapping_with_fake_device(campaign, monkeypatch, new_session):
    # The controller fixture reduces only the pinned W-size constant; the
    # launched Python process supplies an actual live mapping for /proc/smaps.
    monkeypatch.setattr(monitor, 'W_BYTES', 8192)
    campaign.mode = 'canonical'
    campaign.progress = campaign.root / 'canonical.progress.jsonl'
    source = '''
import ctypes,json,mmap,os,sys,time
assert os.environ['C71_CANONICAL_MONITOR']=='1'
memory=mmap.mmap(-1,8192)
memory[:]=bytes(8192)
address=ctypes.addressof(ctypes.c_char.from_buffer(memory))
ticks=int(open('/proc/self/stat').read().rsplit(')',1)[1].split()[19])
sink=os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w')
sequence=0
def emit(event):
    global sequence
    row={'schema':'volta-c71-progress-v1','sequence':sequence,'event':event,
         'joint_allocations':{'payload_limit_bytes':5905580032,'runtime_allowance_bytes':268435456,
                              'temporary_payload_peak_bytes':1024,'temporary_live_bytes':512,
                              'denied_allocations':0,'enforced':True}}
    sink.write(json.dumps(row)+'\\n');sink.flush();sequence+=1
def state(space,value):
    emit({'kind':'resident_w','space':space,'state':value,'pid':os.getpid(),
          'process_start_ticks':ticks,'bytes':8192,'address':address})
state('host','live');state('device','allocating');state('device','live')
time.sleep(0.35)
state('device','retiring');state('device','retired')
state('host','retiring');memory.close();state('host','retired')
emit({'kind':'command_result','complete':True})
'''
    campaign.command = [sys.executable, '-c', source, str(campaign.progress)]
    if new_session:
        campaign.command = [sys.executable, '-c',
            'import subprocess,sys; sys.exit(subprocess.run(sys.argv[1:],start_new_session=True).returncode)',
            *campaign.command]
    assert monitor.run(campaign) == 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert report['stable_samples'] > 0
    assert report['observed_payload_peak_bytes'] == 1024
    assert not any('address' in key for key in report)


def test_zero_samples_are_failure_even_when_child_returns_zero(campaign, monkeypatch):
    class Finished:
        pid = 99999999
        returncode = 0
        def poll(self):
            return 0
        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(monitor.subprocess, 'Popen', lambda *args, **kwargs: Finished())
    monkeypatch.setattr(monitor, 'stop_session', lambda *_args: None)
    assert monitor.run(campaign) != 0
    report = json.loads((campaign.root / 'logs/fixture.summary.json').read_text())
    assert report['samples'] == 0
    assert 'no valid simultaneous' in report['resource_failure']
