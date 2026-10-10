"""Bounded campaign process runner. Samples are diagnostics, never full peak proof."""
import argparse
import csv
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


W_BYTES = 61_394_690_560
PAYLOAD_LIMIT = 5_905_580_032
RUNTIME_ALLOWANCE = 256 << 20
PHYSICAL_LIMIT = PAYLOAD_LIMIT + RUNTIME_ALLOWANCE
GPU_LIMIT = 80_000_000_000
GPU_MARGIN = 1 << 30
DISK_MARGIN = 20_000_000_000
SAMPLE_SECONDS = 0.2
MAX_RECORD_BYTES = 1 << 20
MAX_SMAPS_FAILURES = 64
CGROUP = Path('/sys/fs/cgroup')
TIME_BINARY = '/usr/bin/time'


def process_rows():
    rows = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
            rows[int(path.name)] = (
                int(fields['PPid']), int(fields.get('VmRSS', '0 kB').split()[0]) * 1024,
                int(fields.get('VmSwap', '0 kB').split()[0]) * 1024,
            )
        except (FileNotFoundError, ProcessLookupError):
            continue
    return rows


def host_tree(root_pid, session_id=None):
    rows = process_rows()
    selected = {root_pid}
    if session_id is not None:
        for pid in rows:
            try:
                if os.getsid(pid) == session_id:
                    selected.add(pid)
            except ProcessLookupError:
                pass
    while True:
        extra = {pid for pid, row in rows.items() if row[0] in selected} - selected
        if not extra:
            break
        selected.update(extra)
    return {pid: rows[pid] for pid in selected if pid in rows}


def stop_session(session_id):
    groups = {session_id}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            pid = int(proc.name)
            if os.getsid(pid) == session_id:
                groups.add(os.getpgid(pid))
        except ProcessLookupError:
            pass
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def start_ticks(pid):
    # comm may contain spaces or parentheses; starttime is field 22.
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])


class SmapsCoverageError(ValueError):
    pass


def host_w_residency(smaps, address, size, page_size):
    """Return a lower bound on resident W, plus complete smaps RSS.

    An intersecting mapping can include malloc metadata or another allocation.
    Only its RSS exceeding ALL bytes outside wholly W-owned pages is exempt.
    """
    first = ((address + page_size - 1) // page_size) * page_size
    last = ((address + size) // page_size) * page_size
    exempt = total_rss = covered = 0
    next_page = first
    current = None
    for line in smaps.splitlines():
        match = re.match(r'^([0-9a-f]+)-([0-9a-f]+) ', line)
        if match:
            current = tuple(int(value, 16) for value in match.groups())
        elif line.startswith('Rss:'):
            if current is None:
                raise ValueError('smaps RSS without mapping')
            begin, end = current
            parts = line.split()
            if len(parts) != 3 or parts[2] != 'kB':
                raise ValueError('invalid smaps RSS unit')
            rss = int(parts[1]) * 1024
            if not 0 <= rss <= end - begin:
                raise ValueError('inconsistent smaps mapping RSS')
            interior = max(0, min(end, last) - max(begin, first))
            if interior:
                if max(begin, first) != next_page:
                    raise SmapsCoverageError('noncontiguous resident W coverage in smaps')
                next_page = min(end, last)
            exempt += max(0, rss - (end - begin - interior))
            covered += interior
            total_rss += rss
            current = None
    if covered != max(0, last - first) or total_rss <= 0:
        raise SmapsCoverageError('resident W range missing from smaps')
    return exempt, total_rss


def natural(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f'invalid {name}')
    return value


class Progress:
    """Tail one fresh private log; retain only allocator/lifecycle metadata."""
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.sequence = 0
        self.identity = None
        self.process = None
        self.states = {}
        self.generation = 0
        self.peak = 0
        self.enforced = False
        self.complete = False
        self.live_spaces = set()
        self.smaps_read_failures = 0

    def transition(self):
        return any(row['state'] in ('allocating', 'retiring') for row in self.states.values())

    def read(self):
        try:
            handle = self.path.open('rb')
        except FileNotFoundError:
            if self.identity is not None:
                raise ValueError('progress log disappeared')
            return
        with handle:
            info = os.fstat(handle.fileno())
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('progress must be a private regular file')
            if self.identity not in (None, identity) or info.st_size < self.offset:
                raise ValueError('progress replaced or truncated')
            self.identity = identity
            handle.seek(self.offset)
            while handle.tell() < info.st_size:
                line = handle.readline(MAX_RECORD_BYTES + 1)
                if len(line) > MAX_RECORD_BYTES:
                    raise ValueError('oversized progress record')
                if not line or not line.endswith(b'\n'):
                    break
                self.consume(json.loads(line))
                self.offset = handle.tell()

    def consume(self, record):
        if record.get('schema') != 'volta-c71-progress-v1' or record.get('sequence') != self.sequence:
            raise ValueError('invalid progress schema or sequence')
        self.sequence += 1
        census = record['joint_allocations']
        if census['payload_limit_bytes'] != PAYLOAD_LIMIT or census['runtime_allowance_bytes'] != RUNTIME_ALLOWANCE:
            raise ValueError('canonical allocator limits changed')
        if type(census['enforced']) is not bool:
            raise ValueError('invalid allocator enforcement state')
        peak = natural(census['temporary_payload_peak_bytes'], 'payload peak')
        if natural(census['denied_allocations'], 'denied allocations'):
            raise ValueError('canonical allocator denied an allocation')
        if census['enforced']:
            live = natural(census['temporary_live_bytes'], 'live payload')
            if max(peak, live) > PAYLOAD_LIMIT:
                raise ValueError('canonical payload cap exceeded')
            self.enforced = True
        self.peak = max(self.peak, peak)
        event = record['event']
        if event.get('kind') != 'resident_w':
            if self.transition() and event.get('kind') == 'start':
                raise ValueError('new phase before W residency transition completed')
            if event.get('kind') == 'command_result':
                if type(event['complete']) is not bool:
                    raise ValueError('invalid command completion')
                self.complete = event['complete']
                if self.complete and self.transition():
                    raise ValueError('successful command with unresolved W transition')
            return
        space, state = event['space'], event['state']
        if space not in ('host', 'device') or state not in ('allocating', 'live', 'retiring', 'retired'):
            raise ValueError('invalid W residency lifecycle')
        process = (natural(event['pid'], 'pid'), natural(event['process_start_ticks'], 'start ticks'))
        if not all(process) or self.process not in (None, process):
            raise ValueError('W owner process changed')
        self.process = process
        if natural(event['bytes'], 'W bytes') != W_BYTES:
            raise ValueError('W exemption must identify the pinned packed payload')
        previous = self.states.get(space, {}).get('state')
        allowed = {
            'host': {None: ('live',), 'live': ('retiring',), 'retiring': ('retired',)},
            'device': {None: ('allocating',), 'allocating': ('live', 'retiring'),
                       'live': ('retiring',), 'retiring': ('retired',)},
        }
        if state not in allowed[space].get(previous, ()):
            raise ValueError('invalid W residency transition order')
        row = {'state': state}
        if space == 'host' and state == 'live':
            row['address'] = natural(event['address'], 'W address')
            if not row['address']:
                raise ValueError('null W address')
        self.states[space] = row
        if state == 'live':
            self.live_spaces.add(space)
        self.generation += 1

    def exemptions(self, rows, session_id):
        if self.process is None or all(self.states.get(space, {}).get('state') == 'retired'
                                       for space in ('host', 'device')):
            return 0, 0
        pid, ticks = self.process
        if pid not in rows or start_ticks(pid) != ticks or os.getsid(pid) != session_id:
            raise ValueError('resident W owner is not the monitored process session')
        host = device = 0
        if self.states.get('host', {}).get('state') == 'live':
            # /proc may span VMA changes. Never exempt bytes from a partial walk.
            for attempt in range(3):
                with Path(f'/proc/{pid}/smaps').open() as handle:
                    smaps = handle.read(MAX_RECORD_BYTES + 1)
                if len(smaps) > MAX_RECORD_BYTES:
                    raise ValueError('oversized smaps sample')
                try:
                    host, rss = host_w_residency(smaps, self.states['host']['address'], W_BYTES, os.sysconf('SC_PAGE_SIZE'))
                    break
                except SmapsCoverageError:
                    self.smaps_read_failures += 1
                    failed = self.path.with_name(self.path.name + f'.smaps-failed-{self.smaps_read_failures:04d}.txt')
                    with new_file(failed) as sink:
                        sink.write(smaps)
                        sink.flush()
                        os.fsync(sink.fileno())
                    if attempt == 2 or self.smaps_read_failures >= MAX_SMAPS_FAILURES:
                        raise
            if start_ticks(pid) != ticks:
                raise ValueError('resident W owner changed during smaps read')
            parent, previous_rss, swap = rows[pid]
            rows[pid] = (parent, max(previous_rss, rss), swap)
        if self.states.get('device', {}).get('state') == 'live':
            device = W_BYTES
        return host, device


def check_resources(mode, rss, swap, gpu_used, gpu_total, gpu_free, disk, host_w=0, device_w=0, transition=False):
    values = (rss, swap, gpu_used, gpu_total, gpu_free, disk, host_w, device_w)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError('invalid memory sample')
    if rss <= 0 or gpu_total <= 0 or gpu_used + gpu_free > gpu_total + (1 << 20):
        raise ValueError('missing or inconsistent memory sample')
    if swap or disk < DISK_MARGIN or gpu_used >= GPU_LIMIT or gpu_free < GPU_MARGIN:
        raise RuntimeError('resource stop: GPU/global free margin/swap/free disk')
    if mode == 'calibration':
        if rss > 96 << 30:
            raise RuntimeError('resource stop: calibration RSS exceeds 96 GiB')
        return None
    if transition:
        return None
    if host_w > rss or device_w > gpu_used:
        raise ValueError('resident W exemption exceeds measured residency')
    temporary = rss + gpu_used - host_w - device_w
    if temporary > PHYSICAL_LIMIT:
        raise RuntimeError('resource stop: canonical simultaneous physical temporaries exceed allowance')
    return temporary


def new_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(descriptor, 'w')


def cgroup_oom_events():
    fields = dict(line.split() for line in (CGROUP / 'memory.events').read_text().splitlines())
    return (int(fields['oom']), int(fields['oom_kill']))


def campaign_bounds(seconds, env, now):
    deadline = float(env['AUTHORIZED_END_EPOCH'])
    reserve = int(env['CLOSE_RESERVE_SECONDS'])
    if not math.isfinite(deadline) or reserve <= 0 or seconds <= 0:
        raise ValueError('positive phase duration, finite deadline and positive closeout reserve required')
    end = deadline - reserve
    if now + seconds > end:
        raise ValueError('phase would consume the authorized closeout reserve')
    return deadline, reserve, end


def interrupted(signum, _frame):
    raise KeyboardInterrupt(f'monitor interrupted by signal {signum}')


def run(args):
    start = time.time()
    deadline, reserve, end = campaign_bounds(args.seconds, os.environ, start)
    gpu_uuid = os.environ['CUDA_VISIBLE_DEVICES']
    if not re.fullmatch(r'GPU-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', gpu_uuid):
        raise ValueError('exactly one GPU UUID required')
    if not args.command or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', args.label):
        raise ValueError('command and fresh alphanumeric/hyphen label required')
    if args.mode == 'canonical' and args.progress is None:
        raise ValueError('canonical mode requires --progress for the runner journal sibling')
    if args.mode == 'calibration' and args.progress is not None:
        raise ValueError('--progress is only valid for canonical monitoring')
    progress = Progress(args.progress) if args.mode == 'canonical' else None
    if progress and args.progress.exists():
        raise ValueError('canonical progress path must be new')
    logs = args.root / 'logs'
    logs.mkdir(mode=0o700, exist_ok=True)
    if logs.is_symlink() or any(logs.glob(args.label + '.*')):
        raise ValueError('new private log directory/label required; no overwrite or retry')
    # Reserve all outputs before launching; even interruption cannot reuse a label.
    names = ('start', 'stdout', 'stderr', 'memory.csv', 'time.txt', 'exit', 'end', 'summary.json')
    files = {}
    old_signals = {}
    try:
        for name in names:
            files[name] = new_file(logs / f'{args.label}.{name}')
        files['start'].write(str(start) + '\n')
        files['start'].flush()
        writer = csv.writer(files['memory.csv'])
        writer.writerow(['unix_seconds', 'sample_duration_seconds', 'host_tree_rss_bytes',
                         'host_tree_swap_bytes', 'whole_gpu_used_bytes', 'whole_gpu_free_bytes',
                         'resident_host_W_lower_bound_bytes', 'resident_device_W_bytes',
                         'sampled_temporary_bytes', 'W_transition_incomplete',
                         'cgroup_memory_current_bytes', 'disk_available_bytes', 'smaps_read_failures',
                         'monotonic_sample_start_ns', 'monotonic_sample_end_ns'])
        environment = dict(os.environ, C71_DIAGNOSTIC_TIMEOUT_SECONDS=str(args.seconds))
        if progress:
            environment['C71_CANONICAL_MONITOR'] = '1'
        else:
            environment.pop('C71_CANONICAL_MONITOR', None)
        oom_before = cgroup_oom_events()
        process = subprocess.Popen([TIME_BINARY, '-v', '-o', str(logs / f'{args.label}.time.txt'), *args.command],
                                   stdout=files['stdout'], stderr=files['stderr'], env=environment, start_new_session=True)
        started = time.monotonic()
        stop_at = started + args.seconds
        samples = incomplete = 0
        joint_peak = host_peak = gpu_peak = 0
        failure = None
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_signals[signum] = signal.signal(signum, interrupted)
        try:
            while process.poll() is None:
                before = time.monotonic()
                monotonic_sample_start_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                remaining = min(stop_at - before, end - time.time())
                if remaining <= 0:
                    raise TimeoutError('phase or authorized compute deadline reached')
                if progress:
                    progress.read()
                generation = progress.generation if progress else 0
                smaps_before = progress.smaps_read_failures if progress else 0
                transitioning = progress.transition() if progress else False
                rows = host_tree(os.getpid(), process.pid)
                host_w = device_w = 0
                exemption_error = None
                if progress:
                    try:
                        host_w, device_w = progress.exemptions(rows, process.pid)
                    except (OSError, ValueError) as error:
                        exemption_error = error
                gpu = subprocess.run(['nvidia-smi', '--id=' + gpu_uuid,
                                      '--query-gpu=memory.used,memory.total,memory.free', '--format=csv,noheader,nounits'],
                                     capture_output=True, text=True, timeout=min(10, remaining), check=True)
                fields = gpu.stdout.strip().split(',')
                if len(fields) != 3:
                    raise ValueError('exactly one GPU memory sample required')
                used, total, free = (int(value.strip()) * (1 << 20) for value in fields)
                after = host_tree(os.getpid(), process.pid)
                for pid, (parent, rss, swap) in after.items():
                    old = rows.get(pid, (parent, 0, 0))
                    rows[pid] = (parent, max(rss, old[1]), max(swap, old[2]))
                if progress:
                    progress.read()
                    transitioning |= progress.transition() or generation != progress.generation
                # Teardown can retire the owner between either /proc read.
                # Discard that joint sample only on observed lifecycle/exit.
                transitioning |= process.poll() is not None
                if exemption_error and not transitioning:
                    raise exemption_error
                rss = sum(row[1] for row in rows.values())
                swap = sum(row[2] for row in rows.values())
                cgroup = int((CGROUP / 'memory.current').read_text())
                disk_state = os.statvfs(args.root)
                disk = disk_state.f_bavail * disk_state.f_frsize
                temporary = None if transitioning or args.mode == 'calibration' else rss + used - host_w - device_w
                smaps_failures = progress.smaps_read_failures - smaps_before if progress else 0
                monotonic_sample_end_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                writer.writerow([time.time(), time.monotonic() - before, rss, swap, used, free,
                                 host_w, device_w, temporary, int(transitioning), cgroup, disk, smaps_failures,
                                 monotonic_sample_start_ns, monotonic_sample_end_ns])
                files['memory.csv'].flush()
                samples += 1
                incomplete += int(transitioning or smaps_failures > 0)
                # A recovered read still enforces the physical cap below, but
                # its longer interval is excluded from stable-peak credit.
                if not transitioning and not smaps_failures:
                    joint_peak = max(joint_peak, temporary or 0)
                host_peak, gpu_peak = max(host_peak, rss), max(gpu_peak, used)
                # Keep the offending sample in the summary as well as the CSV.
                if any(after > before for after, before in zip(cgroup_oom_events(), oom_before)):
                    raise RuntimeError('resource stop: cgroup OOM event')
                check_resources(args.mode, rss, swap, used, total, free, disk, host_w, device_w, transitioning)
                if min(stop_at - time.monotonic(), end - time.time()) <= 0:
                    raise TimeoutError('phase or authorized compute deadline reached')
                time.sleep(max(0, min(SAMPLE_SECONDS - (time.monotonic() - before), stop_at - time.monotonic(), end - time.time())))
            if samples == 0:
                raise ValueError('no valid simultaneous resource samples')
            if progress:
                progress.read()
                if progress.transition():
                    raise ValueError('unresolved W residency transition')
                if process.returncode == 0 and not (progress.enforced and progress.complete
                        and progress.live_spaces == {'host', 'device'} and samples > incomplete
                        and all(progress.states.get(space, {}).get('state') == 'retired'
                                for space in ('host', 'device'))):
                    raise ValueError('missing enforced allocator census or successful canonical completion')
        except BaseException as error:
            failure = type(error).__name__ + ': ' + str(error)
        finally:
            stop_session(process.pid)
        try:
            code = process.wait(timeout=max(0, min(5, deadline - time.time())))
        except subprocess.TimeoutExpired:
            code = 1
            failure = (failure + '; ' if failure else '') + 'process did not exit after session kill'
        if failure:
            code = code or 1
        summary = {
            'label': args.label, 'mode': args.mode, 'gpu_uuid': gpu_uuid,
            'authorized_end_epoch': deadline, 'close_reserve_seconds': reserve,
            'compute_end_epoch': end, 'command': args.command, 'exit_code': code,
            'start_unix_seconds': start, 'wall_seconds': time.monotonic() - started,
            'samples': samples, 'incomplete_samples': incomplete,
            'stable_samples': samples - incomplete,
            'smaps_read_failures': progress.smaps_read_failures if progress else 0,
            'sampling_target_seconds': SAMPLE_SECONDS,
            'sample_interval_clock': 'Linux CLOCK_MONOTONIC, absolute nanoseconds on this host boot',
            'sample_interval_scope': 'Start/end bracket collection of the resource sample; no GPU synchronization or instantaneous peak. External profiler clock alignment requires a matching clock or explicit anchor.',
            'sampled_stable_temporary_peak_bytes': joint_peak,
            'sampled_host_rss_peak_bytes': host_peak, 'sampled_whole_gpu_peak_bytes': gpu_peak,
            'observed_payload_peak_bytes': progress.peak if progress else None,
            'payload_limit_bytes': PAYLOAD_LIMIT if progress else None,
            'physical_temporary_limit_bytes': PHYSICAL_LIMIT if progress else None,
            'physical_complete_peak': False, 'resource_failure': failure,
            'sampling_limit': 'Conservative sampled account, includes monitor RSS and whole GPU. Host W exemption requires contiguous complete smaps coverage; at most two retries per read and 64 failed walks per run, with failed snapshots preserved. Recovered reads enforce the physical cap but receive no stable-peak credit. Device W requires owner lifecycle. Shared host pages may be double counted. Allocation/retirement transitions have no joint-memory credit; phase/campaign deadlines and global GPU/free/swap/disk limits apply. Transient peaks and runtime allowance sufficiency remain unproven.',
        }
        for name, value in [('exit', str(code)), ('end', str(time.time())), ('summary.json', json.dumps(summary, indent=2, sort_keys=True))]:
            files[name].write(value + '\n')
        print(json.dumps(summary), flush=True)
        return code
    finally:
        for signum, handler in old_signals.items():
            signal.signal(signum, handler)
        for handle in files.values():
            handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('canonical', 'calibration'), required=True)
    parser.add_argument('--progress', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('label')
    parser.add_argument('seconds', type=int)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    sys.exit(main())
