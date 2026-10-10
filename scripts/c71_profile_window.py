#!/usr/bin/env python3
"""Owned Nsight window around real A group boundaries; diagnostic interruption only."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from c71_campaign_measure import descendant_of, host_tree, new_file, start_ticks


def completed_group(record):
    event = record['event']
    work = event.get('work', {})
    if event.get('phase') != 'pcs_a_resident' or work.get('boundary') != 'end':
        return None
    if event['geometry']['groups'] != 512:
        raise ValueError('expected original 512-group A geometry')
    count = work['completed_groups']
    if type(count) is not int or not 0 <= count <= 512:
        raise ValueError('invalid completed A count')
    return count


def run(args):
    with new_file(args.output / 'window-actions.jsonl') as actions:
        def record(event):
            actions.write(json.dumps(dict(event, monotonic_ns=time.monotonic_ns())) + '\n')
            actions.flush()

        def control(verb):
            command = [args.nsys, verb, '--session=' + args.session]
            if verb == 'start':
                command += ['--sample=none', '--cpuctxsw=none', '--output=' + str(args.output / 'cuda-window')]
            record({'action': verb, 'edge': 'before', 'command': command})
            with new_file(args.output / (verb + '.stdout')) as out, new_file(args.output / (verb + '.stderr')) as err:
                subprocess.run(command, stdout=out, stderr=err, check=True, timeout=60)
            record({'action': verb, 'edge': 'after'})

        command = [args.nsys, 'launch', '--session-new=' + args.session,
                   '--trace=cuda', '--cuda-memory-usage=true', '--wait=all', *args.command]
        record({'action': 'launch', 'command': command, 'credit': False,
                'start_after_completed_groups': args.start, 'stop_after_completed_groups': args.end})
        with new_file(args.output / 'launch.stdout') as out, new_file(args.output / 'launch.stderr') as err:
            launch = subprocess.Popen(command, stdout=out, stderr=err)
            offset, owner, started, stopped = 0, None, False, False
            while launch.poll() is None:
                if args.progress.exists():
                    with args.progress.open('rb') as progress:
                        progress.seek(offset)
                        while line := progress.readline(1048577):
                            if len(line) > 1048576:
                                raise ValueError('oversized progress record')
                            if not line.endswith(b'\n'):
                                break
                            offset += len(line)
                            row = json.loads(line)
                            event = row['event']
                            if event.get('kind') == 'resident_w' and event['state'] == 'live':
                                identity = event['pid'], event['process_start_ticks']
                                if owner not in (None, identity):
                                    raise ValueError('native W owner changed')
                                owner = identity
                            count = completed_group(row)
                            if count is not None and count >= args.start and not started:
                                control('start')
                                started = True
                            if count is not None and count >= args.end and started and not stopped:
                                control('stop')
                                stopped = True
                                if owner is None or not descendant_of(host_tree(os.getpid()), owner[0], launch.pid):
                                    raise ValueError('native process is outside the owned launch tree')
                                descriptor = os.pidfd_open(owner[0])
                                try:
                                    if start_ticks(owner[0]) != owner[1]:
                                        raise ValueError('native PID was reused')
                                    record({'action': 'planned_native_stop', 'complete_canonical': False})
                                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                                finally:
                                    os.close(descriptor)
                time.sleep(0.2)
            record({'action': 'launch_exit', 'exit_code': launch.returncode,
                    'window_started': started, 'window_stop_requested': stopped, 'credit': False})
            return launch.returncode or int(not stopped)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('progress', type=Path)
    parser.add_argument('session')
    parser.add_argument('start', type=int)
    parser.add_argument('end', type=int)
    parser.add_argument('nsys')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1 <= args.start < args.end <= 512 or not args.command:
        parser.error('a bounded A window and native command are required')
    raise SystemExit(run(args))


if __name__ == '__main__':
    main()
