"""Captured subprocesses with finite time and combined output budgets."""
import os
import selectors
import signal
import subprocess
import time
from orgscan.cancellation import check_cancelled

CompletedProcess = subprocess.CompletedProcess
TimeoutExpired = subprocess.TimeoutExpired
OUTPUT_LIMIT = 8_000_000


class OutputLimitExceeded(RuntimeError):
    pass


def run(command, *, timeout=300, max_output_bytes=OUTPUT_LIMIT, capture_output=True,
        text=True, check=False, cwd=None, env=None, output_files=()):
    if not capture_output or check:
        raise ValueError('Bounded execution requires captured output and explicit exit handling')
    check_cancelled()
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=cwd, env=env, start_new_session=True) as process:
        chunks = {process.stdout: bytearray(), process.stderr: bytearray()}
        total, deadline = 0, time.monotonic() + timeout
        def check_report_sizes():
            sizes = 0
            for path in output_files:
                try:
                    sizes += os.stat(path, follow_symlinks=False).st_size
                except FileNotFoundError:
                    continue
            if total + sizes > max_output_bytes:
                raise OutputLimitExceeded('Process output exceeded the allowed limit')
        try:
            with selectors.DefaultSelector() as selector:
                for pipe in chunks:
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    check_cancelled()
                    check_report_sizes()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutExpired('scanner', timeout)
                    ready = selector.select(min(remaining, 0.1)) if selector.get_map() else ()
                    if not selector.get_map():
                        time.sleep(min(remaining, 0.05))
                    for key, _ in ready:
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(block)
                        if total > max_output_bytes:
                            raise OutputLimitExceeded('Process output exceeded the allowed limit')
                        chunks[key.fileobj].extend(block)
                process.wait(timeout=max(deadline-time.monotonic(), 0.001))
                check_report_sizes()
        except BaseException:
            # Kill descendants too: a child may retain a pipe after its parent exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        output = [bytes(chunks[pipe]) for pipe in (process.stdout, process.stderr)]
        if text:
            output = [value.decode('utf-8', errors='replace') for value in output]
        return CompletedProcess(command, process.returncode, *output)
