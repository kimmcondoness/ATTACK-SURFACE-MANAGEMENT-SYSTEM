"""In-memory registry of running scan jobs, keyed by Scan.id.

Single-process only (fine for this app's dev/demo Flask server): each
entry holds the background thread and a ScanControl so an HTTP request
on a different thread (Pause/Resume/Stop) can reach the live job.
"""

import threading

from scanner.base import ScanControl

_lock = threading.Lock()
_jobs = {}


def register(scan_id: int, thread: threading.Thread, control: ScanControl):
    with _lock:
        _jobs[scan_id] = {"thread": thread, "control": control}


def get_control(scan_id: int):
    with _lock:
        entry = _jobs.get(scan_id)
        return entry["control"] if entry else None


def unregister(scan_id: int):
    with _lock:
        _jobs.pop(scan_id, None)


def running_count() -> int:
    with _lock:
        return sum(1 for entry in _jobs.values() if entry["thread"].is_alive())


def is_running(scan_id: int) -> bool:
    with _lock:
        entry = _jobs.get(scan_id)
        return bool(entry and entry["thread"].is_alive())
