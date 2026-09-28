import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import psutil


@dataclass
class ScannerResult:
    success: bool
    source: str  # "real" or "mock"
    data: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    stopped: bool = False


class BaseScanner:
    """Common interface for all scanner integrations.

    Subclasses implement `binary_name`, `build_command(target)`,
    `parse_output(raw_output, target)`, and `mock_result(target)`.
    Real invocation always uses subprocess.Popen with shell=False and an
    explicit argument list -- never a shell string -- to prevent
    command injection. Popen (rather than the simpler subprocess.run) is
    used deliberately so a running scan exposes an OS process that a
    ScanControl can suspend/resume/terminate for real pause and stop
    support instead of only cooperating between pipeline stages.
    """

    binary_name = ""
    timeout_seconds = 60

    def is_available(self) -> bool:
        return shutil.which(self.binary_name) is not None

    def build_command(self, target: str) -> List[str]:
        raise NotImplementedError

    def parse_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def mock_result(self, target: str) -> ScannerResult:
        raise NotImplementedError

    def run(self, target: str, control: Optional["ScanControl"] = None) -> ScannerResult:
        if not self.is_available():
            return self.mock_result(target)

        if control and control.stop_requested():
            return ScannerResult(success=False, source="real", stopped=True, error="Stopped before start.")

        command = self.build_command(target)
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            return ScannerResult(success=False, source="real", error=str(exc))

        if control:
            control.attach_process(process.pid)

        deadline = time.monotonic() + self.timeout_seconds
        while process.poll() is None:
            if control and control.stop_requested():
                _kill_process_tree(process.pid)
                process.wait(timeout=5)
                if control:
                    control.detach_process()
                return ScannerResult(success=False, source="real", stopped=True, error="Stopped by user.")
            if time.monotonic() > deadline:
                _kill_process_tree(process.pid)
                process.wait(timeout=5)
                if control:
                    control.detach_process()
                return ScannerResult(success=False, source="real", error=f"Timed out after {self.timeout_seconds}s.")
            time.sleep(0.3)

        stdout, stderr = process.communicate()
        if control:
            control.detach_process()

        if process.returncode != 0 and not stdout:
            return ScannerResult(success=False, source="real", error=stderr)

        data = self.parse_output(stdout, target)
        return ScannerResult(success=True, source="real", data=data, raw_output=stdout)


def _kill_process_tree(pid: int):
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    for child in parent.children(recursive=True):
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    try:
        parent.terminate()
    except psutil.NoSuchProcess:
        pass


class ScanControl:
    """Shared control surface for one running scan job.

    Lets an HTTP request (Pause/Resume/Stop) reach across threads into
    whatever OS process the scan is currently running, using psutil's
    suspend/resume (NtSuspendProcess on Windows, SIGSTOP on POSIX) for a
    real pause rather than just gating between pipeline stages.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._pid = None
        self._paused_at = None
        self._paused_total = 0.0

    def attach_process(self, pid: int):
        with self._lock:
            self._pid = pid
            if self._paused.is_set():
                self._suspend_pid(pid)

    def detach_process(self):
        with self._lock:
            self._pid = None

    def stop_requested(self) -> bool:
        return self._stop.is_set()

    def request_stop(self):
        self._stop.set()
        with self._lock:
            if self._pid:
                _kill_process_tree(self._pid)

    def request_pause(self):
        self._paused.set()
        with self._lock:
            if self._paused_at is None:
                self._paused_at = time.monotonic()
            if self._pid:
                self._suspend_pid(self._pid)

    def request_resume(self):
        self._paused.clear()
        with self._lock:
            if self._paused_at is not None:
                self._paused_total += time.monotonic() - self._paused_at
                self._paused_at = None
            if self._pid:
                self._resume_pid(self._pid)

    def is_paused(self) -> bool:
        return self._paused.is_set()

    def paused_seconds(self) -> float:
        """Total time spent paused so far, including a pause that is still going on."""
        with self._lock:
            ongoing = time.monotonic() - self._paused_at if self._paused_at is not None else 0.0
            return self._paused_total + ongoing

    def wait_if_paused(self):
        while self._paused.is_set() and not self._stop.is_set():
            time.sleep(0.25)

    @staticmethod
    def _suspend_pid(pid: int):
        try:
            psutil.Process(pid).suspend()
        except psutil.NoSuchProcess:
            pass

    @staticmethod
    def _resume_pid(pid: int):
        try:
            psutil.Process(pid).resume()
        except psutil.NoSuchProcess:
            pass
