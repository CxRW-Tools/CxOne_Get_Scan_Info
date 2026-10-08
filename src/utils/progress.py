"""stderr progress reporting: done/total, rate, ETA."""
import sys
import threading
import time


class Progress:
    def __init__(self, total, label="scans", stream=None, enabled=True, interval=2.0):
        self.total = total
        self.label = label
        self.stream = stream or sys.stderr
        self.enabled = enabled and total > 0
        self.interval = interval
        self.done = 0
        self.start = time.monotonic()
        self._last = 0.0
        self._lock = threading.Lock()
        self._tty = hasattr(self.stream, "isatty") and self.stream.isatty()

    def tick(self, n=1):
        with self._lock:
            self.done += n
            now = time.monotonic()
            if self.enabled and (now - self._last >= self.interval or self.done >= self.total):
                self._last = now
                self._emit(now)

    def _emit(self, now):
        elapsed = max(now - self.start, 1e-9)
        rate = self.done / elapsed
        eta = (self.total - self.done) / rate if rate > 0 else 0
        msg = f"[{self.done}/{self.total} {self.label}] {rate:.1f}/s ETA {int(eta // 60)}m{int(eta % 60):02d}s"
        if self._tty:
            self.stream.write("\r" + msg + " " * 4 + ("\n" if self.done >= self.total else ""))
        else:
            self.stream.write(msg + "\n")
        self.stream.flush()
