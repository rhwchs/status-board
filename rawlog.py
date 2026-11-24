"""A compressed record of what every source reported, run by run, so REAL days can be replayed through new rules.

Hand-built replays can never tell you how noisy the real world is. This log can: each time a collector runs, one line is saved
with its signals (or its error). `replay_raw.py` feeds those lines back through the assessment on a simulated clock and reports how
often each rule would have raised the level and how many notifications would have been sent.

Files: data/raw/raw-YYYY-MM-DD.jsonl.gz (UTC days). Lines are buffered and written in batches (one gzip member per batch), and
files older than `keep_days` are deleted. It stays in data/, which is never published.
"""
import glob
import gzip
import json
import os
import threading
import time


class RawLog:
    def __init__(self, directory, keep_days=14, flush_every=60, enabled=True):
        self.dir, self.keep_days, self.flush_every, self.enabled = directory, keep_days, flush_every, enabled
        self.lock = threading.Lock()
        self.buf = []                      # [(day, json line)]
        self.last_flush = time.time()
        self.last_prune = 0.0
        if enabled:
            os.makedirs(directory, exist_ok=True)

    @staticmethod
    def _day(t):
        return time.strftime("%Y-%m-%d", time.gmtime(t))

    def write(self, t, name, kind, ok, error, secs, signals, metrics):
        """One collector run. signals: list of dicts (Signal.to_dict())."""
        if not self.enabled:
            return
        line = json.dumps({"t": round(t, 1), "name": name, "kind": kind, "ok": ok, "error": error or "", "secs": round(secs, 2),
                           "signals": signals, "metrics": metrics}, default=str, separators=(",", ":"))
        with self.lock:
            self.buf.append((self._day(t), line))
            full = len(self.buf) >= 300
        if full:
            self.flush()

    def maybe_flush(self, now=None):
        now = now or time.time()
        if now - self.last_flush >= self.flush_every:
            self.flush()
        if now - self.last_prune >= 6 * 3600:
            self.prune(now)

    def flush(self):
        if not self.enabled:
            return
        with self.lock:
            buf, self.buf = self.buf, []
            self.last_flush = time.time()
        by_day = {}
        for day, line in buf:
            by_day.setdefault(day, []).append(line)
        for day, lines in by_day.items():
            try:
                with gzip.open(os.path.join(self.dir, f"raw-{day}.jsonl.gz"), "at", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            except OSError:
                pass

    def prune(self, now=None):
        now = now or time.time()
        self.last_prune = now
        cutoff = self._day(now - self.keep_days * 86400)
        for p in glob.glob(os.path.join(self.dir, "raw-*.jsonl.gz")):
            day = os.path.basename(p)[4:14]
            if day < cutoff:
                try:
                    os.remove(p)
                except OSError:
                    pass

    def size_bytes(self):
        return sum(os.path.getsize(p) for p in glob.glob(os.path.join(self.dir, "raw-*.jsonl.gz")))


def read(directory, t_from=None, t_to=None):
    """Yield saved collector runs (dicts) in time order, optionally within [t_from, t_to]."""
    files = sorted(glob.glob(os.path.join(directory, "raw-*.jsonl.gz")))
    out = []
    for p in files:
        day = os.path.basename(p)[4:14]
        if t_from is not None and day < time.strftime("%Y-%m-%d", time.gmtime(t_from)):
            continue
        if t_to is not None and day > time.strftime("%Y-%m-%d", time.gmtime(t_to)):
            continue
        try:
            with gzip.open(p, "rt", encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if (t_from is None or e["t"] >= t_from) and (t_to is None or e["t"] <= t_to):
                        out.append(e)
        except (OSError, EOFError):
            continue                       # a file cut off mid-write: use what could be read
    out.sort(key=lambda e: e["t"])
    return out
