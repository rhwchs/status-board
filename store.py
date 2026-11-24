"""Rolling history + baseline math.

Every numeric reading (headline counts, social post rates, aircraft counts) is
recorded here so a later reading can be judged against "what is normal for this
source", instead of against a guess. History persists to data/history.json so
baselines survive restarts.
"""
import json
import os
import statistics
import threading
import time
from collections import namedtuple

Rate = namedtuple("Rate", "sev baseline ratio n")

KEEP_SECONDS = 14 * 86400   # kept for 14 days; the baseline uses the last 7 once there is enough data
MIN_SAMPLES = 8        # samples needed before a 24h baseline is trusted
MIN_SAMPLES_LONG = 96   # readings needed (about a day) before the 7-day baseline replaces the 24h one
MIN_SAMPLES_HOUR = 3   # samples needed for a same-hour-of-day baseline


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.history = {}
        try:
            with open(path) as f:
                self.history = json.load(f)
        except (OSError, ValueError):
            self.history = {}
        self.extra = self.history.pop("_extra", {}) if isinstance(self.history, dict) else {}   # small state kept between runs

    def record(self, key, value, now=None, keep=None):
        now = now or time.time()
        with self.lock:
            h = self.history.setdefault(key, [])
            h.append([now, value])
            cutoff = now - (keep or KEEP_SECONDS)
            while h and h[0][0] < cutoff:
                h.pop(0)

    def baseline(self, key, same_hour=False, now=None):
        """Median of past readings, or (None, n) while still learning."""
        now = now or time.time()
        with self.lock:
            h = list(self.history.get(key, []))
        if same_hour:
            bucket = int(now // 3600) % 24
            vals = [v for t, v in h if int(t // 3600) % 24 == bucket and now - t > 600]
            need = MIN_SAMPLES_HOUR
        else:
            # A week is long enough that a busy news stretch cannot drag "normal" upward and hide the next spike.
            vals = [v for t, v in h if now - t < 7 * 86400]
            if len(vals) < MIN_SAMPLES_LONG:
                vals = [v for t, v in h if now - t < 86400]
            need = MIN_SAMPLES
        if len(vals) < need:
            return None, len(vals)
        return statistics.median(vals), len(vals)

    def usual(self, key, now=None, min_n=48, min_span=0):
        """What is 'normal' for a reading: (median, low, high, n) over the last 7 days (10th-90th percentile),
        or None while there is not enough history to say. min_span (seconds) makes it also require that the
        readings cover at least that much time, so a burst of runs in one hour cannot define a normal day."""
        now = now or time.time()
        with self.lock:
            pts = [(t, v) for t, v in self.history.get(key, []) if now - t < 7 * 86400]
        if len(pts) < min_n or (pts and max(t for t, _ in pts) - min(t for t, _ in pts) < min_span):
            return None
        vals = sorted(v for _, v in pts)
        pick = lambda q: vals[min(len(vals) - 1, int(q * len(vals)))]
        return statistics.median(vals), pick(0.1), pick(0.9), len(vals)

    def peak(self, key, secs=86400, now=None):
        now = now or time.time()
        with self.lock:
            vals = [v for t, v in self.history.get(key, []) if now - t < secs]
        return max(vals) if vals else None

    def rate_severity(self, key, value, abs_thresholds=None, min_count=5, same_hour=False):
        """Severity 0-3 from absolute thresholds and/or a spike versus baseline.

        abs_thresholds: ascending [t1, t2, t3]; value >= t_i adds a level.
        Spike rule (needs a learned baseline): value >= min_count and
        ratio >= 3 -> 1; ratio >= 6 and value >= 2*min_count -> 2.
        """
        base, n = self.baseline(key, same_hour=same_hour)
        ratio = None
        sev_abs = sum(1 for t in (abs_thresholds or []) if value >= t)
        sev_spike = 0
        if base is not None:
            ratio = value / max(base, 1.0)
            if value >= min_count and ratio >= 3:
                sev_spike = 1
            if value >= 2 * min_count and ratio >= 6:
                sev_spike = 2
        return Rate(max(sev_abs, sev_spike), base, ratio, n)

    def save(self):
        with self.lock:
            data = json.dumps({**self.history, "_extra": self.extra})
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, self.path)
        except OSError:
            pass
