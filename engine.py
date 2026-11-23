"""Scheduler, cross-domain correlation, and alerting."""
import json
import os
import platform
import random
import subprocess
import threading
import time
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from assess import assess
from collectors import CATEGORIES, build_collectors
from score import compute as compute_score
from store import Store
from story import tell

LEVELS = {0: "NORMAL", 1: "WATCH", 2: "ELEVATED", 3: "SUSPECTED ATTACK"}
OFFICIAL = ("gov", "private")


@dataclass
class RunState:
    ok: object = None            # None = never run, True/False = last result
    last_run: float = 0
    last_ok: float = 0
    error: str = ""
    metrics: dict = field(default_factory=dict)
    signals: list = field(default_factory=list)
    secs: float = 0
    fails: int = 0


class Ctx:
    def __init__(self, store, cfg):
        self.store, self.cfg = store, cfg


class Monitor:
    def __init__(self, cfg, data_dir):
        self.cfg = cfg
        self.data_dir = data_dir
        self.store = Store(os.path.join(data_dir, "history.json"))
        self.ctx = Ctx(self.store, cfg)
        self.collectors = build_collectors(cfg, data_dir)
        self.state = {c.name: RunState() for c in self.collectors}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.started = time.time()
        self.log = deque(maxlen=150)
        self.seen = {}            # signal key -> highest severity already announced
        self.last_level = 0
        self.level_notified = 0
        self.analysis = self._empty_analysis()
        self.memory = {}          # onset tracking for the scenario assessment
        self.warmup = 75          # seconds of silence at start so existing conditions don't spam

    # ------------------------------------------------------------ scheduling
    def run_forever(self):
        pool = ThreadPoolExecutor(max_workers=8)
        now = time.time()
        due, n_news = {}, 0
        for i, c in enumerate(self.collectors):
            if c.kind == "news":                  # spread news queries out; a burst gets us rate-limited
                due[c.name] = now + 3 + n_news * 8
                n_news += 1
            else:
                due[c.name] = now + i * 0.7
        running, last_save = set(), now
        while not self.stop.is_set():
            now = time.time()
            for c in self.collectors:
                if c.name not in running and due[c.name] <= now:
                    running.add(c.name)
                    due[c.name] = now + c.interval + random.uniform(0, 5)
                    pool.submit(self._run, c, running)
            if now - last_save > 300:
                self.store.save()
                last_save = now
            self.stop.wait(1)
        self.store.save()

    def run_once(self):
        """Run every collector once (used by --once)."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda c: self._run(c, set()), self.collectors))
        self.warmup = 0

    def run_snapshot(self):
        """Run every source once (for the one-command snapshot). News queries are spaced out so Google does not
        throttle a burst, then everything is analysed together."""
        self.snapshot_mode = True
        news = [c for c in self.collectors if c.kind == "news"]
        rest = [c for c in self.collectors if c.kind != "news"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(self._run, c, set()) for c in rest]
            for c in news:
                futs.append(pool.submit(self._run, c, set()))
                time.sleep(float(os.environ.get("NEWS_GAP", "1.5")) * random.uniform(0.8, 1.25))   # slower on shared servers
            for f in futs:
                f.result()
        self.warmup = 0
        self._score_rec = 0
        self._analyze()

    def _run(self, c, running):
        t0 = time.time()
        try:
            res = c.fn(self.ctx)
            for s in res.signals:
                s.source, s.kind = c.name, c.kind
            with self.lock:
                st = self.state[c.name]
                st.ok, st.last_run, st.last_ok = True, t0, time.time()
                st.error, st.fails = "", 0
                st.metrics, st.signals = res.metrics, res.signals
                st.secs = time.time() - t0
        except Exception as e:  # a failed source is reported, never treated as "all clear"
            with self.lock:
                st = self.state[c.name]
                st.ok, st.last_run = False, t0
                st.error = f"{type(e).__name__}: {str(e)[:160]}"
                st.fails += 1
                st.secs = time.time() - t0
        finally:
            running.discard(c.name)
        self._analyze()

    # ----------------------------------------------------------- correlation
    def _empty_analysis(self):
        return {"level": 0, "label": "NORMAL", "reasons": ["Waiting for first data…"],
                "categories": {}, "blind": False}

    def _analyze(self):
        from collectors import Signal
        now = time.time()
        with self.lock:
            cats = {k: {"label": v, "level": 0, "signals": [], "kinds": set()} for k, v in CATEGORIES.items()}
            ok_n = fail_n = 0
            down = []                 # every source currently failing, whether or not it ever worked
            canary_ok = True
            for c in self.collectors:
                st = self.state[c.name]
                if c.kind == "system":
                    canary_ok = st.ok is not False
                    continue
                if st.ok is None:
                    continue
                if st.ok is False:
                    down.append(c.name)
                if st.ok:
                    ok_n += 1
                elif st.last_ok:
                    fail_n += 1   # worked before, failing now
                if not st.last_ok or now - st.last_ok > max(3 * c.interval, 900):
                    continue      # stale data is dropped rather than shown as current
                for s in st.signals:
                    cats[s.category]["signals"].append(s)
            # many previously-working sources failing while our own connection works
            if canary_ok and (ok_n + fail_n) >= 6 and fail_n / (ok_n + fail_n) >= 0.5:
                cats["internet"]["signals"].append(Signal(
                    "internet", 1, f"{fail_n} of {ok_n + fail_n} sources cannot be reached even though "
                    "your own internet works", key="sys:blind", kind="system", source="Monitor self-check"))

            for k, c in cats.items():
                c["signals"].sort(key=lambda s: (-s.severity, -s.time))
                # Social media is a HINT, not evidence: anyone (including an adversary) can post. It is shown
                # and it can raise a domain to WATCH, but it can never push a domain higher on its own.
                hard = [s for s in c["signals"] if s.kind != "social"]
                c["level"] = max([s.severity for s in hard] or [0])
                c["kinds"] = {s.kind for s in c["signals"] if s.severity >= 1 and s.kind != "system"}
                c["hard_kinds"] = {k for k in c["kinds"] if k != "social"}
                if c["level"] == 0 and any(s.severity >= 1 for s in c["signals"] if s.kind == "social"):
                    c["level"] = 1
                    c["social_only"] = True
                if c["level"] < 2 and len(c["hard_kinds"]) >= 3:
                    c["level"] = 2   # government, private and news sources all pointing at the same domain
                    c["corroborated"] = True

            # Scenario assessment: independence, simultaneity, benign explanations, primary-source evidence.
            nat = {k: v for k, v in cats.items() if k != "local"}   # your county never feeds the national alarm
            res = assess(nat, self.memory, self.cfg.get("assessment", {}), now)
            level, reasons = res["level"], list(res["reasons"])
            if down:
                names = ", ".join(n.replace("News: ", "news: ") for n in down[:3]) + ("…" if len(down) > 3 else "")
                reasons.append(f"Heads up: {len(down)} source(s) are not working right now ({names}). "
                               "A quiet result means less while they are down.")
            chatter = [c["label"] for c in cats.values() if c.get("social_only")]
            if chatter:
                reasons.append("Social media is talking about " + ", ".join(chatter[:3]) + ", but no news outlet, "
                               "government source or status page backs it up. Treated as a hint only.")
            total = sum(1 for c in self.collectors if c.kind != "system" and self.state[c.name].ok is not None)
            blind = (not canary_ok) or (total >= 5 and ok_n < total / 2)
            if not canary_ok:
                reasons.insert(0, "Your internet connection seems to be down, so this monitor cannot see anything right now.")
            elif blind:
                reasons.insert(0, f"Only {ok_n} of {total} sources are reachable, so the real status is unknown. This is NOT an all-clear.")
                level = 0

            out = {}
            for k, c in cats.items():
                out[k] = {"label": c["label"], "level": c["level"], "kinds": sorted(c["kinds"]),
                          "corroborated": c.get("corroborated", False),
                          "signals": [s.to_dict() for s in c["signals"]]}
            label = "NO DATA" if (blind and level == 0) else LEVELS[level]
            self.analysis = {"level": level, "label": label, "reasons": reasons,
                             "categories": out, "blind": blind, "ok": ok_n, "failing": len(down),
                             "assessment": res,
                             "story": tell(label, res, nat, ok_n, total, len(down), down,
                                          cats.get("local"), self.cfg.get("local"))}
            self.analysis["score"] = self._score(label, nat, res, now)
            self._alert(level, cats, now, res["verdict"])

    def _score(self, label, nat, res, now):
        """The 0-100 gauge, plus what a normal day looks like here (median of the last 7 days)."""
        sc = compute_score(label, nat, res)
        if sc is None:
            return {"value": None, "band": "NO DATA"}
        # Record one reading per 5 minutes, but not during start-up or blind spells, so "normal" stays honest.
        if (now - self.started) >= self.warmup and now - getattr(self, "_score_rec", 0) >= 300:
            self._score_rec = now
            self.store.record("score", sc["value"], now)
        # A snapshot run only adds one reading per run, so it needs fewer readings but must span at least a day.
        u = (self.store.usual("score", now, min_n=8, min_span=86400) if getattr(self, "snapshot_mode", False)
             else self.store.usual("score", now))
        sc["usual"] = None if u is None else {"median": round(u[0]), "low": round(u[1]), "high": round(u[2])}
        pk = self.store.peak("score", 86400, now)
        sc["peak24"] = None if pk is None else max(pk, sc["value"])
        return sc

    # --------------------------------------------------------------- alerting
    def _log(self, text, level=None):
        entry = {"t": time.time(), "text": text, "level": level}
        self.log.appendleft(entry)
        try:
            with open(os.path.join(self.data_dir, "events.jsonl"), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _alert(self, level, cats, now, verdict=""):
        warming = (now - self.started) < self.warmup
        live_keys, to_announce = set(), []
        for c in cats.values():
            for s in c["signals"]:
                if s.severity < 1 or not s.key:
                    continue
                live_keys.add(s.key)
                prev = self.seen.get(s.key, 0)
                if s.severity > prev:
                    self.seen[s.key] = s.severity
                    self._log(f"[{CATEGORIES[s.category]}] {s.title}", s.severity)
                    if s.severity >= 2 and s.kind in OFFICIAL and not warming:
                        to_announce.append(s)
        for k in [k for k in self.seen if k not in live_keys]:
            del self.seen[k]
        if level != self.last_level:
            self._log(f"Overall alert level changed: {LEVELS[self.last_level]} → {LEVELS[level]}", level)
            self.last_level = level
        min_level = self.cfg["notify"].get("min_level", 2)
        if not warming:
            if level >= min_level and level > self.level_notified:
                top = verdict or ", ".join(CATEGORIES[k] for k, c in cats.items() if c["level"] >= 2)
                self._notify(f"Status board: {LEVELS[level]}", top, urgent=(level >= 3))
                self.level_notified = level
            elif level < min_level:
                self.level_notified = 0          # re-arm once things calm down
            elif level < self.level_notified:
                self.level_notified = level
            for s in to_announce[:3]:
                self._notify(f"{s.source}: {'CRITICAL' if s.severity >= 3 else 'serious'} signal", s.title, urgent=(s.severity >= 3))

    def _notify(self, title, body, urgent=False):
        threading.Thread(target=self._notify_now, args=(title, body, urgent), daemon=True).start()

    def _notify_now(self, title, body, urgent):
        n = self.cfg["notify"]
        if n.get("macos") and platform.system() == "Darwin":
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            snd = ' sound name "Sosumi"' if n.get("sound") else ""
            try:
                subprocess.run(["osascript", "-e",
                                f'display notification "{esc(body[:200])}" with title "{esc(title)}"{snd}'],
                               timeout=10, check=False)
            except Exception:
                pass
        if n.get("ntfy_topic"):
            try:
                req = urllib.request.Request(
                    f"{n.get('ntfy_server', 'https://ntfy.sh').rstrip('/')}/{n['ntfy_topic']}",
                    data=body.encode("utf-8"), method="POST",
                    headers={"Title": title.encode("ascii", "replace").decode(),
                             "Priority": "5" if urgent else "4", "Tags": "rotating_light"})
                if self.cfg.get("dashboard_url"):
                    req.add_header("Click", self.cfg["dashboard_url"])
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as e:
                self._log(f"ntfy push failed: {e}")

    # -------------------------------------------------------------- reporting
    def snapshot(self):
        with self.lock:
            now = time.time()
            sources = []
            for c in self.collectors:
                st = self.state[c.name]
                sources.append({"name": c.name, "kind": c.kind, "home": c.home, "interval": c.interval,
                                "ok": st.ok, "last_ok": st.last_ok, "last_run": st.last_run,
                                "error": st.error, "metrics": st.metrics, "secs": round(st.secs, 1)})
            return {"now": now, "started": self.started, "analysis": self.analysis, "sources": sources,
                    "log": list(self.log)[:60]}
