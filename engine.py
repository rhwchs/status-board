"""Scheduler, cross-domain correlation, and alerting."""
import copy
import json
import os
import re
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
import credibility
import rawlog
import slowburn
from store import Store
from story import tell

LEVELS = {0: "NORMAL", 1: "WATCH", 2: "ELEVATED", 3: "SUSPECTED ATTACK"}


# Official warnings with a footprint stay REGIONAL: full weight only in the views of the states they cover. Elsewhere, and
# in the nationwide view, a weather or natural-hazard warning counts for at most Watch, and a civil-danger-type warning
# for at most Concern. A warning that covers WIDE_STATES or more states, or whose own wording is explicitly
# national/strategic, is treated as national.
WIDE_STATES = 10
FEDERAL_SHARE = 2 / 3        # when this share of the dark sources are federal feeds, the lost-sight alarm reads as a shutdown
NATIONAL_RX = re.compile(r"missile|ballistic|nuclear (?:attack|strike|detonation|explosion|threat)|national emergency|"
                         r"presidential (?:alert|message)|nationwide|entire (?:country|nation)|all states", re.I)


def _regionalize(sigs, key):
    """Copies of the view's signals with regional official warnings weighted for viewer `key` ('all' or a state code)."""
    out = []
    for s in sigs:
        tags = set(s.tags or [])
        if "regional-only" in tags:             # a state-level feed (wildfire, co-op, roads): context outside its states
            if key in (s.states or []) or not s.states:
                out.append(s)
            else:
                c = copy.copy(s)
                c.severity, c.tags = 0, list(s.tags) + ["regional-elsewhere"]
                out.append(c)
            continue
        weather = s.category == "natural"
        if not (s.kind == "gov" and s.states and len(s.states) < WIDE_STATES
                and ({"official-hazard", "official-strategic"} & tags or weather)):
            out.append(s)
            continue
        text = " ".join([s.title or "", s.detail or ""] + [l.get("title", "") for l in (s.links or [])])
        if "official-strategic" in tags and NATIONAL_RX.search(text):
            out.append(s)                       # the government itself says it is a national / strategic threat
            continue
        inside = key in s.states
        c = copy.copy(s)
        c.tags, c.meta = [t for t in s.tags if t != "official-strategic"], dict(s.meta or {})
        c.meta["regional"] = sorted(s.states)
        if "official-strategic" in tags and inside:
            c.tags.append("official-danger-here")   # a civil danger warning for YOUR area: Likely event, not Confirmed
        if not inside:                              # someone else's warning: at most Watch (weather) or Concern here
            c.severity = min(c.severity, 1 if weather else 2)
            c.tags.append("regional-elsewhere")
        out.append(c)
    return out


def _step_name(level):
    """The page's step name for an engine level, for the change log (step 5 is never inferred here)."""
    from story import STEPS
    return f"Level {level + 1} {STEPS[level][0]}"
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
    cats: set = field(default_factory=set)   # areas this source has reported into (so a failing source still has a home)


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
        saved = (self.store.extra.get("mem") or {}) if time.time() - (self.store.extra.get("mem") or {}).get("saved_at", 0) < 1800 else {}
        self.memory = saved.get("all", {})          # onset tracking for the assessment (kept between runs of the phone version)
        self.view_mem = saved.get("views", {})      # the same, for each personal view (see _analyze)
        self._lost_since = None                     # when many sources were suddenly lost (None = not in that state)
        self._hi_since = None                       # when the level last rose to the alert threshold (None = below it)
        self._lo_since = None                       # when it last fell below it
        self._last_notify = -1e12
        self._sig_since, self._announced = {}, {}    # per official signal: when it appeared, and when it was last announced
        self._last_notified_level = 0
        rl = cfg.get("raw_log", {})
        self.raw = rawlog.RawLog(os.path.join(data_dir, "raw"), keep_days=rl.get("keep_days", 14),
                                 enabled=rl.get("enabled", True))     # what every source said, run by run (see rawlog.py)
        self.warmup = 75          # seconds of silence at start so existing conditions don't spam
        self._weak_rec = {}       # when the slow-burn readings were last saved, per view

    # ------------------------------------------------------------ scheduling
    def run_forever(self):
        pool = ThreadPoolExecutor(max_workers=8)
        news_pool = ThreadPoolExecutor(max_workers=1)         # news searches go one at a time so a wait never blocks the other sources
        os.environ.setdefault("NEWS_GAP", "12")          # seconds between Google searches (14 searches x 12 s fits inside 5 minutes)
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
                    (news_pool if c.kind == "news" else pool).submit(self._run, c, running)
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
                st.cats |= {x.category for x in res.signals}
                st.secs = time.time() - t0
            self.raw.write(t0, c.name, c.kind, True, "", st.secs, [x.to_dict() for x in res.signals], res.metrics)
        except Exception as e:  # a failed source is reported, never treated as "all clear"
            with self.lock:
                st = self.state[c.name]
                st.ok, st.last_run = False, t0
                st.error = f"{type(e).__name__}: {str(e)[:160]}"
                st.fails += 1
                st.secs = time.time() - t0
            self.raw.write(t0, c.name, c.kind, False, st.error, st.secs, [], {})
        finally:
            running.discard(c.name)
        self._analyze()

    # ----------------------------------------------------------- correlation
    def _empty_analysis(self):
        return {"level": 0, "label": "NORMAL", "reasons": ["Waiting for first data…"],
                "categories": {}, "blind": False}

    def _owner_state(self):
        """The state of the person running this monitor (from config 'local'), if known."""
        name = (self.cfg.get("local") or {}).get("name", "")
        tail = name.strip()[-2:].upper()
        return tail if len(name) > 2 and name[-3:-2] in (" ", ",") and tail.isalpha() else None

    @staticmethod
    def _reach(sigs, key):
        """Which signals can reach a person in view `key`: nationwide ones, plus ones whose footprint includes their state.
        'all' = anywhere in the US; 'elsewhere' = a state with no regional event of its own."""
        if key == "all":
            return list(sigs)
        if key == "elsewhere":
            return [s for s in sigs if not s.states]
        return [s for s in sigs if not s.states or key in s.states]

    def _analyze(self):
        from collectors import Signal
        now = time.time()
        with self.lock:
            ok_n = fail_n = 0
            down = []                 # every source currently failing, whether or not it ever worked
            canary_ok = True
            world, all_sigs, recent_fail = [], [], 0
            limited = []              # sources that are rate-limited or blocked: reported, but not a sign that the world went dark
            for c in self.collectors:
                st = self.state[c.name]
                if c.kind == "system":
                    canary_ok = st.ok is not False
                    continue
                if st.ok is None:
                    continue
                if st.ok is False and st.error.startswith(("RuntimeError: Throttled", "RuntimeError: Limited")):
                    limited.append(c.name)
                    if st.last_ok and now - st.last_ok <= max(3 * c.interval, 900):
                        for s in st.signals:
                            (world if s.category == "world" else all_sigs).append(s)
                    continue
                if st.ok is False:
                    down.append(c.name)
                if st.ok:
                    ok_n += 1
                elif st.last_ok:
                    fail_n += 1   # worked before, failing now
                    recent_fail += 1 if now - st.last_ok < 1200 else 0
                if not st.last_ok or now - st.last_ok > max(3 * c.interval, 900):
                    continue      # stale data is dropped rather than shown as current
                for s in st.signals:
                    (world if s.category == "world" else all_sigs).append(s)   # overseas context never joins the alert scale
            # many previously-working sources failing while our own connection works
            if canary_ok and (ok_n + fail_n) >= 6 and fail_n / (ok_n + fail_n) >= 0.5:
                all_sigs.append(Signal(
                    "internet", 1, f"{fail_n} of {ok_n + fail_n} sources cannot be reached even though "
                    "your own internet works", key="sys:blind", kind="system", source="Monitor self-check"))
            total = sum(1 for c in self.collectors if c.kind != "system" and self.state[c.name].ok is not None and c.name not in limited)
            blind = (not canary_ok) or (total >= 5 and ok_n < total / 2)
            # Many sources that WERE working all failing within minutes while our own connection is fine is itself a warning
            # (it is what a big outage or an attack on the net would look like): keep alarmed instead of going quiet.
            lost_suddenly = blind and canary_ok and fail_n >= 6 and recent_fail >= 0.7 * fail_n
            if lost_suddenly and self._lost_since is None:
                self._lost_since = now
            elif not blind:
                self._lost_since = None          # the sources came back: stand down
            # A blip in OUR OWN connection does not clear it: while it lasts the page says our internet is down, and once it is
            # back, sources that are still unreachable are the same outage (their failures are now old, so it would not re-trigger).
            lost_suddenly = lost_suddenly or (blind and canary_ok and self._lost_since is not None)   # and stay alarmed while they stay down

            # Personal views: one for the whole US, plus one per state that has an event of its own (see _reach).
            regional = sorted({st for s in all_sigs if s.category != "local" and s.severity >= 1 for st in s.states})
            keys = ["all"] + (["elsewhere"] + regional if regional else [])
            owner = self._owner_state()
            built = {k: self._view(k, self._reach(all_sigs, k), now, ok_n, total, down, blind, lost_suddenly, fail_n, world)
                     for k in keys}
            main = built["all"]
            self.analysis = dict(main["analysis"])
            self.analysis["limited"] = limited
            self.analysis["views"] = {k: {"label": v["analysis"]["label"], "level": v["analysis"]["level"],
                                          "score": v["analysis"]["score"], "story": v["analysis"]["story"],
                                          "rules": v["analysis"]["assessment"].get("rules", [])}
                                      for k, v in built.items()}
            self.analysis["owner_view"] = owner if owner in built else ("elsewhere" if "elsewhere" in built else "all")
            ov = built[self.analysis["owner_view"]]
            mem = {"all": self.memory, "views": self.view_mem, "saved_at": now}
            self.store.extra["mem"] = mem
            self._alert(ov["analysis"]["level"], main["cats"], now, ov["analysis"]["assessment"]["verdict"], ov["analysis"])

    def _is_federal(self, name):
        """A source run by the US federal government (its own .gov site)."""
        c = next((c for c in self.collectors if c.name == name), None)
        host = re.sub(r"^https?://", "", (getattr(c, "home", "") or "")).split("/")[0].lower()
        return bool(c) and (host.endswith(".gov") or (c.kind == "gov" and not host))

    def _view(self, key, sigs, now, ok_n, total, down, blind, lost_suddenly, fail_n, world):
        """Everything for one personal view: category levels, the assessment, the story and the score."""
        cats = {k: {"label": v, "level": 0, "signals": [], "kinds": set()} for k, v in CATEGORIES.items()}
        for s in _regionalize(sigs, key):
            cats[s.category]["signals"].append(s)
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
        for k, cl in credibility.check_social(nat, self.cfg, now).items():   # score the claims that are spreading
            nat[k]["claims"] = cl
        ns = "" if key == "all" else key
        mem = self.memory if key == "all" else self.view_mem.setdefault(key, {})

        def slow_fn(explained_labels):
            ev = slowburn.evidence(nat, explained_labels)
            if (now - self.started) >= self.warmup and now - self._weak_rec.get(key, 0) >= slowburn.SAMPLE_EVERY:
                self._weak_rec[key] = now
                slowburn.record(self.store, ev, now, ns)
            return slowburn.evaluate(self.store, ev, now, ns)

        res = assess(nat, mem, self.cfg.get("assessment", {}), now, slow_fn=slow_fn)
        level, reasons = res["level"], list(res["reasons"])
        if down:
            names = ", ".join(n.replace("News: ", "news: ") for n in down[:3]) + ("…" if len(down) > 3 else "")
            reasons.append(f"Heads up: {len(down)} source(s) are not working right now ({names}). "
                           "A quiet result means less while they are down.")
        chatter = [c["label"] for c in cats.values() if c.get("social_only")]
        if chatter:
            reasons.append("Social media is talking about " + ", ".join(chatter[:3]) + ", but no news outlet, "
                           "government source or status page backs it up. Treated as a hint only.")
        if lost_suddenly:
            fed = [n for n in down if self._is_federal(n)]
            mostly_fed = len(down) > 0 and len(fed) >= FEDERAL_SHARE * len(down)
            since = time.strftime("%H:%M", time.localtime(self._lost_since or now))
            if mostly_fed:      # government websites going dark together looks like a shutdown or a federal outage
                level = max(level, 1)
                res.setdefault("rules", []).append("lost sight of many sources at once (mostly federal)")
                reasons.insert(0, f"Lost sight of {fail_n} sources at {since}, mostly federal government feeds ({len(fed)} of "
                                  f"{len(down)}), while your own internet works. That usually means a government shutdown "
                                  "or a federal website outage rather than a wider failure: check for yourself.")
            else:
                level = max(level, 2)
                res.setdefault("rules", []).append("lost sight of many sources at once")
                reasons.insert(0, f"Lost sight of {fail_n} sources within minutes of each other at {since} while your own internet works"
                                  + ("" if now - (self._lost_since or now) < 600 else " (still down)")
                                  + ". That can be a big outage or attack, or a fault on this end: check for yourself.")
        elif blind:
            reasons.insert(0, f"Only {ok_n} of {total} sources are reachable, so the real status is unknown. This is NOT an all-clear.")
            level = 0
        out = {}
        for k, c in cats.items():
            out[k] = {"label": c["label"], "level": c["level"], "kinds": sorted(c["kinds"]),
                      "corroborated": c.get("corroborated", False), "claims": c.get("claims", [])[:3],
                      "signals": [s.to_dict() for s in c["signals"]]}
        label = "NO DATA" if (blind and level == 0) else LEVELS[level]
        res["level"] = level
        analysis = {"level": level, "label": label, "reasons": reasons, "categories": out, "blind": blind,
                    "ok": ok_n, "failing": len(down), "assessment": res,
                    "story": tell(label, res, nat, ok_n, total, len(down), down,
                                  cats.get("local"), self.cfg.get("local"), world)}
        analysis["score"] = self._score(label, nat, res, now, record=(key == "all"))
        return {"analysis": analysis, "cats": cats}

    def _score(self, label, nat, res, now, record=True):
        """The 0-100 gauge, plus what a normal day looks like here (median of the last 7 days)."""
        sc = compute_score(label, nat, res)
        if sc is None:
            return {"value": None, "band": "NO DATA"}
        # Record one reading per 5 minutes, but not during start-up or blind spells, so "normal" stays honest.
        if record and (now - self.started) >= self.warmup and now - getattr(self, "_score_rec", 0) >= 300:
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

    def _alert(self, level, cats, now, verdict="", analysis=None):
        """Log new signals, and notify when the level (for the person running this monitor) has HELD at the threshold.
        A notification needs the level to stay up for notify.hold_seconds (default 5 minutes) so a flicker never sends one,
        and the same level will not notify again within notify.cooldown_seconds (default 1 hour); a HIGHER level always
        can. The alert re-arms only after the level has stayed below the threshold for 15 minutes."""
        warming = (now - self.started) < self.warmup
        n = self.cfg["notify"]
        hold, cooldown = n.get("hold_seconds", 300), n.get("cooldown_seconds", 3600)
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
                    # a single official signal is announced once it has held for `hold` seconds, and not again within `cooldown`
                    since = self._sig_since.setdefault(s.key, now)
                    if now - since >= hold and now - self._announced.get(s.key, -1e12) >= cooldown:
                        self._announced[s.key] = now
                        to_announce.append(s)
        for k in [k for k in self.seen if k not in live_keys]:
            del self.seen[k]
        for k in [k for k in self._sig_since if k not in live_keys]:
            del self._sig_since[k]
        if level != self.last_level:
            self._log(f"Overall level changed: {_step_name(self.last_level)} → {_step_name(level)}", level)
            self.last_level = level
        min_level = n.get("min_level", 2)
        if warming:
            return
        if level >= min_level:
            self._lo_since = None
            if self._hi_since is None:
                self._hi_since = now
            if now - self._hi_since >= hold and level > self.level_notified and \
                    (now - self._last_notify >= cooldown or level > self._last_notified_level):
                sc = ((analysis or {}).get("story") or {}).get("scale") or {}
                name = f"{sc.get('step', '')} {sc.get('name', LEVELS[level])}".strip()
                top = verdict or ", ".join(CATEGORIES[k] for k, c in cats.items() if c["level"] >= 2)
                self._notify(f"Probably Fine: {name}", top, urgent=(level >= 3))
                self._record_notification("level", f"Probably Fine: {name}", top, level, analysis, now - self._hi_since)
                self._log(f"Notified: {name} (held {int(now - self._hi_since)}s)", level)
                self.level_notified = self._last_notified_level = level
                self._last_notify = now
        else:
            self._hi_since = None
            if self._lo_since is None:
                self._lo_since = now
            if now - self._lo_since >= 900:
                self.level_notified = 0          # re-arm only after a quarter hour of calm
        if level < self.level_notified and level >= min_level:
            self.level_notified = level
        for s in to_announce[:3]:
            self._notify(f"{s.source}: {'CRITICAL' if s.severity >= 3 else 'serious'} signal", s.title, urgent=(s.severity >= 3))
            self._record_notification("signal", f"{s.source}: {'CRITICAL' if s.severity >= 3 else 'serious'} signal", s.title,
                                      level, analysis, hold)

    def _record_notification(self, kind, title, body, level, analysis, held=0):
        """Every notification, with the rules that caused it (data/notifications.jsonl): the way to count false alarms."""
        a = analysis or {}
        entry = {"t": time.time(), "kind": kind, "title": title, "body": body[:240], "level": level,
                 "step": ((a.get("story") or {}).get("scale") or {}).get("step"), "held_s": int(held),
                 "rules": (a.get("assessment") or {}).get("rules", []), "view": self.analysis.get("owner_view") if self.analysis else None}
        try:
            with open(os.path.join(self.data_dir, "notifications.jsonl"), "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

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
                                "error": st.error, "metrics": st.metrics, "secs": round(st.secs, 1), "cats": sorted(st.cats)})
            return {"now": now, "started": self.started, "analysis": self.analysis, "sources": sources,
                    "log": list(self.log)[:60]}
