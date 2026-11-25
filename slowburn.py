"""Slow-burn detector: several DIFFERENT things going a little wrong together, for hours.

A loud attack is easy to see. A subtler or more spread-out one (several systems degraded a bit at once, none bad
enough to trip an alarm on its own) is not, and that is exactly when piecing it together early matters. The
assessment in assess.py looks at the NOW and at essential services failing within minutes of each other. This module
looks at the last several hours: how many independent areas have shown credible, sustained signs of trouble.

How it works
  * each analysis computes an EVIDENCE number per area: severity x trust of who is saying it
    (government or live telemetry 1.0, several top-tier news outlets 0.85, other news 0.4, social 0.1);
  * a reading per area is saved about every 5 minutes (in the same history file as everything else, so it survives
    between runs of the phone version);
  * an area is "sustained" when it has stayed above a threshold for at least 45 minutes without a long gap;
  * areas that a storm, a solar storm, a cascade or a vendor failure already explains are left out, and so are
    social media (never evidence on its own), the stock market (counts at 60%: markets fall for ordinary reasons)
    and weather/space themselves (they are explanations, not threats).

Rule: three or more areas sustained at the "strong" level, or four at the "weak" level including at least one
strong, raises the alert to ELEVATED. It can never produce SUSPECTED ATTACK by itself: it says "this is unusual and
growing, go look", not "this is an attack". Every number is in the reasons the dashboard shows.
"""
from collectors import CATEGORIES
from trust import credible as news_credible

SKIP = {"elite", "local", "space", "natural", "roads"}
SEV_F = {1: 0.5, 2: 1.0, 3: 1.5}
KIND_F = {"gov": 1.0, "private": 1.0, "news": 0.4, "social": 0.1, "system": 0.0}
CREDIBLE_NEWS_F = 0.85
MARKETS_F = 0.6
STRONG, WEAK = 0.8, 0.5
MIN_POINTS, MIN_SPAN = 3, 45 * 60       # a run of readings this long counts as "sustained"
MAX_GAP = 90 * 60                       # a longer silence breaks the run (the monitor was not looking)
WINDOW = 12 * 3600
SAMPLE_EVERY = 300                      # seconds between saved readings
KEEP = 2 * 86400                        # these readings are only needed for a day or two
_KEY = {v: k for k, v in CATEGORIES.items()}


def evidence(cats, explained_labels=()):
    """{area: evidence 0..1.5} for the current signals. cats: national categories as built by the engine."""
    explained = {_KEY.get(lbl, lbl) for lbl in explained_labels}
    out = {}
    for k, c in cats.items():
        if k in SKIP:
            continue
        best = 0.0
        if k not in explained:
            for s in c["signals"]:
                if s.severity < 1:
                    continue
                f = KIND_F.get(s.kind, 0.4)
                if s.kind == "news" and news_credible(getattr(s, "meta", None)):
                    f = CREDIBLE_NEWS_F
                best = max(best, SEV_F.get(min(3, s.severity), 1.5) * f)
            if k == "markets":
                best *= MARKETS_F
        out[k] = round(best, 2)
    return out


def _key(ns, area):
    return "weak:" + (ns + ":" if ns else "") + area


def record(store, ev, now, ns=""):
    """Save one reading per area (zeros included, so a quiet spell visibly breaks a run). ns = which view (a state)."""
    for k, v in ev.items():
        store.record(_key(ns, k), v, now, keep=KEEP)


def _run(pts, thr, now):
    """Trailing run of readings >= thr ending now: (count, span_seconds). pts: [[t, v], ...] oldest first."""
    run = []
    for t, v in reversed(pts):
        if now - t > WINDOW or v < thr:
            break
        if run and run[-1][0] - t > MAX_GAP:
            break
        run.append((t, v))
    if not run or now - run[0][0] > MAX_GAP:
        return 0, 0
    return len(run), run[0][0] - run[-1][0]


def evaluate(store, ev, now, ns=""):
    """Decide whether a slow burn is under way. ev: the CURRENT evidence (counted as the newest reading)."""
    sustained = {}
    for k, v in ev.items():
        with store.lock:
            pts = [p for p in store.history.get(_key(ns, k), []) if now - p[0] <= WINDOW]
        pts = pts + [[now, v]]
        for tag, thr in (("strong", STRONG), ("weak", WEAK)):
            n, span = _run(pts, thr, now)
            if n >= MIN_POINTS and span >= MIN_SPAN:
                sustained.setdefault(k, {"level": tag, "hours": round(span / 3600, 1), "evidence": v})
                break
    strong = [k for k, d in sustained.items() if d["level"] == "strong"]
    active = len(strong) >= 3 or (len(sustained) >= 4 and len(strong) >= 1)
    out = {"active": active, "areas": [{"key": k, "label": CATEGORIES[k], **d} for k, d in
                                       sorted(sustained.items(), key=lambda kv: -kv[1]["evidence"])],
           "n_strong": len(strong), "n_sustained": len(sustained), "why": ""}
    if active:
        names = ", ".join(a["label"] for a in out["areas"][:5])
        out["why"] = (f"Slow burn: {len(sustained)} different areas ({names}) have each shown credible signs of trouble "
                      f"for {max(a['hours'] for a in out['areas']):g}+ hours. None is dramatic alone, but this many at once is unusual.")
    return out
