#!/usr/bin/env python3
"""One command: check every source once, then show the result. No server, no hosting, works on any computer with Python 3.

    python3 snapshot.py              check everything, save snapshot.html, open it in your browser
    python3 snapshot.py --no-open    same, but only print the summary and save the page
    python3 snapshot.py --out FILE   save the page somewhere else

The saved page is a self-contained copy of the dashboard (score, plain-English message, "Near you", every source link).
It is a SNAPSHOT: it does not update by itself, and says how old it is. Run the command again for fresh results.
Each run also saves what it saw to data/history.json, so the news-spike checks and the score's "normal here" marker
get better the more you use it. (They need readings from at least a day.)
"""
import argparse
import json
import os
import sys
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from engine import Monitor  # noqa: E402


def ask_location(data):
    """First run only: offer a 'Near you' card for the user's own area. Sends the ZIP code to api.zippopotam.us (a free
    lookup service) to get coordinates; the answer is saved in data/local.json. Press Enter to skip."""
    path = os.path.join(data, "local.json")
    try:
        with open(path) as f:
            return json.load(f) or None
    except (OSError, ValueError):
        pass
    if not sys.stdin.isatty():
        return None
    print("\nWant a 'Near you' card with Weather Service alerts for your own area?")
    print("Type your 5-digit ZIP code (it is sent to api.zippopotam.us to look up the location), or press Enter to skip.")
    zip_ = input("ZIP code: ").strip()
    loc = {"skipped": True}
    if zip_:
        try:
            from collectors import fetch_json
            p = fetch_json(f"https://api.zippopotam.us/us/{zip_[:5]}", timeout=15)["places"][0]
            loc = {"name": f"{p['place name']}, {p['state abbreviation']}", "lat": float(p["latitude"]),
                   "lon": float(p["longitude"])}
            print(f"Got it: {loc['name']}.")
        except Exception:
            print("Could not look that ZIP code up, so I will skip this. Delete data/local.json to be asked again.")
    with open(path, "w") as f:
        json.dump(loc, f)
    return None if loc.get("skipped") else loc


def main():
    ap = argparse.ArgumentParser(description="Check every source once and save a snapshot page.")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "snapshot.html"))
    ap.add_argument("--no-open", action="store_true", help="do not open the page in a browser")
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)
    cfg.setdefault("notify", {}).update({"macos": False, "ntfy_topic": ""})   # a snapshot never sends alerts
    data = os.path.join(HERE, "data")
    os.makedirs(data, exist_ok=True)
    if not cfg.get("local"):
        loc = ask_location(data)
        if loc and "lat" in loc:
            cfg["local"] = loc

    mon = Monitor(cfg, data)
    n = len(mon.collectors)
    print(f"Checking {n} sources. This takes about a minute…", flush=True)
    t0 = time.time()
    mon.run_snapshot()
    snap = mon.snapshot()
    a = snap["analysis"]

    with open(os.path.join(HERE, "static", "index.html"), encoding="utf-8") as f:
        page = f.read()
    blob = json.dumps(snap).replace("</", "<\\/")      # keep the data from ever closing the script tag
    page = page.replace("</head>", f"<script>window.__SNAPSHOT__ = {blob};</script>\n</head>", 1)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(page)

    mon.store.save()

    st, sc = a.get("story", {}), a.get("score") or {}
    score = "?" if sc.get("value") is None else f"{sc['value']} / 100"
    u = sc.get("usual")
    ok = sum(1 for s in snap["sources"] if s["ok"])
    bad = [s["name"] for s in snap["sources"] if s["ok"] is False]
    print(f"\n  {a['label']}: {st.get('headline', '')}   Score: {score}"
          + (f"   (normal here: about {u['median']})" if u else "   (still learning what normal looks like)"))
    print(f"  {st.get('summary', '')}")
    print(f"  What to do: {st.get('todo', '')}")
    ny = st.get("near_you")
    if ny:
        print(f"  Near you ({ny['name']}): {ny['headline']}")
    print(f"\n  {ok} of {len(snap['sources'])} sources answered in {time.time() - t0:.0f}s."
          + (f" Not working: {', '.join(bad[:6])}{'…' if len(bad) > 6 else ''}." if bad else ""))
    print(f"  Saved: {args.out}")
    if not args.no_open:
        webbrowser.open("file://" + os.path.abspath(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
