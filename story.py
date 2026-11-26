"""Turns the analysis into one short, calm, plain-English message ("the bottom line").

The dashboard leads with this. Everything else (areas, scores, sources) is detail for people who want to dig.
Rule: every sentence is built from the real analysis, never from a template that ignores the data, and any
line about a specific area links to the best source for it so you can go check.
"""
import re

from collectors import CATEGORIES

NOUN = {
    "aviation": "Flights and air traffic", "telecom": "Phones and 911", "power": "The power grid",
    "internet": "Internet and cloud services", "finance": "Banks and payments", "markets": "The stock market",
    "cyber": "Hacking and cyber attacks", "security": "Attacks and violence",
    "nuclear": "Nuclear, missile or EMP threats", "space": "Solar storms", "natural": "Earthquakes and natural events",
    "emergency": "Civil emergency alerts", "elite": "Wealthy people leaving",
}

HEAD = {
    "NORMAL": ("All quiet.", "Nothing unusual is happening. Carry on."),
    "WATCH": ("Don't freak out.", "Something is getting attention, but nothing confirms it's serious or widespread."),
    "ELEVATED": ("Pay attention. Don't panic.",
                 "Something real is going on in more than one area. It may still turn out to be an accident, "
                 "but go look at the sources."),
    "SUSPECTED ATTACK": ("Take this seriously.",
                         "The pattern fits a deliberate attack better than any accident. Check the sources "
                         "right now and follow official alerts."),
    "NO DATA": ("I can't see well enough right now.", "This is NOT an all-clear. Too many of my sources aren't working."),
}

TODO = {
    "NORMAL": "Nothing. Go about your day.",
    "WATCH": "Nothing needed. If you're curious, tap the links below and see the sources for yourself.",
    "ELEVATED": "Open the linked sources and check your local news. No need to do anything drastic.",
    "SUSPECTED ATTACK": "Check the sources right now, and follow official alerts and local authorities.",
    "NO DATA": "Don't assume everything is fine. Check the sources below yourself, or wait for the monitor to recover.",
}

WHO = [("gov", "a government source flagged it"), ("private", "a monitoring service or company flagged it"),
       ("news", "news outlets are covering it"), ("social", "people are posting about it")]


# What the monitor can ACTUALLY check for each area. Quiet official data only reassures where a fast official feed
# exists. Where none does, say so plainly instead of implying "official data looks normal".
FAST_FEED = {
    "aviation": "the FAA's own flight-status data looks normal",
    "telecom": "the 911-outage alerts and internet-outage trackers I check look normal",
    "power": "the grid-demand data I check (it runs 1 to 2 hours behind) looks normal",
    "internet": "the internet-outage trackers and company status pages I check look normal",
    "space": "NOAA's space-weather data looks normal",
    "natural": "USGS earthquake data looks normal",
    "emergency": "Weather Service alerts look normal",
    "markets": "the major stock indexes and the VIX look normal",
}
NO_FEED = {
    "cyber": "I have no fast official source for this (government cyber warnings can lag by hours or days), "
             "so I can't confirm or rule it out",
    "finance": "I have no official real-time source for bank problems, so I can't confirm or rule it out",
    "security": "apart from DHS's rarely used terrorism alerts I have no official real-time source for this, so I can't confirm or rule it out",
    "nuclear": "apart from Weather Service civil-emergency alerts I have no fast official source for this, "
               "so I can't rule it out",
    "elite": "the only data I have is private-jet traffic, a rough proxy, so I can't confirm or rule it out",
}


# The three things the page now leads with: status, a suggested posture, and punchy reasons.
STATUS_LINE = {
    "NORMAL": "Nothing unusual.",
    "WATCH": "Something unusual, not confirmed.",
    "ELEVATED": "A real problem in more than one area.",
    "SUSPECTED ATTACK": "A serious, spreading event is likely under way.",
    "NO DATA": "Can't see well enough. Not an all-clear.",
}
POSTURE = {
    "NORMAL": ("Normal life", "Nothing to do."),
    "WATCH": ("Stay aware", "Nothing to do. This page will say so if that changes."),
    "ELEVATED": ("Get ready", "Stage your plan: fuel, cash, comms, and where your people are."),
    "SUSPECTED ATTACK": ("Act now", "Run your plan. Reach your people, follow official alerts, be ready to move."),
    "NO DATA": ("Check for yourself", "The monitor is partly blind. Don't read a quiet screen as safe."),
}
AREA = {
    "aviation": "Flights", "telecom": "Phones & 911", "power": "Power", "internet": "Internet", "finance": "Banks",
    "markets": "Markets", "cyber": "Hacking", "security": "Violence", "nuclear": "Nuclear / missile",
    "emergency": "Emergency alerts", "space": "Solar storm", "natural": "Natural events", "roads": "Roads",
}
HYP_SHORT = {"accident": "an accident or equipment failure", "natural": "weather or a solar storm",
             "hoax": "a false alarm or rumor", "cyber": "a cyber attack", "physical": "a physical attack",
             "strategic": "a missile, nuclear or EMP attack"}
_DIR_ORDER = {"up": 0, "soft": 1, "down": 2, "warn": 3}

# The five-step scale shown at the top right. Internally the engine still has four levels (and logs them by their old
# names); the page shows these. Step 5 is never inferred: it needs a government source to say so itself.
STEPS = [
    ("Normal Conditions", "Nothing unusual is happening."),
    ("Watch", "Something unusual is happening, but it is not confirmed."),
    ("Concern", "There is a real problem in more than one area, and the cause isn't clear yet."),
    ("Likely event", "A serious, spreading event is likely under way."),
    ("Confirmed", "Officials confirm a major threat or hazard."),
]
_STEP_OF = {"NORMAL": 1, "WATCH": 2, "ELEVATED": 3, "SUSPECTED ATTACK": 4}


CAUSE = {"accident": "equipment or software failure", "natural": "weather or a natural hazard", "hoax": "a false alarm",
         "cyber": "a cyber attack", "physical": "a physical attack or sabotage", "strategic": "a missile or nuclear threat"}


def _cause(res):
    """Cause is a label, not the trigger: attack, accident, nature, or a mix. Shown when there is an event to explain."""
    hyp = res["hypotheses"]
    if not hyp or hyp[0]["score"] < 2:
        return "It is too early to say what is causing this."
    top = hyp[0]
    nxt = hyp[1] if len(hyp) > 1 and hyp[1]["score"] >= 2 else None
    if nxt and top["score"] - nxt["score"] < 2:
        return f"The cause isn't clear yet: it may be {CAUSE[top['key']]} or {CAUSE[nxt['key']]}."
    return f"So far this looks most like {CAUSE[top['key']]}, but it is too early to be sure." + (
        f" It may also be {CAUSE[nxt['key']]}." if nxt else "")


def _scale(label, cats):
    if label == "NO DATA":
        return {"step": None, "name": "No data", "line": "Too many sources are down to see clearly, so this is not an all-clear.",
                "names": [n for n, _ in STEPS]}
    step = _STEP_OF[label]
    if step == 4 and any(s.kind == "gov" and ("official-strategic" in (s.tags or []) and s.severity >= 2
                                              or "official-hazard" in (s.tags or []) and s.severity >= 3)
                         for c in cats.values() for s in c["signals"]):
        step = 5          # a government source itself reports a nuclear / civil-danger threat, or an imminent major hazard
    reg = _regional_line(step, cats)
    return {"step": step, "name": STEPS[step - 1][0], "line": reg or STEPS[step - 1][1], "regional": bool(reg),
            "names": [n for n, _ in STEPS]}


def _event_name(s):
    ev = (s.meta or {}).get("event")
    if not ev:
        t = s.title or ""
        ev = t.split(": ", 1)[1].split(" \u2014 ")[0] if t.startswith("Weather Service alert: ") else t.split(":")[0]
    return ev.strip().lower()


def _where(codes):
    import geo
    names = {}
    for k, v in geo.STATE_CODES.items():      # state names come first in that table; later entries are cities
        names.setdefault(v, k.title())
    full = [names.get(c, c) for c in codes]
    if len(full) <= 3:
        return full[0] if len(full) == 1 else ", ".join(full[:-1]) + " and " + full[-1]
    return f"{len(full)} states, including {full[0]}, {full[1]} and {full[2]}"


def _regional_line(step, cats):
    """When a regional official warning is what sets the level, say plainly what it is and where."""
    regs = [s for c in cats.values() for s in c["signals"] if (s.meta or {}).get("regional")
            and (s.severity >= 2 or "regional-elsewhere" in (s.tags or []))]
    if step == 5:
        regs = [s for s in regs if "official-hazard" in (s.tags or []) and s.severity >= 3]
    elif step == 4:
        regs = [s for s in regs if "official-danger-here" in (s.tags or [])] or \
               [s for s in regs if "official-hazard" in (s.tags or []) and s.severity >= 3]
    elif step == 2:
        regs = [s for s in regs if "regional-elsewhere" in (s.tags or []) and s.category == "natural"]
    elif step != 3:
        return None
    if not regs:
        return None
    regs.sort(key=lambda s: -s.severity)
    parts = []
    for s in regs[:2]:
        p = f"a {_event_name(s)} is in effect for {_where(s.meta['regional'])}"
        if p not in parts:
            parts.append(p)
    text = " and ".join(parts)
    return text[0].upper() + text[1:] + "."


def _short(text, n=72):
    text = " ".join((text or "").split())
    if len(text) <= n:
        return text
    return text[:n].rsplit(" ", 1)[0].rstrip(",;:- ") + "…"


def _headline(s):
    """A punchy phrase for one signal (the full title stays in the expanded sources)."""
    meta = getattr(s, "meta", None) or {}
    if s.source.startswith("Drudge"):
        n = re.match(r"Drudge Report: (\d+)", s.title)
        return f"Drudge is leading with {n.group(1) if n else 'several'} on this"
    if s.kind == "news" and meta.get("clusters"):
        top = f", {meta['t1']} top-tier" if meta.get("t1") else ""
        return f"{meta['clusters']} outlets reporting{top}"
    if s.kind == "social":
        m = re.search(r"about (\d+) posts", s.title)
        return f"social buzz, ~{m.group(1)} posts/hr" if m else _short(s.title, 56)
    return _short(s.title, 64)


def _because(why):
    """Shorten an 'explained by' reason."""
    m = re.match(r"probably a knock-on effect of the (.+?) problem", why)
    if m:
        return f"likely a knock-on of {m.group(1)}"
    if "weather" in why:
        return "likely the weather"
    if "solar" in why:
        return "likely a solar storm"
    return _short(why, 48)


def _src(s):
    return {"title": s.title, "url": s.url, "by": s.source, "kind": s.kind, "sev": s.severity,
            "links": [{"title": l.get("title", ""), "url": l.get("url", "")} for l in (s.links or [])[:5] if l.get("title")]}


def _reasons(label, res, cats, ok_n, total, down):
    """Short, punchy bullets, each expandable to the sources behind it. dir: up = raises concern, soft = unconfirmed
    hint, down = calming, warn = a blind spot. Every bullet is built from the real analysis."""
    credible = set(res.get("credible", []))
    explained = {e["domain"]: e["why"] for e in res["explained"]}
    out = []

    def add(d, text, tag="", sources=None, why=None, area=None, label=None):
        out.append({"dir": d, "text": text, "tag": tag, "sources": sources or [], "why": why or [],
                    "area": area, "area_label": label})

    for cat, c in sorted(cats.items(), key=lambda kv: -kv[1]["level"]):
        if c["level"] < 1 or cat == "elite":
            continue
        live = [s for s in c["signals"] if s.severity >= 1 and s.kind != "system"]
        if not live or CATEGORIES[cat] in explained:
            continue
        prim = [s for s in live if s.kind in ("gov", "private")]
        best = (prim or [s for s in live if s.kind == "news"] or live)[0]
        if prim:
            d, tag = "up", "Official / live data"
        elif cat in credible:
            d, tag = "up", "Several top outlets"
        elif any(s.kind == "news" for s in live):
            d, tag = "soft", "News only"
        else:
            d, tag = "soft", "Social only"
        add(d, f"{AREA.get(cat, CATEGORIES[cat])}: {_headline(best)}", tag, [_src(s) for s in live[:6]],
            area=cat, label=AREA.get(cat, CATEGORIES[cat]))

    if res.get("canary") and credible:
        add("up", "Top news outlets report it; officials haven't spoken yet", "Early signal",
            [_src(s) for k in credible for s in cats[k]["signals"] if s.kind == "news" and s.severity >= 2][:6],
            ["Several independent top-tier outlets report it. Governments are often slow to confirm bad news."])
    sb = res.get("slow_burn") or {}
    if sb.get("active"):
        names = [a["label"] for a in sb["areas"]]
        add("up", f"{len(names)} areas troubled for hours", "Slow burn",
            [_src(s) for a in sb["areas"][:5] for s in cats[a["key"]]["signals"] if s.severity >= 1][:6],
            [sb["why"]])
    if res.get("simultaneous"):
        add("up", "Problems started within minutes of each other", "Timing")
    top = res["hypotheses"][0] if res["hypotheses"] else None
    if top and res["level"] >= 2 and top["key"] in ("cyber", "physical", "strategic"):
        add("up", f"Fits {HYP_SHORT[top['key']]} (score {top['score']:g})", "Pattern",
            why=[f"{e['pts']:+g} {e['why']}" for e in top["evidence"][:4]])

    calm = []
    for dom, why in explained.items():
        key = next((k for k, v in CATEGORIES.items() if v == dom), None)
        srcs = [_src(s) for s in (cats.get(key, {}).get("signals", []) + cats.get("natural", {}).get("signals", [])
                                  + cats.get("space", {}).get("signals", [])) if s.severity >= 1][:5]
        calm.append(("down", f"{AREA.get(key, dom)}: {_because(why)}", "Harmless cause", srcs, []))
    if top and top["key"] in ("accident", "natural", "hoax") and 1 <= res["level"] <= 2:
        calm.append(("down", f"Most likely {HYP_SHORT[top['key']]}", "Best guess", [],
                     [f"{e['pts']:+g} {e['why']}" for e in top["evidence"][:4]]))
    if res["level"] >= 1 and not any(c["primary"] for c in res["clusters"]) and not res.get("canary"):
        quiet = [s for k in ("aviation", "telecom", "internet", "power") for s in cats[k]["signals"]
                 if s.kind in ("gov", "private") and s.severity == 0][:5]
        calm.append(("down", "No official source confirms a real problem", "Checked", [_src(s) for s in quiet], []))
    for d, t, tag, srcs, why in calm[:3]:
        add(d, t, tag, srcs, why)

    claims = res.get("claims") or []
    if claims and label != "NORMAL":   # on a normal day a loose post did not move anything, so it is not part of the reasoning
        cl = claims[0]
        add("soft" if cl["verdict"] in ("verified", "unverified") else "down",
            f"Viral {cl['platform']} post about {AREA.get(cl['category'], cl['category']).lower()}: {cl['verdict']} ({cl['score']}/100 believability)",
            "Claim check", [{"title": _short(cl["text"], 90), "url": cl["url"], "by": cl["platform"], "kind": "social", "sev": 0,
                             "links": []}], [f"{cl['score']}/100 is how much this post is worth believing, not how serious it is. Spreading (up to 30), the account (up to 30) and outside confirmation (up to 40) add up; fact-checks subtract. 65+ is verified, 35 or lower is a rumor."] + [p["why"] for p in cl["parts"][:4]], area="claim", label="Viral post")
    if down and label != "NO DATA":
        n = len(down)
        add("warn", f"{n} source{'s' if n > 1 else ''} not working: a quiet result counts for less", "Blind spot",
            [{"title": x.replace("News: ", "news: "), "url": "", "by": "", "kind": "system", "sev": 0, "links": []} for x in down[:6]])
    if label == "NO DATA":
        add("warn", f"Only {ok_n} of {total} sources reachable", "Blind spot")
    calm_first = False
    if label == "NORMAL":      # on a normal day the reasoning leads with why it is normal; anything unconfirmed follows it
        quiet = [s for c in cats.values() for s in c["signals"] if s.kind in ("gov", "private") and s.severity == 0][:8]
        add("down", f"All {ok_n} working sources look normal", "Checked", [_src(s) for s in quiet])
        calm_first = True

    out.sort(key=lambda r: _DIR_ORDER[r["dir"]])
    if calm_first:
        out.sort(key=lambda r: r["dir"] != "down")
    return out[:8]


def _join(parts):
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def _area_line(cat, c):
    sigs = c["signals"]
    live = [s for s in sigs if s.severity >= 1 and s.kind != "system"]
    if not live:
        return None
    kinds = {s.kind for s in live}
    who = [txt for k, txt in WHO if k in kinds]
    prim = [s for s in live if s.kind in ("gov", "private")]
    quiet_prim = [s for s in sigs if s.kind in ("gov", "private") and s.severity == 0]
    blind = False
    if prim:
        tail = ""
    elif cat in FAST_FEED and quiet_prim:
        tail = ", but " + FAST_FEED[cat]
    elif cat in FAST_FEED:
        tail = ", but I could not check the official source just now"
    else:
        tail = ", and " + NO_FEED.get(cat, "I have no fast official source for this, so I can't confirm or rule it out")
        blind = True
    best = (prim or [s for s in live if s.kind == "news"] or live)[0]
    return {"text": f"{NOUN.get(cat, CATEGORIES.get(cat, cat))}: {_join(who)}{tail}.",
            "url": best.url, "level": c["level"], "confirmed": bool(prim), "blind": blind}


def _near(local, loc):
    """The 'Near you' card: your own county, kept apart from the national picture."""
    if not loc or local is None:
        return None
    sigs = sorted(local["signals"], key=lambda s: -s.severity)
    worst = max([s.severity for s in sigs] or [0])
    head = {0: "Nothing unusual near you.", 1: "Something near you to keep an eye on.",
            2: "Heads up: this is near you.", 3: "Take this seriously: it is happening near you."}[worst]
    if not sigs:
        head = "My local sources haven't reported yet."
    return {"name": loc["name"], "worst": worst, "headline": head,
            "lines": [{"text": s.title, "url": s.url, "level": s.severity, "detail": s.detail} for s in sigs[:6]]}


WORLD_LABEL = {"Geopolitical escalation": "Geopolitics", "Nuclear / missile / EMP": "Missiles & nuclear",
               "Terror / coordinated attack": "Terror", "Explosions / mass casualty": "Explosions",
               "Cyberattack on infrastructure": "Cyber", "Infrastructure sabotage": "Sabotage"}


# For the place shown beside a world headline: demonyms, leaders and groups name the country they belong to.
_PLACE = {"israeli": "Israel", "iranian": "Iran", "tehran": "Iran", "khamenei": "Iran", "fordow": "Iran", "fordo": "Iran",
          "natanz": "Iran", "isfahan": "Iran", "bushehr": "Iran", "ukrainian": "Ukraine", "kyiv": "Ukraine",
          "zelensky": "Ukraine", "russian": "Russia", "moscow": "Russia", "kremlin": "Russia", "putin": "Russia",
          "chinese": "China", "beijing": "China", "taipei": "Taiwan", "japanese": "Japan", "korean": "Korea",
          "pyongyang": "North Korea", "kim jong": "North Korea", "british": "UK", "britain": "UK", "london": "UK",
          "uk": "UK", "eu": "EU", "uae": "UAE", "european": "Europe", "german": "Germany", "french": "France",
          "spanish": "Spain", "italian": "Italy", "polish": "Poland", "turkish": "Turkey", "indian": "India",
          "pakistani": "Pakistan", "canadian": "Canada", "mexican": "Mexico", "australian": "Australia",
          "netanyahu": "Israel", "tel aviv": "Israel", "hamas": "Gaza", "rafah": "Gaza", "hezbollah": "Lebanon",
          "houthi": "Yemen", "houthis": "Yemen", "taliban": "Afghanistan", "mideast": "Middle East", "dutch": "Netherlands",
          "swedish": "Sweden", "jordanian": "Jordan"}


def _places(headline):
    """Every foreign place a headline names, normalised ('Iranian' -> Iran, 'Pyongyang' -> North Korea), in order."""
    import geo
    text = geo.ACTOR_RX.sub(" ", headline or "")
    out = []
    for m in geo.FOREIGN_RX.finditer(text):
        w = m.group(0).lower()
        if w in ("korea", "korean"):
            before = text[max(0, m.start() - 6):m.start()].lower()
            name = "North Korea" if "north" in before else "South Korea" if "south" in before else "Korea"
        else:
            name = _PLACE.get(w, w.title())
        if name not in out:
            out.append(name)
    return out


def _place(headline):
    p = _places(headline)
    return p[0] if p else "Overseas"


WORLD_MIN_OUTLETS = 2       # distinct credible outlets (trust tier 1-2) that must be covering a world story to show it


def _same_event(a, b):
    """Two headlines about the same overseas event: same place and enough words in common. Looser than trust's
    syndication check, because different outlets word the same event differently."""
    if not set(a["places"]) & set(b["places"]):
        return False
    common = a["tok"] & b["tok"]
    return len(common) >= 2 and len(common) / max(1, min(len(a["tok"]), len(b["tok"]))) >= 0.34


def _world(signals, cfg=None):
    """'World events we're monitoring': overseas stories, context only (they never move the level).
    A story shows only when at least two DIFFERENT credible outlets (trust tier 1-2) are covering it (social posts,
    low-trust sites and Drudge never count) AND its headlines show a plausible path to people in the US (impact.py). One short headline per story, with the place and when it was published.
    Most outlets first, then newest. The page shows the first three and folds the rest under 'and N more'."""
    import impact
    import trust
    heads = []
    for s in signals:
        if (s.key or "").startswith("world:drudge") or (s.source or "").startswith("Drudge") or s.kind == "social":
            continue
        for l in s.links or []:
            title = l.get("title") or ""
            if " \u2014 " not in title:
                continue
            head, pub = (x.strip() for x in title.rsplit(" \u2014 ", 1))
            if not head or not pub or trust.tier_of(pub, None, cfg) > 2:
                continue
            heads.append({"head": head, "pub": pub, "url": l.get("url") or s.url, "t": l.get("t") or s.time,
                          "place": _place(head), "places": _places(head) or ["Overseas"], "tok": trust._tokens(head), "sig": s})
    events = []
    for h in heads:
        ev = next((e for e in events if any(_same_event(h, x) for x in e)), None)
        if ev is None:
            events.append([h])
        else:
            ev.append(h)
    items = []
    for ev in events:
        outlets = {trust._norm(h["pub"]) for h in ev}
        if len(outlets) < WORLD_MIN_OUTLETS:
            continue
        why = impact.tags([h["head"] for h in ev])
        if not why:                     # no plausible path to people in the US: not shown
            continue
        first = ev[0]
        t = max(h["t"] or 0 for h in ev) or None
        norm = re.sub(r"\W+", " ", first["head"].lower()).strip()
        items.append({"dir": "world", "text": "world:" + norm[:80], "headline": _short(first["head"], 90),
                      "place": first["place"], "t": t, "url": first["url"], "outlets": len(outlets), "impact": why,
                      "area": "world", "area_label": first["place"], "tag": "Overseas", "why": [],
                      "sources": [_src(first["sig"])]})
    items.sort(key=lambda i: (-i["outlets"], -(i["t"] or 0)))
    return items[:8]


def tell(label, res, cats, ok_n, total, failing, down=None, local=None, loc=None, world=None):
    """Returns a dict the dashboard renders as the top 'bottom line' card."""
    level = res["level"]
    head, sub = HEAD[label]
    clusters = res["clusters"]
    confirmed = [c["label"] for c in clusters if c["primary"]]
    top = res["hypotheses"][0] if res["hypotheses"] else None

    going = []
    for cat, c in sorted(cats.items(), key=lambda kv: -kv[1]["level"]):
        if c["level"] >= 1 and cat != "elite":
            line = _area_line(cat, c)
            if line:
                going.append(line)
    more = max(0, len(going) - 3)
    going = going[:3]

    calm, worry = [], []
    if label == "NO DATA":
        worry.append(f"Only {ok_n} of {total} sources are reachable.")
    else:
        if level == 1 and not confirmed:
            calm.append("No official source (government, status page or monitoring service) confirms a real problem.")
        if res["explained"]:
            calm.append("; ".join(f"{e['domain']} looks explained by something harmless ({e['why']})"
                                  for e in res["explained"]).capitalize() + ".")
        if level == 1 and len(clusters) < 2:
            calm.append("Nothing is actually failing in several areas at the same time, which is what a deliberate attack would usually look like.")
        if top and top["key"] in ("accident", "natural", "hoax") and 1 <= level <= 2:
            calm.append({"accident": "The most likely cause is an accident or equipment failure, which is what most big outages turn out to be.",
                         "natural": "The most likely cause is weather or a solar storm.",
                         "hoax": "This looks more like a false alarm or rumor than a real event."}[top["key"]])
        if any(c.get("social_only") for c in cats.values()):
            calm.append("Some of the buzz is only on social media, which I treat as a hint, not proof.")
        if confirmed:
            worry.append("Official or technical sources confirm problems in: " + ", ".join(confirmed) + ".")
        if res["simultaneous"]:
            worry.append("The problems started within minutes of each other." if confirmed else
                         "These started showing up within minutes of each other, but none is confirmed by an official source.")
        if level >= 3 and top:
            worry.append(res["verdict"])
        elif level == 2 and top and top["key"] in ("cyber", "physical", "strategic"):
            worry.append("An attack is a possible explanation, but I can't rule out an accident yet.")
    if failing and label != "NO DATA":
        names = [n.replace("News: ", "news: ") for n in (down or [])]
        shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        worry.append((f"{failing} of my sources isn't" if failing == 1 else f"{failing} of my sources aren't")
                     + " working right now" + (f" ({shown})" if shown else "")
                     + ", so a quiet result counts for less.")

    louder = None
    if level < 3 and label != "NO DATA":
        louder = ("I'll get louder if an official source (FAA, CISA, Weather Service) confirms it, or if several "
                  "different services fail at about the same time with no harmless explanation.")

    return {
        "headline": head, "summary": sub, "going_on": going, "going_more": more, "calm": calm, "worry": worry,
        "todo": TODO[label], "louder": louder, "near_you": _near(local, loc), "attack_chance": res["plausibility"].lower(),
        "status_line": STATUS_LINE[label], "posture": {"name": POSTURE[label][0], "line": POSTURE[label][1]},
        "reasons": _reasons(label, res, cats, ok_n, total, down or []),
        "scale": _scale(label, cats), "world": _world(world or []), "cause": _cause(res),
        "checked": f"{ok_n} of {total} sources checked" if total else "",
    }
