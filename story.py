"""Turns the analysis into one short, calm, plain-English message ("the bottom line").

The dashboard leads with this. Everything else (areas, scores, sources) is detail for people who want to dig.
Rule: every sentence is built from the real analysis, never from a template that ignores the data, and any
line about a specific area links to the best source for it so you can go check.
"""
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


def tell(label, res, cats, ok_n, total, failing, down=None, local=None, loc=None):
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
        "checked": f"{ok_n} of {total} sources checked" if total else "",
    }
