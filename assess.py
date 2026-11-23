"""Scenario assessment: does the pattern look like a realistic attack, or like something benign?

Why this exists
---------------
Counting how many domains look bad is not enough. Most multi-sector outages are ACCIDENTS (a bad
software update, a vendor failure, a storm), and an attack is rare. The discriminating questions are:

  * Are the failures INDEPENDENT, or does one upstream failure (power, a cloud vendor) explain the rest?
  * Did they start AT ABOUT THE SAME TIME, or cascade over hours?
  * Is there a BENIGN EXPLANATION on record (storm alerts, geomagnetic storm, a vendor incident, an
    official "not a cyberattack" statement)?
  * Is there PRIMARY evidence (government / telemetry), or only headlines and social posts?
    (Adversaries also use false claims, so unconfirmed viral claims are treated with suspicion.)
  * Does the pattern fit how real operations are staged: lifeline sectors (power, comms, cloud,
    finance, aviation) hit together, with official warnings, near a geopolitical trigger?

Every hypothesis gets a transparent additive score; each point is listed with its reason so you can
see *why* the monitor believes what it believes. All thresholds are in config.json -> "assessment".
"""
import re

from collectors import CATEGORIES

PRIMARY = ("gov", "private")
LIFELINE = ("power", "telecom", "internet", "finance", "aviation")

# If the upstream domain became active first, it can explain the downstream one (a cascade, not a 2nd attack).
DOWNSTREAM = {
    "power":    ("telecom", "internet", "finance", "aviation"),
    "telecom":  ("internet", "finance", "aviation"),
    "internet": ("finance", "aviation", "telecom"),
}

HYP = {
    "accident":  "An accident or equipment/software failure",
    "natural":   "Weather or a solar storm",
    "cyber":     "A cyber attack by hackers",
    "physical":  "A physical attack, sabotage or terrorism",
    "strategic": "A missile, nuclear or EMP attack",
    "hoax":      "A false alarm or deliberate rumor",
}
ATTACK = ("cyber", "physical", "strategic")


def _lc(s):
    """Lower-case the first letter so a label reads naturally mid-sentence."""
    return s[:1].lower() + s[1:]

VERIFY = {
    "cyber": [("CISA cyber alerts and emergency orders", "https://www.cisa.gov/news-events/cybersecurity-advisories"),
              ("SANS cyber-threat level", "https://isc.sans.edu/"),
              ("Cloudflare internet-outage map", "https://radar.cloudflare.com/outage-center"),
              ("Is one company the common cause? (Cloudflare status)", "https://www.cloudflarestatus.com/")],
    "accident": [("Amazon cloud status", "https://health.aws.amazon.com/health/status"),
                 ("Google cloud status", "https://status.cloud.google.com/"),
                 ("Microsoft cloud status", "https://azure.status.microsoft/en-us/status"),
                 ("Company status pages and official statements", "https://www.cloudflarestatus.com/")],
    "physical": [("Weather Service alerts (police and civil-danger warnings)", "https://alerts.weather.gov/"),
                 ("FAA no-fly zones (temporary flight restrictions)", "https://tfr.faa.gov/"),
                 ("FAA airport delays and stops", "https://nasstatus.faa.gov/"),
                 ("Live police and fire radio (Broadcastify)", "https://www.broadcastify.com/listen/")],
    "strategic": [("Weather Service alerts", "https://alerts.weather.gov/"),
                  ("NORAD news", "https://www.norad.mil/Newsroom/"),
                  ("USGS earthquake and explosion map", "https://earthquake.usgs.gov/earthquakes/map/"),
                  ("Ready.gov emergency alerts", "https://www.ready.gov/alerts")],
    "natural": [("Weather Service alerts", "https://alerts.weather.gov/"),
                ("NOAA solar-storm forecasts", "https://www.swpc.noaa.gov/"),
                ("USGS earthquake map", "https://earthquake.usgs.gov/earthquakes/map/")],
    "hoax": [("AP Fact Check", "https://apnews.com/hub/ap-fact-check"),
             ("Official agency sites (FAA, Weather Service, CISA)", "https://nasstatus.faa.gov/")],
}

CYBER_RX = re.compile(r"cyber ?attack|ransomware|hackers?\b|malicious cyber|state-sponsored|nation-state|ddos|wiper", re.I)
PHYS_RX = re.compile(r"explosion|bomb|shooting|gunfire|terror|coordinated attack|attacks? across|sabotage|arson|"
                     r"drone (sighting|incursion)|hostage|mass casualty", re.I)
SAB_RX = re.compile(r"substation|sabotage|cable cut|fiber cut|rail(road)? (line|signal)|pipeline|vandal", re.I)
STRAT_RX = re.compile(r"missile|nuclear|electromagnetic pulse|\bEMP\b|mobiliz|invasion|blockade|declaration of war|"
                      r"escalat|NORAD|defcon", re.I)
DENIAL_RX = re.compile(r"not (a )?cyber ?attack|no evidence of (a )?(cyber|malicious)|no indication of (a )?(cyber|malicious)|"
                       r"not malicious|not related to (a )?cyber|no sign of (a )?cyber", re.I)
VENDOR_RX = re.compile(r"software update|faulty update|configuration (error|change)|technical (issue|glitch|problem|difficult)|"
                       r"human error|equipment failure|routine maintenance|third-party", re.I)
DEBUNK_RX = re.compile(r"\bfake\b|hoax|ai-generated|debunk|misinformation|disinformation|false claim|not true|doctored|fabricated", re.I)


WEATHER_RX = re.compile(r"\bstorms?\b|\bsnow|blizzard|\bicing\b|ice storm|hurricane|tornado|flood|\bwinds?\b|\bweather\b|"
                        r"winter storm|heat wave", re.I)
SPACE_RX = re.compile(r"geomagnetic|solar (storm|flare)|aurora|coronal|radio blackout", re.I)


def _track(mem, name, active, now, warm):
    """Remember when each condition FIRST became active. Conditions already present when the monitor
    started have an unknown onset (None) and are never treated as 'simultaneous'."""
    on, quiet = mem["onset"], mem["quiet"]
    if active:
        quiet.pop(name, None)
        if name not in on:
            on[name] = None if warm else now
    else:
        t = quiet.setdefault(name, now)
        if now - t > 1200:
            on.pop(name, None)
            quiet.pop(name, None)


def assess(cats, mem, params, now):
    """cats: {category: {"level": int, "signals": [Signal]}}; mem: persistent dict for onset tracking."""
    p = params or {}
    sim_window = p.get("simultaneity_minutes", 45) * 60
    heightened = p.get("posture", "normal") == "heightened"
    mult = p.get("heightened_multiplier", 1.5) if heightened else 1.0
    T3, T2, margin = p.get("suspected_score", 6), p.get("elevated_score", 4), p.get("attack_margin", 2)
    prior = p.get("accident_prior", 3) - (1 if heightened else 0)

    mem.setdefault("onset", {})
    mem.setdefault("quiet", {})
    mem.setdefault("t0", now)
    warm = now - mem["t0"] < 180

    sigs = [s for c in cats.values() for s in c["signals"]]
    prim_sigs = [s for s in sigs if s.kind in PRIMARY and s.severity >= 1]
    tags = {t for s in prim_sigs for t in s.tags}
    weather_major = any("weather-major" in s.tags for s in cats["natural"]["signals"])

    def prim(cat):
        return [s for s in cats[cat]["signals"] if s.kind in PRIMARY and s.severity >= 1]

    # ---- 1. which lifeline domains are genuinely active
    active = {}
    for d in LIFELINE:
        lvl, has_p = cats[d]["level"], bool(prim(d))
        on = lvl >= 2 or (lvl >= 1 and has_p)
        _track(mem, d, on, now, warm)
        if on:
            active[d] = {"primary": has_p}

    # ---- 2. does a benign cause explain any of them?
    explained = {}
    hazard = weather_major or bool(prim("natural"))
    space = cats["space"]["level"] >= 2
    onset = mem["onset"]

    # A hazard only explains a disruption if the reports ATTRIBUTE that disruption to it. Storm warnings
    # somewhere in the US must not excuse an unrelated outage (e.g. an airline's IT failure in winter).
    def attributed(d, rx):
        return sum(1 for s in cats[d]["signals"] if s.kind == "news"
                   for l in s.links if rx.search(l.get("title", ""))) >= 2

    def wx_attr(d):
        return any("weather-attributed" in s.tags for s in prim(d)) or attributed(d, WEATHER_RX)

    def space_attr(d):
        return attributed(d, SPACE_RX) or cats["space"]["level"] >= 3

    for d in active:
        if d in ("power", "telecom", "aviation") and hazard and wx_attr(d):
            explained[d] = ("natural", "bad weather is active and the reports blame the weather")
        elif d in ("power", "telecom", "aviation") and space and space_attr(d):
            explained[d] = ("natural", "a strong solar (geomagnetic) storm is underway")
        else:
            for up, downs in DOWNSTREAM.items():
                if up != d and up in active and d in downs and onset.get(d) and onset.get(up) \
                        and onset[up] + 60 < onset[d]:
                    explained[d] = ("cascade", f"probably a knock-on effect of the {CATEGORIES[up]} problem, which started first")
                    break

    # ---- 3. independent clusters (lifeline domains not explained away, plus official threat warnings)
    clusters = {d: {"label": CATEGORIES[d], "primary": active[d]["primary"]} for d in active if d not in explained}
    threat = {"threat:cyber": ("Official cyber warning", "official-cyber", "cyber"),
              "threat:physical": ("Official physical-threat warning", None, "security"),
              "threat:strategic": ("Official strategic warning", "official-strategic", "nuclear")}
    flags = {
        "threat:cyber": "official-cyber" in tags,
        "threat:physical": bool({"official-physical", "security-stop"} & tags),
        "threat:strategic": "official-strategic" in tags,
    }
    for name, (label, _t, _c) in threat.items():
        _track(mem, name, flags[name], now, warm)
        if flags[name]:
            clusters[name] = {"label": label, "primary": True}
    life = [c for c in clusters if c in LIFELINE]
    ons = [onset[c] for c in life if onset.get(c)]
    simultaneous = len(life) >= 2 and len(ons) == len(life) and (max(ons) - min(ons)) <= sim_window
    n_conf = sum(1 for c in clusters.values() if c["primary"])

    # ---- 4. real headlines (news only; social is excluded because adversaries use it too)
    heads = []
    for s in sigs:
        if s.kind == "news":
            heads += [l.get("title", "") for l in s.links]
    heads = list(dict.fromkeys(h for h in heads if h))

    def hits(rx):
        return sum(1 for h in heads if rx.search(h))

    n_cyber, n_phys, n_sab = hits(CYBER_RX), hits(PHYS_RX), hits(SAB_RX)
    n_strat, n_denial = hits(STRAT_RX), hits(DENIAL_RX)
    n_vendor, n_debunk = hits(VENDOR_RX), hits(DEBUNK_RX)
    gate = bool(clusters)

    ev = {h: [] for h in HYP}

    def add(h, pts, why, scaled=False):
        ev[h].append({"pts": round(pts * (mult if scaled and pts > 0 else 1), 1), "why": why})

    # accident / vendor  (the base rate applies to failures that nothing else already explains)
    if gate:
        add("accident", prior, "Most big outages turn out to be accidents, so that is the starting assumption")
    vend = [s for s in prim_sigs if s.key.startswith(("status:", "cloud:", "radar:"))]
    if vend:
        add("accident", 2, f"A company or cloud provider has reported its own problem: {vend[0].title[:80]}")
    if n_denial:
        add("accident", 3, f"{n_denial} headline(s) quote officials saying it was not a cyberattack")
    if n_vendor >= 2:
        add("accident", 1, f"{n_vendor} headlines blame a technical cause (a software update, a setting, equipment)")
    casc = {d: w for d, (k, w) in explained.items() if k == "cascade"}
    if casc:
        add("accident", 2, "One failure probably caused the others: " + "; ".join(f"{CATEGORIES[d]} {w}" for d, w in casc.items()))
    # natural (applies even when the hazard fully explains the failures, so it reads `explained`, not `clusters`)
    nat = {d: w for d, (k, w) in explained.items() if k == "natural"}
    if nat:
        add("natural", 4, "; ".join(f"{CATEGORIES[d]}: {w}" for d, w in nat.items()))
    # cyber
    if "official-cyber" in tags:
        add("cyber", 4, "An official cyber warning is active (a CISA emergency order, a raised SANS threat level, or an outage blamed on hackers)", True)
    if gate and n_cyber >= 2:
        add("cyber", min(3, n_cyber // 2), f"{n_cyber} headlines mention hackers, ransomware or similar attacks", True)
    if simultaneous:
        add("cyber", 3, "Several unrelated essential services failed within "
            f"{int((max(ons) - min(ons)) // 60)} minutes of each other, which is hard to explain with a single bug", True)
    if len(life) >= 2:
        add("cyber", 1, "Essential services hit together: " + ", ".join(CATEGORIES[c] for c in life), True)
    if n_denial:
        add("cyber", -3, "Officials say it was not a cyberattack")
    # physical
    if "official-physical" in tags:
        add("physical", 3, "An official police or civil-danger warning is active", True)
    if "security-stop" in tags:
        add("physical", 2, "The FAA stopped flights for a security-type reason", True)
    if cats["security"]["level"] >= 1 and n_phys >= 2:
        add("physical", min(3, n_phys // 2), f"{n_phys} headlines describe explosions, shootings or attacks", True)
    if n_sab and ({"power", "telecom"} & set(active)):
        add("physical", 2, "Reports of damage to substations, cables, rail or pipelines at the same time as a power or phone outage", True)
    # strategic
    if "official-strategic" in tags:
        add("strategic", 5, "An official nuclear, radiation or civil-danger warning is active (or a nuclear-type reading on earthquake sensors)", True)
    if cats["nuclear"]["level"] >= 1 and n_strat >= 3:
        add("strategic", min(3, n_strat // 2), f"{n_strat} headlines about missiles, nuclear weapons or military mobilization", True)
    if gate and any(s.key == "sys:blind" for s in sigs):
        add("strategic", 2, "Many US websites and services cannot be reached even though your own internet works", True)
    # hoax / information operation
    def sev_of(key):
        v = [s.severity for s in sigs if s.key == key]
        return v[0] if v else None

    air_normal = sev_of("faa:agg") == 0 and sev_of("adsb:total") == 0   # national air-traffic telemetry is healthy
    unconfirmed = [k for k in cats if k != "elite" and cats[k]["level"] >= 2 and not prim(k)]
    contained = [k for k in unconfirmed if k == "aviation" and air_normal]
    rest = [k for k in unconfirmed if k not in contained]
    if contained:
        add("accident", 2, "The news is loud, but nationwide air-traffic data (FAA stops, aircraft count) looks normal: "
                           "this looks specific to one airline or vendor, not a problem with US airspace")
    if rest:
        add("hoax", 2, "No government or live-data source confirms it: " + ", ".join(CATEGORIES[k] for k in rest))
    if n_debunk:
        add("hoax", 3, f"{n_debunk} headline(s) call a claim fake, doctored or misinformation")

    score = {h: max(0.0, round(sum(e["pts"] for e in ev[h]), 1)) for h in HYP}
    A = max(score[h] for h in ATTACK)
    B = max(score[h] for h in ("accident", "natural", "hoax"))
    lead_attack = max(ATTACK, key=lambda h: score[h])
    official_strong = (lead_attack == "cyber" and "official-cyber" in tags) or \
                      (lead_attack == "strategic" and "official-strategic" in tags)

    # ---- 5. level
    official3 = any(s.severity >= 3 for s in prim_sigs)
    corrob = any(cats[k]["level"] >= 2 and len({s.kind for s in cats[k]["signals"]
                                                if s.severity >= 1 and s.kind not in ("system", "social")}) >= 2
                 for k in LIFELINE + ("cyber", "nuclear")     # not 'security': daily local incidents are not national alarms
                 if k not in explained)                       # an explained disruption does not raise the alarm
    any_active = any(cats[k]["level"] >= 1 for k in cats)
    if n_conf >= 1 and A >= T3 and A - B >= margin and (len(clusters) >= 2 or official_strong):
        level = 3
    elif n_conf >= 2 or (len(clusters) >= 2 and n_conf >= 1) or official3 or corrob or \
            (n_conf >= 1 and A >= T2 and lead_attack in ("cyber", "strategic")):
        level = 2
    elif any_active:
        level = 1
    else:
        level = 0

    ranked = sorted(HYP, key=lambda h: -score[h])
    top, second = ranked[0], ranked[1]
    if not any_active:
        verdict = "Nothing unusual is happening right now."
    elif score[top] < 2:
        verdict = "Something is happening, but there is not enough evidence yet to say why."
    elif score[top] - score[second] < margin:
        verdict = (f"The cause is not clear yet. Best guesses so far: {_lc(HYP[top])} (score {score[top]:g}) "
                   f"or {_lc(HYP[second])} (score {score[second]:g}).")
    else:
        verdict = (f"Best explanation so far: {_lc(HYP[top])} (score {score[top]:g}). "
                   f"Second guess: {_lc(HYP[second])} (score {score[second]:g}).")
    plaus = "HIGH" if level == 3 else "MODERATE" if (A >= T2 and A >= B) else "LOW"

    reasons = []
    if level == 3:
        reasons.append(f"The pattern fits {_lc(HYP[lead_attack])} better than any harmless explanation.")
    if len(clusters) >= 2:
        reasons.append("Separate problems at the same time: " + ", ".join(c["label"] for c in clusters.values())
                       + (" — they started within minutes of each other." if simultaneous else "."))
    elif clusters:
        reasons.append("One problem is active: " + ", ".join(c["label"] for c in clusters.values()) + ".")
    if explained:
        reasons.append("These look explained by something else: " + "; ".join(f"{CATEGORIES[d]} ({w})" for d, (_k, w) in explained.items()))
    if not reasons:
        hot = [CATEGORIES[k] for k in cats if cats[k]["level"] >= 1 and k != "elite"]
        reasons.append("Some unusual activity in: " + ", ".join(hot) + " (not confirmed by official sources yet)." if hot else "Nothing unusual is showing up.")
    reasons.append(verdict)

    show = {top, second, lead_attack}
    verify = []
    for h in ranked[:2] + ([lead_attack] if lead_attack not in ranked[:2] else []):
        for t, u in VERIFY[h]:
            if (t, u) not in verify:
                verify.append((t, u))
    return {
        "level": level, "reasons": reasons, "verdict": verdict, "plausibility": plaus,
        "posture": "heightened" if heightened else "normal",
        "scores": {h: score[h] for h in ranked},
        "hypotheses": [{"key": h, "label": HYP[h], "score": score[h], "evidence": ev[h]} for h in ranked
                       if score[h] > 0 or h in show and any_active],
        "clusters": [{"name": k, "label": v["label"], "primary": v["primary"]} for k, v in clusters.items()],
        "explained": [{"domain": CATEGORIES[d], "why": w} for d, (_k, w) in explained.items()],
        "simultaneous": simultaneous,
        "verify": [{"title": t, "url": u} for t, u in verify[:8]],
    }
