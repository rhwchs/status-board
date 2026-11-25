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
from trust import credible as news_credible, tier_of

PRIMARY = ("gov", "private")
LIFELINE = ("power", "telecom", "internet", "finance", "aviation")

# If the upstream domain became active first, it can explain the downstream one (a cascade, not a 2nd attack).
DOWNSTREAM = {
    "power":    ("telecom", "internet", "finance", "aviation"),
    "telecom":  ("internet", "finance", "aviation"),
    "internet": ("finance", "aviation"),
}
CASCADE_MIN, CASCADE_MAX = 600, 3 * 3600     # an upstream failure explains a later one only if it came 10 minutes to 3 hours
                                             # earlier: closer than that, polling jitter decides the order, so it counts as simultaneous
ESSENTIAL = ("power", "telecom", "finance", "internet")   # what people most need working; flights matter less
AREA_WORDS = {   # words that tie a headline to ONE area; a shared word like "outage" does not (a bank-outage hoax is not about power)
    "power": r"blackout|power|grid|electric|utility|utilities", "telecom": r"911|phone|cell|telecom|wireless|carrier",
    "internet": r"internet|cloud|website|online|broadband|\bdns\b", "finance": r"bank|payment|atm\b|card|trading|stock|market|financ|zelle|venmo",
    "aviation": r"flight|airport|airline|\bfaa\b|airspace|ground stop|grounded",
    "security": r"explosion|bomb|shoot|terror|gunfire|blast|hostage|evacuat|sabotage|attack",
}
DOMAIN_KW = {   # words that tie a headline to an area (so a debunk of something else cannot cancel this story)
    "power": r"power|blackout|grid|electric|utility|outage", "telecom": r"911|phone|cell|telecom|carrier|wireless|outage",
    "internet": r"internet|cloud|outage|network|website|online|down", "finance": r"bank|payment|atm|card|market|trading|financ",
    "aviation": r"flight|airport|airline|faa|airspace|ground stop|grounded", "cyber": r"cyber|hack|ransom|breach|malware|ddos",
    "security": r"explosion|bomb|attack|shoot|terror|gunfire|blast|hostage|evacuat|sabotage",
    "nuclear": r"nuclear|missile|radiation|\bemp\b|nuke|strike",
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


def assess(cats, mem, params, now, slow_fn=None):
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
                        and CASCADE_MIN < onset[d] - onset[up] <= CASCADE_MAX:
                    explained[d] = ("cascade", f"probably a knock-on effect of the {CATEGORIES[up]} problem, which started first")
                    break

    # ---- 2b. slow burn: several independent areas sustained-unusual over hours (slowburn.py, needs history)
    sb = slow_fn([CATEGORIES[d] for d in explained]) if slow_fn else None
    slow_on = bool(sb and sb["active"])

    # ---- 3. independent clusters (lifeline domains not explained away, plus official threat warnings)
    clusters = {d: {"label": CATEGORIES[d], "primary": active[d]["primary"]} for d in active if d not in explained}
    threat = {"threat:cyber": ("Official cyber warning", "official-cyber", "cyber"),
              "threat:physical": ("Official physical-threat warning", None, "security"),
              "threat:strategic": ("Official strategic warning", "official-strategic", "nuclear")}
    flags = {
        "threat:cyber": "official-cyber" in tags,
        "threat:physical": bool({"official-physical", "security-stop"} & tags),
        "threat:strategic": "official-strategic" in tags,
        "danger:here": "official-danger-here" in tags,     # an official civil-danger warning that covers this viewer's area
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
    heads, heads_o = [], []
    for s in sigs:
        if s.kind == "news":
            for l in s.links:
                t = l.get("title", "")
                if t:
                    heads.append(t)
                    heads_o.append((t, t.rsplit(" — ", 1)[1] if " — " in t else ""))
    heads = list(dict.fromkeys(h for h in heads if h))

    def hits(rx):
        return sum(1 for h in heads if rx.search(h))

    # Governments are often slow to confirm bad news, so a story that several INDEPENDENT top-tier outlets are
    # reporting counts as credible on its own (see trust.py). {category: highest severity of such a news signal}
    cred = {}
    for k, c in cats.items():
        if k in ("elite", "markets", "space", "natural"):
            continue
        for s in c["signals"]:
            if s.kind == "news" and s.severity >= 2 and news_credible(getattr(s, "meta", None)):
                cred[k] = max(cred.get(k, 0), s.severity)

    # A debunk or denial only counts if it is about the same area as the story it would cancel (an unrelated "hoax bomb
    # threat" or "package was not malicious" headline must not switch off a real blackout), comes from a source with a
    # record, and there are at least two. Denials are never counted as attack headlines.
    rel_areas = set(active) | set(cred) | {k for k in cats if cats[k]["level"] >= 2 and k not in ("elite", "markets", "space", "natural")}
    rel_rx = re.compile("|".join(DOMAIN_KW[k] for k in rel_areas if k in DOMAIN_KW) or r"(?!x)x", re.I)

    def relevant(rx):         # denials: about an outage, from a source with a record, at least two
        got = {h for h, o in heads_o if rx.search(h) and rel_rx.search(h) and tier_of(o) != 4}
        return len(got) if len(got) >= 2 else 0

    # A debunk cancels only the area it is about. A headline naming one area's words belongs to that area; a generic one
    # ("outage claims are false") counts toward every active area. An area is debunked with two such headlines.
    live_areas = [k for k in AREA_WORDS if k in rel_areas]
    deb_count = {k: 0 for k in live_areas}
    for h in {h for h, o in heads_o if DEBUNK_RX.search(h) and tier_of(o) != 4}:
        named = [k for k in AREA_WORDS if re.search(AREA_WORDS[k], h, re.I)]
        for k in (named if named else live_areas):
            if k in deb_count:
                deb_count[k] += 1
    debunked = {k for k, c in deb_count.items() if c >= 2}

    n_cyber = sum(1 for h in heads if CYBER_RX.search(h) and not DENIAL_RX.search(h))
    n_phys, n_sab = hits(PHYS_RX), hits(SAB_RX)
    n_strat, n_denial = hits(STRAT_RX), relevant(DENIAL_RX)
    n_vendor, n_debunk = hits(VENDOR_RX), len(debunked)
    gate = bool(clusters) or slow_on

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
    if slow_on:
        add("cyber", 3 if n_cyber >= 2 else 1, f"A slow burn: {sb['n_sustained']} different essential or threat areas have shown "
            "credible trouble for hours. A rolling, staggered campaign looks like this; one accident usually does not", True)
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
    unconfirmed = [k for k in cats if k != "elite" and cats[k]["level"] >= 2 and not prim(k) and k not in cred]
    contained = [k for k in unconfirmed if k == "aviation" and air_normal]
    rest = [k for k in unconfirmed if k not in contained]
    if contained:
        add("accident", 2, "The news is loud, but nationwide air-traffic data (FAA stops, aircraft count) looks normal: "
                           "this looks specific to one airline or vendor, not a problem with US airspace")
    if rest:
        add("hoax", 2, "No government or live-data source confirms it: " + ", ".join(CATEGORIES[k] for k in rest))
    if n_debunk:
        add("hoax", 3, "News outlets are calling claims about " + ", ".join(sorted(debunked)) + " fake, doctored or misinformation")

    # ---- social claims that are spreading, checked against everything else (credibility.py)
    checks, claim_lines = {}, []
    for k, c in cats.items():
        cl = c.get("claims") or []
        if not cl:
            continue
        best = cl[0]
        checks[k] = best["verdict"]
        if best["verdict"] == "refuted":
            add("hoax", 2, f"A spreading social-media claim about {CATEGORIES[k].lower()} is being called fake by news outlets")
        elif best["verdict"] == "rumor":
            add("hoax", 1, f"A spreading social-media claim about {CATEGORIES[k].lower()} comes from low-credibility accounts "
                           "and nothing else confirms it")
        weak = "; ".join(p["why"] for p in best["parts"][:3])
        claim_lines.append((best["engagement"], f"A {best['platform']} post about {CATEGORIES[k].lower()} is spreading "
                            f"({best['engagement']} reactions). Claim check: {best['score']}/100, {best['verdict']}. {weak}."))
    claim_lines = [t for _, t in sorted(claim_lines, reverse=True)[:2]]

    # a natural hazard with an official warning is a plan-changing event in its own right (and a cause)
    hazard_sev = max([x.severity for x in prim("natural") if "official-hazard" in x.tags] or [0])
    if hazard_sev >= 2:
        add("natural", 4, "An official Weather Service warning is active for a major hazard (hurricane, ice storm, blizzard, extreme wind)")

    # ---- canary: credible reporting while officials are still silent (never replaces telemetry for the top level)
    cred_dom = [k for k in cred if k not in explained and k not in contained]
    life_cred = [k for k in cred_dom if k in LIFELINE]
    life_cred = [k for k in life_cred if k not in debunked]
    sec_cred = cred.get("security", 0) >= 3 and "security" not in debunked
    canary = len(life_cred) >= 2 or sec_cred
    if sec_cred:
        add("physical", 3, "Several independent top-tier news outlets report a large-scale or coordinated attack "
                           "(government sources have not confirmed it yet, and they are often slow to)", True)
    elif len(life_cred) >= 2 and not prim_sigs:
        add("cyber", 1, "Several top-tier outlets credibly report trouble in more than one essential area at once", True)

    score = {h: max(0.0, round(sum(e["pts"] for e in ev[h]), 1)) for h in HYP}
    A = max(score[h] for h in ATTACK)
    B = max(score[h] for h in ("accident", "natural", "hoax"))
    lead_attack = max(ATTACK, key=lambda h: score[h])
    official_strong = (lead_attack == "cyber" and "official-cyber" in tags) or \
                      (lead_attack == "strategic" and "official-strategic" in tags) or \
                      (lead_attack == "physical" and flags["threat:physical"])

    # ---- 5. level. IMPACT FIRST: is something real, confirmed and significant reaching you, and how bad? The CAUSE (accident,
    # weather, attack) is a label on it, and only the top step needs an attack-shaped pattern. A big storm that takes down power
    # counts as an impact just like a hacker would; a cascade or a storm no longer makes a real disruption disappear.
    def official_sev(d):          # routine weather ground stops are not a disruption to anyone's life
        return max([x.severity for x in prim(d) if not (d == "aviation" and "weather-attributed" in x.tags)] or [0])

    sig = {}                      # significant, confirmed disruptions by area: (how we know, severity)
    for d in LIFELINE:
        if d in contained:
            continue
        o = official_sev(d)
        if o >= 2:
            sig[d] = ("official", o)
        elif d in cred and cats[d]["level"] >= 2 and d not in debunked:
            sig[d] = ("credible", 2)               # several top outlets, officials silent so far (unless debunked)
        elif o >= 1 and cats[d]["level"] >= 2:
            sig[d] = ("official", 1)               # a minor official reading that news also reports at level 2
    if hazard_sev >= 2:
        sig["natural"] = ("official", hazard_sev)
    n_sig = len(sig)
    # still going after hours: it is not a blip. An essential service confirmed down for 6+ hours will change plans for days.
    long_lasting = any(k == "official" and d in ESSENTIAL and onset.get(d) and now - onset[d] >= 6 * 3600
                       for d, (k, sv) in sig.items())
    critical = any(k == "official" and sv >= 3 and d in ESSENTIAL for d, (k, sv) in sig.items())
    official3 = any(official_sev(d) >= 3 for d in LIFELINE) or any(x.severity >= 3 for x in prim_sigs if x.category not in LIFELINE)
    corrob = any(cats[k]["level"] >= 2 and len({x.kind for x in cats[k]["signals"]
                                                if x.severity >= 1 and x.kind not in ("system", "social")}) >= 2
                 for k in LIFELINE + ("cyber", "nuclear")     # not 'security': daily local incidents are not national alarms
                 if k not in explained)                       # an explained disruption does not raise the alarm
    any_active = any(cats[k]["level"] >= 1 for k in cats)
    attack_pattern = n_conf >= 1 and A >= T3 and A - B >= margin
    threat_here = flags["threat:cyber"] or flags["threat:physical"]
    rules = []                    # every condition that holds, so a false alarm can be traced to the rule that caused it
    if flags["threat:strategic"]:
        rules.append("official strategic warning")
    if flags["danger:here"]:
        rules.append("official civil-danger warning for this area")
    if hazard_sev >= 3:
        rules.append("official warning of an imminent major hazard")
    if attack_pattern and (n_sig >= 2 or (n_sig >= 1 and official_strong)):
        rules.append("attack-shaped pattern with confirmed disruptions")
    if critical and n_sig >= 2:
        rules.append("critical essential failure that is spreading")
    if n_sig >= 2:
        rules.append(f"{n_sig} confirmed disruptions ({', '.join(sorted(sig))})")
    if critical:
        rules.append("critical failure of an essential service")
    if long_lasting:
        rules.append("essential service down for 6+ hours")
    if hazard_sev == 2:
        rules.append("official warning for a major hazard")
    if official3:
        rules.append("a critical official signal")
    if corrob:
        rules.append("several kinds of source agree on one area")
    if canary:
        rules.append("several top outlets report it (officials silent)")
    if slow_on:
        rules.append("slow burn across several areas")
    if threat_here and n_sig >= 1:
        rules.append("official threat warning plus a disruption")
    if flags["threat:strategic"] or hazard_sev >= 3 or flags["danger:here"]:
        level = 3                                       # an official warning of an imminent major threat: strategic, or a hurricane
    elif attack_pattern and (n_sig >= 2 or (n_sig >= 1 and official_strong)):
        level = 3                                       # an attack-shaped pattern of confirmed disruptions
    elif critical and n_sig >= 2:
        level = 3                                       # a critical failure of something essential, spreading, whatever the cause
    elif n_sig >= 2 or critical or long_lasting or hazard_sev >= 2 or official3 or corrob or canary or slow_on \
            or (threat_here and n_sig >= 1):
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
    reasons += claim_lines
    if slow_on:
        reasons.append(sb["why"])
    if canary and level >= 2 and not n_conf:
        reasons.append("Several independent top-tier news outlets are reporting this and no government source has "
                       "confirmed it yet. Governments are often slow to confirm bad news, so this is treated as credible.")
    if explained:
        reasons.append("These look explained by something else: " + "; ".join(f"{CATEGORIES[d]} ({w})" for d, (_k, w) in explained.items()))
    if not reasons:
        hot = [CATEGORIES[k] for k in cats if cats[k]["level"] >= 1 and k != "elite"]
        cr = [CATEGORIES[k] for k in cred if cats[k]["level"] >= 1]
        if hot:
            reasons.append("Some unusual activity in: " + ", ".join(hot) + " (not confirmed by official sources yet"
                           + (f"; several independent top-tier outlets are reporting {', '.join(cr)}" if cr else "") + ").")
        else:
            reasons.append("Nothing unusual is showing up.")
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
        "credible": sorted(cred), "canary": bool(canary), "impact": {d: {"how": k, "sev": sv} for d, (k, sv) in sig.items()},
        "attack_pattern": bool(attack_pattern), "critical": bool(critical), "long_lasting": bool(long_lasting), "rules": rules, "social_checks": checks,
        "claims": [dict(cl[0], category=k) for k, c in cats.items() for cl in [c.get("claims") or []] if cl][:5], "slow_burn": sb or {"active": False},
        "verify": [{"title": t, "url": u} for t, u in verify[:8]],
    }
