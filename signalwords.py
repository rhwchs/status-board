"""Scores a headline or paragraph on two things, not one: WHAT it is about and WHAT is happening to it.

A flat keyword list floods an early-warning monitor with junk ("Falcons attack the line", "power outage at the mall").
So text only counts when BOTH show up:

    infrastructure noun   what is affected (power grid, pipeline, water treatment plant, cell tower, rail, SCADA...)
    event word            what is happening to it (cyberattack, sabotage, explosion, outage, rupture, shutdown...)

and then multipliers decide how loudly it should count:

    scale       widespread, nationwide, multi-state, millions without power, cascading
    official    state of emergency, federal emergency declaration, evacuation, shelter in place, emergency order
    agency      CISA advisory, emergency directive, FBI warning, DHS bulletin, NTAS, joint advisory
    local       places you care about (kept in data/local_terms.json, never in code, so they stay private)

Event words come in two strengths. STRONG ones say something is wrong by themselves (cyberattack, sabotage, explosion,
derailment, blackout). BROAD ones are everyday words (fire, leak, breach, outage, failure, shutdown) that appear in
ordinary local stories, so a pair built only from broad words can raise a WATCH at most until a second outlet or a
feed confirms it. NEGATIVE words (sports, product outages, market "crashes", movie and TV listings) drop the text
unless an official source confirms it.

Nothing here fetches anything: it is plain text scoring, tested in signalwords_tests.py.
"""
import json
import os
import re

I = re.I


def _rx(*parts):
    return re.compile(r"\b(?:" + "|".join(parts) + r")", I)


# ------------------------------------------------------------------ 1. what is affected, by area
INFRA = {
    "power": _rx(r"power grid", r"grid operators?", r"the grid\b", r"grid failure", r"substations?", r"transformers?", r"transmission lines?", r"blackouts?",
                 r"rolling blackouts?", r"load shedding", r"grid emergency", r"energy emergency alert", r"\bEEA\b",
                 r"\bNERC\b", r"\bFERC\b", r"power plants?", r"electric(?:al)? grid", r"utility", r"utilities",
                 r"power outages?", r"power lines?", r"without power", r"electric(?:ity)? (?:cooperative|co-?op)"),
    "fuel": _rx(r"pipelines?", r"Colonial Pipeline", r"Plantation Pipeline", r"refiner(?:y|ies)", r"natural gas",
                r"compressor stations?", r"fuel shortages?", r"gas stations?", r"gasoline", r"fuel supply", r"\bLNG\b",
                r"fuel terminals?"),
    "water": _rx(r"water treatment", r"water tanks?", r"water systems?", r"water utilit(?:y|ies)", r"boil water", r"water mains?",
                 r"\bdams?\b", r"reservoirs?", r"wastewater", r"drinking water", r"water supply"),
    "telecom": _rx(r"cell towers?", r"cell service", r"fiber cuts?", r"fiber(?:-| )optic", r"\b911\b", r"internet outages?",
                   r"AT&T", r"Verizon", r"T-Mobile", r"undersea cables?", r"subsea cables?", r"GPS jamming",
                   r"GPS spoofing", r"phone service", r"wireless (?:network|service|carrier)", r"data centers?"),
    "transport": _rx(r"rail(?:road|way)?s?", r"trains?", r"derailments?", r"bridges?", r"ports?\b", r"air traffic control",
                     r"FAA", r"ground stops?", r"interstates?", r"highways?", r"airports?", r"airlines?", r"flights?",
                     r"tunnels?", r"shipping lanes?", r"terminals?"),
    "industrial": _rx(r"chemical plants?", r"nuclear (?:plants?|power|reactors?|facilit(?:y|ies))", r"hazmat",
                      r"SCADA", r"\bICS\b", r"industrial control systems?", r"industrial facilit(?:y|ies)",
                      r"manufacturing plants?", r"refineries"),
    "finance": _rx(r"payment systems?", r"ATMs?", r"banking", r"bank outages?", r"supply chains?", r"payment networks?",
                   r"card payments?", r"stock exchanges?"),
    "government": _rx(r"Pentagon", r"military", r"Air Force", r"\bArmy\b", r"\bNavy\b", r"air defense", r"FinCEN", r"cloud (?:platform|systems?)", r"computing platform", r"government (?:systems?|networks?|departments?|agenc(?:y|ies))", r"health care system", r"hospitals?", r"military (?:networks?|systems?|bases?)", r"Air Force", r"federal agenc(?:y|ies)",
                      r"State Department", r"Treasury", r"Department of (?:Defense|Energy|Homeland Security)",
                      r"critical infrastructure"),
}

# ------------------------------------------------------------------ 2. what is happening
STRONG_EVENTS = _rx(
    r"cyber ?attacks?", r"ransomware", r"sabotage", r"sabotaged", r"gunfire", r"shots? fired", r"drone sightings?",
    r"drone incursions?", r"nation-state", r"Volt Typhoon", r"Salt Typhoon", r"zero-days?", r"actively exploited",
    r"explosions?", r"explod\w+", r"blasts?", r"derail\w+", r"collapse[ds]?", r"ruptur\w+", r"blackouts?",
    r"rolling blackouts?", r"grid emergency", r"geomagnetic storms?", r"solar flares?", r"\bCME\b", r"\bG[45]\b",
    r"hackers? (?:breach\w*|hit|took down|disrupt\w*|broke into)", r"hack(?:ed|ing|ers?)\b", r"broke into", r"cyber incident", r"security incident",
    r"takes? (?:systems?|networks?) offline", r"do[- ]not[- ]drink", r"contaminat\w+", r"cyber (?:espionage|intrusion)", r"cut (?:lines?|cables?)",
    r"fiber cuts?", r"shut down nationwide", r"nationwide outage", r"ground stops?",
)
BROAD_EVENTS = _rx(
    r"fires?\b", r"burning", r"leaks?\b", r"leaking", r"spills?\b", r"breach\w*", r"intrusions?", r"vandali[sz]\w+",
    r"outages?", r"failures?", r"failed", r"shutdowns?", r"shut down", r"offline", r"disrupt\w+", r"down\b",
    r"earthquakes?", r"hurricane landfall", r"ice storms?", r"wildfires?", r"flooding", r"floods?", r"without power",
    r"boil water", r"water main break", r"shortages?", r"closure[sd]?", r"closed",
    r"ground(?:ed|ings?)\b", r"halt(?:s|ed)?\b", r"cancel(?:led|ed|s)?\b", r"delays?\b", r"suspend\w+", r"knocked out",
)

# ------------------------------------------------------------------ 3. how big and how urgent
SCALE = _rx(r"widespread", r"nationwide", r"multi-?state", r"regional", r"statewide", r"millions", r"hundreds of thousands",
            r"cascading", r"across the (?:country|nation|region)", r"coast to coast", r"mass outage")
OFFICIAL = _rx(r"state of emergency", r"federal emergency", r"emergency declaration", r"evacuat\w+", r"shelter in place",
               r"emergency order", r"disaster declaration", r"martial law")
AGENCY = _rx(r"CISA", r"emergency directive", r"FBI warn\w*", r"FBI says", r"DHS bulletin", r"\bNTAS\b",
             r"joint advisory", r"cybersecurity advisory", r"Department of Homeland Security")

# ------------------------------------------------------------------ 4. noise to cut
NEGATIVE = re.compile(
    r"\b(?:touchdowns?|playoffs?|quarterback|offensive (?:line|coordinator)|defensive (?:line|end|back|coordinator|tackle)|offense (?:stalls|scores|struggles)|defense (?:holds|stalls)|linebacker|NFL|NBA|MLB|NHL|NCAA|"
    r"attack the (?:basket|line|net|rim)|Falcons|football|basketball|baseball|hockey|"
    r"tournament|box office|trailer|season finale|episode|netflix|hbo|disney\+|streaming|movie|film|"
    r"video game|esports|fortnite|roblox|playstation|xbox|album|concert|stock(?:s| market)? crash\w*|"
    r"crash(?:ed|es|ing)? (?:the )?(?:market|stocks?|shares)|bitcoin|crypto|black friday|"
    r"coupon|horoscope|recipe)\b|"
    r"\bgrid\b.{0,20}\b(?:game|football|basketball)\b|\b(?:game|football|basketball)\b.{0,20}\bgrid\b|"
    r"\b(?:netflix|youtube|instagram|snapchat|tiktok|spotify|twitch|discord|steam|playstation network|xbox live|chatgpt)\b"
    r".{0,30}\b(?:down|outage|not working)\b", I)

LOCAL_FILE = "local_terms.json"


def load_local(data_dir):
    """Places you care about, from data/local_terms.json (a JSON list of words). Private: never part of the published code."""
    try:
        with open(os.path.join(data_dir, LOCAL_FILE), encoding="utf-8") as f:
            terms = [t for t in json.load(f) if isinstance(t, str) and t.strip()]
    except (OSError, ValueError, TypeError):
        return None
    if not terms:
        return None
    return re.compile(r"\b(?:" + "|".join(re.escape(t.strip()) for t in terms) + r")\b", I)


def analyze(text, local_rx=None, category=None):
    """Return what the text is about and what is happening:
    areas      infrastructure areas it names
    strong     strong event words found
    broad      broad (everyday) event words found
    pair       an infrastructure noun AND an event word are both present
    solid      the pair includes a strong event word (a broad-only pair is capped at WATCH by the caller)
    mult       which multipliers apply: scale, official, agency, local
    junk       a noise pattern matched (sports, product outage, market crash, entertainment)
    """
    t = text or ""
    areas = {a for a, rx in INFRA.items() if rx.search(t)}
    strong = {m.group(0).lower() for m in STRONG_EVENTS.finditer(t)}
    broad = {m.group(0).lower() for m in BROAD_EVENTS.finditer(t)}
    mult = set()
    if SCALE.search(t):
        mult.add("scale")
    if OFFICIAL.search(t):
        mult.add("official")
    if AGENCY.search(t):
        mult.add("agency")
    if local_rx is not None and local_rx.search(t):
        mult.add("local")
    pair = bool(areas) and bool(strong or broad)
    if category == "cyber" and strong:          # a hack is its own subject: the target need not be an infrastructure noun
        pair = True
    return {"areas": areas, "strong": strong, "broad": broad, "pair": pair, "solid": pair and bool(strong),
            "mult": mult, "junk": bool(NEGATIVE.search(t))}


def worth_counting(text, local_rx=None, confirmed=False):
    """The rule from the spec: count a text only when infrastructure and event both appear; drop junk unless confirmed."""
    a = analyze(text, local_rx)
    if a["junk"] and not confirmed:
        return False, a
    return a["pair"], a
