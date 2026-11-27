"""Data collectors.

Each collector is a function fn(ctx) -> CollectResult. Raising an exception means
"this source failed" (the dashboard shows it as unreachable; it is never silently
treated as 'all clear').

Severity scale used everywhere:
  0 = status / context only      1 = watch
  2 = elevated                   3 = critical
"""
import copy
import html
import json
import os
import random
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import credibility
import freshness
import geo
import signalwords
import storyread
import trust

UA = "status-board/1.0 (public-data summary page)"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

CATEGORIES = {
    "aviation":  "Air travel",
    "telecom":   "911 & telecom",
    "power":     "Electric power",
    "internet":  "Internet & cloud",
    "cyber":     "Hacking and cyber attacks",
    "security":  "Attacks and violence",
    "nuclear":   "Nuclear, missile and EMP threats",
    "emergency": "Civil emergency alerts",
    "finance":   "Banks and payments",
    "markets":   "Stock market",
    "space":     "Solar storms (can act like an EMP)",
    "natural":   "Earthquakes and natural events",
    "roads":     "Roads and highways",
    "fuel":      "Fuel and gas",
    "water":     "Water systems",
    "transport": "Rail, ports and bridges",
    "industrial": "Industrial and chemical sites",
    "elite":     "Wealthy people leaving (weak signal)",
    "local":     "Near you",          # your own county: shown on its own card, never feeds the national alarm
}


@dataclass
class Signal:
    category: str
    severity: int
    title: str
    url: str = ""
    detail: str = ""
    key: str = ""
    time: float = field(default_factory=time.time)
    links: list = field(default_factory=list)   # [{"title":..., "url":...}]
    tags: list = field(default_factory=list)    # evidence tags read by assess.py (e.g. "official-cyber")
    source: str = ""                             # filled in by the engine
    kind: str = ""                               # gov | private | news | social
    meta: dict = field(default_factory=dict)     # extra evidence: news trust summary, social claim checks
    states: list = field(default_factory=list)   # footprint: state codes this is about; empty = nationwide / unknown

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class CollectResult:
    signals: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)


# --------------------------------------------------------------------- helpers

def _ssl_context():
    """python.org builds on macOS ship without root certs; fall back to the system bundle.
    Verification stays ON in every case."""
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except ImportError:
        if os.path.exists("/etc/ssl/cert.pem"):
            ctx.load_verify_locations("/etc/ssl/cert.pem")
    return ctx


SSL_CTX = _ssl_context()


def fetch(url, browser=False, timeout=20, max_bytes=12_000_000, headers=None, curl_first=False, gzip_ok=False):
    if gzip_ok:          # ask for a compressed answer (big JSON feeds shrink about tenfold) and unpack it here
        import gzip
        data = fetch(url, browser, timeout, max_bytes, dict(headers or {}, **{"Accept-Encoding": "gzip"}), curl_first)
        return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
    h = {"User-Agent": BROWSER_UA if browser else UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    if curl_first:       # a few sites (Yahoo Finance) answer curl but throttle Python's TLS handshake
        data = _curl(url, h, timeout)
        if len(data) > max_bytes:
            raise ValueError("response too large")
        return data
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            data = r.read(max_bytes + 1)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        # Some public feeds reject Python's TLS handshake (403) or serve an incomplete
        # certificate chain. The system curl handles both; verification stays on.
        retry = (isinstance(e, urllib.error.HTTPError) and e.code == 403) or \
                isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError)
        if not retry:
            raise
        data = _curl(url, h, timeout)
    if len(data) > max_bytes:
        raise ValueError("response too large")
    return data


def _curl(url, headers, timeout):
    cmd = ["curl", "-sSL", "--fail", "--max-time", str(timeout), "-A", headers["User-Agent"]]
    for k, v in headers.items():
        if k != "User-Agent":
            cmd += ["-H", f"{k}: {v}"]
    r = subprocess.run(cmd + [url], capture_output=True, timeout=timeout + 5)
    if r.returncode != 0:
        raise RuntimeError(f"curl fallback failed ({r.returncode}): {r.stderr.decode()[:120].strip()}")
    return r.stdout


def fetch_json(url, **kw):
    return json.loads(fetch(url, **kw).decode("utf-8-sig"))


def parse_time(s):
    if not s:
        return None
    s = s.strip()
    try:
        dt = parsedate_to_datetime(s)
    except Exception:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_feed(data):
    """RSS or Atom -> [{'title','link','time','source'}]."""
    root = ET.fromstring(data)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        d = {"title": "", "link": "", "time": None, "source": ""}
        for ch in el:
            ln = _local(ch.tag).lower()
            if ln == "title":
                d["title"] = (ch.text or "").strip()
            elif ln == "link" and not d["link"]:
                d["link"] = (ch.get("href") or ch.text or "").strip()
            elif ln in ("pubdate", "updated", "published") and d["time"] is None:
                d["time"] = parse_time(ch.text)
            elif ln == "source":
                d["source"] = (ch.text or "").strip()
        out.append(d)
    return out


def rate_per_hour(times, limit, now):
    """Posts/hour from a newest-first sample capped at `limit` results. If the cap was hit
    with every post inside the last hour, extrapolate from how fast the sample filled."""
    recent = [t for t in times if t and now - t < 3600]
    if len(times) < limit or len(recent) < limit:
        return len(recent)
    span_h = max((now - min(recent)) / 3600, 1 / 120)
    return int(min(limit / span_h, 5000))


def strip_html(s):
    return html.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


def short(s, n=140):
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def ago(ts):
    d = max(0, time.time() - ts)
    return f"{int(d // 60)}m" if d < 3600 else f"{d / 3600:.1f}h"


# ------------------------------------------------------------------ government

def faa_nas(ctx):
    """FAA National Airspace System status: ground stops, delays, closures."""
    root = ET.fromstring(fetch("https://nasstatus.faa.gov/api/airport-status-information"))
    sus = re.compile(r"secur|equip|outage|telecom|atc|power|system|cyber|threat|tfr|evacu|fire|emergen|national", re.I)
    stops = [(p.findtext("ARPT") or "?", (p.findtext("Reason") or "").strip())
             for p in root.iter("Program")]
    delays = len(list(root.iter("Ground_Delay")))
    odd = [(a, r) for a, r in stops if sus.search(r)]
    n, k = len(stops), len(odd)
    if n >= 15 or k >= 5:
        sev = 3
    elif n >= 6 or k >= 3:
        sev = 2
    elif n >= 3 or k >= 1:
        sev = 1
    else:
        sev = 0
    url = "https://nasstatus.faa.gov/"
    secstop = ["security-stop"] if any(re.search(r"secur|threat|evacu|tfr", r, re.I) for _, r in stops) else []
    if stops and not odd:
        secstop = secstop + ["weather-attributed"]   # every stop has a routine reason (weather, volume, runway)
    listing = ", ".join(f"{a} ({r or 'no reason given'})" for a, r in stops[:14])
    sigs = [Signal("aviation", sev, f"{n} airports have flights stopped by the FAA ({k} not for weather)",
                   url, listing or "No flight stops.", key="faa:agg", tags=secstop)]
    for a, r in odd[:6]:
        sigs.append(Signal("aviation", 1, f"Flights stopped at {a}: {r or 'no reason given'}", url,
                           key=f"faa:stop:{a}"))
    return CollectResult(sigs, {"ground_stops": n, "non_weather": k, "ground_delays": delays})


# event name -> (category, base severity, states needed for +1 bump)
NWS_EVENTS = {
    "911 Telephone Outage Emergency": ("telecom", 2, 2),
    "Civil Emergency Message": ("emergency", 1, 3),
    "Civil Danger Warning": ("emergency", 2, 3),
    "Nuclear Power Plant Warning": ("nuclear", 3, 99),
    "Radiological Hazard Warning": ("nuclear", 3, 99),
    "Hazardous Materials Warning": ("emergency", 1, 5),
    "Shelter In Place Warning": ("emergency", 1, 4),
    "Law Enforcement Warning": ("security", 1, 3),
    "Local Area Emergency": ("emergency", 1, 4),
    "Tsunami Warning": ("natural", 2, 99),
    "Earthquake Warning": ("natural", 2, 99),
}


def _nws_tags(event, sev):
    """Evidence tags for the assessment: which NWS products signal a deliberate/strategic threat."""
    if event == "Law Enforcement Warning":      # routinely used for local manhunts: a threat only when it spans several states
        return ["official-physical"] if sev >= 2 else []
    if event == "Civil Danger Warning":
        return ["official-physical"] + (["official-strategic"] if sev >= 3 else [])
    if event in ("Nuclear Power Plant Warning", "Radiological Hazard Warning"):
        return ["official-strategic"]
    return []


def nws_alerts(ctx):
    """National Weather Service emergency-class alerts (also carries EAS/WEA civil alerts)."""
    q = urllib.parse.quote(",".join(NWS_EVENTS), safe=",")
    url = f"https://api.weather.gov/alerts/active?status=actual&message_type=alert,update&event={q}"
    feats = fetch_json(url, headers={"Accept": "application/geo+json"}).get("features", [])
    by = {}
    for f in feats:
        p = f.get("properties", {})
        by.setdefault(p.get("event"), []).append(f)
    sigs = []
    for ev, (cat, base, bump_at) in NWS_EVENTS.items():
        items = by.get(ev)
        if not items:
            continue
        states = set()
        for f in items:
            for u in (f["properties"].get("geocode") or {}).get("UGC", []):
                states.add(u[:2])
        sev = min(3, base + (1 if len(states) >= bump_at else 0))
        links = [{"title": short(f["properties"].get("headline") or f["properties"].get("areaDesc"), 110),
                  "url": f.get("id", "")} for f in items[:6]]
        sigs.append(Signal(cat, sev, f"Weather Service alert: {ev} — {len(items)} active in {len(states)} state(s)",
                           "https://alerts.weather.gov/", ", ".join(sorted(states)), key=f"nws:{ev}",
                           links=links, tags=_nws_tags(ev, sev), states=sorted(states & geo.VALID_STATES),
                           meta={"event": ev}))
    if not sigs:
        sigs.append(Signal("emergency", 0, "No emergency-level Weather Service alerts right now",
                           "https://alerts.weather.gov/", key="nws:none"))
    return CollectResult(sigs, {"active_emergency_alerts": len(feats)})


WEATHER_EVENTS = ("Hurricane Warning", "Tropical Storm Warning", "Tornado Warning", "Blizzard Warning",
                  "Ice Storm Warning", "Winter Storm Warning", "Extreme Wind Warning", "Storm Surge Warning",
                  "Excessive Heat Warning", "Extreme Heat Warning", "High Wind Warning", "Flash Flood Warning",
                  "Fire Warning", "Evacuation Immediate", "Extreme Cold Warning")
HAZARD_SEVERITY = {"Hurricane Warning": 3, "Storm Surge Warning": 3, "Extreme Wind Warning": 2, "Ice Storm Warning": 2,
                   "Blizzard Warning": 2, "Fire Warning": 2, "Evacuation Immediate": 2,
                   "Extreme Cold Warning": 2}  # official warnings people rearrange their next few days around
# The "emergency" tag inside an ordinary warning: catastrophic damage threat (Tornado Emergency, Flash Flood Emergency)
EMERGENCY_TAGS = {"Tornado Warning": ("tornadoDamageThreat", "Tornado Emergency"),
                  "Flash Flood Warning": ("flashFloodDamageThreat", "Flash Flood Emergency")}


def _states_of(items):
    st = set()
    for f in items:
        for u in (f["properties"].get("geocode") or {}).get("UGC", []):
            st.add(u[:2])
    return st & geo.VALID_STATES


def _hazard_signal(ev, sev, items):
    st = _states_of(items)
    return Signal("natural", sev, f"{ev}: {len(items)} active in {', '.join(sorted(st)) or 'the US'}",
                  "https://alerts.weather.gov/", "An official Weather Service warning for a hazard that changes plans for days.",
                  key=f"nws:hazard:{ev}", tags=["official-hazard"], states=sorted(st), meta={"event": ev},
                  links=[{"title": short(f["properties"].get("headline") or f["properties"].get("areaDesc"), 110),
                          "url": f.get("id", "")} for f in items[:6]])
WEATHER_MAJOR = ("Hurricane Warning", "Ice Storm Warning", "Blizzard Warning", "Extreme Wind Warning",
                 "Storm Surge Warning")


def nws_weather(ctx):
    """Severe-weather context. Never raises an alarm itself; it lets the assessment recognise when a storm
    is a plausible, benign explanation for regional power / telecom / flight disruptions."""
    q = urllib.parse.quote(",".join(WEATHER_EVENTS), safe=",")
    feats = fetch_json("https://api.weather.gov/alerts/active?status=actual&message_type=alert,update&event=" + q,
                       headers={"Accept": "application/geo+json"}).get("features", [])
    counts = {}
    for f in feats:
        e = f.get("properties", {}).get("event")
        counts[e] = counts.get(e, 0) + 1
    major = (any(counts.get(e) for e in WEATHER_MAJOR) or counts.get("Tornado Warning", 0) >= 5
             or len(feats) >= 150)
    top = ", ".join(f"{k} x{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:4])
    sigs = [Signal("natural", 0, f"Severe weather right now: {len(feats)} active warnings" + (" (major storms)" if major else ""),
                   "https://www.weather.gov/", top or "none", key="nws:weather",
                   tags=["weather-major"] if major else [])]
    # Major hazards that change people's plans for days (a hurricane, an ice storm) are real events with a footprint.
    for ev, sev in HAZARD_SEVERITY.items():
        items = [f for f in feats if f.get("properties", {}).get("event") == ev]
        if items:
            sigs.append(_hazard_signal(ev, sev, items))
    for ev, (param, name) in EMERGENCY_TAGS.items():
        items = [f for f in feats if f.get("properties", {}).get("event") == ev
                 and "CATASTROPHIC" in [str(x).upper() for x in ((f["properties"].get("parameters") or {}).get(param) or [])]]
        if items:
            sigs.append(_hazard_signal(name, 2, items))
    return CollectResult(sigs, {"weather_warnings": len(feats), "major": major})


def swpc(ctx):
    """NOAA Space Weather scales: geomagnetic storms (the natural 'EMP-like' risk to grids)."""
    d = fetch_json("https://services.swpc.noaa.gov/products/noaa-scales.json")["0"]
    g, r, s = (int(d[k]["Scale"] or 0) for k in ("G", "R", "S"))
    sev = max({0: 0, 1: 0, 2: 0, 3: 0, 4: 2, 5: 3}.get(g, 3),
              {0: 0, 1: 0, 2: 0, 3: 1, 4: 2, 5: 3}.get(r, 3),
              {0: 0, 1: 0, 2: 0, 3: 1, 4: 2, 5: 3}.get(s, 3))
    return CollectResult(
        [Signal("space", sev, f"Solar-storm levels now: geomagnetic G{g}, radio blackout R{r}, radiation S{s} (0 = calm, 5 = extreme)",
                "https://www.swpc.noaa.gov/", "A level 4 or 5 geomagnetic storm can strain power grids and satellites.", key="swpc")],
        {"G": g, "R": r, "S": s})


def usgs(ctx):
    """USGS: large earthquakes and explosion-type seismic events (last hour)."""
    d = fetch_json("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_hour.geojson")
    sigs = []
    for f in d.get("features", []):
        p = f["properties"]
        mag, typ = p.get("mag") or 0, p.get("type") or "earthquake"
        if typ == "nuclear explosion":
            sigs.append(Signal("nuclear", 3, f"Earthquake sensors: possible NUCLEAR EXPLOSION, magnitude {mag}, {p.get('place')}",
                               p.get("url", ""), key=f"usgs:{f['id']}", tags=["official-strategic"]))
        elif typ == "explosion":
            sigs.append(Signal("nuclear", 1, f"Earthquake sensors: explosion-type event, magnitude {mag}, {p.get('place')}",
                               p.get("url", ""), key=f"usgs:{f['id']}"))
        elif mag >= 6:
            sigs.append(Signal("natural", 2 if mag >= 7 else 1, f"Earthquake, magnitude {mag}, {p.get('place')}",
                               p.get("url", ""), key=f"usgs:{f['id']}", time=(p.get("time") or 0) / 1000))
    if not sigs:
        sigs.append(Signal("natural", 0, "No major earthquakes or explosion-type events in the last hour",
                           "https://earthquake.usgs.gov/earthquakes/map/", key="usgs:none"))
    return CollectResult(sigs, {"events_4.5+_1h": len(d.get("features", []))})


def sans_infocon(ctx):
    """SANS Internet Storm Center threat level (volunteer-run global cyber early warning)."""
    st = fetch_json("https://isc.sans.edu/api/infocon?json").get("status", "green")
    sev = {"green": 0, "yellow": 1, "orange": 2, "red": 3}.get(st, 0)
    return CollectResult([Signal("cyber", sev, f"Internet cyber-threat level (SANS): {st.upper()}",
                                 "https://isc.sans.edu/", key="sans",
                                 tags=["official-cyber"] if sev >= 2 else [])], {"infocon": st})


def cisa(ctx):
    """CISA alerts & advisories: Emergency Directives, joint Cybersecurity Advisories (CSAs), KEVs."""
    items = parse_feed(fetch("https://www.cisa.gov/cybersecurity-advisories/all.xml", timeout=40))[:40]
    now = time.time()
    ed = re.compile(r"emergency directive", re.I)
    csa = re.compile(r"cybersecurity advisory|#stopransomware|joint|partners urge|\bAA\d\d-", re.I)
    sigs, kev = [], 0
    for it in items:
        age = now - (it["time"] or now)
        if age > 36 * 3600:
            continue
        t = it["title"]
        if re.search(r"known exploited", t, re.I):
            kev += 1
        if ed.search(t) and age > 6 * 3600:          # an emergency order is a fresh warning, not a day-and-a-half one
            continue
        if csa.search(t) and not ed.search(t) and age > 12 * 3600:
            continue
        if ed.search(t):
            sigs.append(Signal("cyber", 2, f"CISA EMERGENCY ORDER to federal agencies: {t}", it["link"], key="cisa:" + it["link"],
                               tags=["official-cyber"]))
        elif csa.search(t):
            sigs.append(Signal("cyber", 1, f"CISA advisory: {t}", it["link"], key="cisa:" + it["link"]))
    sigs.append(Signal("cyber", 0, f"CISA (US cyber agency): {len(sigs)} new advisories and {kev} newly exploited-flaw update(s) in the last 36 hours",
                       "https://www.cisa.gov/news-events/cybersecurity-advisories", key="cisa:status"))
    return CollectResult(sigs, {"advisories_36h": len(sigs) - 1, "kev_updates_36h": kev})


def ioda(ctx):
    """Georgia Tech IODA: nationwide internet outage detection for the US."""
    now = int(time.time())
    d = fetch_json("https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary?"
                   f"entityType=country&entityCode=US&from={now - 7200}&until={now}", timeout=45)
    data = d.get("data") or []
    sev = 0 if not data else (2 if len(data) >= 3 else 1)
    title = ("Internet outage tracker (IODA): no US outages detected in the last 2 hours" if not data
             else f"Internet outage tracker (IODA): {len(data)} US outage report(s) in the last 2 hours")
    return CollectResult([Signal("internet", sev, title, "https://ioda.inetintelligence.cc.gatech.edu/country/US",
                                 short(json.dumps(data[:1]), 300) if data else "", key="ioda")],
                         {"outage_records": len(data)})


def make_cloudflare_radar(token):
    """Cloudflare Radar outage annotations for the US (needs a free API token).

    Response shape handled defensively: result.annotations[] with startDate, endDate (null while
    ongoing), description, outage.{outageCause,outageType}, linkedUrl. Only the endpoint and auth
    behaviour were verified live; field names follow Cloudflare's documented schema.
    """
    def fn(ctx):
        d = fetch_json("https://api.cloudflare.com/client/v4/radar/annotations/outages"
                       "?dateRange=1d&location=US&limit=30",
                       headers={"Authorization": f"Bearer {token}"})
        if not d.get("success", False):
            raise RuntimeError("Radar API error: " + short(json.dumps(d.get("errors")), 120))
        ann = (d.get("result") or {}).get("annotations") or []
        ongoing = [a for a in ann if not a.get("endDate")]
        cause_cat = {"POWER_OUTAGE": "power", "CYBER_ATTACK": "cyber"}
        sigs = []
        for a in ongoing[:8]:
            o = a.get("outage") or {}
            cause = (o.get("outageCause") or "UNKNOWN").upper()
            sev = 2 if cause in ("CYBER_ATTACK", "MILITARY_ACTION") else 1
            sigs.append(Signal(cause_cat.get(cause, "internet"), sev,
                               f"Cloudflare Radar: ongoing US {o.get('outageType', 'outage').lower()} "
                               f"({cause.replace('_', ' ').title()})",
                               a.get("linkedUrl") or "https://radar.cloudflare.com/outage-center?location=US",
                               short(a.get("description"), 200), key="radar:" + str(a.get("id", len(sigs))),
                               time=parse_time(a.get("startDate")) or time.time(),
                               tags=["official-cyber"] if cause == "CYBER_ATTACK" else []))
        if len(ongoing) >= 3:
            sigs.append(Signal("internet", 2, f"Cloudflare Radar: {len(ongoing)} simultaneous ongoing US outages",
                               "https://radar.cloudflare.com/outage-center?location=US", key="radar:multi"))
        if not ongoing:
            sigs.append(Signal("internet", 0, "Cloudflare Radar: no ongoing US outages (last 24h)",
                               "https://radar.cloudflare.com/outage-center?location=US", key="radar:none"))
        return CollectResult(sigs, {"us_outages_24h": len(ann), "ongoing": len(ongoing)})
    return fn


GRID_STATES = {   # which states each grid operator's area covers (approximate: operators' areas are not state-shaped)
    "ERCO": ["TX"], "CISO": ["CA"], "NYIS": ["NY"], "ISNE": ["CT", "MA", "ME", "NH", "RI", "VT"],
    "PJM": ["DE", "DC", "IL", "IN", "KY", "MD", "MI", "NJ", "NC", "OH", "PA", "TN", "VA", "WV"],
    "MISO": ["AR", "IL", "IN", "IA", "KY", "LA", "MI", "MN", "MS", "MO", "MT", "ND", "SD", "TX", "WI"],
    "SWPP": ["AR", "IA", "KS", "LA", "MN", "MO", "MT", "NE", "NM", "ND", "OK", "SD", "TX", "WY"],
    "SOCO": ["AL", "FL", "GA", "MS"], "TVA": ["AL", "GA", "KY", "MS", "NC", "TN", "VA"], "US48": [],
}
GRID_MIN_REPORTING = 0.85      # share of grid operators that must report the newest hour before the national total counts
GRID_REGIONS = {
    "US48": "Lower 48 (national)", "PJM": "PJM (Mid-Atlantic/Midwest)", "MISO": "MISO (Midwest)",
    "ERCO": "ERCOT (Texas)", "CISO": "CAISO (California)", "NYIS": "New York", "ISNE": "New England",
    "SWPP": "SPP (Plains)", "SOCO": "Southern Company", "TVA": "TVA",
}


def make_eia_grid(key):
    """EIA Hourly Electric Grid Monitor: actual demand vs the grid operators' own forecast.

    A large mass outage shows up as demand collapsing below forecast. This is the only free national power
    signal, and it lags about 1-2 hours, so it confirms big events rather than catching them in seconds.
    To avoid false alarms from a partly-reported latest hour, a dip must appear in the two latest hours.
    """
    def fn(ctx):
        params = [("api_key", key), ("frequency", "hourly"), ("data[0]", "value"),
                  ("sort[0][column]", "period"), ("sort[0][direction]", "desc"), ("length", "300")]
        params += [("facets[type][]", t) for t in ("D", "DF")]
        params += [("facets[respondent][]", r) for r in GRID_REGIONS]
        # EIA's server answers in under a second when healthy but sometimes hangs or drops the connection, so try
        # a few quick attempts instead of one long wait.
        url = "https://api.eia.gov/v2/electricity/rto/region-data/data/?" + urllib.parse.urlencode(params)
        d, last = None, None
        for attempt in range(4):
            try:
                d = fetch_json(url, timeout=15)
                break
            except Exception as e:
                last = e
                time.sleep(2 * (attempt + 1))
        if d is None:
            raise RuntimeError(f"EIA did not answer after 4 quick tries ({type(last).__name__}: {str(last)[:80]})")
        rows = (d.get("response") or {}).get("data") or []
        if not rows:
            raise RuntimeError("EIA returned no rows")
        by = {}
        for r in rows:
            try:
                v = float(r["value"])
            except (TypeError, ValueError, KeyError):
                continue
            by.setdefault(r["respondent"], {}).setdefault(r["period"], {})[r["type"]] = v
        # How many grid operators reported in the newest hour versus the hour before. If many are missing, the
        # national total is short for that reason, not because demand fell: no demand-drop call on it.
        periods = sorted({p for r in by.values() for p, v in r.items() if "D" in v}, reverse=True)   # forecasts run ahead
        regions = [r for r in GRID_REGIONS if r != "US48"]
        rep = lambda p: sum(1 for r in regions if "D" in by.get(r, {}).get(p, {}))
        newest, prev = (rep(periods[0]), rep(periods[1])) if len(periods) >= 2 else (0, 0)
        partial = prev > 0 and newest / prev < GRID_MIN_REPORTING
        sigs, summary, lows = [], {}, 0
        for resp, label in GRID_REGIONS.items():
            hours = [(p, v) for p, v in sorted(by.get(resp, {}).items(), reverse=True) if "D" in v and "DF" in v]
            if not hours:
                continue
            pairs = [(v["D"] / v["DF"], p, v) for p, v in hours[:2] if v["DF"] > 0]
            if not pairs:
                continue
            ratio, p, v = max(pairs, key=lambda x: x[0])   # both recent hours must be low before we call it a dip
            t1, t2 = (0.93, 0.86) if resp == "US48" else (0.85, 0.75)
            sev = 2 if ratio <= t2 else 1 if ratio <= t1 else 0
            if resp == "US48" and partial:
                sev = 0                    # too few operators reported: the national figure is not reliable this hour
            ts = datetime.strptime(p, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc).timestamp()
            if resp == "US48":
                if time.time() - ts > 8 * 3600:
                    raise RuntimeError(f"EIA's own grid data has stopped updating: newest hour is {p} UTC, about {int((time.time() - ts) // 3600)} hours old (the delay is at EIA)")
                summary = {"data_hour_utc": p, "us48_demand_vs_forecast": f"{ratio:.0%}",
                           "regions_reporting": f"{newest} of {prev} (hour before)"}
            if sev == 0 and resp != "US48":
                continue
            lows += 1 if sev else 0
            sigs.append(Signal("power", sev,
                               f"Electricity use in {label} is {ratio:.0%} of what was forecast ({v['D']:,.0f} vs {v['DF']:,.0f} MW)",
                               "https://www.eia.gov/electricity/gridmonitor/dashboard/electric_overview/US48/US48",
                               f"Latest data is from {p} UTC (about 1-2 hours behind). A big, lasting drop can mean widespread power outages."
                               + (f" Only {newest} of {prev} grid operators have reported this hour, so the national figure is not reliable yet."
                                  if resp == "US48" and partial else ""),
                               key=f"eia:{resp}", states=GRID_STATES.get(resp, [])))
        if not sigs:
            raise RuntimeError("EIA response had no usable demand/forecast pairs")
        summary["regions_low"] = lows
        return CollectResult(sigs, summary)
    return fn


# -------------------------------------------------------------- private status

STATUS_SUMMARY_EVERY = 900      # while a page reports a problem, re-read its full summary at most every 15 minutes
_STATUS_CACHE = {}              # page name -> (time fetched, [incident names])
STATUS_MULTI = 3                # this many pages in a serious outage at once = a strong internet signal
PAYMENT_MULTI = 2               # this many payment processors in a serious outage at once = a payments signal


def make_status_pages(pages):
    """Statuspage.io-style status for big platforms. Simultaneous major outages = signal.
    Each check reads the tiny status-only file (about 230 bytes). Only when a page reports something other than
    all-good is the full summary read (to name the incidents), and then at most every STATUS_SUMMARY_EVERY seconds."""
    def incidents(p, base):
        hit = _STATUS_CACHE.get(p["name"])
        if hit and time.time() - hit[0] < STATUS_SUMMARY_EVERY:
            return hit[1]
        try:
            d = fetch_json(base + "summary.json", timeout=15)
            names = [i.get("name", "") for i in d.get("incidents", [])][:3]
        except Exception:
            names = hit[1] if hit else []
        _STATUS_CACHE[p["name"]] = (time.time(), names)
        return names

    def fn(ctx):
        sigs, ok, failed, bad, pay_bad = [], 0, [], 0, []
        for p in pages:
            base = p["url"].rstrip("/") + "/api/v2/"
            try:
                d = fetch_json(base + "status.json", timeout=15)
            except Exception:
                failed.append(p["name"])
                continue
            ok += 1
            ind = d.get("status", {}).get("indicator", "none")
            sev = {"none": 0, "minor": 0, "major": 1, "critical": 2}.get(ind, 0)
            cat = p.get("category", "internet")
            if sev >= 1:
                bad += 1
                if cat == "finance":
                    pay_bad.append(p["name"])
            if ind == "none":
                _STATUS_CACHE.pop(p["name"], None)     # all good again: the next problem gets a fresh summary
                continue
            sigs.append(Signal(cat, sev, f"{p['name']}: {d['status'].get('description', ind)}",
                               p["url"], "; ".join(incidents(p, base)), key=f"status:{p['name']}"))
        if bad >= STATUS_MULTI:
            sigs.append(Signal("internet", 2, f"{bad} big online services report serious outages at the same time",
                               "", key="status:multi"))
        if len(pay_bad) >= PAYMENT_MULTI:
            sigs.append(Signal("finance", 2, f"{' and '.join(pay_bad)} both report serious outages: card payments may fail",
                               "", key="status:payments"))
        if ok == 0:
            raise RuntimeError("no status page reachable")
        return CollectResult(sigs, {"pages_ok": ok, "pages_failed": ", ".join(failed) or "-", "major": bad})
    return fn


def cloud_providers(ctx):
    """AWS, Google Cloud, and Azure public health feeds."""
    sigs, active_clouds, notes = [], 0, {}
    # AWS (UTF-16 JSON list of recent events)
    try:
        raw = fetch("https://health.aws.amazon.com/public/currentevents")
        ev = json.loads(raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig"))
        live = [e for e in ev if time.time() - float(e.get("date", 0)) < 6 * 3600]
        notes["aws"] = len(live)
        if live:
            active_clouds += 1
            sigs.append(Signal("internet", 2 if len(live) >= 3 else 1, f"AWS: {len(live)} recent health event(s)",
                               "https://health.aws.amazon.com/health/status",
                               "; ".join(f"{e.get('service_name')}: {e.get('summary')}" for e in live[:4]),
                               key="cloud:aws"))
    except Exception as e:
        notes["aws"] = f"err {type(e).__name__}"
    # Google Cloud
    try:
        inc = [i for i in fetch_json("https://status.cloud.google.com/incidents.json") if not i.get("end")]
        notes["gcp"] = len(inc)
        if inc:
            active_clouds += 1
            sigs.append(Signal("internet", 2 if len(inc) >= 3 else 1, f"Google Cloud: {len(inc)} ongoing incident(s)",
                               "https://status.cloud.google.com/",
                               "; ".join(short(i.get("external_desc"), 70) for i in inc[:3]), key="cloud:gcp"))
    except Exception as e:
        notes["gcp"] = f"err {type(e).__name__}"
    # Azure
    try:
        az = parse_feed(fetch("https://rssfeed.azure.status.microsoft/en-us/status/feed/"))
        notes["azure"] = len(az)
        if az:
            active_clouds += 1
            sigs.append(Signal("internet", 2 if len(az) >= 3 else 1, f"Azure: {len(az)} active incident(s)",
                               "https://azure.status.microsoft/en-us/status",
                               "; ".join(short(i["title"], 70) for i in az[:3]), key="cloud:azure"))
    except Exception as e:
        notes["azure"] = f"err {type(e).__name__}"
    if all(str(v).startswith("err") for v in notes.values()):
        raise RuntimeError("no cloud status feed reachable")
    if active_clouds >= 2:
        sigs.append(Signal("internet", 2, f"{active_clouds} of the 3 biggest cloud providers report problems right now",
                           "", key="cloud:multi"))
    if not sigs:
        sigs.append(Signal("internet", 0, "Amazon, Google and Microsoft cloud: no problems reported", "",
                           key="cloud:none"))
    return CollectResult(sigs, notes)


# ------------------------------------------------------------------------ news

_GOOGLE_BACKOFF = {"until": 0, "n": 0}      # n = how many throttles in a row (the wait doubles each time)
_GOOGLE_GATE = {"lock": threading.Lock(), "last": 0.0}
_NEWS_CACHE = {}                            # query -> (time, CollectResult) of the last good Google result
NEWS_CACHE_MAX_AGE = 1200                   # seconds a last-good result may stand in while Google is limiting us


def _google_gap():
    return float(os.environ.get("NEWS_GAP", "1.5"))


def _google_wait():
    """One Google News request at a time, at least a gap apart. Fourteen searches fired together is what got us throttled."""
    with _GOOGLE_GATE["lock"]:
        wait = _GOOGLE_GATE["last"] + _google_gap() * random.uniform(0.9, 1.2) - time.time()
        if wait > 0:
            time.sleep(wait)
        _GOOGLE_GATE["last"] = time.time()


def _google_throttled(code=None):
    n = _GOOGLE_BACKOFF["n"] = _GOOGLE_BACKOFF.get("n", 0) + 1
    _GOOGLE_BACKOFF["until"] = time.time() + min(300 * 2 ** (n - 1), 1800)    # 5, 10, 20, then 30 minutes


def _stand_in(query):
    """The last good result for this query if it is recent enough, marked as such; else None."""
    hit = _NEWS_CACHE.get(query)
    if not hit or time.time() - hit[0] > NEWS_CACHE_MAX_AGE:
        return None
    age = int((time.time() - hit[0]) / 60)
    sigs = []
    for sg in hit[1].signals:
        sg = copy.copy(sg)
        sg.detail = (sg.detail + " · " if sg.detail else "") + f"last good check {age} min ago (Google is limiting requests)"
        sigs.append(sg)
    return CollectResult(sigs, dict(hit[1].metrics, stale_min=age))


# Headlines that are not breaking news. Google matches words ANYWHERE in the story, so entertainment and
# "explosion of growth" style headlines slip in; and a big event produces days of explainer / "it was not an
# attack" follow-ups that should not look like fresh trouble.
NEWS_NOISE_RX = re.compile(
    r"\b(movie|movies|film|films|trailer|box office|netflix|hbo|streaming|season \d+|episode|novel|album|"
    r"video game|actor|actress|starring|premieres?|tv series|documentary|sitcom|thriller|horror|marvel)\b", re.I)
NEWS_FOLLOWUP_RX = re.compile(
    r"\b(restored|resolved|back online|back up and running|what we know|what to know|explained|explainer|"
    r"why did|why do|how did|what caused|root cause|aftermath|anniversary|years? ago|apolog(?:y|ies|ize|izes)|"
    r"lessons|no evidence|not (?:a |an )?(?:cyber ?)?attack|not malicious|ruled out|probe|culprit|investigation into|"
    r"(?:days?|weeks?|months?|years?) after)\b", re.I)


# Areas where a headline must pair an infrastructure noun with an event word (see signalwords.py). Violence and
# geopolitics are about people, not assets, so they keep the plain keyword search and only get the noise filter.
PAIR_AREAS = {"power", "telecom", "internet", "cyber", "aviation", "finance", "fuel", "water", "transport", "industrial"}
_LOCAL_RX = [None]       # private place names, loaded from data/local_terms.json by build_collectors


def _old_news(text):
    """True for a post or headline about an event that is already over: follow-ups, probes, or an older date."""
    return bool(NEWS_FOLLOWUP_RX.search(text) or freshness.stale_reason(text))


def parse_yahoo_news(raw, now=None):
    """Yahoo News search results come back as a web page, not a feed. Pull out title, outlet, age and the real
    article address (the result links are redirects that carry it in the RU= part)."""
    now = now or time.time()
    page = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    items = []
    for blk in re.split(r'<div class="dd [^"]*NewsArticle', page)[1:]:
        t = re.search(r'<h4 class="s-title[^>]*>\s*<a [^>]*href="([^"]+)"[^>]*>(.*?)</a>', blk, re.S)
        if not t:
            continue
        href, title = t.group(1), re.sub(r"\s+", " ", strip_html(t.group(2))).strip()
        m = re.search(r"/RU=([^/]+)/R[KV]=", href)
        link = urllib.parse.unquote(m.group(1)) if m else html.unescape(href)
        src = re.search(r'<span class="s-source[^>]*>(.*?)<span', blk, re.S) or re.search(r'<span class="s-source[^>]*>(.*?)</span>', blk, re.S)
        age = re.search(r"(\d+)\s*(minute|hour|day|week)s?\s+ago", blk)
        secs = {"minute": 60, "hour": 3600, "day": 86400, "week": 604800}
        when = now - int(age.group(1)) * secs[age.group(2)] if age else None
        pub = re.split(r"\s{2,}|\s\|\s|\s\u00b7\s|&middot;", strip_html(src.group(1)))[0].strip() if src else ""
        items.append({"title": title, "link": link, "source": pub, "time": when})
    return items


def make_news(q):
    """Headline-volume detector. Counts distinct outlets covering a topic in the last hour
    and judges it against both fixed thresholds and this query's own learned baseline."""
    def fn(ctx):
        query = q["query"]
        g = ("https://news.google.com/rss/search?q=" + urllib.parse.quote(query + " when:1h")
             + "&hl=en-US&gl=US&ceid=US:en")
        b = ("https://www.bing.com/news/search?q=" + urllib.parse.quote(query)
             + "&format=rss&qft=interval%3d%224%22")
        link = "https://news.google.com/search?q=" + urllib.parse.quote(query + " when:1h")
        items, used, err1 = None, "Google", None
        if time.time() >= _GOOGLE_BACKOFF["until"]:
            try:
                _google_wait()
                items = parse_feed(fetch(g, browser=True))
                _GOOGLE_BACKOFF["n"] = 0
            except Exception as e1:
                err1 = e1
                if isinstance(e1, urllib.error.HTTPError) and e1.code == 429:
                    _google_throttled()
        else:
            err1 = "throttled, backing off"
        if items is None:
            try:                       # Yahoo News is the first backup; it also gives the real article address
                y = ("https://news.search.yahoo.com/rss?p=" + urllib.parse.quote(query) + "&btf=d&sort=time")
                items = parse_yahoo_news(fetch(y, browser=True, timeout=15))
                if not items:
                    raise RuntimeError("Yahoo returned no results")
                used = "Yahoo"
                link = "https://news.search.yahoo.com/search?p=" + urllib.parse.quote(query) + "&btf=d&sort=time"
            except Exception as e_y:
                err1 = f"{err1}; Yahoo: {e_y}"
                items = None
        if items is None:
            try:
                items = parse_feed(fetch(b, browser=True))
                used = "Bing"
                link = "https://www.bing.com/news/search?q=" + urllib.parse.quote(query)
            except Exception as e2:
                held = _stand_in(query)
                if held:
                    return held
                raise RuntimeError(f"{'Throttled: ' if _GOOGLE_BACKOFF['until'] > time.time() else ''}Google: {err1}; Bing: {e2}")
        now = time.time()
        recent = [i for i in items if i["time"] is None or now - i["time"] < 7200]
        pubs = set()
        for i in recent:
            pub = i["source"] or urllib.parse.urlparse(i["link"]).netloc
            i["pub"] = pub
            pubs.add(pub)
            if pub and i["title"].endswith(" - " + pub):
                i["title"] = i["title"][: -len(pub) - 3]
            m = re.search(r"[?&]url=([^&]+)", i["link"]) if "bing.com/news/apiclick" in i["link"] else None
            if m:
                i["link"] = urllib.parse.unquote(m.group(1))
        n = len(pubs)
        raw_n = n
        # Drop unrelated matches and follow-up stories before counting. Context queries (official denials,
        # debunked claims) exist to find exactly those headlines, so they skip the follow-up filter.
        ctx_only = q.get("max_sev") == 0
        req = [re.compile(r, re.I) for r in q.get("require_all", [])]
        exc = re.compile(q["exclude"], re.I) if q.get("exclude") else None
        kept, unrelated, followups = [], 0, 0
        for i in recent:
            t = i["title"]
            sw = signalwords.analyze(t, _LOCAL_RX[0], q["category"])
            if NEWS_NOISE_RX.search(t) or (exc and exc.search(t)) or not all(r.search(t) for r in req) \
                    or (not ctx_only and (sw["junk"] or (q["category"] in PAIR_AREAS and not sw["pair"]))):
                unrelated += 1
            elif not ctx_only and (NEWS_FOLLOWUP_RX.search(t) or freshness.stale_reason(t, now)):
                followups += 1
            else:
                kept.append(i)
        # Read the stories behind the headlines that would count: a keyword match alone is not evidence.
        story_read, story_dropped, story_old, story_earlier = 0, 0, 0, 0
        if kept and not ctx_only and ctx.cfg.get("story_read", True):
            kept, dropped_items, story_read = storyread.screen(kept, q["category"], fetch)
            story_dropped = len(dropped_items)
            story_read = sum(1 for i in kept + dropped_items if i.get('story') in ('real', 'earlier', 'passing', 'stale'))
            story_old = sum(1 for i in dropped_items if i.get('story') == 'stale')
            story_earlier = sum(1 for i in kept if i.get('story') == 'earlier')
        kept_sw = [signalwords.analyze(i["title"], _LOCAL_RX[0], q["category"]) for i in kept]
        priority = any(x["pair"] and x["mult"] for x in kept_sw)        # scale / official / agency / local wording
        solid = any(x["solid"] for x in kept_sw)                        # at least one strong event word
        # Stories about places overseas are WORLD context (a quiet line on the page), never evidence for the US alert scale.
        recent, abroad = geo.split(kept)
        if q.get("scope") == "world":                       # a whole query that is about the world, not about home
            recent, abroad = [], kept
        world_sigs = []
        if abroad:
            winfo = trust.summarize(abroad, q["category"], ctx.cfg)
            world_sigs.append(Signal("world", 0, f"{q['name']}: {winfo['clusters']} reports from {len({i['pub'] for i in abroad})} outlets overseas",
                                     link, "About places outside the US. Shown as context only; it never moves the alert scale.",
                                     key="world:" + q["name"],
                                     links=[{"title": f"{short(i['title'], 100)} — {i['pub']}", "url": i["link"], "t": i["time"]}
                                            for i in abroad[:6]],
                                     meta=winfo))
        n = len({i["pub"] for i in recent})                 # distinct outlets (shown, and kept for the filter checks)
        info = trust.summarize(recent, q["category"], ctx.cfg)   # who is reporting, with copies counted once
        not_current = story_read >= 2 and story_earlier * 2 >= story_read     # most stories read say it happened earlier
        if not_current:
            info = dict(info, t1=0)          # not a right-now confirmation, so no "several top outlets" credit
        n_eff = info["n_eff"] + (1.0 if priority and not ctx_only else 0)   # urgent wording counts as one more independent report
        if used in ("Bing", "Yahoo") and raw_n == 0:
            # Bing's index lags by hours, so an empty Bing result proves nothing. Report the source as
            # failed (keeps the previous alert alive) rather than a false "no coverage".
            held = _stand_in(query)
            if held:
                return held
            raise RuntimeError(f"Throttled: Google News unavailable ({err1}); Bing fallback cannot confirm last-hour coverage")
        key = "news:" + q["name"]
        skey = "newsw:" + q["name"]      # trust-weighted independent reports: its own history (old counts used other units)
        rate = ctx.store.rate_severity(skey, n_eff, q.get("thresholds"), ctx.cfg.get("social_min_count", 5))
        ctx.store.record(skey, n_eff)
        sev = min(rate.sev, q.get("max_sev", 3))
        if not_current:
            sev = 0                  # reported now, but it happened earlier: listed under Sources, never moves the level
        if q["category"] in PAIR_AREAS and not ctx_only and kept and not solid:
            sev = min(sev, 1)        # only everyday words (fire, leak, outage): a WATCH at most until something confirms it
        ignored = unrelated + followups + story_dropped
        if n == 0:
            out = CollectResult(world_sigs, {"outlets_1h": 0, "ignored": ignored, "overseas_1h": len(abroad)})
            if used == "Google":
                _NEWS_CACHE[query] = (time.time(), out)
            return out
        base = (f"usually about {rate.baseline:g}" if rate.baseline is not None
                else f"still learning what is normal for this ({rate.n} of 8 readings)")
        base += (f" · {info['clusters']} independent report(s) from {n} outlet(s), {info['t1']} from top-tier outlets"
                 + (f", {info['syndicated']} copies of the same story counted once" if info["syndicated"] else ""))
        if story_read:
            base += (f" · read {story_read} stor{'y' if story_read == 1 else 'ies'}"
                     + (f", {story_dropped} dropped ({story_old} about older events)" if story_dropped
                        else "" if not_current else ", all describe a real disruption")
                     + (f"; {story_earlier} say it happened earlier, so it is listed quietly and does not move the level" if not_current else ""))
        if ignored:
            base += (f" · ignored {unrelated} unrelated and {followups} follow-up stor"
                     f"{'y' if unrelated + followups == 1 else 'ies'} about events already over")
        if used in ("Bing", "Yahoo"):
            base += f" · via {used} (Google is limiting requests)"
        links = [{"title": f"{short(i['title'], 100)} — {i['pub']}", "url": i["link"]} for i in recent[:6]]
        out = CollectResult([Signal(q["category"], sev, f"News: {q['name']} — {info['clusters']} independent reports from {n} outlets in the last hour",
                                    link, base, key=key, links=links, meta=info,
                                    states=geo.states_for([i["title"] for i in recent]))] + world_sigs,
                            {"outlets_1h": n, "independent_1h": info["clusters"], "top_tier_1h": info["t1"], "ignored": ignored,
                             "overseas_1h": len(abroad)})
        if used == "Google":
            _NEWS_CACHE[query] = (time.time(), out)
        return out
    return fn


# ---------------------------------------------------------------------- social

def _emit_social(ctx, platform, home, counts, samples, covered, labelmap, claims=None):
    """Turn per-category post counts into signals, judged against learned baselines."""
    sigs = []
    minc = ctx.cfg.get("social_min_count", 5)
    for cat in covered:
        c = counts.get(cat, 0)
        key = f"social:{platform}:{cat}"
        rate = ctx.store.rate_severity(key, c, None, minc)
        ctx.store.record(key, c)
        if c == 0:
            continue
        sev = min(rate.sev, 2)
        base = (f"usually about {rate.baseline:g} per hour" if rate.baseline is not None
                else f"still learning what is normal for this ({rate.n} of 8 readings)")
        posts = sorted((claims or {}).get(cat, []), key=lambda x: -x["engagement"])[:5]   # the spreading ones (see credibility.py)
        sigs.append(Signal(cat, sev, f"{platform}: about {c} posts per hour mentioning {labelmap.get(cat, cat)}",
                           home, base, key=key, links=samples.get(cat, [])[:5], meta={"posts": posts} if posts else {}))
    return sigs


def make_reddit(cfg):
    kw = {c: re.compile(p, re.I) for c, p in cfg["social_keywords"].items()}

    def fn(ctx):
        counts, samples, scanned, ok = {}, {}, 0, 0
        now = time.time()
        for sub in cfg["reddit_subs"]:
            try:
                items = parse_feed(fetch(f"https://old.reddit.com/r/{sub}/new/.rss?limit=50", browser=True))
            except Exception:
                time.sleep(6)   # Reddit rate-limits bursts (HTTP 429); back off and move on
                continue
            ok += 1
            time.sleep(5)       # be polite to Reddit
            for it in items:
                if it["time"] and now - it["time"] > 3600:
                    continue
                if _old_news(it["title"]):
                    continue
                scanned += 1
                for cat, rx in kw.items():
                    if rx.search(it["title"]):
                        counts[cat] = counts.get(cat, 0) + 1
                        samples.setdefault(cat, []).append(
                            {"title": f"r/{sub}: {short(it['title'], 110)}", "url": it["link"]})
        if ok == 0:
            raise RuntimeError("Limited: Reddit refuses requests from this connection (no subreddit feed reachable)")
        sigs = _emit_social(ctx, "Reddit", "https://www.reddit.com/", counts, samples, list(kw),
                            {c: c for c in kw})
        return CollectResult(sigs, {"subs_ok": f"{ok}/{len(cfg['reddit_subs'])}", "posts_scanned_1h": scanned})
    return fn


def make_bluesky(cfg):
    def fn(ctx):
        counts, samples, ok, claims = {}, {}, 0, {}
        since = datetime.fromtimestamp(time.time() - 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for q in cfg["bluesky_queries"]:
            url = ("https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=" + urllib.parse.quote(q["q"])
                   + f"&sort=latest&limit=100&since={since}")
            try:
                posts = fetch_json(url).get("posts", [])
            except Exception:
                continue
            ok += 1
            cat = q["category"]
            posts = [p for p in posts if not _old_news((p.get("record") or {}).get("text", ""))]   # chatter about an older event
            times = [parse_time(p.get("indexedAt")) for p in posts]
            counts[cat] = counts.get(cat, 0) + rate_per_hour(times, 100, time.time())
            for p in posts[:3]:
                rkey = p["uri"].rsplit("/", 1)[-1]
                handle = p["author"]["handle"]
                samples.setdefault(cat, []).append(
                    {"title": f"{q['q']}: {short(p['record'].get('text', ''), 110)}",
                     "url": f"https://bsky.app/profile/{handle}/post/{rkey}"})
            for p in posts:
                cnt = {"likes": p.get("likeCount", 0), "reposts": p.get("repostCount", 0),
                       "quotes": p.get("quoteCount", 0), "replies": p.get("replyCount", 0)}
                if credibility.engagement_of(cnt) >= cfg.get("social_viral_min", credibility.VIRAL_MIN) / 4 \
                        and geo.classify((p.get("record") or {}).get("text", "")) != "foreign":
                    a = p.get("author") or {}
                    claims.setdefault(cat, []).append(credibility.make_candidate(
                        "Bluesky", f"https://bsky.app/profile/{a.get('handle', '')}/post/{p['uri'].rsplit('/', 1)[-1]}",
                        (p.get("record") or {}).get("text", ""), cnt,
                        {"created": a.get("createdAt"), "followers": None, "posts": None, "bot": False,
                         "handle": a.get("handle", ""), "did": a.get("did", "")}))
            time.sleep(0.5)
        if ok == 0:
            raise RuntimeError("Bluesky search unreachable")
        # Search results lack follower counts, so look up just the accounts behind the spreading posts (one batched call).
        top = sorted((c for lst in claims.values() for c in lst), key=lambda c: -c["engagement"])[:25]
        dids = list(dict.fromkeys(c["acct"]["did"] for c in top if c["acct"].get("did")))
        if dids:
            try:
                prof = fetch_json("https://api.bsky.app/xrpc/app.bsky.actor.getProfiles?" +
                                  "&".join("actors=" + urllib.parse.quote(d) for d in dids[:25])).get("profiles", [])
                by = {x["did"]: x for x in prof}
                for c in top:
                    x = by.get(c["acct"].get("did"))
                    if x:
                        c["acct"]["followers"], c["acct"]["posts"] = x.get("followersCount"), x.get("postsCount")
            except Exception:
                pass                                   # unknown account facts are neutral, never an error
        sigs = _emit_social(ctx, "Bluesky", "https://bsky.app/search", counts, samples,
                            sorted({q["category"] for q in cfg["bluesky_queries"]}), CATEGORIES, claims)
        return CollectResult(sigs, {"queries_ok": f"{ok}/{len(cfg['bluesky_queries'])}"})
    return fn


# ----------------------------------------------------------------------- Drudge Report

DRUDGE_URL = "https://www.drudgereport.com/"
_A_RX = re.compile(r'<a\s[^>]*?href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.I | re.S)


def parse_drudge(raw):
    """Front-page links in page order (the first is the main headline): [{"title", "url", "outlet", "tier", "pos"}]."""
    page = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    out, seen = [], set()
    for url, inner in _A_RX.findall(page):
        title = re.sub(r"\s+", " ", strip_html(inner)).strip()
        host = re.sub(r"^https?://", "", url.lower()).split("/")[0]
        if not title or "drudgereport.com" in host or url in seen:
            continue
        seen.add(url)
        outlet = trust.outlet_from_url(url)
        out.append({"title": title, "url": url, "outlet": outlet, "tier": trust.tier_of(outlet), "pos": len(out)})
    return out


def make_drudge(cfg):
    """Drudge Report's front page as a POINTER, not a witness. Its editors pick stories and its links often go to
    sites of mixed quality, so it is judged by WHO each headline links to (trust.py), counts for at most severity 1, and
    only when it is making a theme of a topic (several headlines, some of them linking to outlets you trust). Its job is
    to show you what it is leading with and where to go look."""
    d = cfg.get("drudge", {})
    kw = {c: re.compile(p, re.I) for c, p in d.get("keywords", {}).items()}
    need_n, need_trusted = d.get("min_headlines", 3), d.get("min_trusted", 2)

    def fn(ctx):
        links = parse_drudge(fetch(DRUDGE_URL, browser=True))[:60]
        if len(links) < 15:
            raise RuntimeError("Drudge Report page layout changed (too few headlines found)")
        sigs = []
        for cat, rx in kw.items():
            hits = [l for l in links[:45] if rx.search(l["title"])]
            hits_all = hits
            hits = [l for l in hits if geo.classify(l["title"]) != "foreign"]
            abroad = [l for l in hits_all if geo.classify(l["title"]) == "foreign"]
            if abroad:
                sigs.append(Signal("world", 0, f"Drudge Report: {len(abroad)} front-page headline(s) about {CATEGORIES[cat].lower()} overseas",
                                   DRUDGE_URL, "About places outside the US. Context only.", key="world:drudge:" + cat,
                                   links=[{"title": f"{short(l['title'], 100)} — {l['outlet']}", "url": l["url"]} for l in abroad[:6]]))
            if not hits:
                continue
            trusted = [l for l in hits if l["tier"] <= 2]
            sev = 1 if (len(hits) >= need_n and len(trusted) >= need_trusted) else 0
            shown = []
            for l in hits[:6]:
                flag = "" if l["tier"] <= 2 else " [unvetted source]" if l["tier"] == 3 else " [low-trust source: a lead to check, not proof]"
                shown.append({"title": f"{short(l['title'], 100)} — {l['outlet']}{flag}", "url": l["url"]})
            info = trust.summarize([{"title": l["title"], "pub": l["outlet"]} for l in hits], cat, ctx.cfg)
            sigs.append(Signal(cat, sev, f"Drudge Report: {len(hits)} front-page headline(s) about {CATEGORIES[cat].lower()}, "
                                         f"{len(trusted)} linking to outlets with a good record",
                               DRUDGE_URL, "A pointer, not evidence: Drudge picks stories and links out, sometimes to weak sources. "
                                           "Click through and judge the linked outlet.", key="drudge:" + cat,
                               links=shown, meta=info))
        top = links[0]
        return CollectResult(sigs, {"headlines": len(links), "on_topic": sum(len(s.links) > 0 for s in sigs if s.category != "world"),
                                    "main_headline": short(top["title"], 90), "main_source": top["outlet"]})
    return fn


# ------------------------------------------------------------------- air traffic

def adsb(ctx):
    """OpenSky live aircraft over the continental US.

    (1) Total airborne count: collapses if the FAA grounds the fleet.
    (Private jets are covered by the Apocalypse Early Warning System collector below, which is much better at it.)
    """
    d = fetch_json("https://opensky-network.org/api/states/all?lamin=24&lomin=-125&lamax=50&lomax=-66",
                   timeout=30)
    states = d.get("states")
    if states is None:
        raise RuntimeError("OpenSky returned no state vector")
    air = [s for s in states if not s[8]]
    total = len(air)
    sigs = []
    r_total = ctx.store.baseline("adsb:airborne", same_hour=True)
    base_total = r_total[0]
    ctx.store.record("adsb:airborne", total)
    sev = 0
    if total < 100:
        sev = 3
    elif total < 300:
        sev = 2
    if base_total:
        ratio = total / base_total
        sev = max(sev, 3 if ratio < 0.15 else 2 if ratio < 0.4 else 0)
    note = (f"normal for this hour is about {base_total:.0f}" if base_total
            else "still learning what is normal for this hour (needs about a day)")
    sigs.append(Signal("aviation", sev, f"Aircraft in the air over the US right now: {total}", "https://opensky-network.org/network/explorer",
                       note, key="adsb:total"))
    return CollectResult(sigs, {"airborne_us": total})


EWS_URL = "https://pub-49bb6a6f314c47be9b481c25e5f6ca9e.r2.dev/dashboard.json"
EWS_SEV = {1: 0, 2: 0, 3: 1, 4: 1, 5: 2}   # a proxy for "wealthy people leaving", so it is never allowed above severity 2


def ews_jets(ctx):
    """Apocalypse Early Warning System (Kyle McDonald): how many business jets are airborne worldwide right now
    versus what is normal for this half-hour of the week, from adsb.fi flight data. Its own 1-5 emergency level is
    calibrated so level 5 is reached only on the single busiest day of a typical year. Updates every 30 minutes.
    """
    d = fetch_json(EWS_URL, timeout=40)
    cur, live = d["current"], d.get("liveStatus", {})
    when = parse_time(cur.get("asOf"))
    if not when or time.time() - when > 3 * 3600:
        raise RuntimeError("the jet tracker's data is more than 3 hours old"
                           + (f" ({live['lastError'][:80]})" if live.get("lastError") else ""))
    level = max(1, min(5, int(cur["emergencyLevel"])))
    n, exp, z = int(cur["concurrentCount"]), float(cur["baselineMean"]), float(cur["zScore"])
    hol = ((d.get("signals") or {}).get("composite") or {}).get("holidayLabel")
    detail = (f"{z:+.1f} standard deviations from the usual count for this half-hour of the week"
              + (f" (holiday period: {hol})" if hol else "")
              + ". Counts business jets worldwide, so it is a rough sign of wealthy people leaving, not proof of anything")
    sig = Signal("elite", EWS_SEV[level], f"Business jets in the air: {n:,} (usual about {exp:,.0f}), emergency level {level} of 5",
                 "https://ews.kylemcdonald.net/", detail, key="ews:jets", time=when)
    return CollectResult([sig], {"level": f"{level}/5", "airborne": n, "sigma": round(z, 1)})


YAHOO_CHART = "https://query1.finance.yahoo.com/v8/finance/chart/{}?range=5d&interval=1d"
# (symbol, plain name, category). Index quotes can be delayed up to 15 minutes.
MARKET_SYMS = [("^GSPC", "S&P 500", "markets"), ("^DJI", "Dow", "markets"), ("^IXIC", "Nasdaq", "markets"),
               ("^VIX", "VIX fear index", "markets"), ("KRE", "Regional bank stocks (KRE fund)", "finance")]


def _quote(sym):
    """(last price, previous session's close, time of last trade) from Yahoo Finance's public chart data."""
    r = fetch_json(YAHOO_CHART.format(urllib.parse.quote(sym)), timeout=20, curl_first=True)["chart"]["result"][0]
    closes = [c for c in r["indicators"]["quote"][0]["close"] if c is not None]
    if len(closes) < 2:
        raise RuntimeError(f"{sym}: not enough price history")
    return float(r["meta"]["regularMarketPrice"]), float(closes[-2]), float(r["meta"]["regularMarketTime"])


def stock_market(ctx):
    """Is the market crashing? Daily drop in the S&P 500, Dow and Nasdaq, the VIX 'fear index', and regional bank stocks.

    Only DROPS count (a rally is not a warning). Markets fall for ordinary economic reasons far more often than from
    attacks, so this is context and can never raise the alarm by itself: the stock indexes and VIX are capped at
    severity 2. Regional banks (the first thing to break in a bank scare) go to the Banks category.
    """
    sigs, shown, got, by_cat = [], [], 0, {}
    best = {}                                          # category -> (severity, how bad, text, symbol, time)
    for sym, name, cat in MARKET_SYMS:
        try:
            price, prev, t = _quote(sym)
        except Exception:
            continue
        if time.time() - t > 5 * 86400:
            continue                                   # no recent trading: ignore rather than guess
        got += 1
        chg = (price / prev - 1) * 100
        if sym == "^VIX":
            sev, bad = (2 if price >= 40 else 1 if price >= 30 else 0), price / 10
            txt = f"{name} at {price:.1f}" + (" (above 30 means real fear)" if sev else "")
            shown.append(f"{name} {price:.1f}")
            by_cat.setdefault(cat, []).append(f"{name} {price:.1f}")
        else:
            if cat == "finance":
                sev = 2 if chg <= -12 else 1 if chg <= -7 else 0
            else:
                sev = 2 if chg <= -5 else 1 if chg <= -3 else 0
            bad, txt = -chg, f"{name} {chg:+.1f}% from the last close"
            shown.append(f"{name} {chg:+.1f}%")
            by_cat.setdefault(cat, []).append(f"{name} {chg:+.1f}%")
        cand = (sev, bad, txt, sym, t)
        if cat not in best or cand[:2] > best[cat][:2]:
            best[cat] = cand
    if got < 3:
        raise RuntimeError("could not read enough market prices")
    for cat, label in (("markets", "Stock market"), ("finance", "Regional banks")):
        if cat in best:
            sev, _bad, txt, sym, t = best[cat]
            if sev == 0:      # nothing flagged: show the day's moves instead of picking one at random
                txt = ", ".join(by_cat[cat])
            sigs.append(Signal(cat, sev, f"{label}: {txt}", f"https://finance.yahoo.com/quote/{urllib.parse.quote(sym)}/",
                               "Price data may be delayed up to 15 minutes. Markets fall for ordinary economic reasons "
                               "far more often than because of an attack", key=f"mkt:{cat}", time=t))
    return CollectResult(sigs, {"moves": ", ".join(shown)})


NTAS_URL = "https://www.dhs.gov/national-terrorism-advisory-system"


def ntas(ctx):
    """DHS National Terrorism Advisory System: the only public, official US terrorism warning.

    There is no data feed, so this reads DHS's own advisory page. It FAILS (source NOT WORKING) if it cannot read the page,
    so a redesign can never look like an all-clear. Bulletins are DHS's general 'heightened threat environment' notices and
    can stay in force for months, so they are shown but do not raise the alarm. An Alert (a specific, credible threat) is
    far rarer and does.
    """
    raw = fetch(NTAS_URL, timeout=30).decode("utf-8", "replace")
    raw = re.sub(r"<(script|style).*?</\1>", " ", raw, flags=re.S | re.I)
    text = re.sub(r"\s+", " ", strip_html(raw))
    i, j = text.find("Current Advisories"), text.find("Expired Advisories")
    if i < 0 or j < i:
        raise RuntimeError("the DHS advisory page has changed layout, so I cannot read it")
    sec = text[i + len("Current Advisories"):j].strip()
    if re.search(r"no current advisor", sec, re.I):
        return CollectResult([Signal("security", 0, "DHS terrorism advisory (NTAS): no current advisories", NTAS_URL,
                                     "DHS issues these only when it has specific, credible threat information",
                                     key="ntas:none")], {"current": 0})
    parts = re.split(r"(?=National Terrorism Advisory System (?:Bulletin|Alert)\b)", sec)
    sigs, expired = [], 0
    for part in parts:
        m = re.match(r"National Terrorism Advisory System (Bulletin|Alert)\b([^|]*)", part)
        if not m:
            continue
        exp = re.search(r"Expires:\s*(\d{4}-\d{2}-\d{2})(?:\s+(\d{1,2}):(\d{2})\s*([ap]m))?", part, re.I)
        if exp:
            try:
                hh = int(exp.group(2) or 23) % 12 + (12 if (exp.group(4) or "pm").lower() == "pm" else 0)
                end = datetime.strptime(exp.group(1), "%Y-%m-%d").replace(hour=hh, minute=int(exp.group(3) or 59))
                if end.timestamp() + 5 * 3600 < time.time():
                    expired += 1
                    continue                           # already expired but still on the page
            except ValueError:
                pass
        kind, title = m.group(1), m.group(0).strip(" -")
        body = part.split("View PDF Version", 1)[-1]
        body = re.split(r"Effective:", body)[0]
        body = re.sub(r"(En español|Sa Tagalog|한국어로|trong tiếng việt|بالعربية|读中文|讀中文|ในภาษาไทย)", "", body).strip()
        sev, tags = 0, []
        if kind == "Alert":
            sev, tags = (3 if re.search(r"imminent", part, re.I) else 2), ["official-physical"]
        sigs.append(Signal("security", sev, f"DHS terrorism advisory in effect: {title}", NTAS_URL, short(body, 280),
                           key="ntas:" + title[:60], tags=tags))
    if not sigs and expired:
        return CollectResult([Signal("security", 0, "DHS terrorism advisory (NTAS): no current advisories", NTAS_URL,
                                     "The only listing has already expired", key="ntas:none")], {"current": 0})
    if not sigs:
        raise RuntimeError("the DHS advisory page lists something I could not read")
    return CollectResult(sigs, {"current": len(sigs)})


# ----------------------------------------------------------------- connectivity

def canary(ctx):
    """Is YOUR connection working? If not, every other source failing means nothing."""
    tests = ["http://captive.apple.com/hotspot-detect.html",
             "https://www.cloudflare.com/cdn-cgi/trace",
             "https://www.google.com/generate_204"]
    ok = 0
    for u in tests:
        try:
            fetch(u, timeout=8, max_bytes=100000)
            ok += 1
        except Exception:
            pass
    if ok == 0:
        raise RuntimeError("no internet connectivity from this machine")
    return CollectResult([], {"reachable": f"{ok}/{len(tests)}", "host": socket.gethostname()})


# --------------------------------------------------------------------- registry

@dataclass
class Collector:
    name: str
    kind: str       # gov | private | news | social
    home: str
    interval: int
    fn: object


def load_cloudflare_token(data_dir):
    """Env var CLOUDFLARE_API_TOKEN, else data/cloudflare_token.txt. Never read from config.json."""
    tok = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not tok and data_dir:
        try:
            with open(os.path.join(data_dir, "cloudflare_token.txt")) as f:
                tok = f.read().strip()
        except OSError:
            pass
    return tok


def load_eia_key(data_dir):
    """Env var EIA_API_KEY, else data/eia_key.txt, else the shared DEMO_KEY (~50 requests/day/IP)."""
    key = os.environ.get("EIA_API_KEY", "").strip()
    if not key and data_dir:
        try:
            with open(os.path.join(data_dir, "eia_key.txt")) as f:
                key = f.read().strip()
        except OSError:
            pass
    return key or "DEMO_KEY"


# ---------------------------------------------------------------------- local (your county)

def make_local_nws(loc):
    """Every active Weather Service alert for your exact spot (tornado, flood, winter storm, ...)."""
    lat, lon, name = loc["lat"], loc["lon"], loc["name"]
    page = f"https://forecast.weather.gov/MapClick.php?lat={lat}&lon={lon}"
    sev_map = {"Extreme": 3, "Severe": 2, "Moderate": 1}

    def fn(ctx):
        feats = fetch_json(f"https://api.weather.gov/alerts/active?status=actual&point={lat},{lon}",
                           headers={"Accept": "application/geo+json"}).get("features", [])
        sigs = []
        for f in feats:
            p = f.get("properties", {})
            ev = p.get("event", "Weather alert")
            sev = sev_map.get(p.get("severity"), 0)
            if ev in ("Tornado Warning", "Flash Flood Emergency", "Tornado Emergency"):
                sev = 3
            until = parse_time(p.get("ends") or p.get("expires"))
            sigs.append(Signal("local", sev, f"Weather Service alert for {name}: {ev}", page,
                               short(p.get("headline") or "", 140), key=f"nwsl:{p.get('id', ev)}",
                               links=[{"title": short(p.get("headline") or ev, 120), "url": f.get("id", page)}],
                               time=parse_time(p.get("sent")) or time.time()))
        if not sigs:
            sigs.append(Signal("local", 0, f"No active Weather Service alerts for {name}", page, key="nwsl:none"))
        return CollectResult(sigs, {"alerts_here": len(feats)})
    return fn


def make_local_power(loc):
    """Your electric co-op's own outage map data (the same file its public map loads)."""
    url, home, util, county = loc["outage_data"], loc["outage_map"], loc["utility"], loc["county"]

    def fn(ctx):
        d = fetch_json(url)
        age = time.time() - d.get("lastUpdate", 0) / 1000
        if age > 2700:
            raise RuntimeError(f"{util} outage map has not updated in {round(age / 60)} minutes")
        regions = {r["id"]: r for ds in d.get("regionDataSets", []) for r in ds.get("regions", [])}
        here = regions.get(county, {})
        here_out, here_served = here.get("numberOut", 0), here.get("numberServed", 0)
        total_served = d.get("totalServed") or 1
        total_out = sum(r.get("numberOut", 0) for r in regions.values())
        pct = max(here_out / here_served if here_served else 0, total_out / total_served)
        count = here_out if here_served and here_out / here_served >= total_out / total_served else total_out
        sev = 0
        if count >= 25:
            sev = 1 if pct >= 0.01 else 0
            sev = 2 if pct >= 0.05 else sev
            sev = 3 if pct >= 0.20 else sev
        title = (f"{util}: {here_out:,} of {here_served:,} members in {county} County are without power "
                 f"({total_out:,} of {total_served:,} across the whole system)")
        return CollectResult([Signal("local", sev, title, home, "from the co-op's own outage map",
                                     key="local:power", time=d["lastUpdate"] / 1000,
                                     links=[{"title": f"{util} outage map", "url": home}])],
                             {"members_out_here": here_out, "members_out_total": total_out})
    return fn


# ------------------------------------------------------------ phone carriers (IODA, live)
CARRIERS = {"AT&T": "7018", "Verizon": "701", "T-Mobile": "21928"}
CARRIER_DROP = 0.85            # a carrier is "down" when its reachable address blocks fall below 85% of its recent median
CARRIER_WINDOW = 6 * 3600      # the baseline: the carrier's own last six hours (absorbs normal daily swings)


def carrier_drop(values):
    """(ratio, latest) for one carrier's active-probing series: the lower of the last two readings against the
    median of the earlier ones. Both of the last two must be low, so one noisy reading never counts."""
    vals = [v for v in values if isinstance(v, (int, float))]
    if len(vals) < 8:
        return None, None
    base = sorted(vals[:-2])[len(vals[:-2]) // 2]
    if base <= 0:
        return None, None
    ratio = max(vals[-2:]) / base
    return ratio, vals[-1]


def make_radar_carriers(token):
    """Cloudflare Radar, per carrier: ongoing network outages and traffic anomalies on AT&T, Verizon and T-Mobile.
    Replaces the IODA carrier check when IODA is down, and works alongside it when it is up."""
    def fn(ctx):
        h = {"Authorization": f"Bearer {token}"}
        base = "https://api.cloudflare.com/client/v4/radar/"
        down, answered = [], 0
        for name, asn in CARRIERS.items():
            hit = False
            for ep, key in (("annotations/outages", "annotations"), ("traffic_anomalies", "trafficAnomalies")):
                try:
                    d = fetch_json(f"{base}{ep}?dateRange=1d&asn={asn}&limit=10", headers=h, timeout=20)
                except Exception:
                    continue
                if not d.get("success", False):
                    continue
                answered += 1
                for a in (d.get("result") or {}).get(key) or []:
                    ended = a.get("endDate") or (a.get("endTime"))
                    if not ended and str(a.get("status", "")).upper() != "FALSE_POSITIVE":
                        hit = True
            if hit:
                down.append(name)
        if answered == 0:
            raise RuntimeError("Cloudflare Radar carrier data unavailable")
        url = "https://radar.cloudflare.com/outage-center?location=US"
        sigs = [Signal("telecom", 1, f"{n} network: Cloudflare Radar reports an ongoing outage or traffic anomaly", url,
                       "Live measurement of the carrier's own network traffic.", key=f"radar:carrier:{n}") for n in down]
        if len(down) >= 2:
            sigs.append(Signal("telecom", 2, f"{' and '.join(down)} networks affected at the same time", url,
                               "Two or more major carriers showing outages together.", key="radar:carriers"))
        if not down:
            sigs.append(Signal("telecom", 0, "Cloudflare Radar: no ongoing outages on AT&T, Verizon or T-Mobile", url, key="radar:carriers:none"))
        return CollectResult(sigs, {"carriers_with_outage": ", ".join(down) or "none"})
    return fn


def ioda_carriers(ctx):
    """Georgia Tech IODA active probing per mobile/home carrier network: how many of each carrier's address blocks
    answer, against that carrier's own last six hours. One carrier dropping = a phones signal; two at once = stronger."""
    now = int(time.time())
    down, ok, notes, sigs = [], 0, {}, []
    for name, asn in CARRIERS.items():
        try:
            d = fetch_json(f"https://api.ioda.inetintel.cc.gatech.edu/v2/signals/raw/asn/{asn}"
                           f"?from={now - CARRIER_WINDOW}&until={now}&datasource=ping-slash24", timeout=30)
            series = next(s for s in d["data"][0] if s.get("datasource") == "ping-slash24")
        except Exception:
            continue
        ratio, _latest = carrier_drop(series.get("values") or [])
        if ratio is None:
            continue
        ok += 1
        notes[name] = f"{ratio:.0%}"
        if ratio < CARRIER_DROP:
            down.append((name, ratio))
    if ok == 0:
        raise RuntimeError("IODA carrier signals unavailable")
    url = "https://ioda.inetintelligence.cc.gatech.edu/country/US"
    for name, ratio in down:
        sigs.append(Signal("telecom", 1, f"{name} network: only {ratio:.0%} of its usual address blocks answer",
                           url, "Live network measurement (IODA active probing), against the carrier's own last six hours.",
                           key=f"ioda:carrier:{name}"))
    if len(down) >= 2:
        sigs.append(Signal("telecom", 2, f"{' and '.join(n for n, _ in down)} networks dropped at the same time",
                           url, "Two or more major carriers losing reachability together.", key="ioda:carriers"))
    return CollectResult(sigs, {"carriers_vs_usual": ", ".join(f"{k} {v}" for k, v in notes.items())})


# ------------------------------------------------------------ market-wide circuit breakers (Nasdaq Trader)
NASDAQ_HALTS = "https://www.nasdaqtrader.com/rss.aspx?feed=tradehalts"
MWCB = {"MWC1": (2, "Level 1 (7% drop)"), "MWC2": (2, "Level 2 (13% drop)"), "MWC3": (3, "Level 3 (20% drop, closed for the day)"),
        "MWC0": (2, "carried over from the day before")}


def nasdaq_halts(ctx):
    """Trading halts. Only a MARKET-WIDE circuit breaker counts; ordinary single-stock halts happen every day."""
    root = ET.fromstring(fetch(NASDAQ_HALTS, browser=True))
    ns = {"ndaq": "http://www.nasdaqtrader.com/"}
    items = root.findall(".//item")
    today = datetime.now(timezone.utc)
    hits = {}
    for it in items:
        code = (it.findtext("ndaq:ReasonCode", "", ns) or "").strip().upper()
        if code not in MWCB:
            continue
        try:
            day = datetime.strptime(it.findtext("ndaq:HaltDate", "", ns).strip(), "%m/%d/%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (today - day).days <= 1:
            hits[code] = day
    sigs = []
    for code in sorted(hits, key=lambda c: -MWCB[c][0]):
        sev, what = MWCB[code]
        sigs.append(Signal("finance", sev, f"Market-wide trading halt: circuit breaker {what}", "https://www.nasdaqtrader.com/Trader.aspx?id=TradeHalts",
                           "All US stock trading was paused by the exchanges' market-wide circuit breaker.", key=f"halt:{code}"))
        break
    return CollectResult(sigs, {"halts_listed": len(items), "market_wide": ", ".join(hits) or "-"})


# ------------------------------------------------------------ storm context (SPC + NHC)
SPC_RSS = "https://www.spc.noaa.gov/products/spcrss.xml"
NHC_RSS = "https://www.nhc.noaa.gov/index-at.xml"
TROPICAL_RX = re.compile(r"\b(hurricane|tropical storm|tropical depression|potential tropical cyclone)\b", re.I)


def storm_outlooks(ctx):
    """Storm Prediction Center watches and outlooks, and Hurricane Center Atlantic systems. CONTEXT ONLY: it can
    tell the assessment that big storms are active (a harmless explanation for outages), never raise the level."""
    notes, ok = [], 0
    try:
        root = ET.fromstring(fetch(SPC_RSS))
        ok += 1
        for it in root.findall(".//item"):
            t, desc = it.findtext("title", ""), it.findtext("description", "")
            if re.search(r"tornado watch", t, re.I):
                notes.append(re.sub(r"^SPC\s*-?\s*", "", t).strip())
            elif "Day 1 Convective Outlook" in t and re.search(r"\b(HIGH|MODERATE) RISK\b", desc):
                notes.append("Day 1 outlook: " + re.search(r"\b(HIGH|MODERATE) RISK\b", desc).group(0).lower())
    except Exception:
        pass
    try:
        root = ET.fromstring(fetch(NHC_RSS))
        ok += 1
        names = {re.split(r"\s+(?:Public|Forecast|Intermediate|Graphics|Wind|Tropical Cyclone Update)", it.findtext("title", ""))[0]
                 for it in root.findall(".//item") if TROPICAL_RX.search(it.findtext("title", ""))}
        notes += sorted(n for n in names if n)[:3]
    except Exception:
        pass
    if ok == 0:
        raise RuntimeError("SPC and NHC feeds unavailable")
    title = ("Storms active: " + "; ".join(notes[:4])) if notes else "No tornado watches, high-risk outlooks or Atlantic tropical systems"
    return CollectResult([Signal("natural", 0, title, "https://www.spc.noaa.gov/", "Context only: never raises the level.",
                                 key="spc-nhc", tags=["weather-major"] if notes else [])], {"items": len(notes)})


# ------------------------------------------------------------ bank failures (FDIC)
FDIC_CSV = "https://www.fdic.gov/bank-failures/download-data.csv"


def fdic_failures(ctx):
    """FDIC failed bank list. A failure in the last 7 days is a low-weight banks signal (never more than Watch alone)."""
    text = fetch(FDIC_CSV).decode("utf-8", "replace")
    import csv
    rows = [r for r in csv.reader(text.splitlines()[1:]) if r]
    now, recent = datetime.now(timezone.utc), []
    for r in rows:
        if len(r) < 6:
            continue
        try:
            day = datetime.strptime(r[5].strip(), "%d-%b-%y").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if 0 <= (now - day).days <= 7:
            recent.append((r[0].strip(), r[2].strip(), day))
    sigs = [Signal("finance", 1, f"FDIC closed {name} ({st}) on {day:%b %d}", "https://www.fdic.gov/bank-failures/failed-bank-list",
                   "An official bank failure. One alone is routine; depositors are normally protected.", key=f"fdic:{name}",
                   states=[st] if st in geo.VALID_STATES else [])
            for name, st, day in recent]
    return CollectResult(sigs, {"failures_last_7_days": len(recent), "banks_listed": len(rows)})


# ------------------------------------------------------------ state-level feeds
# These are REGIONAL: a signal counts in the views of the states it names and is context everywhere else
# (tag "regional-only", see engine._regionalize). On its own none of them goes above Watch.

WILDFIRE_URL = ("https://services3.arcgis.com/T4QMspbfLg3qTGWY/arcgis/rest/services/WFIGS_Incident_Locations_Current/"
                "FeatureServer/0/query")
WILDFIRE_MIN_ACRES = 1000      # a large fire
WILDFIRE_MAX_CONTAINED = 80    # mostly contained fires are winding down
WILDFIRE_MAX_AGE = 48 * 3600   # incidents nobody has updated in two days are not "active news"


def wildfires(ctx):
    """NIFC national wildfire incidents (free, no key): large, not-yet-contained, recently updated fires, per state."""
    q = urllib.parse.urlencode({
        "where": f"IncidentSize>={WILDFIRE_MIN_ACRES} AND IncidentTypeCategory='WF' AND "
                 f"(PercentContained IS NULL OR PercentContained<{WILDFIRE_MAX_CONTAINED})",
        "outFields": "POOState,IncidentName,IncidentSize,PercentContained,ModifiedOnDateTime_dt",
        "orderByFields": "IncidentSize DESC", "resultRecordCount": "200", "f": "json"})
    d = fetch_json(WILDFIRE_URL + "?" + q, timeout=30)
    if "features" not in d:
        raise RuntimeError("wildfire layer answered without data")
    now, by = time.time(), {}
    for f in d["features"]:
        a = f.get("attributes") or {}
        st = (a.get("POOState") or "")[-2:].upper()
        if st not in geo.VALID_STATES or now - (a.get("ModifiedOnDateTime_dt") or 0) / 1000 > WILDFIRE_MAX_AGE:
            continue
        by.setdefault(st, []).append(a)
    sigs = []
    for st, fires in sorted(by.items()):
        fires.sort(key=lambda a: -(a.get("IncidentSize") or 0))
        top = fires[0]
        pc = top.get("PercentContained")
        sigs.append(Signal("natural", 1, f"Wildfire: {len(fires)} large fire(s) in {st}, biggest {top.get('IncidentName', '?').title()} "
                           f"({top.get('IncidentSize', 0):,.0f} acres{'' if pc is None else f', {pc:.0f}% contained'})",
                           "https://www.nifc.gov/fire-information/nfn", "National Interagency Fire Center incident data.",
                           key=f"fire:{st}", tags=["regional-only"], states=[st], meta={"event": "Wildfire"}))
    return CollectResult(sigs, {"states_with_large_fires": ", ".join(sorted(by)) or "-"})


COOP_DATA = "https://outagemap-data.cloud.coop/{slug}/Hosted_Outage_Map/summary.json"


def coop_severity(out, served):
    """The local co-op reader's scale, capped at 2: one co-op is one area, never a national alarm by itself."""
    if out < 25 or not served:
        return 0
    pct = out / served
    return 2 if pct >= 0.05 and out >= 500 else 1 if pct >= 0.01 else 0


def make_coops(coops):
    """Electric co-op outage maps on the shared outagemap.coop platform: one small file per co-op, updated every minute."""
    def fn(ctx):
        if not coops:
            return CollectResult([], {"coops_ok": "none configured"})
        sigs, ok, failed, notes = [], 0, [], []
        for c in coops:
            try:
                d = fetch_json(COOP_DATA.format(slug=c["slug"]), timeout=15)
                if time.time() - d.get("lastUpdate", 0) / 1000 > 2700:
                    raise RuntimeError("stale")
            except Exception:
                failed.append(c["name"])
                continue
            ok += 1
            sets = d.get("regionDataSets") or []
            regions = sets[0].get("regions", []) if sets else []
            out = sum(r.get("numberOut", 0) for r in regions)
            served = d.get("totalServed") or sum(r.get("numberServed", 0) for r in regions)
            sev = coop_severity(out, served)
            notes.append(f"{c['name']} {out:,}")
            if sev:
                sigs.append(Signal("power", sev, f"{c['name']} ({c['state']}): {out:,} of {served:,} members without power",
                                   c.get("map") or f"https://{c['slug']}.outagemap.coop/", "From the co-op's own outage map.",
                                   key=f"coop:{c['slug']}", tags=["regional-only"], states=[c["state"]]))
        if ok == 0:
            raise RuntimeError("no co-op outage map reachable")
        return CollectResult(sigs, {"coops_ok": f"{ok}/{len(coops)}", "out": ", ".join(notes),
                                    "failed": ", ".join(failed) or "-"})
    return fn


ROAD_RX = re.compile(r"\b(I|IH|Interstate|US|U\.S\.|SR|State Route|State Highway|Hwy|Highway|M|K|MN|MO|KS|IA|WI|IN|LA|MD|MS|NJ|NH|VT|ME|AZ|FL)[\s-]*\d", re.I)
ROAD_MIN_CLOSURES = 5          # a state needs at least this many full highway closures before a jump can count
ROAD_SPIKE = 2.0               # ...and at least twice its own usual number


def major_closures(feed):
    """Full closures of numbered highways in one WZDx feed: (count, sample road names)."""
    n, roads = 0, []
    for f in feed.get("features", []):
        p = f.get("properties") or {}
        core = p.get("core_details") or {}
        if p.get("vehicle_impact") != "all-lanes-closed":
            continue
        names = core.get("road_names") or []
        if any(ROAD_RX.search(str(x)) for x in names):
            n += 1
            roads.append(str(names[0]))
    return n, roads


def make_wzdx(feeds):
    """State road-event feeds in the federal WZDx format. Routine work zones are ignored: only a sudden jump in FULL
    closures of numbered highways, against that state's own recent numbers, counts. Context: Watch at most."""
    def fn(ctx):
        if not feeds:
            return CollectResult([], {"feeds_ok": "none configured"})
        sigs, ok, failed, counts = [], 0, [], {}
        for fd in feeds:
            try:
                d = fetch_json(fd["url"], timeout=40, gzip_ok=True)
                if not isinstance(d.get("features"), list):
                    raise RuntimeError("not WZDx")
            except Exception:
                failed.append(fd["name"])
                continue
            ok += 1
            n, roads = major_closures(d)
            c = counts.setdefault("/".join(fd["states"]), [0, [], fd["states"]])
            c[0] += n
            c[1] += roads
        for st, (n, roads, states) in sorted(counts.items()):
            key = f"roads:{st}"
            base, _n = ctx.store.baseline(key) if ctx else (None, 0)
            ctx and ctx.store.record(key, n)
            if base is None or n < ROAD_MIN_CLOSURES or n < ROAD_SPIKE * max(base, 1):
                continue
            sample = ", ".join(sorted(set(roads))[:3])
            sigs.append(Signal("roads", 1, f"Roads in {st}: {n} full highway closures (usually about {base:g})",
                               "https://www.transportation.gov/av/data/wzdx", f"From the state's road-event feed. {sample}",
                               key=key, tags=["regional-only"], states=list(states)))
        if ok == 0:
            raise RuntimeError("no state road-event feed reachable")
        return CollectResult(sigs, {"feeds_ok": f"{ok}/{len(feeds)}", "full_closures": ", ".join(f"{s} {v[0]}" for s, v in sorted(counts.items())),
                                    "failed": ", ".join(failed) or "-"})
    return fn


def build_collectors(cfg, data_dir=None):
    iv = cfg["intervals"]
    _LOCAL_RX[0] = signalwords.load_local(data_dir) if data_dir else None
    cs = [
        Collector("FAA air traffic status", "gov", "https://nasstatus.faa.gov/", iv["faa"], faa_nas),
        Collector("NWS emergency alerts", "gov", "https://alerts.weather.gov/", iv["nws"], nws_alerts),
        Collector("NWS severe-weather context", "gov", "https://www.weather.gov/", iv.get("nws_weather", 300),
                  nws_weather),
        Collector("NOAA space weather", "gov", "https://www.swpc.noaa.gov/", iv["swpc"], swpc),
        Collector("USGS seismic", "gov", "https://earthquake.usgs.gov/earthquakes/map/", iv["usgs"], usgs),
        Collector("CISA advisories (CSA/ED/KEV)", "gov", "https://www.cisa.gov/news-events/cybersecurity-advisories",
                  iv["cisa"], cisa),
        Collector("SANS Internet Storm Center", "private", "https://isc.sans.edu/", iv["sans"], sans_infocon),
        Collector("Georgia Tech IODA internet outages", "private",
                  "https://ioda.inetintelligence.cc.gatech.edu/country/US", iv["ioda"], ioda),
        Collector("Platform status pages", "private", "https://www.cloudflarestatus.com/", iv["status_pages"],
                  make_status_pages(cfg["status_pages"])),
        Collector("AWS / Google Cloud / Azure health", "private", "https://status.cloud.google.com/", iv["cloud"],
                  cloud_providers),
        Collector("OpenSky live US air traffic", "private", "https://opensky-network.org/network/explorer",
                  iv["adsb"], adsb),
        Collector("Private-jet tracker (Apocalypse Early Warning System)", "private", "https://ews.kylemcdonald.net/",
                  iv.get("ews", 1800), ews_jets),
        Collector("Stock market and bank stocks", "private", "https://finance.yahoo.com/markets/",
                  iv.get("markets", 600), stock_market),
        Collector("DHS terrorism advisory (NTAS)", "gov", NTAS_URL, iv.get("ntas", 3600), ntas),
        Collector("IODA phone carriers (AT&T, Verizon, T-Mobile)", "private",
                  "https://ioda.inetintelligence.cc.gatech.edu/country/US", iv.get("carriers", 300), ioda_carriers),
        Collector("Nasdaq market-wide halts", "private", "https://www.nasdaqtrader.com/Trader.aspx?id=TradeHalts",
                  iv.get("halts", 120), nasdaq_halts),
        Collector("NOAA storm outlooks (SPC / NHC)", "gov", "https://www.spc.noaa.gov/", iv.get("storms", 600), storm_outlooks),
        Collector("Wildfires (NIFC)", "gov", "https://www.nifc.gov/fire-information/nfn", iv.get("wildfires", 900), wildfires),
        Collector("Co-op outage maps", "private", "https://outagemap-data.cloud.coop/", iv.get("coops", 300),
                  make_coops(cfg.get("coops", []))),
        Collector("State road events (WZDx)", "gov", "https://www.transportation.gov/av/data/wzdx", iv.get("wzdx", 600),
                  make_wzdx(cfg.get("wzdx_feeds", []))),
        Collector("FDIC failed banks", "gov", "https://www.fdic.gov/bank-failures/failed-bank-list", iv.get("fdic", 21600),
                  fdic_failures),
        Collector("Reddit", "social", "https://www.reddit.com/", iv["reddit"], make_reddit(cfg)),
        Collector("Bluesky", "social", "https://bsky.app/search", iv["bluesky"], make_bluesky(cfg)),
        Collector("Connectivity check", "system", "", iv["canary"], canary),
    ]
    eia_key = load_eia_key(data_dir)
    demo = eia_key == "DEMO_KEY"
    cs.append(Collector("EIA grid demand vs forecast", "gov",
                        "https://www.eia.gov/electricity/gridmonitor/dashboard/electric_overview/US48/US48",
                        2200 if demo else iv.get("grid", 900), make_eia_grid(eia_key)))   # DEMO_KEY: stay under ~50/day
    cf_token = load_cloudflare_token(data_dir)
    if cf_token:   # optional: only registered when a token exists, so it never shows as a "failed" source
        cs.append(Collector("Cloudflare Radar outages", "private", "https://radar.cloudflare.com/outage-center",
                            iv.get("radar", 300), make_cloudflare_radar(cf_token)))
        cs.append(Collector("Cloudflare Radar carrier outages (AT&T, Verizon, T-Mobile)", "private",
                            "https://radar.cloudflare.com/outage-center", iv.get("radar", 300), make_radar_carriers(cf_token)))
    loc = cfg.get("local")
    if loc:
        cs.append(Collector(f"Weather Service alerts for {loc['name']}", "gov",
                            f"https://forecast.weather.gov/MapClick.php?lat={loc['lat']}&lon={loc['lon']}",
                            iv.get("local_nws", 120), make_local_nws(loc)))
        if loc.get("outage_data"):
            cs.append(Collector(f"{loc['utility']} outages", "private", loc["outage_map"],
                                iv.get("local_power", 300), make_local_power(loc)))
    for q in cfg["news_queries"]:
        cs.append(Collector("News: " + q["name"], "news", "https://news.google.com/", iv["news"], make_news(q)))
    if cfg.get("drudge", {}).get("enabled"):
        cs.append(Collector("Drudge Report front page", "news", DRUDGE_URL, iv.get("drudge", 600), make_drudge(cfg)))
    return cs
