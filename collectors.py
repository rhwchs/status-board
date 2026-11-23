"""Data collectors.

Each collector is a function fn(ctx) -> CollectResult. Raising an exception means
"this source failed" (the dashboard shows it as unreachable; it is never silently
treated as 'all clear').

Severity scale used everywhere:
  0 = status / context only      1 = watch
  2 = elevated                   3 = critical
"""
import html
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

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


def fetch(url, browser=False, timeout=20, max_bytes=12_000_000, headers=None, curl_first=False):
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
    sus = re.compile(r"secur|equip|outage|telecom|atc|staff|unspec|other|power|system|cyber|"
                     r"threat|tfr|evacu|fire|emergen|national", re.I)
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
    if event == "Law Enforcement Warning":
        return ["official-physical"]
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
                           links=links, tags=_nws_tags(ev, sev)))
    if not sigs:
        sigs.append(Signal("emergency", 0, "No emergency-level Weather Service alerts right now",
                           "https://alerts.weather.gov/", key="nws:none"))
    return CollectResult(sigs, {"active_emergency_alerts": len(feats)})


WEATHER_EVENTS = ("Hurricane Warning", "Tropical Storm Warning", "Tornado Warning", "Blizzard Warning",
                  "Ice Storm Warning", "Winter Storm Warning", "Extreme Wind Warning", "Storm Surge Warning",
                  "Excessive Heat Warning", "High Wind Warning")
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
    return CollectResult(
        [Signal("natural", 0, f"Severe weather right now: {len(feats)} active warnings" + (" (major storms)" if major else ""),
                "https://www.weather.gov/", top or "none", key="nws:weather",
                tags=["weather-major"] if major else [])],
        {"weather_warnings": len(feats), "major": major})


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
        d = fetch_json("https://api.eia.gov/v2/electricity/rto/region-data/data/?" + urllib.parse.urlencode(params),
                       timeout=40)
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
            ts = datetime.strptime(p, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc).timestamp()
            if resp == "US48":
                if time.time() - ts > 8 * 3600:
                    raise RuntimeError(f"EIA data is stale (latest hour {p} UTC)")
                summary = {"data_hour_utc": p, "us48_demand_vs_forecast": f"{ratio:.0%}"}
            if sev == 0 and resp != "US48":
                continue
            lows += 1 if sev else 0
            sigs.append(Signal("power", sev,
                               f"Electricity use in {label} is {ratio:.0%} of what was forecast ({v['D']:,.0f} vs {v['DF']:,.0f} MW)",
                               "https://www.eia.gov/electricity/gridmonitor/dashboard/electric_overview/US48/US48",
                               f"Latest data is from {p} UTC (about 1-2 hours behind). A big, lasting drop can mean widespread power outages.",
                               key=f"eia:{resp}"))
        if not sigs:
            raise RuntimeError("EIA response had no usable demand/forecast pairs")
        summary["regions_low"] = lows
        return CollectResult(sigs, summary)
    return fn


# -------------------------------------------------------------- private status

def make_status_pages(pages):
    """Statuspage.io-style summaries for big platforms. Simultaneous major outages = signal."""
    def fn(ctx):
        sigs, ok, failed, bad = [], 0, [], 0
        for p in pages:
            try:
                d = fetch_json(p["url"].rstrip("/") + "/api/v2/summary.json", timeout=15)
            except Exception:
                failed.append(p["name"])
                continue
            ok += 1
            ind = d.get("status", {}).get("indicator", "none")
            sev = {"none": 0, "minor": 0, "major": 1, "critical": 2}.get(ind, 0)
            if sev >= 1:
                bad += 1
            if ind != "none":
                inc = [i.get("name", "") for i in d.get("incidents", [])][:3]
                sigs.append(Signal("internet", sev, f"{p['name']}: {d['status'].get('description', ind)}",
                                   p["url"], "; ".join(inc), key=f"status:{p['name']}"))
        if bad >= 3:
            sigs.append(Signal("internet", 2, f"{bad} big online services report serious outages at the same time",
                               "", key="status:multi"))
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

_GOOGLE_BACKOFF = {"until": 0}


# Headlines that are not breaking news. Google matches words ANYWHERE in the story, so entertainment and
# "explosion of growth" style headlines slip in; and a big event produces days of explainer / "it was not an
# attack" follow-ups that should not look like fresh trouble.
NEWS_NOISE_RX = re.compile(
    r"\b(movie|movies|film|films|trailer|box office|netflix|hbo|streaming|season \d+|episode|novel|album|"
    r"video game|actor|actress|starring|premieres?|tv series|documentary|sitcom|thriller|horror|marvel)\b", re.I)
NEWS_FOLLOWUP_RX = re.compile(
    r"\b(restored|resolved|back online|back up and running|what we know|what to know|explained|explainer|"
    r"why did|why do|how did|what caused|root cause|aftermath|anniversary|years? ago|apolog(?:y|ies|ize|izes)|"
    r"lessons|no evidence|not (?:a |an )?(?:cyber ?)?attack|not malicious|ruled out|"
    r"(?:days?|weeks?|months?|years?) after)\b", re.I)


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
                items = parse_feed(fetch(g, browser=True))
            except Exception as e1:
                err1 = e1
                if isinstance(e1, urllib.error.HTTPError) and e1.code == 429:
                    _GOOGLE_BACKOFF["until"] = time.time() + 1200   # throttled: stop asking for 20 min
        else:
            err1 = "throttled, backing off"
        if items is None:
            try:
                items = parse_feed(fetch(b, browser=True))
                used = "Bing"
                link = "https://www.bing.com/news/search?q=" + urllib.parse.quote(query)
            except Exception as e2:
                raise RuntimeError(f"Google: {err1}; Bing: {e2}")
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
            if NEWS_NOISE_RX.search(t) or (exc and exc.search(t)) or not all(r.search(t) for r in req):
                unrelated += 1
            elif not ctx_only and NEWS_FOLLOWUP_RX.search(t):
                followups += 1
            else:
                kept.append(i)
        recent = kept
        n = len({i["pub"] for i in recent})
        if used == "Bing" and raw_n == 0:
            # Bing's index lags by hours, so an empty Bing result proves nothing. Report the source as
            # failed (keeps the previous alert alive) rather than a false "no coverage".
            raise RuntimeError(f"Google News unavailable ({err1}); Bing fallback cannot confirm last-hour coverage")
        key = "news:" + q["name"]
        skey = "newsf:" + q["name"]      # filtered counts: separate history so old unfiltered baselines don't linger
        rate = ctx.store.rate_severity(skey, n, q.get("thresholds"), ctx.cfg.get("social_min_count", 5))
        ctx.store.record(skey, n)
        sev = min(rate.sev, q.get("max_sev", 3))
        ignored = unrelated + followups
        if n == 0:
            return CollectResult([], {"outlets_1h": 0, "ignored": ignored})
        base = (f"usually about {rate.baseline:g}" if rate.baseline is not None
                else f"still learning what is normal for this ({rate.n} of 8 readings)")
        if ignored:
            base += (f" · ignored {unrelated} unrelated and {followups} follow-up stor"
                     f"{'y' if unrelated + followups == 1 else 'ies'} about events already over")
        if used == "Bing":
            base += " · via Bing (Google is limiting requests)"
        links = [{"title": f"{short(i['title'], 100)} — {i['pub']}", "url": i["link"]} for i in recent[:6]]
        return CollectResult([Signal(q["category"], sev, f"News: {q['name']} — {n} news outlets covering this in the last hour",
                                     link, base, key=key, links=links)], {"outlets_1h": n, "ignored": ignored})
    return fn


# ---------------------------------------------------------------------- social

def _emit_social(ctx, platform, home, counts, samples, covered, labelmap):
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
        sigs.append(Signal(cat, sev, f"{platform}: about {c} posts per hour mentioning {labelmap.get(cat, cat)}",
                           home, base, key=key, links=samples.get(cat, [])[:5]))
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
                scanned += 1
                for cat, rx in kw.items():
                    if rx.search(it["title"]):
                        counts[cat] = counts.get(cat, 0) + 1
                        samples.setdefault(cat, []).append(
                            {"title": f"r/{sub}: {short(it['title'], 110)}", "url": it["link"]})
        if ok == 0:
            raise RuntimeError("no subreddit feed reachable")
        sigs = _emit_social(ctx, "Reddit", "https://www.reddit.com/", counts, samples, list(kw),
                            {c: c for c in kw})
        return CollectResult(sigs, {"subs_ok": f"{ok}/{len(cfg['reddit_subs'])}", "posts_scanned_1h": scanned})
    return fn


def make_mastodon(cfg):
    def fn(ctx):
        counts, samples, ok, saturated = {}, {}, 0, 0
        now = time.time()
        for tag, cat in cfg["mastodon_tags"].items():
            try:
                posts = fetch_json(f"https://mastodon.social/api/v1/timelines/tag/{tag}?limit=40")
            except Exception:
                continue
            ok += 1
            times = [parse_time(p.get("created_at")) for p in posts]
            recent = [p for p, t in zip(posts, times) if t and now - t < 3600]
            if len(recent) >= 40:
                saturated += 1
            counts[cat] = counts.get(cat, 0) + rate_per_hour(times, 40, now)
            for p in recent[:3]:
                samples.setdefault(cat, []).append(
                    {"title": f"#{tag}: {short(strip_html(p.get('content')), 110)}", "url": p.get("url", "")})
        if ok == 0:
            raise RuntimeError("Mastodon unreachable")
        sigs = _emit_social(ctx, "Mastodon", "https://mastodon.social/explore", counts, samples,
                            sorted(set(cfg["mastodon_tags"].values())), CATEGORIES)
        return CollectResult(sigs, {"tags_ok": f"{ok}/{len(cfg['mastodon_tags'])}", "saturated_tags": saturated})
    return fn


def make_bluesky(cfg):
    def fn(ctx):
        counts, samples, ok = {}, {}, 0
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
            times = [parse_time(p.get("indexedAt")) for p in posts]
            counts[cat] = counts.get(cat, 0) + rate_per_hour(times, 100, time.time())
            for p in posts[:3]:
                rkey = p["uri"].rsplit("/", 1)[-1]
                handle = p["author"]["handle"]
                samples.setdefault(cat, []).append(
                    {"title": f"{q['q']}: {short(p['record'].get('text', ''), 110)}",
                     "url": f"https://bsky.app/profile/{handle}/post/{rkey}"})
            time.sleep(0.5)
        if ok == 0:
            raise RuntimeError("Bluesky search unreachable")
        sigs = _emit_social(ctx, "Bluesky", "https://bsky.app/search", counts, samples,
                            sorted({q["category"] for q in cfg["bluesky_queries"]}), CATEGORIES)
        return CollectResult(sigs, {"queries_ok": f"{ok}/{len(cfg['bluesky_queries'])}"})
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


def build_collectors(cfg, data_dir=None):
    iv = cfg["intervals"]
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
        Collector("Reddit", "social", "https://www.reddit.com/", iv["reddit"], make_reddit(cfg)),
        Collector("Mastodon", "social", "https://mastodon.social/explore", iv["mastodon"], make_mastodon(cfg)),
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
    return cs
