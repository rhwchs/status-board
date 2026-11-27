"""Read the story, not just the headline.

A headline can match a scary keyword while the story is about something else (a political piece that says "explosion",
a sports piece that says "blackout"). Before a headline is counted as evidence, this module opens the story and checks
that the body actually describes a disruption: the topic AND a concrete effect (an outage, people affected, flights
cancelled, injuries, a service offline) close together in the same paragraph.

    verdict "real"     the body describes a disruption in this area; the headline counts
    verdict "passing"  the body only mentions the topic in passing; the headline is dropped
    verdict "earlier"  the body describes a real event, but one that happened some weeks ago and is only now reported;
                       it counts, but never as proof of something happening right now
    verdict "stale"    the body is about an event from days or weeks ago (dates, "two weeks ago"); the headline is dropped
    verdict "unread"   the story could not be opened (paywall, block, timeout); the headline counts as before, marked unread

Verdicts are cached for hours, and each news check opens only a few stories, so this adds little traffic.
"""
import html
import re
import time

import freshness

CACHE_HOURS = 6
MAX_READS = 4            # stories opened per news check
_CACHE = {}              # url -> (time, verdict)

TOPIC = {
    "aviation": r"flights?|airports?|ground stop|air traffic|\bFAA\b|airlines?|planes?",
    "telecom": r"\b911\b|cell(ular)?|wireless|phone|carrier|network|dispatch|\bservice\b",
    "power": r"power|electric\w*|\bgrid\b|outages?|blackout|substation|utility|utilities",
    "cyber": r"cyber\w*|ransomware|hack\w*|breach\w*|malware|\bsystems?\b|network",
    "security": r"explosions?|blasts?|bomb\w*|attack\w*|shooting|gunfire|casualt\w*|killed|injured|evacuat\w*",
    "nuclear": r"nuclear|missiles?|\bEMP\b|pulse|radiation|strikes?",
    "fuel": r"pipelines?|refiner\w+|fuel|gasoline|natural gas|gas stations?|\bLNG\b",
    "water": r"water|\bdams?\b|reservoirs?|wastewater|treatment",
    "transport": r"rail\w*|trains?|derail\w+|bridges?|\bports?\b|interstate|highway|tunnel",
    "industrial": r"chemical|nuclear|hazmat|\bSCADA\b|industrial|plant",
    "finance": r"banks?|banking|\bATMs?\b|payments?|withdraw\w*|markets?|trading|\bFDIC\b|deposits?",
}
# a concrete effect on people or services, deliberately not generic words like "officials said"
IMPACT = (r"outages?|without (power|electricity|service|water)|lost (power|service)|customers|residents|thousands|"
          r"hundreds|millions|cancel+ed|delay(ed|s)|grounded|offline|knocked out|shut ?down|halted|suspended|"
          r"injur\w+|killed|dead|died|casualt\w+|evacuat\w+|damage\w*|disrupt\w+|unable to|could(n't| not) (call|connect|log)|"
          r"service (was|is|remains) (down|interrupted|disrupted)")


def _text(raw):
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    extra = []        # pages built by scripts have no <p> text, but usually carry a summary in their metadata
    for m in re.finditer(r'(?is)<meta\b[^>]*?(?:property|name)=["\'](?:og:description|description|twitter:description)["\'][^>]*?content=["\'](.*?)["\']', s):
        extra.append(html.unescape(m.group(1)))
    for m in re.finditer(r'(?is)"(?:articleBody|description)"\s*:\s*"((?:[^"\\]|\\.){60,3000})"', s):
        extra.append(html.unescape(m.group(1).encode().decode("unicode_escape", "ignore")) if "\\u" in m.group(1) else m.group(1))
    s = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer|header|aside|form)\b.*?</\1>", " ", s)
    paras = re.findall(r"(?is)<p\b[^>]*>(.*?)</p>", s)
    out = []
    for p in paras:
        t = html.unescape(re.sub(r"(?s)<[^>]+>", " ", p))
        t = re.sub(r"\s+", " ", t).strip()
        if len(t) >= 60:
            out.append(t)
    for t in extra:
        t = re.sub(r"\s+", " ", t).strip()
        if len(t) >= 60:
            out.append(t)
    return out[:40]


# Hacks are described by what was reached, not by outages, so the cyber check also accepts these effects.
CYBER_IMPACT = (r"compromis\w+|exposed|stolen|steal\w*|accessed|breach(?:ed|es)\b|sensitive|classified|unauthori[sz]ed|"
                r"intrud\w+|infiltrat\w+|exfiltrat\w+|ransom\w*|encrypted|locked out|data")


def judge(paragraphs, category):
    """Pure text check, no network: 'real' if one paragraph holds both the topic and a concrete effect."""
    if not paragraphs:
        return "unread"
    if freshness.stale_reason(" ".join(paragraphs[:6])):      # the opening paragraphs say the event was long ago
        return "stale"
    topic = re.compile(TOPIC.get(category, TOPIC["security"]), re.I)
    impact = re.compile(IMPACT + ("|" + CYBER_IMPACT if category == "cyber" else ""), re.I)
    for p in paragraphs:
        if topic.search(p) and impact.search(p):
            return "earlier" if freshness.earlier_reason(" ".join(paragraphs[:6])) else "real"
    return "passing"


def read(url, category, fetch, now=None):
    """Open one story and return its verdict. `fetch` is the engine's own fetch function (so tests can fake it)."""
    now = now or time.time()
    hit = _CACHE.get(url)
    if hit and now - hit[0] < CACHE_HOURS * 3600:
        return hit[1]
    try:
        v = judge(_text(fetch(url, browser=True, timeout=10, max_bytes=600_000)), category)
    except Exception:
        v = "unread"
    if v != "unread":                  # an unreadable story is retried next time
        _CACHE[url] = (now, v)
    return v


def screen(items, category, fetch, max_reads=MAX_READS, now=None):
    """items: [{"title", "link", ...}] newest first. Opens up to max_reads stories and returns
    (kept, dropped, read_count). Stories beyond the cap, and ones that cannot be opened, are kept as before."""
    kept, dropped, reads = [], [], 0
    for i in items:
        url = i.get("link") or ""
        cached = _CACHE.get(url)
        if not url or (not cached and reads >= max_reads):
            kept.append(i)
            continue
        if not cached:
            reads += 1
        v = read(url, category, fetch, now)
        i["story"] = v
        (dropped if v in ("passing", "stale") else kept).append(i)
    return kept, dropped, reads
