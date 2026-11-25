"""Who is saying it matters as much as how many are saying it.

Counting "outlets covering a story" treats the Associated Press and a content-farm aggregator as equals, and counts
one wire story reprinted by 15 sites as 15 independent confirmations. This module fixes both:

  * every outlet gets a TRUST TIER (1 = wire services, major networks and papers, and the trade press for that
    topic; 2 = other established or local-network outlets; 3 = unknown; 4 = aggregators, content farms and
    state-controlled media, which can be an attacker's megaphone). A tier is a weight, never a verdict.
  * headlines that are near-identical are one SYNDICATED story, counted once, at the best outlet's weight.

The result is an "effective" count of independent reports, plus how many came from top-tier outlets. A story that
several independent top-tier outlets are reporting is CREDIBLE even before any government source acknowledges it
(governments are often slow to confirm bad news); the assessment uses that as a leading indicator, but never lets
it replace live telemetry for the top alarm level.

Everything here is a default you can override in config.json under "trust" (lists of outlet names per tier).
"""
import re

WEIGHT = {1: 1.0, 2: 0.7, 3: 0.4, 4: 0.1}
CREDIBLE_TOP_TIER = 3          # independent top-tier reports that make a story credible

TIER1 = {
    "reuters", "associated press", "ap", "ap news", "bbc", "bbc news", "cnn", "nbc news", "abc news", "cbs news",
    "fox news", "npr", "pbs", "pbs newshour", "bloomberg", "bloomberg.com", "the new york times", "new york times",
    "the washington post", "washington post", "wall street journal", "the wall street journal", "wsj",
    "usa today", "politico", "axios", "the guardian", "financial times", "the associated press", "al jazeera",
    "the economist", "time", "los angeles times", "afp", "agence france-presse", "msnbc", "ms now",
}
TIER2 = {
    "the hill", "newsweek", "business insider", "forbes", "cnbc", "marketwatch", "the atlantic", "vox", "slate",
    "the independent", "sky news", "nbc news", "the verge", "wired", "ars technica", "techcrunch", "the daily beast",
    "washington examiner", "new york post", "the telegraph", "globe and mail", "cbc", "abc australia",
    "the times of israel", "haaretz", "the jerusalem post", "the straits times", "nikkei asia", "japan times",
}
TIER4 = {
    "msn", "newsbreak", "yahoo news", "yahoo", "yahoo finance", "dailyhunt", "flipboard", "ground news", "news break",
    "bignewsnetwork", "dnyuz", "newsbreak local",
    # state-controlled media of adversary governments (can amplify an attacker's claims)
    "rt", "rt.com", "sputnik", "tass", "press tv", "tasnim news agency", "fars news agency", "irna", "xinhua",
    "global times", "cgtn", "china daily", "kcna", "al mayadeen", "tehran times", "sputnik news",
}
# The outlets the owner trusts most (override with config "trust": {"core": [...]}). They are all tier 1 already; this
# only lets the dashboard say how many of the reporters were from this inner circle.
CORE = {"the new york times", "new york times", "cnn", "the guardian", "financial times", "axios", "associated press", "ap",
        "ap news", "the associated press"}
# Sites with a documented record of conspiracy content or repeatedly false claims. Tier 4: they can still be a LEAD worth
# checking (see credibility.py / drudge), but they never count as confirmation.
TIER4 |= {"infowars", "natural news", "naturalnews", "before it's news", "beforeitsnews", "the gateway pundit",
          "gateway pundit", "global research", "zerohedge", "zero hedge", "activist post", "great game india",
          "stillness in the storm", "x", "twitter", "truth social", "telegram", "facebook", "tiktok", "reddit"}
# website domain -> outlet name, so a LINK (e.g. from Drudge Report's front page) can be judged by who it points to
DOMAINS = {
    "nytimes.com": "The New York Times", "cnn.com": "CNN", "msnbc.com": "MSNBC", "ms.now": "MS NOW", "theguardian.com": "The Guardian", "ft.com": "Financial Times",
    "axios.com": "Axios", "apnews.com": "Associated Press", "reuters.com": "Reuters", "bbc.co.uk": "BBC News",
    "bbc.com": "BBC News", "washingtonpost.com": "The Washington Post", "wsj.com": "Wall Street Journal",
    "bloomberg.com": "Bloomberg", "npr.org": "NPR", "pbs.org": "PBS", "politico.com": "Politico", "usatoday.com": "USA Today",
    "nbcnews.com": "NBC News", "cbsnews.com": "CBS News", "abcnews.go.com": "ABC News", "foxnews.com": "Fox News",
    "latimes.com": "Los Angeles Times", "economist.com": "The Economist", "aljazeera.com": "Al Jazeera",
    "cnbc.com": "CNBC", "marketwatch.com": "MarketWatch", "thehill.com": "The Hill", "newsweek.com": "Newsweek",
    "nypost.com": "New York Post", "telegraph.co.uk": "The Telegraph", "businessinsider.com": "Business Insider",
    "forbes.com": "Forbes", "skynews.com": "Sky News", "news.sky.com": "Sky News", "independent.co.uk": "The Independent",
    "dailymail.co.uk": "Daily Mail", "rt.com": "RT", "sputnikglobe.com": "Sputnik", "tass.com": "TASS",
    "presstv.ir": "Press TV", "xinhuanet.com": "Xinhua", "globaltimes.cn": "Global Times",
    "infowars.com": "Infowars", "naturalnews.com": "Natural News", "beforeitsnews.com": "Before It's News",
    "thegatewaypundit.com": "The Gateway Pundit", "globalresearch.ca": "Global Research", "zerohedge.com": "ZeroHedge",
    "activistpost.com": "Activist Post", "x.com": "X", "twitter.com": "X", "t.me": "Telegram", "truthsocial.com": "Truth Social",
    "facebook.com": "Facebook", "tiktok.com": "TikTok", "reddit.com": "Reddit", "msn.com": "MSN",
    "yahoo.com": "Yahoo News", "news.yahoo.com": "Yahoo News", "newsbreak.com": "NewsBreak",
}

# trade press that is first-rate FOR ITS OWN TOPIC (tier 1 for that category only)
DOMAIN_TIER1 = {
    "aviation": {"aviation week", "flightglobal", "simple flying", "aviation international news", "airline geeks"},
    "cyber": {"bleepingcomputer", "the record", "the record from recorded future", "cyberscoop", "securityweek",
              "dark reading", "krebs on security", "krebsonsecurity", "the hacker news", "ars technica", "wired"},
    "power": {"utility dive", "e&e news", "power engineering", "reuters", "the energy mix", "rtoinsider"},
    "telecom": {"light reading", "fierce network", "fierce wireless", "telecompetitor", "the register"},
    "internet": {"the register", "bleepingcomputer", "downdetector", "data center dynamics", "ars technica"},
    "finance": {"american banker", "cnbc", "marketwatch", "barron's", "financial times", "bloomberg"},
    "nuclear": {"defense one", "breaking defense", "the war zone", "military times", "stars and stripes",
                "defense news", "janes", "institute for the study of war", "the drive", "task & purpose"},
    "security": {"military times", "stars and stripes", "defense one", "the war zone"},
}
# local broadcast affiliates (WABC-TV, KTLA, "Fox 5", "NBC 4") are established but not national: tier 2
LOCAL_AFFIL_RX = re.compile(r"(?<![a-z])(abc|nbc|cbs|fox|cw|pbs)\s?-?\d*(?![a-z])|^[kw][a-z]{2,3}(-tv| tv| news)?(\s|$)"
                            r"|\b(tribune|herald|gazette|dispatch|courier|journal|sentinel|chronicle|post-gazette|"
                            r"star-ledger|inquirer|plain dealer|ledger)\b", re.I)

_STOP = set("a an the of to in on at for and or is are was were be by with as from that this it its after over "
            "amid new says say said live updates what we know".split())
_SUFFIX = re.compile(r"\s+[-–—|]\s+[^|–—]{2,40}$")          # " - Outlet" / " | AP" (spaces around the dash)
_PAREN = re.compile(r"\s*\((ap|reuters|afp|upi)\)\s*", re.I)


def _norm(name):
    n = re.sub(r"\.(com|org|net|co\.uk)$", "", (name or "").strip().lower())
    return re.sub(r"\s+", " ", n)


def tier_of(outlet, category=None, cfg=None):
    """1-4 trust tier for an outlet name (optionally relative to a topic)."""
    n = _norm(outlet)
    over = (cfg or {}).get("trust", {}) if isinstance(cfg, dict) else {}
    for t in (1, 2, 3, 4):
        if n in {_norm(x) for x in over.get(f"tier{t}", [])}:
            return t
    if n in TIER4:
        return 4
    if n in TIER1:
        return 1
    if category and n in DOMAIN_TIER1.get(category, ()):
        return 1
    if n in TIER2 or LOCAL_AFFIL_RX.search(n):
        return 2
    return 3


def outlet_from_url(url):
    """Outlet name for a link, from its website. Unknown sites keep their domain name (tier 3 unless configured)."""
    host = re.sub(r"^https?://", "", (url or "").lower()).split("/")[0].split(":")[0]
    host = host[4:] if host.startswith("www.") else host
    for dom, name in DOMAINS.items():
        if host == dom or host.endswith("." + dom):
            return name
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_core(outlet, cfg=None):
    over = (cfg or {}).get("trust", {}).get("core") if isinstance(cfg, dict) else None
    pool = {_norm(x) for x in over} if over else CORE
    return _norm(outlet) in pool


def _tokens(title):
    t = _PAREN.sub(" ", title or "")
    t = _SUFFIX.sub("", t) if " - " in t or " | " in t else t
    return {w for w in re.findall(r"[a-z0-9']+", t.lower()) if w not in _STOP and len(w) > 1}


def _same_story(a, b, cut=0.8):
    if not a or not b:
        return False
    return len(a & b) / len(a | b) >= cut


def summarize(items, category=None, cfg=None):
    """items: [{"title", "pub"}...]. Returns the weighted, de-duplicated picture of who is reporting.

    n_raw      distinct outlets (what the old counter reported)
    n_eff      effective independent reports: syndicated copies count once, weighted by the best outlet's tier
    t1 / t2    independent reports whose best outlet is tier 1 / tier 2
    syndicated how many extra outlets were copies of a story already counted
    """
    rows = [(i.get("pub") or "", _tokens(i.get("title", ""))) for i in items]
    outlets = {p for p, _ in rows if p}
    clusters = []                                    # each: {"tok": set, "tiers": [..]}
    for pub, tok in rows:
        tier = tier_of(pub, category, cfg)
        for c in clusters:
            if _same_story(tok, c["tok"]):
                c["tiers"].append(tier)
                break
        else:
            clusters.append({"tok": tok, "tiers": [tier]})
    best = [min(c["tiers"]) for c in clusters]
    n_eff = sum(WEIGHT[t] for t in best)
    return {
        "n_raw": len(outlets),
        "n_eff": round(n_eff, 1),
        "clusters": len(clusters),
        # distinct top-tier OUTLETS, never more than the independent stories: three pieces from one outlet are one voice
        "t1": min(sum(1 for t in best if t == 1), len({p for p, _ in rows if p and tier_of(p, category, cfg) == 1})),
        "t2": sum(1 for t in best if t == 2),
        "core": len({p for p, _ in rows if p and is_core(p, cfg)}),   # distinct inner-circle outlets among the reporters
        "syndicated": len(rows) - len(clusters),
        "top": sorted({(p, tier_of(p, category, cfg)) for p, _ in rows if p}, key=lambda x: (x[1], x[0]))[:6],
    }


def credible(meta):
    """Is this news signal backed by several INDEPENDENT top-tier reports? (meta = the dict from summarize)"""
    return bool(meta) and meta.get("t1", 0) >= CREDIBLE_TOP_TIER
