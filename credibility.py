"""Is this viral social-media claim worth believing? Four checks, each one itemized.

Social media is the fastest signal and also the easiest to fake, so a post only counts for anything when it is
(1) actually spreading, (2) from an account that looks real, (3) backed by someone else, and (4) not already
debunked. The result is a 0-100 CLAIM SCORE with its reasons; the monitor never treats it as proof.

    virality      0-30   engagement (likes + reposts + quotes + replies) well above ordinary chatter
    the poster    0-30   account age, followers, posting volume, bot flag, shouting / conspiracy language
    corroboration 0-40   a government or live-data source in the same area (+40), several independent top-tier news
                         outlets (+30), any news coverage (+12), nothing at all (0)
    fact-check    -60    news outlets are calling claims of this kind fake / a hoax

    >= 65  "verified"    a spreading claim from a credible account that something else confirms
    <= 35 and a low-credibility poster   "rumor"; debunked = "refuted"
    in between           "unverified"

What it can and cannot do: it works from public profile and engagement numbers and a few language patterns. It
cannot read minds ("is this person crazy?" becomes "is this account new, tiny, hyperactive or shouting?"), and it
cannot see private groups, Telegram or X, and it does not yet know WHERE a post is about (a post about a blackout abroad is
scored like any other). Reddit's feed shows no engagement numbers, so Reddit posts are not scored.
"""
import math
import re
import time
from datetime import datetime, timezone

VIRAL_MIN = 100             # engagement at which a post counts as "going viral" (config: social_viral_min)
VERIFIED, RUMOR = 65, 35

SHOUT_RX = re.compile(r"[A-Z][A-Z !?]{14,}")
CONSPIRACY_RX = re.compile(r"false flag|crisis actors?|wake up|sheeple|they don'?t want you to know|mainstream media (won'?t|"
                           r"is hiding)|plandemic|deep state|new world order|globalists?|psyop|share before (it'?s )?(deleted|removed)|"
                           r"\bshare this\b|\bretweet\b|\bgo viral\b|\bnot a drill\b|\bbreaking\s*:\s*[A-Z]{3,}", re.I)


def _age_days(iso, now):
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return max(0.0, (now - t.timestamp()) / 86400)


def account_credibility(acct, text="", now=None):
    """acct: {"created": iso, "followers": int|None, "posts": int|None, "bot": bool, "handle": str}.
    Returns (score 0..1, [reasons]). Unknown facts are neutral, not penalized."""
    now = now or time.time()
    score, why = 0.5, []
    age = _age_days(acct.get("created"), now)
    if age is not None:
        if age < 14:
            score -= 0.3
            why.append(f"account is only {age:.0f} days old")
        elif age < 90:
            score -= 0.1
            why.append(f"account is {age:.0f} days old")
        elif age > 730:
            score += 0.1
    fol = acct.get("followers")
    if fol is not None:
        if fol < 10:
            score -= 0.25
            why.append(f"only {fol} followers")
        elif fol < 100:
            score -= 0.08
        elif fol >= 10000:
            score += 0.25
        elif fol >= 1000:
            score += 0.15
    posts = acct.get("posts")
    if posts is not None and age:
        rate = posts / max(age, 1.0)
        if rate > 200:
            score -= 0.25
            why.append(f"posts about {rate:.0f} times a day (bot-like)")
        elif posts < 10 and age > 30:
            score -= 0.05
    if acct.get("bot"):
        score -= 0.3
        why.append("marked as an automated account")
    if re.search(r"\d{6,}$", acct.get("handle", "") or ""):
        score -= 0.1
        why.append("handle ends in a long run of digits")
    if text:
        if SHOUT_RX.search(text):
            score -= 0.1
            why.append("post is shouting in capitals")
        if CONSPIRACY_RX.search(text):
            score -= 0.25
            why.append("uses conspiracy or share-this language")
    return round(max(0.0, min(1.0, score)), 2), why


def engagement_of(counts):
    """likes + reposts + quotes + half the replies (replies are often arguments, not agreement)."""
    return int(counts.get("likes", 0) + counts.get("reposts", 0) + counts.get("quotes", 0) + 0.5 * counts.get("replies", 0))


def virality_points(eng, vmin=VIRAL_MIN):
    if eng < vmin / 4:
        return 0.0
    if eng < vmin:
        return 6.0
    return round(15 + 15 * min(1.0, math.log10(eng / vmin) / 2), 1)


def make_candidate(platform, url, text, counts, acct, now=None):
    """What a collector attaches to its signal for each post that is spreading."""
    return {"platform": platform, "url": url, "text": (text or "")[:200], "engagement": engagement_of(counts), "acct": acct}


def claim_score(post, support, debunked, vmin=VIRAL_MIN, now=None):
    """post: a candidate from make_candidate. support: {"gov": bool, "t1": int, "news": bool}. Returns a dict."""
    parts = []
    v = virality_points(post["engagement"], vmin)
    parts.append((v, f"{post['engagement']} likes/reposts" + (" (spreading fast)" if v >= 15 else " (some traction)" if v else " (little traction)")))
    cred, why = account_credibility(post["acct"], post.get("text", ""), now)
    parts.append((round(30 * cred, 1), "poster looks credible" if cred >= 0.6 else
                  "poster: " + ("; ".join(why) if why else "nothing known about this account")))
    if support.get("gov"):
        parts.append((40, "a government or live-data source in the same area agrees"))
    elif support.get("t1", 0) >= 3:
        parts.append((30, "several independent top-tier news outlets report it"))
    elif support.get("news"):
        parts.append((12, "some news coverage, not widely confirmed"))
    else:
        parts.append((0, "no news or government source confirms it"))
    if debunked:
        parts.append((-60, "news outlets are calling claims like this fake or a hoax"))
    score = int(max(0, min(100, round(sum(p for p, _ in parts)))))
    if debunked:
        verdict = "refuted"
    elif score >= VERIFIED:
        verdict = "verified"
    elif score <= RUMOR and cred < 0.5:        # a credible poster with nothing backing yet is "unverified", not a rumor
        verdict = "rumor"
    else:
        verdict = "unverified"
    return {"score": score, "verdict": verdict, "cred": cred, "engagement": post["engagement"], "url": post.get("url", ""),
            "text": post.get("text", ""), "platform": post.get("platform", ""), "parts": [{"pts": p, "why": w} for p, w in parts]}


def check_social(cats, cfg=None, now=None):
    """Score every spreading post found by the social collectors, using what the OTHER sources say right now.
    Returns {category: [claim dicts, best first]}. cats: national categories (each has "signals")."""
    cfg = cfg or {}
    vmin = cfg.get("social_viral_min", VIRAL_MIN)
    kw = {c: re.compile(p, re.I) for c, p in (cfg.get("social_keywords") or {}).items()}
    deb = []
    for c in cats.values():
        for s in c["signals"]:
            if s.key == "news:Debunked / fake claims":
                deb += [l.get("title", "") for l in s.links]
    out = {}
    for k, c in cats.items():
        posts = [p for s in c["signals"] if s.kind == "social" for p in (getattr(s, "meta", None) or {}).get("posts", [])]
        if not posts:
            continue
        gov = any(s.kind in ("gov", "private") and s.severity >= 1 for s in c["signals"])
        news = [s for s in c["signals"] if s.kind == "news" and s.severity >= 1]
        t1 = max([(s.meta or {}).get("t1", 0) for s in news] or [0])
        debunked = bool(k in kw and any(kw[k].search(h) for h in deb))
        claims = [claim_score(p, {"gov": gov, "t1": t1, "news": bool(news)}, debunked, vmin, now) for p in posts]
        claims.sort(key=lambda x: -x["score"])
        out[k] = claims
    return out
