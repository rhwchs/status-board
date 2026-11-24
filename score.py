"""The 0-100 "how bad is it" gauge.

This is a SEVERITY GAUGE, not a probability. 0 means nothing unusual anywhere; 100 means several essential
services confirmed down at once with an attack pattern. It is built from the same evidence as the alert level
and always agrees with it: each alert level owns a band of the scale, and the evidence decides where in the band
you land.

    NORMAL            0 -  9
    WATCH            10 - 29
    ELEVATED         30 - 59
    SUSPECTED ATTACK 60 - 100

Evidence that counts for more: official (government / status page / monitoring service) confirmation, essential
services (power, phones, internet, banks, flights), several independent problems, problems starting together.
Evidence that counts for less: headlines alone, social media alone, problems with a harmless explanation.
Every point is listed with its reason, so nothing about the number is a black box.
"""
from collectors import CATEGORIES

BANDS = {"NORMAL": (0, 9), "WATCH": (10, 29), "ELEVATED": (30, 59), "SUSPECTED ATTACK": (60, 100)}
CAP = {"NORMAL": 1, "WATCH": 12, "ELEVATED": 24, "SUSPECTED ATTACK": 36}   # raw points that fill a band

WEIGHT = {"power": 10, "telecom": 10, "nuclear": 10, "aviation": 8, "internet": 8, "finance": 8, "cyber": 8,
          "security": 6, "emergency": 6, "markets": 4, "natural": 4, "space": 3, "elite": 1}
LEVEL_F = {1: 0.4, 2: 1.0, 3: 1.8}


def compute(label, cats, res):
    """cats: national categories (no 'local'); res: result of assess(). Returns {"value", "parts", "band"} or None."""
    if label == "NO DATA":
        return None
    lo, hi = BANDS[label]
    explained = {e["domain"] for e in res["explained"]}
    credible = set(res.get("credible", []))
    parts = []
    for k, c in cats.items():
        if c["level"] < 1:
            continue
        official = any(s.kind in ("gov", "private") and s.severity >= 1 for s in c["signals"])
        if CATEGORIES[k] in explained:
            f, how = 0.3, "has a harmless explanation"
        elif official:
            f, how = 1.0, "confirmed by an official source"
        elif k in credible:
            f, how = 0.85, "reported by several independent top-tier news outlets (no official confirmation yet)"
        elif c.get("social_only"):
            v = (res.get("social_checks") or {}).get(k)
            f, how = ((0.4, "people posting, and the spreading claim checks out") if v == "verified" else
                      (0.1, "people posting, but the spreading claim looks like a rumor") if v in ("rumor", "refuted") else
                      (0.25, "only people posting"))
        else:
            f, how = 0.5, "reported by news, not confirmed"
        pts = WEIGHT.get(k, 4) * LEVEL_F.get(c["level"], 1.8) * f
        if pts >= 0.5:
            parts.append({"pts": round(pts, 1), "why": f"{CATEGORIES[k]}: {how}"})
    sb = res.get("slow_burn") or {}
    if sb.get("active"):
        parts.append({"pts": min(8.0, 2.0 * sb["n_sustained"]),
                      "why": f"{sb['n_sustained']} different areas have shown trouble for hours (slow burn)"})
    n_cl = len(res["clusters"])
    if n_cl >= 2:
        parts.append({"pts": 4.0 * (n_cl - 1), "why": f"{n_cl} separate problems at once"})
    if res["simultaneous"]:
        parts.append({"pts": 6.0, "why": "they started within minutes of each other"})
    attack = max([h["score"] for h in res["hypotheses"] if h["key"] in ("cyber", "physical", "strategic")] or [0])
    if attack >= 2:
        parts.append({"pts": round(min(8.0, attack), 1), "why": "the pattern leans toward an attack"})
    raw = sum(p["pts"] for p in parts)
    frac = min(1.0, raw / CAP[label])
    value = lo + round((hi - lo) * frac)
    return {"value": int(value), "band": label, "raw": round(raw, 1),
            "parts": sorted(parts, key=lambda p: -p["pts"])[:6]}
