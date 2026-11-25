"""Does an overseas story have a plausible path to people in the US? Keyword groups over the story's headlines, each
with a short, calm tag shown on the page. Stdlib only. An overseas story with no match is not shown at all."""
import re


def _rx(*parts):
    return re.compile(r"(?<![\w-])(?:" + "|".join(parts) + r")(?![\w-])", re.I)


# (tag, pattern). Order matters only for which two tags show when a story matches more than two groups.
GROUPS = [
    ("Energy supply", _rx(
        r"oil", r"crude", r"natural gas", r"gas (?:supply|supplies|prices?|field|fields|exports?|imports?|pipeline|shortage)",
        r"lng", r"pipelines?", r"refiner(?:y|ies)", r"opec\+?", r"(?:oil |gas )?tankers?", r"strait of hormuz", r"hormuz",
        r"red sea", r"suez(?: canal)?", r"bab[ -]el[ -]mandeb", r"shipping lanes?")),
    ("Supply chain", _rx(
        r"port (?:closures?|closed|shut(?:down)?|strike)", r"ports? (?:closed|shut)", r"shipping", r"container ships?",
        r"container shipping", r"semiconductors?", r"chipmakers?", r"chip (?:shortage|supply|supplies|exports?|makers?|plants?|factor(?:y|ies)|industry|curbs?|ban)",
        r"tsmc", r"taiwan strait", r"export (?:bans?|controls?|curbs?|restrictions?)", r"grain", r"wheat exports?",
        r"food supply", r"food supplies", r"(?:medicine|drug) shortages?", r"rare earths?")),
    ("Travel / Americans abroad", _rx(
        r"u\.?s\.? citizens?", r"americans", r"american (?:tourists?|citizens?|hostages?|travell?ers?)", r"u\.?s\.? embassy",
        r"travel (?:advisory|advisories|warnings?)", r"state department", r"flights? (?:cancell?ed|grounded|suspended|halted)",
        r"airports? (?:closed|shut)", r"airspace (?:closed|closure|shut)", r"u\.?s\.? troops", r"u\.?s\.? (?:military )?bases?",
        r"(?:u\.?s\.?|american) service ?members")),
    ("Spreading cyber / outage", _rx(
        r"(?:cyber\w*|ransomware|hack\w*)\b[^.]{0,60}?\b(?:software|cloud|internet|microsoft|windows|google|amazon|aws|apple|networks?)",
        r"undersea cables?", r"subsea cables?", r"internet (?:cables?|outages?|blackouts?|shutdowns?)", r"cloud outages?",
        r"gps (?:jamming|interference|outages?|spoofing)", r"satellite (?:outages?|disruptions?|failures?)")),
    ("Allies / escalation", _rx(
        r"nato", r"article 5", r"israel", r"israeli", r"japan", r"japanese", r"south korea", r"south korean", r"taiwan",
        r"philippines", r"uk", r"britain", r"british", r"nuclear", r"missile launch(?:es)?", r"ballistic missiles?",
        r"launch(?:es|ed)? (?:a |an |two |several )?(?:ballistic |cruise )?missiles?", r"mobili[sz]ation", r"mobili[sz]es",
        r"declares? war", r"declaration of war", r"invasion", r"invades?", r"invaded")),
]
MAX_TAGS = 2


def tags(headlines):
    """Up to MAX_TAGS plain-word reasons an overseas story could reach people in the US ([] = no plausible path)."""
    text = " | ".join(h for h in headlines if h)
    return [tag for tag, rx in GROUPS if rx.search(text)][:MAX_TAGS]
