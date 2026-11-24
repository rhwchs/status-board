"""Where is a story about? The monitor is for people in the US, so a headline about a missile strike in Riyadh or a terror
case in Amman is WORLD context: worth a quiet line, never a reason to move the alert scale.

Rule of thumb (deliberately simple and explainable, not a language model):
  * if the text names a US place or a clearly domestic institution, it is "us";
  * else if it names a foreign place, it is "foreign";
  * else we cannot tell ("unknown") and it is treated as possibly domestic, so a real US event is never dropped
    just because the headline is terse.
A story that names BOTH (for example "US strikes Iran") has no US place in it, so it is "foreign": the event is over
there. If the effect reaches the US (a domestic attack, airspace closures, a pipeline shutdown) US places show up in the
coverage and it counts. Gas-price stories and the like are out of scope by design.
"""
import re

_US_WORDS = (
    "alabama|alaska|arizona|arkansas|california|colorado|connecticut|delaware|florida|hawaii|idaho|illinois|indiana|iowa|"
    "kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|minnesota|mississippi|missouri|montana|nebraska|"
    "nevada|ohio|oklahoma|oregon|pennsylvania|tennessee|texas|utah|vermont|virginia|wisconsin|wyoming|"
    "new hampshire|new jersey|new mexico|new york(?! times| post| magazine)|north carolina|north dakota|rhode island|south carolina|south dakota|"
    "west virginia|washington state|washington, d\\.c\\.|d\\.c\\.|"
    "los angeles|chicago|houston|phoenix|philadelphia|san antonio|san diego|dallas|san jose|austin|jacksonville|fort worth|"
    "columbus|charlotte|san francisco|indianapolis|seattle|denver|boston|el paso|nashville|detroit|oklahoma city|portland|"
    "las vegas|memphis|louisville|baltimore|milwaukee|albuquerque|tucson|fresno|sacramento|kansas city|atlanta|omaha|raleigh|"
    "miami|oakland|minneapolis|tulsa|tampa|new orleans|cleveland|pittsburgh|cincinnati|st\\. louis|salt lake city|honolulu|"
    "anchorage|brooklyn|manhattan|"
    "nationwide|across the (?:u\\.?s\\.?|united states|country|nation)|u\\.?s\\.? (?:airports?|cities|hospitals?|banks?|states|grid|"
    "power|military bases?|soil|homeland|schools?|customers)|american (?:airports?|cities|hospitals?|banks?)|"
    "guam|puerto rico|virgin islands|american samoa|saipan|northern mariana|u\\.?s\\.? territor\\w+|"
    "(?:u\\.?s\\.?|american) (?:telecom\\w*|water|energy|infrastructure|compan\\w+|firms?|networks?|systems?|utilit\\w+|pipelines?|"
    "ports?|rail\\w*|government agenc\\w+|agencies|federal agenc\\w+)|"
    "\\bfaa\\b|\\bfema\\b|\\bcisa\\b|national weather service|homeland security|\\bdhs\\b|\\bnws\\b"
)
_FOREIGN_WORDS = (
    "israel|israeli|gaza|west bank|tehran|iran|iranian|iraq|baghdad|syria|damascus|lebanon|beirut|yemen|houthis?|saudi|riyadh|"
    "qatar|doha|\\buae\\b|emirates|dubai|abu dhabi|amman|jordanian|egypt|cairo|ankara|istanbul|turkish|ukraine|ukrainian|kyiv|kharkiv|"
    "odesa|dnipro|russia|russian|moscow|kremlin|belarus|poland|polish|germany|german|berlin|france|french|paris|"
    "\\buk\\b|britain|british|london|england|scotland|ireland|spain|spanish|italy|italian|rome|netherlands|dutch|sweden|"
    "swedish|norway|finland|denmark|european|\\beu\\b|china|chinese|beijing|taiwan|hong kong|japan|japanese|tokyo|korea|"
    "korean|seoul|pyongyang|india|indian|delhi|mumbai|pakistan|pakistani|karachi|islamabad|afghanistan|kabul|bangladesh|"
    "indonesia|jakarta|philippines|manila|vietnam|thailand|australia|australian|sydney|new zealand|canada|canadian|toronto|"
    "ottawa|mexico|mexican|brazil|argentina|venezuela|colombia|cuba|nigeria|kenya|ethiopia|sudan|somalia|congo|south africa|"
    "libya|algeria|morocco|tunisia|gulf of aden|strait of hormuz|hormuz|red sea|middle east|mideast|fordow|fordo|natanz|isfahan|"
    "bushehr|khamenei|donetsk|crimea|zaporizhzhia|kherson|rafah|tel aviv|jerusalem|haifa|idlib|aleppo|mosul|kandahar|taipei|"
    "kim jong|putin|zelensky|netanyahu|hezbollah|hamas|taliban|al udeid"
)
US_RX = re.compile(r"(?<![a-z])(?:" + _US_WORDS + r")(?![a-z])", re.I)
FOREIGN_RX = re.compile(r"(?<![a-z])(?:" + _FOREIGN_WORDS + r")(?![a-z])", re.I)


# Who is attacking is not where it is happening: "Chinese hackers breach water utilities" says nothing about the target.
_ACTORS = r"(?:chinese|iranian|russian|north korean|china|iran|russia|north korea|beijing|moscow|tehran|pyongyang|kremlin)"
_ACTOR_NOUNS = r"(?:hackers?|hacking|cyber\w*|apt\d*|threat actors?|ransomware|spies|spy|group|gang|malware)"
ACTOR_RX = re.compile(
    r"\b" + _ACTORS + r"(?:[- ](?:linked|backed|based|sponsored|state[- ]sponsored))?\s+" + _ACTOR_NOUNS + r"\b"      # "Beijing-backed hackers"
    r"|\b" + _ACTOR_NOUNS + r"\s+(?:tied|linked|connected|affiliated)\s+(?:to|with)\s+" + _ACTORS +                  # "hackers tied to Iran's military"
    r"(?:'s?(?:\s+(?:military|government|intelligence|revolutionary guards?|irgc|security services?|regime))?)?\b", re.I)


def classify(text):
    """'us', 'foreign' or 'unknown' for a headline or post."""
    t = text or ""
    us, fo = bool(US_RX.search(t)), bool(FOREIGN_RX.search(ACTOR_RX.sub(" ", t)))
    if us:
        return "us"
    return "foreign" if fo else "unknown"


def split(items, key=lambda i: i["title"]):
    """(domestic_or_unknown, foreign) lists, preserving order."""
    dom, forn = [], []
    for it in items:
        (forn if classify(key(it)) == "foreign" else dom).append(it)
    return dom, forn


# ---- which STATES a story is about (its footprint). Empty = nationwide or can't tell.
STATE_CODES = {
    "alabama": "AL", "alaska": "AK", "arizona": "AZ", "arkansas": "AR", "california": "CA", "colorado": "CO",
    "connecticut": "CT", "delaware": "DE", "florida": "FL", "georgia": "GA", "hawaii": "HI", "idaho": "ID", "illinois": "IL",
    "indiana": "IN", "iowa": "IA", "kansas": "KS", "kentucky": "KY", "louisiana": "LA", "maine": "ME", "maryland": "MD",
    "massachusetts": "MA", "michigan": "MI", "minnesota": "MN", "mississippi": "MS", "missouri": "MO", "montana": "MT",
    "nebraska": "NE", "nevada": "NV", "new hampshire": "NH", "new jersey": "NJ", "new mexico": "NM", "new york": "NY",
    "north carolina": "NC", "north dakota": "ND", "ohio": "OH", "oklahoma": "OK", "oregon": "OR", "pennsylvania": "PA",
    "rhode island": "RI", "south carolina": "SC", "south dakota": "SD", "tennessee": "TN", "texas": "TX", "utah": "UT",
    "vermont": "VT", "virginia": "VA", "washington state": "WA", "west virginia": "WV", "wisconsin": "WI", "wyoming": "WY",
    "washington, d.c.": "DC", "d.c.": "DC",
    # big cities that make the state obvious
    "los angeles": "CA", "san francisco": "CA", "san diego": "CA", "sacramento": "CA", "chicago": "IL", "houston": "TX",
    "dallas": "TX", "austin": "TX", "san antonio": "TX", "phoenix": "AZ", "philadelphia": "PA", "pittsburgh": "PA",
    "seattle": "WA", "denver": "CO", "boston": "MA", "detroit": "MI", "nashville": "TN", "memphis": "TN", "atlanta": "GA",
    "miami": "FL", "tampa": "FL", "orlando": "FL", "jacksonville": "FL", "las vegas": "NV", "portland": "OR",
    "minneapolis": "MN", "kansas city": "MO", "st. louis": "MO", "new orleans": "LA", "baltimore": "MD",
    "charlotte": "NC", "raleigh": "NC", "cleveland": "OH", "columbus": "OH", "cincinnati": "OH", "indianapolis": "IN",
    "milwaukee": "WI", "oklahoma city": "OK", "salt lake city": "UT", "honolulu": "HI", "anchorage": "AK",
    "brooklyn": "NY", "manhattan": "NY",
}
_STATE_RX = re.compile(r"(?<![a-z])(" + "|".join(sorted((re.escape(k) for k in STATE_CODES), key=len, reverse=True)) + r")(?![a-z])", re.I)
_NATIONAL_RX = re.compile(r"nationwide|across the (?:u\.?s\.?|united states|country|nation)|coast to coast|national", re.I)
VALID_STATES = set(STATE_CODES.values())


def states_in(text):
    """Set of state codes a piece of text names (also by big city)."""
    out = set()
    for m in _STATE_RX.finditer(text or ""):
        w = m.group(1).lower()
        if w == "new york" and re.search(r"new york (?:times|post|magazine)", text, re.I):
            continue
        out.add(STATE_CODES[w])
    return out


def states_for(headlines):
    """The footprint of a news story from its headlines: states named by at least ~40% of them (at least 2, unless there is
    only one headline). If any headline says it is nationwide, or none names a state, the story is nationwide: []."""
    n = len(headlines)
    if n == 0 or any(_NATIONAL_RX.search(h or "") for h in headlines):
        return []
    need = 1 if n == 1 else max(2, -(-n * 4 // 10))
    counts = {}
    for h in headlines:
        for st in states_in(h):
            counts[st] = counts.get(st, 0) + 1
    return sorted(st for st, c in counts.items() if c >= need)
