"""Is this story or post about something that is happening now, or something that already happened?

News searches ask for "the last hour", but that means "published in the last hour", not "about something in the last
hour". Days after a big event, outlets keep running follow-ups and people keep posting about it, and a counter that only
sees fresh timestamps mistakes that for a new event. This module reads the TEXT for dates and says when the thing it
describes happened well before now: an explicit past date ("on Nov. 13"), or phrases like "two weeks ago", "last week"
or "earlier this month". Words that mark live events ("today", "tonight", "this morning", "just now") cancel it, since
a story about today can still mention a date in the past.
"""
import re
import time
from datetime import datetime, timedelta, timezone

MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "sept": 9,
          "oct": 10, "nov": 11, "dec": 12}
_MONTH = r"(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sept?(?:ember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
DATE_RX = re.compile(r"\b" + _MONTH + r"\.?\s+(\d{1,2})(?:st|nd|rd|th)?\b(?!\s*(?:%|percent|million|billion|people|years?))", re.I)
DATE2_RX = re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+" + _MONTH + r"\b", re.I)
AGO_RX = re.compile(r"\b(?:(?:two|three|four|five|six|seven|several|a few|few|\d+)\s+(?:weeks?|months?)\s+ago|"
                    r"last\s+(?:week|month)|earlier\s+this\s+(?:month|week)|"
                    r"(?:three|four|five|six|seven|\d+)\s+days\s+ago)\b", re.I)
LIVE_RX = re.compile(r"\b(?:today|tonight|this\s+(?:morning|afternoon|evening)|right\s+now|just\s+now|breaking|"
                     r"minutes?\s+ago|an\s+hour\s+ago|hours?\s+ago|currently|ongoing|still\s+(?:down|out|grounded))\b", re.I)
OLD_DAYS = 3


def _mentioned_dates(text, now):
    out = []
    for rx, mi, di in ((DATE_RX, 1, 2), (DATE2_RX, 2, 1)):
        for m in rx.finditer(text):
            mon = MONTHS.get(m.group(mi).lower()[:4].rstrip("."), None) or MONTHS.get(m.group(mi).lower()[:3])
            day = int(m.group(di))
            if not mon or not 1 <= day <= 31:
                continue
            year = datetime.fromtimestamp(now, timezone.utc).year
            try:
                d = datetime(year, mon, day, tzinfo=timezone.utc)
            except ValueError:
                continue
            if d.timestamp() > now + 60 * 86400:      # far ahead in this year means it was last year
                try:
                    d = datetime(year - 1, mon, day, tzinfo=timezone.utc)
                except ValueError:
                    continue
            out.append(d.timestamp())
    return out


def stale_reason(text, now=None):
    """Return a short reason if the text is about an older event, else ''."""
    if not text:
        return ""
    now = now or time.time()
    if LIVE_RX.search(text):
        return ""
    dates = _mentioned_dates(text, now)
    if dates and (now - max(dates)) >= OLD_DAYS * 86400:     # even the newest date it mentions is old
        days = int((now - max(dates)) // 86400)
        return f"about something from {days} days ago"
    if AGO_RX.search(text):
        return "about something from weeks ago"
    return ""
