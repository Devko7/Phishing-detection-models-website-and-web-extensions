from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

import ssl
import whois
import re
import urllib.request


FEED_URL = "https://openphish.com/feed.txt"
FEED_TIMEOUT = 10
_CACHE_PATH = Path(__file__).parent / ".blacklist_cache.txt"
_BLACKLIST: set[str] = set()


def _normalize_url(url: str) -> str:
    """Normalize a URL for blacklist comparison."""
    url = url.strip().lower()
    url = url.split('#')[0]   # strip fragment
    url = url.split('?')[0]   # strip query string - phishing URLs in feed rarely have these
    url = url.rstrip('/')
    return url

def _fetch_feed() -> set[str]:
    """Download fresh feed, return normalized set."""
    with urllib.request.urlopen(FEED_URL, timeout=FEED_TIMEOUT) as resp:
        lines = resp.read().decode('utf-8', errors='ignore').splitlines()
    return {_normalize_url(line) for line in lines if line.strip()}

def _load_cache() -> set[str]:
    """Load previously saved feed from disk as fallback."""
    if not _CACHE_PATH.exists():
        return set()
    with open(_CACHE_PATH, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}

def _save_cache(entries: set[str]) -> None:
    """Persist feed to disk so we have a fallback for next boot if network fails."""
    with open(_CACHE_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(entries))

def load_blacklist() -> None:
    """Fetch fresh blacklist feed on startup. Falls back to disk cache on failure."""
    global _BLACKLIST
    try:
        entries = _fetch_feed()
        _save_cache(entries)
        _BLACKLIST = entries
    except Exception:
        # network failure, timeout, etc. - use whatever we have on disk
        _BLACKLIST = _load_cache()


# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
class url_detector:
    '''A deterministic url detector that checks if a given url is a valid url.
    code is based on a set of rules and heuristics, listed below,
    this is based on the paper "Phishing Websites Features" link: https://eprints.hud.ac.uk/id/eprint/24330/6/MohammadPhishing14July2015.pdf'''

    def __init__(self):
        self.url = None


    def set_url(self, url: str):
        '''Set the url to be checked.'''
        self.url = url

    def url_score(self) -> dict:
        '''Return a dict with score and label indicating the likelihood that the URL is valid.
        high score = high risk, score range 0-100
        label: "benign" (0-40), "defacement" (41-70), "malware" (71-100)
        '''

        if self.url is None:
            raise ValueError("no url set")
        else:
            return check_url(self.url)

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _score_to_label(score: float) -> str:
    '''Convert a risk score (0-100) to a threat label.
    0-40 benign
    41-70 defacement
    71-100 malware
    '''
    if score <= 40:
        return "benign"
    elif score <= 70:
        return "defacement"
    else:
        return "malware"

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def check_url(url: str) -> dict:
    '''contains the checkers, parallel the checking for speed.
    returns {"score": float, "label": str}
    '''
    checkers = [
        _check_regex_patterns,
        _check_ip_pattern,
        _check_domain_age,
        _check_https,
        _check_suspicious_tld,
    ]

    with ThreadPoolExecutor() as executor:
        blacklist_future = executor.submit(_check_blacklist, url)
        futures = {executor.submit(checker, url): checker for checker in checkers}

        #return immediately if blacklisted,rest finish in background - this is the speed checker for quick response for instant sus links
        if blacklist_future.result():
            return {"score": 100, "label": "malware"}

        results = {}
        for future in as_completed(futures):
            checker = futures[future]
            results[checker.__name__] = future.result()



    score = compute_final_verdict([
        results["_check_regex_patterns"],
        results["_check_ip_pattern"],
        results["_check_domain_age"],
        results["_check_https"],
        results["_check_suspicious_tld"],
    ])

    return {"score": score, "label": _score_to_label(score)}

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def compute_final_verdict(results) -> int:
    '''computes the final score based on the checkers results.
    score is 0-100, higher = riskier'''
    regex_score, ip_score, domain_age_score, https, tld_score = results

    # weighted scoring for the rest
    WEIGHTS = {
        "https": 0.3,
        "regex": 0.25,
        "ip": 0.20,
        "domain_age": 0.15,
        "tld": 0.10,
    }

    https_score = 100 if not https else 0

    score = (
            https_score * WEIGHTS["https"] +
            regex_score * WEIGHTS["regex"] +
            ip_score * WEIGHTS["ip"] +
            domain_age_score * WEIGHTS["domain_age"] +
            tld_score * WEIGHTS["tld"]
    )

    return score

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_blacklist(url: str) -> int:
    '''Check if the url is in a known blacklist.'''
    if _normalize_url(url) in _BLACKLIST : return 100 
    else: return 0

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_regex_patterns(url: str) -> int:
    '''Check if the url matches common phishing patterns using regex.
    Rules applied:
    - Section 1.1.4: "@" symbol in url
    - Section 1.1.5: "//" position > 7 in url
    - Section 1.1.6: "-" in domain name
    - Section 1.1.7: dots in domain: 2=Suspicious, 3+=Phishing
    - Section 1.1.2: URL length < 54=Legitimate, 54-75=Suspicious, >75=Phishing
    - Section 1.1.3: URL shortening service used
    - Section 1.1.12: "https" token in domain part (not as protocol)
    '''
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()


    #"@" symbol forces browser to ignore everything before it
    if re.search(r'@', url):
        score += 20

    #"//" appearing after position 7 indicates redirect
    #https:// has // at 6-7
    last_double_slash = url.rfind('//')
    if last_double_slash > 7:
        score += 20

    # Section 1.1.6 - hyphen/dash in domain rarely used by legitimate sites
    if re.search(r'-', domain):
        score += 10   # Suspicious

    #Section 1.1.7 - count dots in domain (excluding www.)
    domain_stripped = re.sub(r'^www\.', '', domain)
    dot_count = domain_stripped.count('.')
    if dot_count == 2:
        score += 10   # Suspicious
    elif dot_count >= 3:
        score += 20   # Phishing

    # Section 1.1.2 - URL length thresholds
    url_length = len(url)
    if 54 <= url_length <= 75:
        score += 10   # Suspicious
    elif url_length > 75:
        score += 20   # Phishing

    # Section 1.1.3 - URL shortening services hide true destination
    SHORTENERS = r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly)'
    if re.search(SHORTENERS, url, re.IGNORECASE):
        score += 30

    # Section 1.1.12 - "https" token embedded in domain to trick users
    # e.g. http://https-www-paypal.soft-hair.com
    if 'https' in domain and not url.startswith('https://'):
        score += 20

    return min(score, 100)

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_ip_pattern(url: str) -> int:
    '''Check if the url uses an IP address instead of a domain name.'''
    parsed = urlparse(url)
    host = parsed.hostname or ''

    # standard IPv4 pattern
    ipv4_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    if re.match(ipv4_pattern, host):
        return 100

    #hex-encoded IPv4 pattern e.g. 0x58.0xCC.0xCA.0x62
    hex_ip_pattern = r'^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$'
    if re.match(hex_ip_pattern, host):
        return 100

    return 0

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_domain_age(url: str) -> int:
    '''Check the age of the domain, the younger the domain, the higher the risk.'''

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        w = whois.whois(domain)
        creation_date = w.creation_date

        # creation_date can be a list or a single datetime
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            # no WHOIS record found - treat as phishing per Section 1.4.2
            return 100

        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.utcnow() - creation_date).days

        if age_days < 180:      # < 6 months : phishing suspect
            return 100
        elif age_days < 365:    # 6-12 months : sus attempt
            return 50
        else:                   # > 1 year : Legit
            return 0

    except Exception:
        # WHOIS lookup failed - no record is itself a phishing signal
        return 100

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_https(url: str) -> bool:
    '''Check if the url uses SSL (https). if http - high risk'''
    return url.startswith('https://')

# Main writer: Shaked Gayer
# Reviewer: Jon Zdovc
# Contributor: -
def _check_suspicious_tld(url: str) -> int:
    '''Check if the url uses a suspicious top-level domain (TLD).
    this is based on the domains that are commonly used in phishing attacks.'''

    common_phishing_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq','.top', '.xyz', '.pw', '.cc', '.su', '.online', '.site','.click', '.link', '.work', '.party', '.loan', '.win', '.download', '.zip'}

    parsed = urlparse(url)
    host = parsed.netloc.lower()

    # extract TLD (last dot-separated part)
    parts = host.split('.')
    if len(parts) < 2:
        return 0  # no TLD found, treat as low risk

    tld = '.' + parts[-1]

    if tld in common_phishing_TLDS:
        return 100

    return 0

load_blacklist()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python url_detector.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    result = check_url(url)
    print(f"URL: {url}")
    print(f"Score: {result['score']:.1f} / 100")
    print(f"Label: {result['label']}")