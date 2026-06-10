import re

PHISHING_THRESHOLD = 50

# Main writer: Theodotos Neokleous
# Reviewer: David Vasilev
# Contributor: Olivier van Leeuwen
class DeterministicPhishingClassifier:
    """
    A deterministic email phishing classifier that uses a set of heuristics to classify emails as phishing or legitimate.
    """
    def __init__(self):
        # keywords and patterns for heuristics
        self.urgent_keywords = [
            r"urgent", r"immediate action", r"account suspended", 
            r"verify your account", r"security alert", r"final notice"
        ]
        self.sensitive_info_keywords = [
            r"password", r"social security", r"ssn", 
            r"credit card", r"bank account", r"routing number"
        ]
        self.generic_greetings = [
            r"dear customer", r"dear user", r"dear member", r"hello user"
        ]
        self.suspicious_link_patterns = [
            r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 
            r"bit\.ly", r"tinyurl\.com", r"ow\.ly"      
        ]

        self.urgent_patterns = [re.compile(k, re.IGNORECASE) for k in self.urgent_keywords]
        self.sensitive_patterns = [re.compile(k, re.IGNORECASE) for k in self.sensitive_info_keywords]
        self.greeting_patterns = [re.compile(k, re.IGNORECASE) for k in self.generic_greetings]
        self.link_patterns = [re.compile(p, re.IGNORECASE) for p in self.suspicious_link_patterns]

        self.subject = None
        self.body = None

    def set_email(self, subject: str, body: str) -> None:
        """Set the email fields to be classified."""
        self.subject = subject
        self.body = body

    def analyze_email(self, subject, body):
        """Analyze the email and return (risk score 0-100, label)."""
        score = 0

        # 1. Check for urgent language (20 points)
        if any(p.search(subject) or p.search(body) for p in self.urgent_patterns):
            score += 20

        # 2. Check for generic greetings (15 points)
        if any(p.search(body) for p in self.greeting_patterns):
            score += 15

        # 3. Check for requests for sensitive info (30 points)
        if any(p.search(body) for p in self.sensitive_patterns):
            score += 30

        # 4. Check for suspicious links (20 points)
        if any(p.search(body) for p in self.link_patterns):
            score += 20

        score = min(score, 100)
        return score, label_from_score(score)


def label_from_score(score: int, threshold: int = PHISHING_THRESHOLD) -> str:
    """Map a risk score (0-100) to 'phishing' or 'legit'."""
    return "phishing" if score >= threshold else "legit"


def classify_email(subject: str, body: str) -> tuple[int, str]:
    """Classify a single email; returns (risk score 0-100, label)."""
    return DeterministicPhishingClassifier().analyze_email(subject, body)
