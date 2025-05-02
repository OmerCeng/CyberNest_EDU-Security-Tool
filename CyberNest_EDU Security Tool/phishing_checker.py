from urllib.parse import urlparse
import re

# List of suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "account", "verify", "banking", "signin", "submit"
]

def is_ip_address(url):
    # Check if the URL uses an IP address
    return re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url) is not None

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path.lower()

    score = 0
    reasons = []

    # Rule 1: IP address in the URL
    if is_ip_address(url):
        score += 2
        reasons.append("Uses an IP address instead of a domain.")

    # Rule 2: Too many subdomains
    if domain.count('.') > 2:
        score += 1
        reasons.append("Contains too many subdomains.")

    # Rule 3: Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in path or keyword in domain:
            score += 1
            reasons.append(f"Contains suspicious keyword: '{keyword}'.")

    # Rule 4: Long domain name
    if len(domain) > 30:
        score += 1
        reasons.append("Domain name is unusually long.")

    return score, reasons

def run():
    print("""
    ==== Phishing URL Analyzer ====
    This tool analyzes a URL to determine if it's potentially a phishing link.
    """)
    url = input("Enter the URL to analyze (e.g., https://secure-login.example.com/login): ")

    score, reasons = analyze_url(url)

    print("\n[Analysis Result]")
    if score >= 3:
        print("⚠️ This URL is likely a phishing attempt!")
    elif score == 2:
        print("⚠️ This URL may be suspicious.")
    else:
        print("✅ This URL appears to be safe.")
    
    print("\n[Reasons]")
    for r in reasons:
        print(f"- {r}")
