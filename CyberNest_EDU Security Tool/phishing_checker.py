from urllib.parse import urlparse
import re
import email
from email.parser import Parser
import base64

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

# List of suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "account", "verify", "banking", "signin", "submit"
]

# Email phishing indicators
PHISHING_SUBJECT_KEYWORDS = [
    "urgent", "immediate", "suspended", "expired", "verify", "confirm", "click here",
    "act now", "limited time", "congratulations", "winner", "prize", "free",
    "security alert", "account locked", "unusual activity", "unauthorized access"
]

PHISHING_SENDER_PATTERNS = [
    r"no-reply@[^.]+\.tk$", r".*@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$",
    r".*@.*\.tk$", r".*@.*\.ml$", r".*@.*\.ga$", r".*@.*\.cf$",
    r".*-[0-9]+@.*", r".*[0-9]{3,}@.*", r"noreply.*@.*"
]

PHISHING_CONTENT_KEYWORDS = [
    "click here immediately", "verify your account", "suspended account",
    "unusual activity", "security breach", "update payment", "confirm identity",
    "act within 24 hours", "your account will be closed", "refund pending",
    "tax refund", "inheritance", "million dollars", "lottery winner"
]

LEGITIMATE_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "apple.com",
    "microsoft.com", "google.com", "amazon.com", "paypal.com", "ebay.com",
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com"
]

def analyze_email_headers(email_content):
    """Analyze email headers for phishing indicators"""
    score = 0
    reasons = []
    
    try:
        # Parse email
        if isinstance(email_content, str):
            msg = Parser().parsestr(email_content)
        else:
            msg = email_content
        
        # Check sender
        sender = msg.get('From', '').lower()
        reply_to = msg.get('Reply-To', '').lower()
        
        # Sender analysis
        if sender:
            # Check for suspicious sender patterns
            for pattern in PHISHING_SENDER_PATTERNS:
                if re.match(pattern, sender):
                    score += 2
                    reasons.append(f"Suspicious sender pattern: {sender}")
                    break
            
            # Check if sender domain is legitimate
            sender_domain = sender.split('@')[-1] if '@' in sender else ''
            if sender_domain and sender_domain not in LEGITIMATE_DOMAINS:
                if any(tld in sender_domain for tld in ['.tk', '.ml', '.ga', '.cf']):
                    score += 2
                    reasons.append(f"Suspicious domain TLD: {sender_domain}")
        
        # Reply-To mismatch
        if reply_to and sender and reply_to != sender:
            score += 1
            reasons.append("Reply-To address differs from sender")
        
        # Check for missing SPF/DKIM (simulated)
        received_headers = msg.get_all('Received', [])
        if len(received_headers) < 2:
            score += 1
            reasons.append("Insufficient email routing information")
        
        return score, reasons
        
    except Exception as e:
        return 0, [f"Error parsing email headers: {str(e)}"]

def analyze_email_content(email_content):
    """Analyze email content for phishing indicators"""
    score = 0
    reasons = []
    
    try:
        # Parse email
        if isinstance(email_content, str):
            msg = Parser().parsestr(email_content)
        else:
            msg = email_content
        
        # Get subject and body
        subject = msg.get('Subject', '').lower()
        
        # Get email body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore').lower()
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore').lower()
        
        # Subject analysis
        subject_keyword_count = 0
        for keyword in PHISHING_SUBJECT_KEYWORDS:
            if keyword in subject:
                subject_keyword_count += 1
                reasons.append(f"Suspicious subject keyword: '{keyword}'")
        
        if subject_keyword_count >= 2:
            score += 2
        elif subject_keyword_count == 1:
            score += 1
        
        # Content analysis
        content_keyword_count = 0
        for keyword in PHISHING_CONTENT_KEYWORDS:
            if keyword in body:
                content_keyword_count += 1
                reasons.append(f"Suspicious content phrase: '{keyword}'")
        
        if content_keyword_count >= 3:
            score += 3
        elif content_keyword_count >= 2:
            score += 2
        elif content_keyword_count == 1:
            score += 1
        
        # URL analysis in email body
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        suspicious_url_count = 0
        for url in urls:
            url_score, url_reasons = analyze_url(url)
            if url_score >= 2:
                suspicious_url_count += 1
                reasons.append(f"Suspicious URL in content: {url}")
        
        if suspicious_url_count >= 2:
            score += 2
        elif suspicious_url_count == 1:
            score += 1
        
        # Check for urgency indicators
        urgency_words = ["urgent", "immediate", "asap", "within 24 hours", "expires today", "act now"]
        urgency_count = sum(1 for word in urgency_words if word in body)
        if urgency_count >= 2:
            score += 2
            reasons.append("Multiple urgency indicators detected")
        elif urgency_count == 1:
            score += 1
            reasons.append("Urgency indicator detected")
        
        return score, reasons
        
    except Exception as e:
        return 0, [f"Error analyzing email content: {str(e)}"]

def analyze_email_comprehensive(email_content):
    """Comprehensive email phishing analysis"""
    header_score, header_reasons = analyze_email_headers(email_content)
    content_score, content_reasons = analyze_email_content(email_content)
    
    total_score = header_score + content_score
    all_reasons = header_reasons + content_reasons
    
    return total_score, all_reasons

def analyze_email_from_file(file_path):
    """Analyze email from .eml file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            email_content = f.read()
        return analyze_email_comprehensive(email_content)
    except Exception as e:
        return 0, [f"Error reading email file: {str(e)}"]

def analyze_email_from_text(email_text):
    """Analyze email from raw text input"""
    return analyze_email_comprehensive(email_text)

def is_ip_address(url):
    """Check if the URL uses an IP address"""
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
    print(f"""{CYAN}
🔍 Advanced Phishing Detection System
{'='*60}
URL and Email phishing analysis with machine learning patterns
{RESET}""")
    
    while True:
        print(f"\n{BOLD}{GREEN}===== Phishing Detection System ====={RESET}")
        print(f"{BLUE}1.{RESET} {WHITE}Analyze URL{RESET}")
        print(f"{BLUE}2.{RESET} {WHITE}Analyze Email from File (.eml){RESET}")
        print(f"{BLUE}3.{RESET} {WHITE}Analyze Email from Text Input{RESET}")
        print(f"{BLUE}4.{RESET} {WHITE}Quick Email Headers Check{RESET}")
        print(f"{BLUE}0.{RESET} {RED}Return to Menu{RESET}")
        
        choice = input(f"\n{BOLD}{WHITE}Select analysis type: {RESET}")
        
        if choice == '0':
            break
            
        elif choice == '1':
            # URL Analysis
            url = input(f"{YELLOW}Enter URL to analyze: {RESET}").strip()
            
            if not url.startswith(('http://', 'https://')):
                print(f"{RED}❌ Please enter a valid URL starting with http:// or https://{RESET}")
                continue

            score, reasons = analyze_url(url)
            
            print(f"\n{BOLD}{BLUE}🎯 URL ANALYSIS RESULTS{RESET}")
            print(f"{WHITE}{'='*50}{RESET}")
            
            if score >= 3:
                print(f"{RED}🚨 HIGH RISK - Likely phishing URL!{RESET}")
            elif score == 2:
                print(f"{YELLOW}⚠️  MEDIUM RISK - Suspicious URL{RESET}")
            elif score == 1:
                print(f"{YELLOW}⚠️  LOW RISK - Minor concerns{RESET}")
            else:
                print(f"{GREEN}✅ SAFE - URL appears legitimate{RESET}")
            
            print(f"\n{BOLD}{MAGENTA}📊 Risk Score: {score}/5{RESET}")
            print(f"\n{BOLD}{CYAN}🔍 Analysis Details:{RESET}")
            if reasons:
                for reason in reasons:
                    print(f"   {YELLOW}•{RESET} {reason}")
            else:
                print(f"   {GREEN}• No suspicious patterns detected{RESET}")
        
        elif choice == '2':
            # Email file analysis
            file_path = input(f"{YELLOW}Enter path to .eml file: {RESET}").strip()
            
            try:
                score, reasons = analyze_email_from_file(file_path)
                
                print(f"\n{BOLD}{BLUE}📧 EMAIL ANALYSIS RESULTS{RESET}")
                print(f"{WHITE}{'='*50}{RESET}")
                
                if score >= 6:
                    print(f"{RED}🚨 HIGH RISK - Likely phishing email!{RESET}")
                elif score >= 4:
                    print(f"{YELLOW}⚠️  MEDIUM RISK - Suspicious email{RESET}")
                elif score >= 2:
                    print(f"{YELLOW}⚠️  LOW RISK - Minor concerns{RESET}")
                else:
                    print(f"{GREEN}✅ SAFE - Email appears legitimate{RESET}")
                
                print(f"\n{BOLD}{MAGENTA}📊 Risk Score: {score}/10{RESET}")
                print(f"\n{BOLD}{CYAN}🔍 Analysis Details:{RESET}")
                if reasons:
                    for reason in reasons:
                        print(f"   {YELLOW}•{RESET} {reason}")
                else:
                    print(f"   {GREEN}• No suspicious patterns detected{RESET}")
                    
            except Exception as e:
                print(f"{RED}❌ Error: {e}{RESET}")
        
        elif choice == '3':
            # Email text analysis
            print(f"{YELLOW}Paste email content (Press Ctrl+D or Ctrl+Z when finished):{RESET}")
            email_lines = []
            try:
                while True:
                    line = input()
                    email_lines.append(line)
            except EOFError:
                pass
            
            email_text = '\n'.join(email_lines)
            
            if email_text.strip():
                score, reasons = analyze_email_from_text(email_text)
                
                print(f"\n{BOLD}{BLUE}📧 EMAIL ANALYSIS RESULTS{RESET}")
                print(f"{WHITE}{'='*50}{RESET}")
                
                if score >= 6:
                    print(f"{RED}🚨 HIGH RISK - Likely phishing email!{RESET}")
                elif score >= 4:
                    print(f"{YELLOW}⚠️  MEDIUM RISK - Suspicious email{RESET}")
                elif score >= 2:
                    print(f"{YELLOW}⚠️  LOW RISK - Minor concerns{RESET}")
                else:
                    print(f"{GREEN}✅ SAFE - Email appears legitimate{RESET}")
                
                print(f"\n{BOLD}{MAGENTA}📊 Risk Score: {score}/10{RESET}")
                print(f"\n{BOLD}{CYAN}🔍 Analysis Details:{RESET}")
                if reasons:
                    for reason in reasons:
                        print(f"   {YELLOW}•{RESET} {reason}")
                else:
                    print(f"   {GREEN}• No suspicious patterns detected{RESET}")
            else:
                print(f"{RED}❌ No email content provided{RESET}")
        
        elif choice == '4':
            # Quick headers check
            sender = input(f"{YELLOW}Enter sender email: {RESET}").strip()
            subject = input(f"{YELLOW}Enter email subject: {RESET}").strip()
            
            if sender and subject:
                # Create minimal email for analysis
                minimal_email = f"From: {sender}\nSubject: {subject}\n\nQuick analysis content"
                score, reasons = analyze_email_from_text(minimal_email)
                
                print(f"\n{BOLD}{BLUE}📧 QUICK EMAIL CHECK{RESET}")
                print(f"{WHITE}{'='*40}{RESET}")
                
                if score >= 3:
                    print(f"{RED}🚨 SUSPICIOUS - Check carefully!{RESET}")
                elif score >= 2:
                    print(f"{YELLOW}⚠️  CAUTION - Some concerns{RESET}")
                else:
                    print(f"{GREEN}✅ LOOKS OK - Basic check passed{RESET}")
                
                print(f"\n{BOLD}{MAGENTA}📊 Risk Score: {score}/10{RESET}")
                if reasons:
                    print(f"\n{BOLD}{CYAN}🔍 Concerns:{RESET}")
                    for reason in reasons:
                        print(f"   {YELLOW}•{RESET} {reason}")
            else:
                print(f"{RED}❌ Please provide both sender and subject{RESET}")
        
        else:
            print(f"{RED}❌ Invalid selection!{RESET}")
            
        input(f"\n{BOLD}{CYAN}Press Enter to continue...{RESET}")
