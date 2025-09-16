
# 🔐 CyberNest_EDU-Security-Tool v1.4

A comprehensive and modular cybersecurity toolkit designed for professional penetration testing and security research.  
This advanced suite provides industry-standard security testing capabilities for cybersecurity professionals, penetration testers, and security researchers.

**Latest Updates in v1.4:**
- 🆕 **XSS Vulnerability Scanner** - Professional Cross-Site Scripting detection with advanced payload library
- ✅ Advanced XSS testing capabilities: Reflected, Stored, DOM-based XSS detection
- ✅ 50+ XSS payload library with WAF bypass techniques
- ✅ Professional reporting with OWASP compliance mapping
- ✅ Enhanced web security testing suite (SQL Injection + XSS)
- ✅ Enterprise-grade vulnerability assessment capabilities

**Previous Updates in v1.3:**
- 🆕 **SQL Injection Tester** - Advanced web application vulnerability scanner
- ✅ Enhanced Hash Cracker with verbose debugging and better wordlist support
- ✅ Improved Password Security Testing with CTF/Pentest modes
- ✅ Updated main interface with professional color coding
- ✅ Comprehensive error handling and user experience improvements

**Previous Updates in v1.2:**
- ✅ Added ARP Network Scanner for local device discovery
- ✅ Added Web Directory Scanner for hidden file detection
- ✅ Enhanced main menu with new security tools
- ✅ Improved error handling across all modules

"CyberNest Security-Tool is being developed for professional cybersecurity experts and penetration testers. This version provides enterprise-grade security testing capabilities for authorized security assessments."

### ⚠️ Important Notes

This tool is developed **strictly for educational and testing purposes**. Please consider the following points:

- 📊 The **machine learning dataset** is intentionally kept **small** to focus on demonstrating the concept of password strength classification.
- 🔐 The **brute-force module** is **limited to 4-digit numeric passwords** to prevent long execution times and excessive system resource usage.
- 📂 The **wordlist used for hash cracking** is kept **minimal** to allow faster testing and clearer educational demonstrations.

> ⚠️⚠️⚠️ The **CyberNest_EDU-Security-Tool** is built solely for **lab-based training and educational purposes**.  
> It is **not intended for malicious use** and does **not pose any threat** to third parties.  
> All development has been carried out **within legal and ethical boundaries**. ⚠️⚠️⚠️


................................................................................................................................................................................................................................

### 🔧 Module Descriptions

| Tool Name                                             | Description                                                                                         |
|-------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **1. Port Scanner**                                   | Scans the specified IP address to detect open ports. Useful for basic network reconnaissance and service enumeration.  |
| **2. Phishing Checker**                               | Analyzes a given URL and checks whether it could be a phishing site using advanced pattern recognition and suspicious keyword detection.         |
| **3. Hash Cracker**                                   | Attempts to crack given hashes (MD5, SHA1, SHA256, SHA512) using wordlists. Supports auto-algorithm detection and verbose debugging.                |
| **4. Password Security Testing Tools** | Comprehensive password analysis suite combining heuristic analysis, machine learning model for strength prediction, brute-force testing for numeric PINs, and intelligent recommendation engine. |
| **5. Social Engineering-Based Custom Wordlist Generator** | Generates personalized wordlists using social engineering techniques with inputs like personal information, mutations, and common patterns.              |
| **6. Web Directory Scanner** | Scans websites for hidden directories, admin panels, configuration files, backup files, and other sensitive resources using comprehensive wordlists. |
| **7. ARP Network Scanner** | Discovers active devices on the local network by scanning IP ranges and analyzing ARP tables. Shows IP addresses, MAC addresses, hostnames, and device vendors with detailed network mapping. |
| **8. SQL Injection Tester** | Advanced web application security scanner that tests for SQL injection vulnerabilities using Error-based, Union-based, Boolean-based, and Time-based injection techniques. Includes automatic form discovery and batch testing capabilities. |
| **9. XSS Vulnerability Scanner** | **🆕 NEW!** Professional Cross-Site Scripting detection tool that tests for Reflected, Stored, and DOM-based XSS vulnerabilities. Features 50+ advanced payload library with WAF bypass techniques, professional reporting with OWASP compliance mapping, and comprehensive web security assessment capabilities. |

.................................................................................................................................................................................................................................

### 📦 Installation (Linux/macOS)

Follow the steps below to install and run the tool on a Linux or macOS system:

```bash
# Clone the repository
git clone https://github.com/OmerCeng/CyberNest_EDU-Security-Tool.git

# Navigate to the project directory
cd CyberNest_EDU-Security-Tool

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install project dependencies
pip install -r requirements.txt

# Run the tool
python3 main.py
```

### 🚀 Quick Start

```bash
# Direct execution
cd "CyberNest_EDU Security Tool"
python3 main.py

# Choose from 9 powerful security tools:
# 1. Port Scanner     - Network reconnaissance
# 2. Phishing Checker - URL safety analysis  
# 3. Hash Cracker     - Password hash analysis
# 4. Password Tester  - Security evaluation
# 5. Wordlist Gen     - Social engineering
# 6. Directory Scan   - Web reconnaissance
# 7. ARP Scanner      - Network discovery
# 8. SQL Injection    - Web vulnerability testing
# 9. XSS Scanner      - Cross-Site Scripting detection
```

..................................................................................................................................................................................................................................
### 🗂️ Project Structure

```
CyberNest_EDU-Security-Tool/
├── CyberNest_EDU Security Tool/     # Main application directory
│   ├── models/                      # Trained machine learning model files
│   │   ├── model.joblib            # Saved RandomForestClassifier model for password strength prediction
│   │   └── encoder.joblib          # LabelEncoder to encode password strength categories
│   │
│   ├── wordlist/                   # Wordlists used in brute-force and hash cracking
│   │   ├── wordlist.txt            # General-purpose wordlist for hash cracking (1722+ passwords)
│   │   └── custom_wordlist.txt     # Generated wordlist using social engineering inputs
│   │
│   ├── main.py                     # Main application entry point with interactive menu
│   ├── password_checker.py         # Advanced password analysis with ML and brute-force testing
│   ├── hash_cracker.py             # Multi-algorithm hash cracker with auto-detection
│   ├── phishing_checker.py         # URL phishing detection with pattern analysis
│   ├── port_scanner.py             # TCP port scanner with service detection
│   ├── password_generator.py       # Social engineering wordlist generator
│   ├── web_directory_scanner.py    # Web directory and file discovery scanner
│   ├── arp_scanner.py              # ARP-based network device discovery
│   ├── sql_injection_tester.py     # Advanced SQL injection vulnerability scanner
│   ├── xss_vulnerability_scanner.py # 🆕 Professional XSS vulnerability detection tool
│   └── requirements.txt            # Python dependencies
│
├── README.md                       # Project documentation
└── LICENSE                         # Project license
```

..................................................................................................................................................................................................................................

### 🛠️ Advanced Features in v1.4

#### 🔥 XSS Vulnerability Scanner Capabilities

The new XSS Vulnerability Scanner provides professional Cross-Site Scripting detection:

**XSS Types Supported:**
- **Reflected XSS** - Immediate script execution in responses
- **Stored XSS** - Persistent script storage testing
- **DOM-based XSS** - Client-side DOM manipulation attacks
- **Universal XSS** - Cross-domain scripting vulnerabilities

**Advanced Payload Library:**
```bash
• 50+ XSS Payloads        - Comprehensive attack vectors
• WAF Bypass Techniques   - Advanced evasion methods
• OWASP Compliance       - Industry standard testing
• Severity Scoring       - Professional vulnerability assessment
```

**Testing Features:**
- **Multi-threaded Scanning** - Fast concurrent vulnerability testing
- **Form Discovery** - Automatic web form detection and testing
- **Professional Reporting** - Detailed vulnerability reports with CVSS-style scoring
- **Custom Payload Support** - Advanced payload customization capabilities

#### 🔥 SQL Injection Tester Capabilities

The SQL Injection Tester provides comprehensive web application security testing:

**Injection Types Supported:**
- **Error-based Injection** - Detects SQL errors in responses (MySQL, PostgreSQL, MSSQL, Oracle)
- **Union-based Injection** - Tests UNION SELECT attacks for data extraction
- **Boolean-based Blind** - Logic-based injection testing
- **Time-based Blind** - Temporal injection with delay analysis
- **Authentication Bypass** - Login bypass techniques

**Testing Modes:**
```bash
1. Manual URL Testing    - Specific parameter testing
2. Automatic Form Scan   - Discovers and tests web forms
3. Batch URL Testing     - Multiple URLs from file
```

**Example Usage:**
```bash
# XSS Testing Example
URL: http://example.com/search.php?q=test
Payload: <script>alert('XSS')</script>
Result: Reflected XSS vulnerability detected - High severity

# Advanced WAF Bypass
Payload: <img src=x onerror=alert(String.fromCharCode(88,83,83))>
Result: WAF bypass successful - XSS execution confirmed
```

**Example Usage:**
```bash
# Test a login form
URL: http://example.com/login.php?id=1
Payload: ' OR 1=1--
Result: Potential authentication bypass detected

# Time-based injection
Payload: '; WAITFOR DELAY '00:00:05'--
Result: Response delayed by 5.23 seconds - Time-based injection found
```



..................................................................................................................................................................................................................................

### 🎯 Usage Examples

#### Port Scanner
```bash
Target: 192.168.1.1
Port Range: 1-1000
Result: Open ports found - 22 (SSH), 80 (HTTP), 443 (HTTPS)
```

#### SQL Injection Tester  
```bash
Target: http://vulnerable-site.com/product.php?id=1
Payload: ' UNION SELECT 1,2,database()--
Result: Database name extracted - 'shop_db'
```

#### Hash Cracker
```bash
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Algorithm: MD5 (auto-detected)
Result: Password found - 'password' (Line 2, 2 attempts)
```

#### ARP Network Scanner
```bash
Network: 192.168.1.0/24
Results: 
- 192.168.1.1   AA:BB:CC:DD:EE:FF   Router         Cisco Systems
- 192.168.1.100 11:22:33:44:55:66   Desktop-PC     Intel Corp
```

..................................................................................................................................................................................................................................

### 🔒 Security & Ethics

**⚠️ IMPORTANT LEGAL NOTICE:**

This tool is designed for **educational purposes only**. Users must:

- ✅ Only test on systems they **own** or have **explicit written permission** to test
- ✅ Use in **controlled lab environments** for learning purposes
- ✅ Respect all applicable **local and international laws**
- ❌ **Never use for malicious purposes** or unauthorized access
- ❌ **Not target systems** without proper authorization

**Recommended Use Cases:**
- 🎓 **Educational Labs** - Cybersecurity courses and training
- 🏠 **Home Labs** - Personal learning environments  
- 🔬 **Research** - Academic security research
- 💼 **Authorized Pentesting** - With proper contracts and permissions

..................................................................................................................................................................................................................................

### 📊 Technical Specifications

**System Requirements:**
- **Python 3.8+** (Tested on 3.9-3.13)
- **Memory:** 512MB RAM minimum
- **Storage:** 50MB free space
- **Network:** Internet connection for updates
- **OS:** Linux, macOS, Windows (WSL recommended)

**Dependencies:**
- `scikit-learn>=1.7.0` - Machine learning capabilities
- `pandas>=2.2.0` - Data processing
- `requests>=2.31.0` - HTTP client for web testing
- `beautifulsoup4>=4.12.0` - HTML parsing for XSS detection
- `joblib>=1.3.0` - Model serialization

**Performance Metrics:**
- **Hash Cracking:** 1000+ hashes/second
- **Port Scanning:** 100+ ports/second  
- **SQL Injection:** 50+ payloads/minute
- **XSS Scanning:** 100+ payloads/minute with multi-threading
- **Network Discovery:** Full /24 subnet in <30 seconds

..................................................................................................................................................................................................................................

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 🙏 Acknowledgments

- **Cybersecurity Community** for ongoing research and tools
- **Educational Institutions** for providing learning frameworks
- **Open Source Projects** that inspire and enable this work
- **Security Researchers** for vulnerability discovery techniques




