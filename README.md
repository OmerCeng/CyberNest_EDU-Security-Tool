
# 🔐 CyberNest_EDU-Security-Tool

A lightweight and modular cybersecurity toolkit designed for hands-on practice in controlled educational environments.  
This suite helps students and enthusiasts explore real-world security concepts through safe and legal simulations.

"CyberNest Security-Tool is being developed for cybersecurity professionals. This version is the first phase and is a limited version for educational purposes."

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
| **1. Port (TCP) Scanner**                             | Scans the specified IP address to detect open TCP ports. Useful for basic network reconnaissance.  |
| **2. Phishing Checker**                               | Analyzes a given URL and checks whether it could be a phishing site using predefined rules.         |
| **3. Hash Cracker**                                   | Attempts to crack a given hash (MD5, SHA1, SHA256, SHA512) using a limited wordlist.                |
| **4. Password Security Testing Tools** | Combines heuristic analysis, a machine learning model for password strength prediction, a brute-force tester for numeric PINs, and a recommendation engine that suggests improvements to weak passwords. |
| **5. Social Engineering-Based Custom Wordlist Generator** | Generates a personalized wordlist using inputs like name, birth year, job, and location.              |

.................................................................................................................................................................................................................................

### 📦 Installation (Linux)

Follow the steps below to install and run the tool on a Linux system:

```bash
# Clone the repository
git clone https://github.com/OmerCeng/CyberNest_EDU-Security-Tool.git

# Navigate to the project directory
cd CyberNest_EDU-Security-Tool

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install project dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

..................................................................................................................................................................................................................................
### 🗂️ Project Structure

```
CyberNest_EDU-Security-Tool/
├── models/                          # Trained machine learning model files
│   ├── model.joblib                 # Saved RandomForestClassifier model for password strength prediction
│   └── encoder.joblib               # LabelEncoder to encode password strength categories
│
├── wordlist/                       # Wordlists used in brute-force and hash cracking
│   ├── wordlist.txt                # General-purpose wordlist for hash cracking
│   └── custom_wordlist.txt         # Wordlist generated using social engineering inputs (name, birth year, job, etc.)
│
├── password_checker.py             # Password analysis module using machine learning
├── hash_cracker.py                 # Module to crack hashes using various algorithms and wordlists
├── phishing_checker.py             # Module to check if a URL is a potential phishing site
├── port_scanner.py                 # Basic TCP port scanner for given host and port range
├── password_generator.py           # Generates custom password wordlist using user info (for social engineering)
├── main.py                         # Command-line interface (CLI) to access all tools
├── requirements.txt                # Python dependencies required to run the project
└── README.md                       # Project description and installation instructions
```


