⚠️ Important Notes
This tool is built for learning and testing purposes. As such:

The machine learning dataset is intentionally small, focusing on concept demonstration.

The brute force logic is limited to 4-digit numeric passwords to avoid system overload and long wait times.

The wordlist used for hash cracking is kept minimal for fast execution and clarity in educational scenarios.

⚠️⚠️⚠️ The CyberNest_EDU-Security-Tool I have developed is designed solely for laboratory and educational purposes. It does not pose any threat to any third party. It has been developed entirely within legal frameworks. ⚠️⚠️⚠️


..............................................................................................................
📦 Installation (Linux)
git clone https://github.com/OmerCeng/CyberNest_EDU-Security-Tool.git
cd /CyberNest_EDU-Security-Tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
..............................................................................................................
🗂️ Project Structure
CyberNest_EDU-Security-Tool
├── models/                          # Trained machine learning model files
│   ├── model.joblib                 # Saved RandomForestClassifier model for password strength prediction
│   └── encoder.joblib               # LabelEncoder to encode password strength categories
│
├── wordlist/                        # Wordlists used in brute-force and hash cracking
│   ├── wordlist.txt                 # General-purpose wordlist for hash cracking
│   └── custom_wordlist.txt          # Wordlist generated using social engineering inputs (name, birth year, job, etc.)
│
├── password_checker.py             # Password analysis module using machine learning
├── hash_cracker.py                 # Module to crack hashes using various algorithms and wordlists
├── phishing_checker.py            # Module to check if a URL is a potential phishing site
├── port_scanner.py                # Basic TCP port scanner for given host and port range
├── social_wordlist_generator.py   # Generates custom password wordlist using user info (for social engineering)
├── main.py                         # Command-line interface (CLI) to access all tools
├── requirements.txt                # Python dependencies required to run the project
└── README.md                       # Project description and installation instructions
.................................................................................................................
