# 🛡️ CyberShield: Password Strength Checker & Secure Generator

A cybersecurity-grade Python application providing in-depth password strength analysis, Shannon entropy calculation, Have I Been Pwned (HIBP) k-Anonymity breach detection, brute-force crack time modeling across modern hardware tiers, and a cryptographically secure random password & passphrase generator.

---

## ✨ Features

- **Mathematical Shannon Entropy**: Computes exact information entropy ($E = L \times \log_2(R)$ bits) with repetition dampening.
- **NIST SP 800-63B Compliance Engine**: Validates password length and modern NIST digital identity guidelines.
- **Have I Been Pwned (HIBP) Integration**: Zero-knowledge **k-Anonymity** model using SHA-1 prefix matching to check whether a password appears in real-world breaches without ever exposing the password or full hash.
- **Hardware Brute-Force Projections**: Calculates time-to-crack across 4 realistic attack profiles:
  - Online rate-limited (100 guesses/s)
  - Online unthrottled botnet (10,000 guesses/s)
  - Offline single GPU (10 GH/s on RTX 4090)
  - Offline high-end cracking rig (1 TH/s GPU cluster)
- **Vulnerability & Pattern Scans**: Detects repeated characters, keyboard walks (e.g. `qwerty`, `asdfgh`), sequential series (`12345`, `abcd`), and common dictionary passwords.
- **CSPRNG Password & Passphrase Generator**:
  - Uses Python's `secrets` module (cryptographically secure pseudo-random number generator).
  - **Random Password**: Custom length, lowercase, uppercase, digits, symbols, ambiguous character exclusion (`l, 1, I, O, 0, |`).
  - **Diceware / XKCD Passphrase**: Memorable multi-word phrases with custom delimiters, capitalization, and appended numbers.
  - **Numeric PINs & Formatted License Keys**: Fixed-width numeric or token blocks.
- **Multiple User Interfaces**:
  - **Modern Webpage Frontend (HTML5/CSS3/JS)**: Clean, high-performance dark cyber UI with circular score ring, live slider generators, copy-to-clipboard, and bulk auditing.
  - **FastAPI REST Backend**: Fast endpoints (`/api/analyze`, `/api/generate`, `/api/bulk-analyze`) with interactive Swagger docs at `/docs`.
  - **Streamlit Web Dashboard**: Real-time gauge, dark cybersecurity HUD theme, crack time cards, and educational guides.
  - **Interactive & Scriptable CLI**: Formatted terminal output with ANSI colors and flags for automation.

---

## 🚀 Quick Start

### 1. Installation

Ensure you have Python 3.10+ installed. Install the dependencies:

```bash
pip install -r requirements.txt
```

---

### 2. Launch the Webpage Frontend (Recommended)

#### Option A: One-Click on Windows
Simply double-click the **[`run_web.bat`](file:///f:/Cyber%20Security%20Projects/Password%20Strength%20Checker%20&%20Secure%20Password%20Generator/run_web.bat)** file! It starts the server and opens `http://localhost:8000` automatically in your default browser.

#### Option B: From Terminal
```bash
python server.py
```
Then visit **`http://localhost:8000`** in your browser.
Interactive API documentation is accessible at **`http://localhost:8000/docs`**.

---

### 3. Launch the Streamlit Web Application

```bash
streamlit run app.py
```
The Streamlit dashboard opens at **`http://localhost:8501`**.

---

### 4. Using the Command Line Interface (CLI)

#### Interactive Terminal Mode:
```bash
python main.py
```

#### Analyze a Password:
```bash
# Full analysis with HaveIBeenPwned breach check
python main.py --check "P@ssw0rd123!"

# Offline check only (skip network lookup)
python main.py --check "P@ssw0rd123!" --no-breach
```

#### Generate Secure Passwords:
```bash
# Generate 20-character password without ambiguous characters
python main.py --generate -l 20 --exclude-ambiguous

# Generate a 5-word Diceware passphrase
python main.py --passphrase --words 5 --separator "-"

# Generate a 6-digit secure PIN
python main.py --pin -l 6
```

---

## 🔒 Security & Privacy Architecture

### Have I Been Pwned k-Anonymity
When checking breach records, this tool adheres strictly to the **k-Anonymity** standard:
1. The tool hashes the password locally using **SHA-1**: `hash = SHA1(password)`.
2. Only the **first 5 characters** (the prefix) are sent to `https://api.pwnedpasswords.com/range/{prefix}`.
3. The server responds with ~500–1,000 anonymous hash suffixes matching that prefix.
4. The remaining 35 characters are compared locally on your machine.

**Neither your password nor your full hash ever traverses the internet.**

---

## 🧪 Running Unit Tests

Run the test suite covering entropy math, generator constraints, and vulnerability matchers:

```bash
python -m unittest discover tests
```

---

## 📁 Project Structure

```
├── run_web.bat             # Windows 1-click launcher for the Webpage Frontend
├── server.py               # FastAPI backend & static file server
├── app.py                  # Streamlit Web Application
├── main.py                 # CLI interface (Interactive & Flags)
├── requirements.txt        # Project dependencies
├── web/                    # Modern Webpage Frontend
│   ├── index.html          # HTML5 UI structure
│   ├── style.css           # Dark cyber styling & glassmorphism
│   └── app.js              # Reactive JavaScript, API calls, and copy logic
├── core/
│   ├── __init__.py         # Package exports
│   ├── checker.py          # Password analysis & scoring engine
│   ├── generator.py        # CSPRNG generator (Passwords, Passphrases, PINs)
│   ├── entropy.py          # Shannon entropy & brute force crack time calculations
│   ├── pwned.py            # HIBP k-Anonymity API integration
│   └── wordlist.py         # Diceware wordlist & common password blacklist
└── tests/
    └── test_checker.py     # Comprehensive automated test suite
```
