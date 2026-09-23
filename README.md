# 🛡️ CyberShield: Password Strength Checker & Secure Password Generator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Vercel-Deployed-black?style=for-the-badge&logo=vercel&logoColor=white" alt="Vercel" />
  <img src="https://img.shields.io/badge/Security-NIST%20SP%20800--63B-emerald?style=for-the-badge" alt="NIST Compliant" />
  <img src="https://img.shields.io/badge/Privacy-HIBP%20k--Anonymity-cyan?style=for-the-badge" alt="k-Anonymity" />
</p>

An enterprise-grade, cybersecurity-focused Python application that provides mathematical **Shannon entropy analysis**, **NIST SP 800-63B digital identity guideline compliance**, **Have I Been Pwned (HIBP) k-Anonymity breach detection**, **multi-tier brute-force crack time projections**, and a **cryptographically secure random password & Diceware passphrase generator**.

Delivered with a **high-performance Webpage Frontend**, **FastAPI REST API**, **Streamlit Web Dashboard**, and an **Interactive Terminal CLI**.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Live Demo & Screenshots](#-live-demo--preview)
- [Architecture & Cryptographic Principles](#-architecture--cryptographic-principles)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites & Installation](#1-installation)
  - [Running the Webpage Frontend](#2-webpage-frontend-recommended)
  - [Using the Command Line Interface (CLI)](#3-command-line-interface-cli)
  - [Running the Streamlit Dashboard](#4-streamlit-web-dashboard)
- [REST API Endpoints](#-rest-api-documentation)
- [Deployment on Vercel](#-deploying-live-on-vercel)
- [Running Unit Tests](#-running-automated-tests)
- [Project Directory Structure](#-project-directory-structure)
- [License & Security Policy](#-security--privacy-guarantee)

---

## ✨ Key Features

### 🔍 1. Real-Time Password Strength Auditor
- **Mathematical Shannon Entropy**: Calculates exact entropy ($E = L \times \log_2(R)$ bits) with repetition dampening penalties.
- **NIST SP 800-63B Standard Compliance**: Validates credentials against modern NIST rules (length over arbitrary symbol quotas, breach bans, predictable patterns).
- **Vulnerability & Pattern Scans**:
  - Sequential letters and numbers (`12345`, `abcdef`, `98765`).
  - Keyboard walk sequences (`qwerty`, `asdfgh`, `zxcvbn`, `1qaz`).
  - Consecutive character repetition (`aaaa`, `1111`).
  - Common leaked dictionary passwords blacklist.
- **Zero-Knowledge Breach Detection (Have I Been Pwned)**:
  - Implements SHA-1 **k-Anonymity** by transmitting only the 5-character hash prefix over HTTPS. Full passwords and hashes never leave memory.
- **Hardware Brute-Force Crack Projections**:
  - Online rate-limited (100 guesses/s — standard web login).
  - Online unthrottled botnet (10,000 guesses/s — API credential stuffing).
  - Offline single GPU (10 GH/s on NVIDIA RTX 4090 — MD5/NTLM hashes).
  - Offline high-end GPU cluster (1 TH/s — multi-GPU dedicated cracking rig).
- **Visual Analytics**: Interactive circular SVG score meter, character composition bars, vulnerability severity badges, and actionable recommendations.

### ⚡ 2. Cryptographically Secure Generator
- Built on Python's `secrets` module (CSPRNG — Cryptographically Secure Pseudo-Random Number Generator, not weak PRNGs like `random`).
- **Modes**:
  - **Random Password**: Configurable length (8 to 64+), lowercase, uppercase, digits, symbols, ambiguous character filtering (`l, 1, I, O, 0, |`), and guaranteed character class inclusion.
  - **Diceware / XKCD Passphrase**: High-entropy, human-memorable multi-word passphrases using a curated 300+ word dictionary, custom separators (`-`, `_`, `.`), title casing, and optional appended digits or symbols.
  - **Numeric PIN**: Fixed-width numeric codes (4 to 16 digits) for tokens or OTPs.
  - **Formatted License Token**: Grouped blocks (e.g. `ABCD-EFGH-1234-WXYZ`).
- **1-Click Copy & Audit**: Copies to clipboard with toast notification or sends directly into the Strength Auditor for inspection.

### 📋 3. Bulk Password Auditor
- Paste multi-line credential datasets (one per line).
- Aggregates overall statistics: average security score, NIST compliance rate, high-risk credentials, and breach occurrences.
- Searchable data table with individual scores, ratings, entropy, and vulnerability tags.

---

## 🔒 Architecture & Cryptographic Principles

### 1. Shannon Information Entropy Formula

Entropy measures the unpredictability and uncertainty of a password:

$$\text{Entropy (bits)} = L \times \log_2(R)$$

Where:
- $L$ is password length.
- $R$ is the size of the character pool (lowercase: 26, uppercase: 26, digits: 10, symbols: 32+).

| Entropy Range | Strength Rating | Resistance Level |
|---|---|---|
| **< 30 bits** | Very Weak | Cracked in milliseconds on consumer GPUs. |
| **30 – 50 bits** | Weak | Vulnerable to targeted dictionary attacks and fast hash dumps. |
| **50 – 70 bits** | Fair | Resilient against throttled web logins; vulnerable offline. |
| **70 – 90 bits** | Strong | Resistant to high-end multi-GPU cracking rigs. |
| **90+ bits** | Very Strong | Virtually uncrackable for centuries. |

---

### 2. Have I Been Pwned k-Anonymity Model

To query compromised credential databases without risking exposure:

```
[User Password] ──(SHA-1 Hash)──> 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                                     │
                     [Prefix: 5BAA6] ┴ [Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8]
                               │                                     │
          (Sent to HIBP API)  ▼                                     │
       https://api.pwnedpasswords.com/range/5BAA6                   │
                               │                                     │
       (Server returns ~800 candidate suffixes)                     │
                               ▼                                     │
                      [Local Client Comparison] <────────────────────┘
                               │
               (Exact match found = Breached)
```

**Privacy Guarantee**: The full password and full hash never leave your computer.

---

## 🚀 Quick Start Guide

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/girishm03/Password-Strength-Checker-Secure-Password-Generator-.git
cd Password-Strength-Checker-Secure-Password-Generator-
pip install -r requirements.txt
```

---

### 2. Webpage Frontend (Recommended)

#### Option A: One-Click on Windows
Double-click **`run_web.bat`**. It launches the server and automatically opens `http://localhost:8000` in your default browser.

#### Option B: From Terminal
```bash
python server.py
```
Open **`http://localhost:8000`** in your browser.

---

### 3. Command Line Interface (CLI)

#### Interactive Cyber Menu:
```bash
python main.py
```

#### Analyze a Specific Password:
```bash
# With live HaveIBeenPwned breach check
python main.py --check "P@ssw0rd123!"

# Offline audit only
python main.py --check "P@ssw0rd123!" --no-breach
```

#### Generate Secure Credentials:
```bash
# 20-character password without ambiguous characters
python main.py --generate -l 20 --exclude-ambiguous

# 5-word Diceware passphrase
python main.py --passphrase --words 5 --separator "-"

# 6-digit secure PIN
python main.py --pin -l 6
```

---

### 4. Streamlit Web Dashboard

```bash
streamlit run app.py
```
Opens in your browser at `http://localhost:8501`.

---

## 🌐 REST API Documentation

The FastAPI backend provides automated Swagger documentation at **`http://localhost:8000/docs`**:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Real-time security, entropy, crack time, and breach check |
| `POST` | `/api/generate` | CSPRNG password, passphrase, PIN, or token generation |
| `POST` | `/api/bulk-analyze` | Multi-password batch audit with statistical summaries |

#### Example API Request:
```bash
curl -X POST "http://localhost:8000/api/analyze" \
     -H "Content-Type: application/json" \
     -d '{"password": "Admin@2026_Secure!", "check_breach": false}'
```

---

## ☁️ Deploying Live on Vercel

The repository is pre-configured with [`vercel.json`](vercel.json), [`api/index.py`](api/index.py), and [`public/`](public/) for seamless zero-config Vercel deployment:

1. Go to **[Vercel Dashboard](https://vercel.com/dashboard)**.
2. Click **"Add New..."** → **"Project"**.
3. Import the GitHub repository:  
   `girishm03/Password-Strength-Checker-Secure-Password-Generator-`
4. Leave all build settings as default (Framework: **Other**, Root: `./`).
5. Click **"Deploy"**.

Your application will be live globally in under 60 seconds with SSL and edge caching!

---

## 🧪 Running Automated Tests

Run the unit test suite verifying entropy math, generator randomness constraints, ambiguous character exclusion, and pattern detection:

```bash
python -m unittest -v tests.test_checker
```

Output:
```
test_empty_password ... ok
test_entropy_scaling ... ok
test_format_duration ... ok
test_pool_size_calculation ... ok
test_common_password_detection ... ok
test_empty_password_check ... ok
test_keyboard_walk_detection ... ok
test_sequential_pattern_detection ... ok
test_strong_password_analysis ... ok
test_exclude_ambiguous_characters ... ok
test_generate_formatted_token ... ok
test_generate_passphrase ... ok
test_generate_pin ... ok
test_random_password_character_enforcement ... ok
test_random_password_length ... ok

Ran 15 tests in 0.003s - OK
```

---

## 📁 Project Directory Structure

```
.
├── .gitignore                  # Git exclusions for pycache, venv, and vercel
├── vercel.json                 # Vercel deployment & routing configuration
├── requirements.txt            # Python dependencies (FastAPI, uvicorn, streamlit, etc.)
├── run_web.bat                 # 1-click Windows launcher for Webpage Frontend
├── server.py                   # FastAPI REST backend & static file server
├── app.py                      # Streamlit Web Application
├── main.py                     # Command Line Interface (Interactive & Flags)
├── README.md                   # Project documentation
├── api/
│   └── index.py                # Vercel Serverless Function entry point
├── public/                     # Static production bundle served by Vercel edge CDN
│   ├── index.html
│   ├── style.css
│   └── app.js
├── web/                        # Local source Webpage Frontend assets
│   ├── index.html              # HTML5 structure with responsive tabs
│   ├── style.css               # Vanilla CSS with glassmorphism & cyber dark theme
│   └── app.js                  # Reactive ES6 JS, debounced audit, and copy logic
├── core/
│   ├── __init__.py             # Core package initialization
│   ├── checker.py              # Multi-factor password analysis & scoring engine
│   ├── generator.py            # CSPRNG generator (Passwords, Diceware, PINs, Tokens)
│   ├── entropy.py              # Shannon entropy & brute force crack time estimator
│   ├── pwned.py                # Have I Been Pwned SHA-1 k-Anonymity breach client
│   └── wordlist.py             # Curated Diceware dictionary & common leaked passwords
└── tests/
    ├── __init__.py
    └── test_checker.py         # Automated unit test suite (15 unit tests)
```

---

## 🛡️ Security & Privacy Guarantee

- **Zero-Storage Policy**: No passwords, hashes, or evaluation metadata are ever logged, persisted, or stored.
- **k-Anonymity Cryptography**: When querying breach status, only the first 5 characters of the SHA-1 hash are queried over HTTPS; candidate matching occurs strictly in local memory.
- **CSPRNG Generation**: All passwords, passphrases, and tokens are generated using the operating system's cryptographic random number source (`os.urandom` via Python's `secrets` module).

---

<p align="center">
  <b>Developed by Girish M</b> • Cyber Security Projects • 2026
</p>
