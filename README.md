# 🔐 Password Strength Checker & Breach Alert

## 🚨 Security Impact
- Detects weak and compromised passwords used in real-world breaches
- Prevents credential stuffing and account takeover attacks
- Uses k-anonymity to securely check leaked passwords without exposing them

A Python security tool that analyses password strength using entropy-based scoring, checks passwords against real-world breach databases via the HaveIBeenPwned API, and generates cryptographically strong passwords — all with both a CLI and a Tkinter GUI.

---

## 🎯 Features

| Feature | Details |
|---|---|
| 🔢 Strength Scoring | Entropy-based analysis (0–100 score) |
| 🚨 Breach Detection | HaveIBeenPwned API with k-anonymity |
| 🔑 Password Generator | Configurable random password generator |
| 📝 Passphrase Generator | Memorable word-based passphrases |
| 🚫 Common Password Blocklist | Flags top common/weak passwords |
| 🖥️ Dual Interface | Both CLI (terminal) and GUI (Tkinter) |
| 📋 Detailed Checklist | 10-point security checklist per password |

---

## 🛡️ Security: How Breach Check Works (k-Anonymity)

Your password is **never sent** to any server.

1. Password is hashed locally using SHA-1
2. Only the **first 5 characters** of the hash are sent to the HIBP API
3. The API returns all matching hash suffixes
4. The tool checks if your full hash suffix appears — **locally**

This is called the **k-anonymity model** — your actual password never leaves your machine.

```
SHA-1("password123") = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
                                          ↑
                          Only "CBFDA" is sent to API
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3 |
| GUI | Tkinter (built-in) |
| Packet Analysis | hashlib, math, re (built-in) |
| Breach API | HaveIBeenPwned v3 |
| HTTP | urllib (built-in, no extra deps) |

---

## 📁 Project Structure

```
password-strength-checker/
│
├── checker.py               # Core logic (strength, breach, generator)
├── cli.py                   # Command-line interface
├── gui.py                   # Tkinter GUI
├── wordlists/
│   └── common_passwords.txt # Blocklist of common passwords
├── requirements.txt
└── README.md
```

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/santhoshreddy28/Password-Strength-Checker-and-Breach-Alert.git
cd Password-Strength-Checker-and-Breach-Alert
```

### 2. No pip install needed!
All dependencies are Python standard library. Just run:

### 3a. Launch GUI
```bash
python gui.py
```

### 3b. Launch CLI (interactive)
```bash
python cli.py
```

### 3c. CLI with Arguments
```bash
# Check a password
python cli.py --check

# Generate a strong password (16 chars)
python cli.py --generate

# Generate a passphrase
python cli.py --passphrase

# Generate 24-char password
python cli.py --generate --length 24

# Check without breach lookup
python cli.py --check --no-breach
```

---

## 📊 Strength Scoring Breakdown

| Criteria | Points |
|---|---|
| 8+ characters | +10 |
| 12+ characters | +10 |
| 16+ characters | +10 |
| Has uppercase | +15 |
| Has lowercase | +15 |
| Has numbers | +15 |
| Has special chars | +15 |
| No repeated chars | +5 |
| No sequential patterns | +5 |
| **Common password penalty** | Score capped at 10 |

| Score | Label |
|---|---|
| 0–20 | 🔴 Very Weak |
| 21–40 | 🟠 Weak |
| 41–60 | 🟡 Moderate |
| 61–80 | 🟢 Strong |
| 81–100 | ✅ Very Strong |

---

## 📸 Screenshots

> CLI and GUI screenshots to be added after deployment.

---

## 💡 Sample CLI Output

```
──────────────────────────────────────────────────
  🔍 PASSWORD ANALYSIS
──────────────────────────────────────────────────
  Strength   : Very Strong
  Score      : [██████████████████████████████] 95/100
  Length     : 18 characters
  Entropy    : 117.6 bits

  📋 CHECKLIST
    ✓  8+ characters
    ✓  12+ characters
    ✓  16+ characters
    ✓  Uppercase letters
    ✓  Lowercase letters
    ✓  Numbers
    ✓  Special characters
    ✓  No repeated chars
    ✓  No sequential patterns
    ✓  Not a common password

  💡 SUGGESTIONS
    ✅ Excellent password!
──────────────────────────────────────────────────

  🌐 BREACH CHECK (HaveIBeenPwned)
──────────────────────────────────────────────────
  ✅ Safe! Not found in any known data breach.
──────────────────────────────────────────────────
```

---

## 🔮 Future Improvements

- [ ] Export report as PDF
- [ ] Password history tracker
- [ ] Browser extension
- [ ] Docker deployment
- [ ] REST API wrapper

---

## ⚠️ Disclaimer

This tool is built for educational and personal use. The breach check uses the public HaveIBeenPwned API. No passwords are stored or transmitted beyond what the k-anonymity model requires.

---

## 👨‍💻 Author

**Santhosh Reddy**  
GitHub: [santhoshreddy28](https://github.com/santhoshreddy28)
