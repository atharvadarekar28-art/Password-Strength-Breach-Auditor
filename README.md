# Password Strength Checker & Breach Auditor (k-Anonymity)

A desktop cybersecurity auditing tool built with **Python**, **hashlib**, **requests**, and **PyQt6** (no Tkinter). It evaluates password length, information entropy, and common vulnerability patterns, while verifying whether the password has appeared in known public data breaches using the **Have I Been Pwned (HIBP)** zero-knowledge **k-Anonymity API**.

---

## 🛡️ Zero-Knowledge k-Anonymity Protocol

The biggest concern with checking passwords against online databases is sending sensitive credentials over the internet. This tool implements the **k-Anonymity model**:

1. **Local SHA-1 Hashing:** When you enter a password, the application generates a 40-character SHA-1 hash strictly in memory on your local machine using Python's `hashlib`.
2. **5-Character Prefix Transmission:** Only the first **5 hexadecimal characters** (e.g., `CD8FB` or `5BAA6`) are sent to the HIBP API endpoint via HTTPS (`https://api.pwnedpasswords.com/range/{prefix}`).
3. **Range Response:** The HIBP API returns a list of hundreds of hash suffixes that begin with those same 5 characters, along with their observed breach frequency counts.
4. **Client-Side Suffix Verification:** The application matches the remaining **35 characters** locally on your computer.
5. **Absolute Privacy:** The remote server never knows which of the hundreds of returned suffixes belongs to you. **Your plaintext password NEVER leaves your computer.**

---

## 🚀 Features

- **k-Anonymity Breach Verification:** Instant verification against 850+ million breached passwords from public data dumps.
- **Shannon & Combinatorial Entropy Analysis:**
  - Evaluates character pool sizes ($R$) across lowercase, uppercase, digits, symbols, spaces, and unicode.
  - Calculates search space combinations ($R^L$) and raw information entropy ($E = L \times \log_2(R)$ bits).
  - Calculates frequency-adjusted effective entropy.
- **Realistic Brute-Force Crack Simulation:**
  - Simulates attack speeds against Online Throttled (100 guesses/s), Fast API (10k/s), Standard CPU (100k/s), High-End GPU (NVIDIA RTX 4090 - 10B/s), 8x GPU Mining Rig (80B/s), and Supercomputer / Botnet (100T/s).
- **Vulnerability Pattern Detection:**
  - Sequential numbers (`1234`, `9876`)
  - Sequential letters (`abcd`, `zyxw`)
  - Repetitive characters (`aaa`, `111`)
  - Keyboard walk spatial paths (`qwerty`, `asdfgh`, `1qaz`)
  - Common dictionary passwords (`password`, `admin`, `welcome`, etc.)
  - Leetspeak substitutions (`p@ssw0rd`, `m@st3r`, `1ove`)
  - Four-digit calendar/birth years (`1998`, `2024`)
  - Predictable structural templates (e.g. Capital + Word + Numbers + Symbol)
- **High-Contrast Developer UI:**
  - Native dark developer console aesthetic inspired by authentic security utilities.
  - High DPI aware with crystal-clear, readable contrast across all tabs, buttons, badges, and labels.
- **Cryptographic Password Generator:**
  - Cryptographically secure random passwords (using Python's `secrets` module).
  - Diceware multi-word passphrases (e.g. `Correct-Horse-Battery-Staple`).

---

## 📦 Installation & Running

### Requirements
- Python 3.8+
- `requests`
- `PyQt6`

### Quick Run
```bash
# Install dependency
pip install -r requirements.txt

# Launch application
python main.py
```
