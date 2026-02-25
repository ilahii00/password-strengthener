# 🔐 Password Strengthener

A lightweight Python CLI tool that analyses password strength using Python's built-in **`hashlib`** module — no third-party dependencies required.

---

## Features

- **Strength scoring** (0–100) with four bands: Weak 🔴 / Fair 🟠 / Good 🟡 / Strong 🟢  
- **Criteria checks** — length, uppercase, lowercase, digits, symbols  
- **Pattern detection** — sequential chars, keyboard walks, repeated characters  
- **Common password blacklist** — instantly flags the 10 000 most-used passwords  
- **Multiple hash algorithms** — MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512  
- **HaveIBeenPwned breach check** (optional `--breach` flag, k-anonymity — your password is never sent in full)  
- **Zero dependencies** — pure Python 3.8+

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/password-strengthener.git
cd password-strengthener

# Run (password prompted securely)
python password_checker.py

# Pass a password directly
python password_checker.py "MyP@ssw0rd!"

# Check against breach database
python password_checker.py "MyP@ssw0rd!" --breach

# Show a different hash algorithm
python password_checker.py "MyP@ssw0rd!" --hash sha512
```

---

## Example Output

```
==================================================
  Password Report for: M*********!
==================================================
  Strength : 🟢  Strong  (88/100)
  Length   : 11 characters

  ✅  Lowercase letters
  ✅  Uppercase letters
  ✅  Numbers
  ✅  Special chars

  Suggestions:
    ✅ Great password! Keep it unique and don't reuse it.

  SHA-256 hash:
    3b4c8f... (64 hex chars)
==================================================
```

---

## Running Tests

```bash
python -m pytest test_password_checker.py -v
```

---

## How the Scoring Works

| Criteria | Points |
|---|---|
| Length ≥ 16 | +30 |
| Length ≥ 12 | +20 |
| Length ≥ 8  | +10 |
| Each character class (lower/upper/digit/symbol) | +12 each |
| Sequential or repeated pattern detected | −15 |
| Common password | Score → 0 |

---

## Security Note

> `hashlib` digests (SHA-256 etc.) shown in this tool are for **demonstration** purposes. For real password storage, always use a slow adaptive hash like **`hashlib.pbkdf2_hmac`**, **bcrypt**, or **argon2**.

---

## License

MIT © 2024 Your Name
