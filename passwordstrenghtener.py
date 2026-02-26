
"""
Password Strengthener
=====================
A Python tool to analyze and score password strength using hashlib
and common security heuristics.

Author: Prabhleen
License: MIT
"""

import hashlib
import re
import string
import sys


# ── Breach check (HaveIBeenPwned k-anonymity API) ────────────────────────────
def check_pwned(password: str) -> int:
    """
    Check if the password has appeared in known data breaches using the
    HaveIBeenPwned Pwned Passwords API (k-anonymity model — your full
    password is NEVER sent over the network).

    Returns the number of times the password was found (0 = not found).
    """
    try:
        import urllib.request

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")

        for line in body.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return -1  # -1 = could not reach API


# ── Hash utilities ────────────────────────────────────────────────────────────
def hash_password(password: str, algorithm: str = "sha256") -> str:
    """
    Return a hex digest of the password using the chosen algorithm.
    Supported: md5, sha1, sha224, sha256, sha384, sha512.
    (For real storage, use hashlib.pbkdf2_hmac or bcrypt instead.)
    """
    algos = {
        "md5":    hashlib.md5,
        "sha1":   hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    if algorithm not in algos:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {list(algos)}")
    return algos[algorithm](password.encode("utf-8")).hexdigest()


# ── Strength analysis ─────────────────────────────────────────────────────────
def analyze_password(password: str) -> dict:
    """
    Analyze a password and return a detailed report dict.

    Score bands
    -----------
    0-39   → Weak
    40-59  → Fair
    60-79  → Good
    80-100 → Strong
    """
    score = 0
    feedback = []
    criteria = {}

    # ── Length ──────────────────────────────────────────────────────────────
    length = len(password)
    criteria["length"] = length

    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        feedback.append("❌ Too short — use at least 8 characters (12+ recommended).")

    # ── Character variety ────────────────────────────────────────────────────
    has_lower  = bool(re.search(r"[a-z]", password))
    has_upper  = bool(re.search(r"[A-Z]", password))
    has_digit  = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^\w]", password))

    criteria.update({
        "lowercase":  has_lower,
        "uppercase":  has_upper,
        "digits":     has_digit,
        "symbols":    has_symbol,
    })

    variety_score = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety_score * 12   # up to 48 pts

    if not has_lower:
        feedback.append("❌ Add lowercase letters.")
    if not has_upper:
        feedback.append("❌ Add uppercase letters.")
    if not has_digit:
        feedback.append("❌ Add numbers.")
    if not has_symbol:
        feedback.append("❌ Add special characters (e.g. !@#$%).")

    # ── Penalise common patterns ─────────────────────────────────────────────
    common_patterns = [
        r"(.)\1{2,}",            # repeated chars (aaa, 111)
        r"(012|123|234|345|456|567|678|789|890)",
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
        r"(qwerty|azerty|qwertz|asdf|zxcv)",
    ]
    has_pattern = any(re.search(p, password.lower()) for p in common_patterns)
    if has_pattern:
        score -= 15
        feedback.append("⚠️  Avoid sequential or repeated characters (e.g. 'abc', '111', 'qwerty').")

    # ── Common weak passwords ────────────────────────────────────────────────
    common_passwords = {
        "password", "password1", "123456", "12345678", "qwerty",
        "abc123", "letmein", "monkey", "1234567890", "iloveyou",
        "admin", "welcome", "login", "passw0rd",
    }
    if password.lower() in common_passwords:
        score = 0
        feedback.append("🚫 This is one of the most commonly used passwords — change it immediately!")

    # ── Clamp score ──────────────────────────────────────────────────────────
    score = max(0, min(score, 100))

    # ── Band ─────────────────────────────────────────────────────────────────
    if score < 40:
        band = "Weak"
        band_icon = "🔴"
    elif score < 60:
        band = "Fair"
        band_icon = "🟠"
    elif score < 80:
        band = "Good"
        band_icon = "🟡"
    else:
        band = "Strong"
        band_icon = "🟢"

    if score >= 80 and not feedback:
        feedback.append("✅ Great password! Keep it unique and don't reuse it.")

    return {
        "score":     score,
        "band":      band,
        "band_icon": band_icon,
        "criteria":  criteria,
        "feedback":  feedback,
        "sha256":    hash_password(password, "sha256"),
    }


# ── Pretty printer ────────────────────────────────────────────────────────────
def print_report(password: str, check_breach: bool = False) -> None:
    report = analyze_password(password)
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"

    print("\n" + "=" * 50)
    print(f"  Password Report for: {masked}")
    print("=" * 50)
    print(f"  Strength : {report['band_icon']}  {report['band']}  ({report['score']}/100)")
    print(f"  Length   : {report['criteria']['length']} characters")
    print()

    checks = [
        ("Lowercase letters", report["criteria"]["lowercase"]),
        ("Uppercase letters", report["criteria"]["uppercase"]),
        ("Numbers",           report["criteria"]["digits"]),
        ("Special chars",     report["criteria"]["symbols"]),
    ]
    for label, passed in checks:
        icon = "✅" if passed else "❌"
        print(f"  {icon}  {label}")

    if report["feedback"]:
        print("\n  Suggestions:")
        for tip in report["feedback"]:
            print(f"    {tip}")

    if check_breach:
        print("\n  Checking breach databases…")
        count = check_pwned(password)
        if count == -1:
            print("  ⚠️  Could not reach HaveIBeenPwned API (offline?).")
        elif count == 0:
            print("  ✅  Not found in any known data breach.")
        else:
            print(f"  🚨  Found {count:,} times in known data breaches! Change this password NOW.")

    print(f"\n  SHA-256 hash:")
    print(f"    {report['sha256']}")
    print("=" * 50 + "\n")


# ── CLI entry point ───────────────────────────────────────────────────────────
def main() -> None:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        description="Check the strength of a password using hashlib."
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to check (omit to be prompted securely).",
    )
    parser.add_argument(
        "--breach",
        action="store_true",
        help="Check the password against HaveIBeenPwned breach database.",
    )
    parser.add_argument(
        "--hash",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        default="sha256",
        help="Hashing algorithm to display (default: sha256).",
    )

    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check: ")
    if not password:
        print("No password provided.")
        sys.exit(1)

    print_report(password, check_breach=args.breach)

    if args.hash != "sha256":
        print(f"  {args.hash.upper()} hash: {hash_password(password, args.hash)}\n")


if __name__ == "__main__":
    main()

