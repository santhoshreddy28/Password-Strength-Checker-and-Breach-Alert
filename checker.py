"""
checker.py - Core logic for Password Strength Checker & Breach Alert
"""

import hashlib
import math
import random
import re
import string
import urllib.request
import urllib.error
import os

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMMON_PASSWORDS_FILE = os.path.join(BASE_DIR, "wordlists", "common_passwords.txt")

# ─────────────────────────────────────────────
# LOAD COMMON PASSWORDS BLOCKLIST
# ─────────────────────────────────────────────
def load_common_passwords() -> set:
    """Load common passwords from wordlist file into a set."""
    if not os.path.exists(COMMON_PASSWORDS_FILE):
        return set()
    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}

COMMON_PASSWORDS = load_common_passwords()


# ─────────────────────────────────────────────
# STRENGTH SCORING
# ─────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits."""
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return round(math.log2(charset_size) * len(password), 2)


def check_strength(password: str) -> dict:
    """
    Analyse password and return a detailed strength report.

    Returns:
        {
            score: int (0–100),
            label: str,
            color: str (hex),
            entropy: float,
            feedback: list[str],
            checks: dict
        }
    """
    checks = {
        "length_8":      len(password) >= 8,
        "length_12":     len(password) >= 12,
        "length_16":     len(password) >= 16,
        "has_upper":     bool(re.search(r"[A-Z]", password)),
        "has_lower":     bool(re.search(r"[a-z]", password)),
        "has_digit":     bool(re.search(r"\d", password)),
        "has_special":   bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password)),
        "no_repeats":    not bool(re.search(r"(.)\1{2,}", password)),
        "no_sequential": not bool(re.search(
            r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|"
            r"ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|"
            r"uvw|vwx|wxy|xyz)", password.lower())),
        "not_common":    password.lower() not in COMMON_PASSWORDS,
    }

    score = 0
    score += 10 if checks["length_8"]      else 0
    score += 10 if checks["length_12"]     else 0
    score += 10 if checks["length_16"]     else 0
    score += 15 if checks["has_upper"]     else 0
    score += 15 if checks["has_lower"]     else 0
    score += 15 if checks["has_digit"]     else 0
    score += 15 if checks["has_special"]   else 0
    score += 5  if checks["no_repeats"]    else 0
    score += 5  if checks["no_sequential"] else 0

    # Penalty: common password
    if not checks["not_common"]:
        score = min(score, 10)

    # Clamp
    score = max(0, min(100, score))

    # Label + color
    if score <= 20:
        label, color = "Very Weak",  "#e74c3c"
    elif score <= 40:
        label, color = "Weak",       "#e67e22"
    elif score <= 60:
        label, color = "Moderate",   "#f1c40f"
    elif score <= 80:
        label, color = "Strong",     "#2ecc71"
    else:
        label, color = "Very Strong","#27ae60"

    # Feedback tips
    feedback = []
    if not checks["length_8"]:
        feedback.append("❌ Use at least 8 characters")
    elif not checks["length_12"]:
        feedback.append("⚠️  Aim for 12+ characters for better security")
    elif not checks["length_16"]:
        feedback.append("💡 16+ characters makes it even stronger")
    if not checks["has_upper"]:
        feedback.append("❌ Add uppercase letters (A–Z)")
    if not checks["has_lower"]:
        feedback.append("❌ Add lowercase letters (a–z)")
    if not checks["has_digit"]:
        feedback.append("❌ Add numbers (0–9)")
    if not checks["has_special"]:
        feedback.append("❌ Add special characters (!@#$% etc.)")
    if not checks["no_repeats"]:
        feedback.append("⚠️  Avoid repeated characters (aaa, 111)")
    if not checks["no_sequential"]:
        feedback.append("⚠️  Avoid sequential patterns (abc, 123)")
    if not checks["not_common"]:
        feedback.append("🚨 This is a commonly used password — change it!")
    if not feedback:
        feedback.append("✅ Excellent password!")

    return {
        "score":   score,
        "label":   label,
        "color":   color,
        "entropy": calculate_entropy(password),
        "length":  len(password),
        "feedback": feedback,
        "checks":  checks,
    }


# ─────────────────────────────────────────────
# HIBP BREACH CHECK  (k-anonymity — password never sent)
# ─────────────────────────────────────────────
def check_breach(password: str) -> dict:
    """
    Check password against HaveIBeenPwned using k-anonymity model.
    Only the first 5 chars of the SHA-1 hash are sent to the API.

    Returns:
        { "pwned": bool, "count": int, "error": str|None }
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker-Python"})
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")

        for line in body.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix.upper() == suffix:
                return {"pwned": True, "count": int(count), "error": None}

        return {"pwned": False, "count": 0, "error": None}

    except urllib.error.URLError as e:
        return {"pwned": False, "count": 0, "error": f"Network error: {e.reason}"}
    except Exception as e:
        return {"pwned": False, "count": 0, "error": str(e)}


# ─────────────────────────────────────────────
# PASSWORD GENERATOR
# ─────────────────────────────────────────────
def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
) -> str:
    """Generate a cryptographically strong random password."""
    charset = ""
    required_chars = []

    if use_lower:
        charset += string.ascii_lowercase
        required_chars.append(random.choice(string.ascii_lowercase))
    if use_upper:
        charset += string.ascii_uppercase
        required_chars.append(random.choice(string.ascii_uppercase))
    if use_digits:
        charset += string.digits
        required_chars.append(random.choice(string.digits))
    if use_special:
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        charset += special
        required_chars.append(random.choice(special))

    if not charset:
        charset = string.ascii_letters + string.digits

    # Fill remaining length with random choices
    remaining = length - len(required_chars)
    all_chars = required_chars + [random.choice(charset) for _ in range(remaining)]

    # Shuffle to avoid predictable positions
    random.shuffle(all_chars)
    return "".join(all_chars)


def generate_passphrase(word_count: int = 4) -> str:
    """Generate a memorable passphrase using random words."""
    words = [
        "apple", "bridge", "castle", "dragon", "eagle", "forest", "guitar",
        "harbor", "island", "jungle", "knight", "lemon", "mountain", "noble",
        "ocean", "planet", "queen", "river", "silver", "tiger", "umbrella",
        "violet", "walnut", "xenon", "yellow", "zebra", "anchor", "blizzard",
        "candle", "dagger", "eclipse", "falcon", "glacier", "horizon", "ivory",
        "jaguar", "kettle", "lantern", "marble", "nectar", "opal", "prism",
        "quartz", "raven", "sapphire", "thunder", "ultra", "vortex", "whisper"
    ]
    chosen = random.choices(words, k=word_count)
    separator = random.choice(["-", "_", ".", "!"])
    number = str(random.randint(10, 99))
    return separator.join(chosen) + separator + number
