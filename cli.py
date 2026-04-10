"""
cli.py - Command-Line Interface for Password Strength Checker & Breach Alert
Usage:
    python cli.py                  # interactive mode
    python cli.py --check          # check a password
    python cli.py --generate       # generate a strong password
    python cli.py --passphrase     # generate a passphrase
"""

import argparse
import getpass
import sys
from checker import check_strength, check_breach, generate_password, generate_passphrase

# ─────────────────────────────────────────────
# COLOURS (ANSI)
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def coloured(text: str, colour: str) -> str:
    return f"{colour}{text}{C.RESET}"

def strength_colour(label: str) -> str:
    return {
        "Very Weak":   C.RED,
        "Weak":        C.ORANGE,
        "Moderate":    C.YELLOW,
        "Strong":      C.GREEN,
        "Very Strong": C.GREEN,
    }.get(label, C.RESET)

def score_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    colour = C.RED if score <= 20 else C.ORANGE if score <= 40 else C.YELLOW if score <= 60 else C.GREEN
    return f"{colour}[{bar}]{C.RESET} {score}/100"


# ─────────────────────────────────────────────
# DISPLAY RESULTS
# ─────────────────────────────────────────────
def display_strength(result: dict) -> None:
    print()
    print(coloured("─" * 50, C.DIM))
    print(coloured("  🔍 PASSWORD ANALYSIS", C.BOLD))
    print(coloured("─" * 50, C.DIM))

    colour = strength_colour(result["label"])
    print(f"  Strength   : {coloured(result['label'], colour + C.BOLD)}")
    print(f"  Score      : {score_bar(result['score'])}")
    print(f"  Length     : {result['length']} characters")
    print(f"  Entropy    : {result['entropy']} bits")

    print()
    print(coloured("  📋 CHECKLIST", C.BOLD))
    checks = result["checks"]
    items = [
        ("8+ characters",         checks["length_8"]),
        ("12+ characters",        checks["length_12"]),
        ("16+ characters",        checks["length_16"]),
        ("Uppercase letters",     checks["has_upper"]),
        ("Lowercase letters",     checks["has_lower"]),
        ("Numbers",               checks["has_digit"]),
        ("Special characters",    checks["has_special"]),
        ("No repeated chars",     checks["no_repeats"]),
        ("No sequential patterns",checks["no_sequential"]),
        ("Not a common password", checks["not_common"]),
    ]
    for name, passed in items:
        icon   = coloured("✓", C.GREEN) if passed else coloured("✗", C.RED)
        status = coloured(name, C.DIM)
        print(f"    {icon}  {status}")

    print()
    print(coloured("  💡 SUGGESTIONS", C.BOLD))
    for tip in result["feedback"]:
        print(f"    {tip}")

    print(coloured("─" * 50, C.DIM))


def display_breach(result: dict) -> None:
    print()
    print(coloured("  🌐 BREACH CHECK (HaveIBeenPwned)", C.BOLD))
    print(coloured("─" * 50, C.DIM))

    if result["error"]:
        print(f"  {coloured('⚠️  Could not reach API:', C.YELLOW)} {result['error']}")
    elif result["pwned"]:
        count = f"{result['count']:,}"
        print(f"  {coloured('🚨 BREACHED!', C.RED + C.BOLD)} Found {coloured(count, C.RED)} times in data breaches.")
        print(f"  {coloured('→  Do NOT use this password. Change it immediately!', C.RED)}")
    else:
        print(f"  {coloured('✅ Safe!', C.GREEN + C.BOLD)} Not found in any known data breach.")
        print(f"  {coloured('   (This does not guarantee 100% safety)', C.DIM)}")

    print(coloured("─" * 50, C.DIM))


# ─────────────────────────────────────────────
# INTERACTIVE MODE
# ─────────────────────────────────────────────
def interactive_mode() -> None:
    print()
    print(coloured("╔══════════════════════════════════════════════╗", C.CYAN))
    print(coloured("║    🔐 Password Strength Checker & Breach Alert ║", C.CYAN + C.BOLD))
    print(coloured("╚══════════════════════════════════════════════╝", C.CYAN))
    print()

    while True:
        print("  Options:")
        print(f"    {coloured('[1]', C.CYAN)} Check a password")
        print(f"    {coloured('[2]', C.CYAN)} Generate a strong password")
        print(f"    {coloured('[3]', C.CYAN)} Generate a passphrase")
        print(f"    {coloured('[q]', C.DIM)} Quit")
        print()

        choice = input("  Choose option: ").strip().lower()

        if choice == "1":
            password = getpass.getpass("\n  Enter password (hidden): ")
            if not password:
                print(coloured("  ⚠️  No password entered.", C.YELLOW))
                continue

            result = check_strength(password)
            display_strength(result)

            breach_check = input("\n  Run breach check? (y/n): ").strip().lower()
            if breach_check == "y":
                print(coloured("  Checking HaveIBeenPwned...", C.DIM))
                breach = check_breach(password)
                display_breach(breach)

        elif choice == "2":
            try:
                length = int(input("\n  Password length (default 16): ").strip() or "16")
            except ValueError:
                length = 16
            pwd = generate_password(length=length)
            print(f"\n  Generated: {coloured(pwd, C.GREEN + C.BOLD)}")
            print(coloured("  (Copy it to a password manager!)", C.DIM))

            show_analysis = input("\n  Analyse this password? (y/n): ").strip().lower()
            if show_analysis == "y":
                display_strength(check_strength(pwd))

        elif choice == "3":
            phrase = generate_passphrase()
            print(f"\n  Passphrase: {coloured(phrase, C.GREEN + C.BOLD)}")
            print(coloured("  (Memorable and strong — good for master passwords!)", C.DIM))

            show_analysis = input("\n  Analyse this passphrase? (y/n): ").strip().lower()
            if show_analysis == "y":
                display_strength(check_strength(phrase))

        elif choice == "q":
            print(coloured("\n  Goodbye! Stay secure. 🔒\n", C.CYAN))
            sys.exit(0)

        else:
            print(coloured("  Invalid option. Try again.", C.YELLOW))

        print()


# ─────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="🔐 Password Strength Checker & Breach Alert",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--check",      action="store_true", help="Check a password directly")
    parser.add_argument("--generate",   action="store_true", help="Generate a strong password")
    parser.add_argument("--passphrase", action="store_true", help="Generate a passphrase")
    parser.add_argument("--length",     type=int, default=16,  help="Length for generated password (default: 16)")
    parser.add_argument("--no-breach",  action="store_true",   help="Skip breach check")

    args = parser.parse_args()

    if args.generate:
        pwd = generate_password(length=args.length)
        print(f"\n  Generated Password: {coloured(pwd, C.GREEN + C.BOLD)}\n")
        display_strength(check_strength(pwd))

    elif args.passphrase:
        phrase = generate_passphrase()
        print(f"\n  Passphrase: {coloured(phrase, C.GREEN + C.BOLD)}\n")
        display_strength(check_strength(phrase))

    elif args.check:
        password = getpass.getpass("\n  Enter password (hidden): ")
        result = check_strength(password)
        display_strength(result)
        if not args.no_breach:
            print(coloured("  Checking breach database...", C.DIM))
            breach = check_breach(password)
            display_breach(breach)

    else:
        interactive_mode()


if __name__ == "__main__":
    main()
