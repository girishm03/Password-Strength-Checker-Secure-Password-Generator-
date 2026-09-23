"""
Password Strength Checker & Secure Password Generator - Command Line Interface.
Supports both non-interactive script flags and an interactive cybersecurity terminal menu.
"""
import argparse
import sys
import getpass
from core.checker import PasswordChecker
from core.generator import PasswordGenerator


# ANSI color codes for terminal formatting
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def print_banner():
    banner = f"""{Style.CYAN}{Style.BOLD}
========================================================================
   ____   _    ____ ____  _    _  ___  ____  ____  
  |  _ \\ / \\  / ___/ ___|| |  | |/ _ \\|  _ \\|  _ \\ 
  | |_) / _ \\ \\___ \\___ \\| |/\\| | | | | |_) | | | |
  |  __/ ___ \\ ___) |__) \\  /\\  / |_| |  _ <| |_| |
  |_| /_/   \\_\\____/____/ \\/  \\/ \\___/|_| \\_\\____/ 
                                                    
  CYBERSECURITY PASSWORD ANALYZER & SECURE GENERATOR
========================================================================{Style.RESET}"""
    print(banner)


def colorize_rating(rating: str) -> str:
    if rating == "Very Strong":
        return f"{Style.GREEN}{Style.BOLD}[ {rating.upper()} ]{Style.RESET}"
    elif rating == "Strong":
        return f"{Style.GREEN}[ {rating.upper()} ]{Style.RESET}"
    elif rating == "Fair":
        return f"{Style.YELLOW}[ {rating.upper()} ]{Style.RESET}"
    elif rating == "Weak":
        return f"{Style.RED}[ {rating.upper()} ]{Style.RESET}"
    else:
        return f"{Style.BG_RED}{Style.WHITE}{Style.BOLD}[ {rating.upper()} ]{Style.RESET}"


def display_analysis_report(analysis):
    print("\n" + f"{Style.BOLD}--- PASSWORD SECURITY AUDIT REPORT ---{Style.RESET}")
    print(f"Overall Rating:       {colorize_rating(analysis.rating)}")
    print(f"Security Score:       {Style.BOLD}{analysis.score}/100{Style.RESET}")
    print(f"Shannon Entropy:      {Style.CYAN}{analysis.entropy.entropy_bits} bits{Style.RESET}")
    print(f"Character Pool Size:  {analysis.entropy.pool_size} possible characters")
    print(f"Password Length:      {analysis.length} characters")

    # NIST compliance
    if analysis.nist_compliant:
        print(f"NIST SP 800-63B:      {Style.GREEN}COMPLIANT (Passes baseline requirements){Style.RESET}")
    else:
        print(f"NIST SP 800-63B:      {Style.RED}NON-COMPLIANT (Fails security criteria){Style.RESET}")

    # Breach status
    if analysis.is_breached:
        print(f"Breach Status (HIBP): {Style.RED}{Style.BOLD}EXPOSED! {analysis.breach_status_message}{Style.RESET}")
    else:
        print(f"Breach Status (HIBP): {Style.GREEN}{analysis.breach_status_message}{Style.RESET}")

    # Character composition
    print(f"\n{Style.BOLD}Character Composition:{Style.RESET}")
    counts = analysis.char_counts
    print(f"  - Lowercase: {counts['lower']} | Uppercase: {counts['upper']} | Digits: {counts['digits']} | Symbols: {counts['symbols']} | Spaces: {counts['spaces']}")

    # Crack time estimations
    print(f"\n{Style.BOLD}Estimated Time to Crack (Brute Force):{Style.RESET}")
    for key, item in analysis.entropy.crack_times.items():
        print(f"  * {item.scenario:<30} : {Style.YELLOW}{item.formatted}{Style.RESET}")
        print(f"    {Style.DIM}({item.rate_desc}){Style.RESET}")

    # Vulnerability findings
    if analysis.vulnerabilities:
        print(f"\n{Style.BOLD}Detected Vulnerabilities ({len(analysis.vulnerabilities)}):{Style.RESET}")
        for v in analysis.vulnerabilities:
            color = Style.RED if v.severity == "HIGH" else (Style.YELLOW if v.severity == "MEDIUM" else Style.CYAN)
            print(f"  [{color}{v.severity}{Style.RESET}] {Style.BOLD}{v.title}{Style.RESET}: {v.description}")

    # Recommendations
    if analysis.suggestions:
        print(f"\n{Style.BOLD}Security Recommendations:{Style.RESET}")
        for s in analysis.suggestions:
            print(f"  -> {s}")
    print("--------------------------------------\n")


def interactive_mode():
    print_banner()
    while True:
        print(f"{Style.BOLD}Main Menu:{Style.RESET}")
        print("  1. Check Password Strength (Live input)")
        print("  2. Generate Secure Random Password")
        print("  3. Generate Memorable Passphrase (Diceware/XKCD)")
        print("  4. Generate Numeric PIN")
        print("  5. Generate Formatted Token / License Key")
        print("  6. Exit")

        choice = input(f"\n{Style.CYAN}Select an option (1-6): {Style.RESET}").strip()

        if choice == "1":
            print(f"\n{Style.DIM}Tip: You can press Enter after typing or use hidden input.{Style.RESET}")
            mask_choice = input("Mask password input on screen? (y/n, default: n): ").strip().lower()
            if mask_choice == "y":
                pw = getpass.getpass("Enter password to analyze: ")
            else:
                pw = input("Enter password to analyze: ")

            check_hibp = input("Query HaveIBeenPwned API for breach leaks? (y/n, default: y): ").strip().lower() != "n"
            print(f"{Style.DIM}Analyzing security profile...{Style.RESET}")
            analysis = PasswordChecker.analyze(pw, check_breach=check_hibp)
            display_analysis_report(analysis)

        elif choice == "2":
            print(f"\n{Style.BOLD}--- Secure Password Generator ---{Style.RESET}")
            try:
                length_str = input("Length (default: 16): ").strip()
                length = int(length_str) if length_str else 16
            except ValueError:
                length = 16

            no_symbols = input("Exclude symbols? (y/n, default: n): ").strip().lower() == "y"
            no_digits = input("Exclude numbers? (y/n, default: n): ").strip().lower() == "y"
            exclude_ambig = input("Exclude ambiguous characters (l, 1, I, O, 0)? (y/n, default: y): ").strip().lower() != "n"

            gen = PasswordGenerator.generate_random_password(
                length=length,
                use_symbols=not no_symbols,
                use_digits=not no_digits,
                exclude_ambiguous=exclude_ambig,
            )

            print(f"\n{Style.GREEN}{Style.BOLD}Generated Password:{Style.RESET} {gen.password}")
            print(f"Entropy: {Style.CYAN}{gen.entropy_bits} bits{Style.RESET} | Rating: {colorize_rating(gen.rating)}\n")

        elif choice == "3":
            print(f"\n{Style.BOLD}--- Memorable Passphrase Generator ---{Style.RESET}")
            try:
                words_str = input("Number of words (default: 5): ").strip()
                num_words = int(words_str) if words_str else 5
            except ValueError:
                num_words = 5

            sep = input("Separator character (default: '-'): ").strip()
            separator = sep if sep else "-"

            add_num = input("Include random digits? (y/n, default: y): ").strip().lower() != "n"
            add_sym = input("Include random symbol? (y/n, default: n): ").strip().lower() == "y"

            gen = PasswordGenerator.generate_passphrase(
                num_words=num_words,
                separator=separator,
                include_number=add_num,
                include_symbol=add_sym,
            )

            print(f"\n{Style.GREEN}{Style.BOLD}Generated Passphrase:{Style.RESET} {gen.password}")
            print(f"Entropy: {Style.CYAN}{gen.entropy_bits} bits{Style.RESET} | Rating: {colorize_rating(gen.rating)}\n")

        elif choice == "4":
            try:
                len_str = input("PIN Length (default: 6): ").strip()
                length = int(len_str) if len_str else 6
            except ValueError:
                length = 6
            gen = PasswordGenerator.generate_pin(length=length)
            print(f"\n{Style.GREEN}{Style.BOLD}Generated PIN:{Style.RESET} {gen.password} (Entropy: {gen.entropy_bits} bits)\n")

        elif choice == "5":
            gen = PasswordGenerator.generate_formatted_token()
            print(f"\n{Style.GREEN}{Style.BOLD}Generated Token:{Style.RESET} {gen.password} (Entropy: {gen.entropy_bits} bits)\n")

        elif choice == "6":
            print(f"\n{Style.CYAN}Exiting. Stay secure!{Style.RESET}\n")
            sys.exit(0)
        else:
            print(f"{Style.RED}Invalid option. Please choose 1-6.{Style.RESET}\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker & Cryptographically Secure Generator"
    )
    parser.add_argument("-c", "--check", type=str, help="Password string to analyze")
    parser.add_argument("--no-breach", action="store_true", help="Skip HaveIBeenPwned API network check")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate a secure password")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols from generated password")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits from generated password")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous chars (1, l, I, 0, O)")
    parser.add_argument("--passphrase", action="store_true", help="Generate a Diceware/XKCD multi-word passphrase")
    parser.add_argument("--words", type=int, default=5, help="Number of words in passphrase (default: 5)")
    parser.add_argument("--separator", type=str, default="-", help="Passphrase delimiter (default: '-')")
    parser.add_argument("--pin", action="store_true", help="Generate a numeric PIN")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive terminal menu")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.check is not None:
        analysis = PasswordChecker.analyze(args.check, check_breach=not args.no_breach)
        display_analysis_report(analysis)
    elif args.passphrase:
        gen = PasswordGenerator.generate_passphrase(
            num_words=args.words, separator=args.separator
        )
        print(f"Generated Passphrase: {gen.password} ({gen.entropy_bits} bits entropy, {gen.rating})")
    elif args.pin:
        gen = PasswordGenerator.generate_pin(length=args.length if args.length != 16 else 6)
        print(f"Generated PIN: {gen.password} ({gen.entropy_bits} bits entropy)")
    elif args.generate:
        gen = PasswordGenerator.generate_random_password(
            length=args.length,
            use_symbols=not args.no_symbols,
            use_digits=not args.no_digits,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        print(f"Generated Password: {gen.password} ({gen.entropy_bits} bits entropy, {gen.rating})")
    else:
        # Default to interactive mode if no arguments are provided
        interactive_mode()


if __name__ == "__main__":
    main()
