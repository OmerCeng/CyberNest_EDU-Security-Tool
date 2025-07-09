def main(): 
    # ANSI color codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    while True:
        print(f"""{CYAN}
{'*' * 80}
{YELLOW}   ██████╗ ██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗
   ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝
   ██████╔╝██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ███████╗
   ██╔═══╝ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ╚════██║
   ██║     ╚██████╔╝██║  ██║███████╗██║  ██║██║ ╚████║███████╗███████║
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{CYAN}
{'*' * 80}
{MAGENTA}{BOLD}{'CyberNest v1.1'.center(78)}{RESET}
{CYAN}{'*' * 80}{RESET}
""")
        print(f"{BOLD}{GREEN}=========== CyberNest_EDU Security Tool ============{RESET}")
        print(f"{BLUE}1.{RESET} {YELLOW}Port (TCP) Scanner{RESET}")
        print(f"{BLUE}2.{RESET} {CYAN}Phishing Checker{RESET}")
        print(f"{BLUE}3.{RESET} {MAGENTA}Hash Cracker{RESET}")
        print(f"{BLUE}4.{RESET} {GREEN}Password Security Testing Tools{RESET}")
        print(f"{BLUE}5.{RESET} {YELLOW}Social Engineering-Based Custom Wordlist Generator{RESET}")
        print(f"{BLUE}6.{RESET} {WHITE}Help{RESET}")
        print(f"{BLUE}0.{RESET} {RED}Exit{RESET}")

        choice = input(f"{BOLD}{WHITE}Enter your choice: {RESET}")

        if choice == '1':
            print(f"\n {YELLOW}======== Port Scanner ========{RESET}")
            try:
                from port_scanner import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Port Scanner: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '2':
            print(f"\n {CYAN}======== Phishing Checker ========{RESET}")
            try:
                from phishing_checker import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Phishing Checker: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '3':
            print(f"\n {MAGENTA}======== Hash Cracker ========{RESET}")
            try:
                from hash_cracker import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Hash Cracker: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '4':
            print(f"\n {GREEN}======== Password Security Testing Tools ========{RESET}")
            print(f"{YELLOW}======== Loading libraries... ========{RESET}")
            try:
                from password_checker import run 
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Password Checker: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")
            
        elif choice == '5':
            print(f"\n {YELLOW}======== Create Custom Wordlist ========{RESET}")
            try:
                from password_generator import run 
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Password Generator: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")  

        elif choice == '6':
            print(f"\n {WHITE}======== Help & Information ========{RESET}")
            print(f"""{BOLD}
{YELLOW}1. Port (TCP) Scanner:{RESET} {WHITE}Scans the specified IP address and port range for open ports.{RESET}
   {BLUE}• Features:{RESET} {WHITE}TCP port scanning, service detection, customizable port ranges{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Network reconnaissance, service enumeration{RESET}

{CYAN}2. Phishing Checker:{RESET} {WHITE}Analyzes URLs for potential phishing indicators.{RESET}
   {BLUE}• Features:{RESET} {WHITE}URL pattern analysis, suspicious keyword detection, risk scoring{RESET}
   {BLUE}• Use case:{RESET} {WHITE}URL safety verification, phishing awareness{RESET}

{MAGENTA}3. Hash Cracker:{RESET} {WHITE}Attempts to crack MD5, SHA1, SHA256, and SHA512 hashes.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Multiple hash algorithms, custom wordlists, auto-detection{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Password recovery, hash analysis{RESET}

{GREEN}4. Password Security Testing:{RESET} {WHITE}Tests password strength and performs security analysis.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Strength evaluation, brute-force simulation, ML analysis{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Password policy testing, security awareness{RESET}

{YELLOW}5. Custom Wordlist Generator:{RESET} {WHITE}Creates personalized wordlists for security testing.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Social engineering wordlists, personal info combinations{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Targeted password attacks, social engineering{RESET}

{MAGENTA}📌 CyberNest v1.1 - Educational Security Tool Suite{RESET}
{BLUE}⚠️  Warning:{RESET} {WHITE}This tool is for educational and authorized testing purposes only.{RESET}
{RED}0. Exit:{RESET} {WHITE}Exits the program.{RESET}
""")
            input(f"\n{BOLD}{CYAN}Press Enter to return to the menu...{RESET}")
            continue  

        elif choice == '0':
            print(f"{RED}Exiting...{RESET}")
            break
        else:
            print(f"{RED}❌ Invalid selection! Please choose 0-6.{RESET}")
            input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")
            continue

if __name__ == "__main__":
    main()
