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
{MAGENTA}{BOLD}{'CyberNest v1.4'.center(78)}{RESET}
{CYAN}{'*' * 80}{RESET}
""")
        print(f"{BOLD}{GREEN}=========== CyberNest Security Tool ============{RESET}")
        print(f"{BLUE}1.{RESET} {YELLOW}Port Scanner{RESET}")
        print(f"{BLUE}2.{RESET} {CYAN}Phishing Checker{RESET}")
        print(f"{BLUE}3.{RESET} {MAGENTA}Hash Cracker{RESET}")
        print(f"{BLUE}4.{RESET} {GREEN}Password Security Testing Tools{RESET}")
        print(f"{BLUE}5.{RESET} {YELLOW}Social Engineering-Based Custom Wordlist Generator{RESET}")
        print(f"{BLUE}6.{RESET} {CYAN}Web Directory Scanner{RESET}")
        print(f"{BLUE}7.{RESET} {MAGENTA}ARP Network Scanner{RESET}")
        print(f"{BLUE}8.{RESET} {RED}SQL Injection Tester{RESET}")
        print(f"{BLUE}9.{RESET} {GREEN}XSS Vulnerability Scanner{RESET}")
        print(f"{BLUE}10.{RESET} {WHITE}Help{RESET}")
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
            print(f"\n {CYAN}======== Web Directory Scanner ========{RESET}")
            try:
                from web_directory_scanner import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading Web Directory Scanner: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '7':
            print(f"\n {MAGENTA}======== ARP Network Scanner ========{RESET}")
            try:
                from arp_scanner import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading ARP Scanner: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '8':
            print(f"\n {RED}======== SQL Injection Tester ========{RESET}")
            try:
                from sql_injection_tester import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading SQL Injection Tester: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '9':
            print(f"\n {GREEN}======== XSS Vulnerability Scanner ========{RESET}")
            try:
                from xss_vulnerability_scanner import run
                run()  
            except Exception as e:
                print(f"{RED}❌ Error loading XSS Vulnerability Scanner: {e}{RESET}")
                input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")

        elif choice == '10':
            print(f"\n {WHITE}======== Help & Information ========{RESET}")
            print(f"""{BOLD}
{YELLOW}1. Port Scanner:{RESET} {WHITE}Scans the specified IP address and port range for open ports.{RESET}
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

{YELLOW}5. Social Engineering-Based Custom Wordlist Generator:{RESET} {WHITE}Creates personalized wordlists for security testing.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Social engineering wordlists, personal info combinations, mutation algorithms{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Targeted password attacks, social engineering assessments, penetration testing{RESET}

{CYAN}6. Web Directory Scanner:{RESET} {WHITE}Scans for hidden directories, admin panels, and sensitive files.{RESET}
   {BLUE}• Features:{RESET} {WHITE}robots.txt, admin panels, login pages, config files, backup detection{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Web reconnaissance, security assessment, penetration testing{RESET}

{MAGENTA}7. ARP Network Scanner:{RESET} {WHITE}Discovers devices on the local network with IP and MAC addresses.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Network device discovery, MAC address vendor identification, hostname resolution{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Network reconnaissance, device inventory, security assessment{RESET}

{RED}8. SQL Injection Tester:{RESET} {WHITE}Tests web applications for SQL injection vulnerabilities.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Error-based, Union-based, Boolean-based, Time-based injection testing{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Web application security testing, penetration testing{RESET}

{GREEN}9. XSS Vulnerability Scanner:{RESET} {WHITE}Detects Cross-Site Scripting vulnerabilities in web applications.{RESET}
   {BLUE}• Features:{RESET} {WHITE}Reflected, Stored, DOM-based XSS detection, WAF bypass techniques{RESET}
   {BLUE}• Use case:{RESET} {WHITE}Web application security testing, OWASP Top 10 compliance{RESET}

{MAGENTA}📌 CyberNest v1.4 - Security Tool Suite{RESET}
{RED}0. Exit:{RESET} {WHITE}Exits the program.{RESET}
""")
            input(f"\n{BOLD}{CYAN}Press Enter to return to the menu...{RESET}")
            continue  

        elif choice == '0':
            print(f"{RED}Exiting...{RESET}")
            break
        else:
            print(f"{RED}❌ Invalid selection! Please choose 0-10.{RESET}")
            input(f"{BOLD}{CYAN}Press Enter to continue...{RESET}")
            continue

if __name__ == "__main__":
    main()
