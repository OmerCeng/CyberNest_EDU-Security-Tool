#!/usr/bin/env python3

import argparse
import sys
import os

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

def display_cli_logo():
    """Display CyberNest logo for CLI mode"""
    print(f"""{CYAN}
{'*' * 80}
{YELLOW}   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ███████╗   ██║   
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ╚════██║   ██║   
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████║   ██║   
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   {CYAN}
{'*' * 80}
{MAGENTA}{BOLD}{'CyberNest v1.4 - Professional Penetration Testing Toolkit'.center(78)}{RESET}
{CYAN}{'*' * 80}{RESET}
""")

def display_interactive_menu():
    """Interactive menu system (original functionality)"""
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
{YELLOW}   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗████████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  ███████╗   ██║   
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ╚════██║   ██║   
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████║   ██║   
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   {CYAN}
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

def setup_command_line_parser():
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        prog='cybernest',
        description='CyberNest Security Tool Suite v1.4 - Professional Penetration Testing Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage='cybernest [-h] [--help] [-menu] [--menu] {portscan,xss,hashcrack,sqli,phishing,wordlist,password,dirscan,arpscan} ...'
    )
    
    # Menu mode flag
    parser.add_argument('-menu', '--menu', action='store_true', 
                       help='Launch interactive menu mode')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available security tools')
    
    # Port Scanner
    port_parser = subparsers.add_parser('portscan', help='TCP Port Scanner')
    port_parser.add_argument('target', help='Target IP address or hostname')
    port_parser.add_argument('-p', '--ports', default='1-1000', 
                           help='Port range (e.g., 1-1000, 80,443,8080)')
    port_parser.add_argument('-t', '--threads', type=int, default=100, 
                           help='Number of threads (default: 100)')
    
    # XSS Scanner
    xss_parser = subparsers.add_parser('xss', help='XSS Vulnerability Scanner')
    xss_parser.add_argument('url', help='Target URL to test')
    xss_parser.add_argument('--payloads', type=int, default=10, 
                          help='Number of payloads to test (default: 10)')
    xss_parser.add_argument('--forms', action='store_true',
                          help='Test all forms on the page')
    
    # Hash Cracker
    hash_parser = subparsers.add_parser('hashcrack', help='Hash Cracking Tool')
    hash_parser.add_argument('hash', help='Hash value to crack')
    hash_parser.add_argument('-w', '--wordlist', default='wordlist/wordlist.txt',
                           help='Wordlist file path')
    hash_parser.add_argument('-a', '--algorithm', 
                           choices=['md5', 'sha1', 'sha256', 'sha512', 'auto'],
                           default='auto', help='Hash algorithm')
    
    # SQL Injection Tester
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Tester')
    sqli_parser.add_argument('url', help='Target URL to test')
    sqli_parser.add_argument('--forms', action='store_true',
                           help='Test all forms on the page')
    sqli_parser.add_argument('--param', help='Specific parameter to test')
    
    # Phishing Checker
    phish_parser = subparsers.add_parser('phishing', help='Phishing URL Checker')
    phish_parser.add_argument('url', help='URL to check for phishing')
    
    # Password Generator
    wordlist_parser = subparsers.add_parser('wordlist', help='Custom Wordlist Generator')
    wordlist_parser.add_argument('-n', '--name', help='Target name')
    wordlist_parser.add_argument('-s', '--surname', help='Target surname')
    wordlist_parser.add_argument('-b', '--birthdate', help='Birth date (YYYY)')
    wordlist_parser.add_argument('-p', '--pet', help='Pet name')
    wordlist_parser.add_argument('-t', '--team', help='Favorite team')
    wordlist_parser.add_argument('--hometown', help='Hometown')
    wordlist_parser.add_argument('--profession', help='Profession')
    
    # Password Checker
    password_parser = subparsers.add_parser('password', help='Password Security Checker')
    password_parser.add_argument('password', help='Password to analyze')
    password_parser.add_argument('-m', '--mode', choices=['analyze', 'ml', 'brute'], 
                               default='analyze', help='Analysis mode')
    
    # Web Directory Scanner
    dirscan_parser = subparsers.add_parser('dirscan', help='Web Directory Scanner')
    dirscan_parser.add_argument('url', help='Target website URL')
    dirscan_parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    dirscan_parser.add_argument('-t', '--threads', type=int, default=20,
                               help='Number of threads (default: 20)')
    
    # ARP Scanner
    arp_parser = subparsers.add_parser('arpscan', help='ARP Network Scanner')
    arp_parser.add_argument('network', help='Network range (e.g., 192.168.1.0/24)')
    
    return parser

def setup_detailed_help_parser():
    """Setup command line argument parser with detailed examples"""
    parser = argparse.ArgumentParser(
        description='CyberNest Security Tool Suite v1.4 - Professional Penetration Testing Toolkit',
        epilog='''
═══════════════════════════════════════════════════════════════════════════════
                            🛡️  CYBERNEST USAGE EXAMPLES  🛡️                            
═══════════════════════════════════════════════════════════════════════════════

🔷 INTERACTIVE MENU MODE:
  cybernest -menu                                    # Launch full interactive menu

🔷 PORT SCANNING:
  cybernest portscan 192.168.1.1                    # Scan common ports
  cybernest portscan 192.168.1.1 -p 1-1000         # Scan ports 1-1000
  cybernest portscan 192.168.1.1 -p 22,80,443      # Scan specific ports
  cybernest portscan 192.168.1.0/24 -p 22          # Scan subnet for SSH

🔷 XSS VULNERABILITY SCANNING:
  cybernest xss http://example.com/search.php       # Test GET parameter XSS
  cybernest xss http://example.com/login.php        # Test form-based XSS
  cybernest xss https://target.com/page?q=test      # Test specific parameter

🔷 HASH CRACKING:
  cybernest hashcrack d41d8cd98f00b204e9800998ecf8427e    # Crack MD5 hash
  cybernest hashcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  # SHA256
  cybernest hashcrack aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f  # SHA256

🔷 SQL INJECTION TESTING:
  cybernest sqli http://example.com/login.php       # Test login form for SQLi
  cybernest sqli http://shop.com/product.php?id=1   # Test GET parameter SQLi
  cybernest sqli https://site.com/search.php        # Test search functionality

🔷 PHISHING URL DETECTION:
  cybernest phishing http://suspicious-site.com     # Check if URL is phishing
  cybernest phishing https://fake-bank.org          # Verify legitimate bank site
  cybernest phishing http://phishing-test.com       # Test suspicious domains

🔷 CUSTOM WORDLIST GENERATION:
  cybernest wordlist -n John -s Doe                 # Basic name wordlist
  cybernest wordlist -n John -s Doe -b 1990         # Add birth year variations
  cybernest wordlist -n Alice -s Smith -b 1985 -c TechCorp  # Add company name

🔷 PASSWORD SECURITY ANALYSIS:
  cybernest password mypassword123 -m analyze       # Analyze password strength
  cybernest password "P@ssw0rd!" -m analyze         # Check complex password
  cybernest password generate -l 16                 # Generate 16-char password

🔷 WEB DIRECTORY SCANNING:
  cybernest dirscan http://example.com              # Scan with default wordlist
  cybernest dirscan http://example.com -t 20        # Use 20 threads
  cybernest dirscan https://target.com -w custom.txt # Use custom wordlist

🔷 ARP NETWORK SCANNING:
  cybernest arpscan 192.168.1.0/24                 # Scan local network
  cybernest arpscan 10.0.0.0/24                    # Scan different subnet
  cybernest arpscan 172.16.1.0/24                  # Corporate network scan

═══════════════════════════════════════════════════════════════════════════════
📚 DOCS: Each tool has detailed help - try 'cybernest portscan --help'
⚡ FAST: All tools support concurrent/threaded scanning for speed
🔒 SAFE: Educational purposes only - always get permission before testing
═══════════════════════════════════════════════════════════════════════════════
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Copy all arguments from main parser
    # Menu mode flag
    parser.add_argument('-menu', '--menu', action='store_true', 
                       help='Launch interactive menu mode')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available security tools')
    
    # Port Scanner
    port_parser = subparsers.add_parser('portscan', help='TCP Port Scanner')
    port_parser.add_argument('target', help='Target IP address or hostname')
    port_parser.add_argument('-p', '--ports', default='1-1000', 
                           help='Port range (e.g., 1-1000, 80,443,8080)')
    port_parser.add_argument('-t', '--threads', type=int, default=100, 
                           help='Number of threads (default: 100)')
    
    # XSS Scanner
    xss_parser = subparsers.add_parser('xss', help='XSS Vulnerability Scanner')
    xss_parser.add_argument('url', help='Target URL to test')
    xss_parser.add_argument('--payloads', type=int, default=10, 
                          help='Number of payloads to test (default: 10)')
    xss_parser.add_argument('--forms', action='store_true',
                          help='Test all forms on the page')
    
    # Hash Cracker
    hash_parser = subparsers.add_parser('hashcrack', help='Hash Cracking Tool')
    hash_parser.add_argument('hash', help='Hash value to crack')
    hash_parser.add_argument('-w', '--wordlist', default='wordlist/wordlist.txt',
                           help='Wordlist file path')
    hash_parser.add_argument('-a', '--algorithm', 
                           choices=['md5', 'sha1', 'sha256', 'sha512', 'auto'],
                           default='auto', help='Hash algorithm')
    
    # SQL Injection Tester
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Tester')
    sqli_parser.add_argument('url', help='Target URL to test')
    sqli_parser.add_argument('--forms', action='store_true',
                           help='Test all forms on the page')
    sqli_parser.add_argument('--param', help='Specific parameter to test')
    
    # Phishing Checker
    phish_parser = subparsers.add_parser('phishing', help='Phishing URL Checker')
    phish_parser.add_argument('url', help='URL to check for phishing')
    
    # Password Generator
    wordlist_parser = subparsers.add_parser('wordlist', help='Custom Wordlist Generator')
    wordlist_parser.add_argument('-n', '--name', help='Target name')
    wordlist_parser.add_argument('-s', '--surname', help='Target surname')
    wordlist_parser.add_argument('-b', '--birthdate', help='Birth date (YYYY)')
    wordlist_parser.add_argument('-p', '--pet', help='Pet name')
    wordlist_parser.add_argument('-t', '--team', help='Favorite team')
    wordlist_parser.add_argument('--hometown', help='Hometown')
    wordlist_parser.add_argument('--profession', help='Profession')
    
    # Password Checker
    password_parser = subparsers.add_parser('password', help='Password Security Checker')
    password_parser.add_argument('password', help='Password to analyze')
    password_parser.add_argument('-m', '--mode', choices=['analyze', 'ml', 'brute'], 
                               default='analyze', help='Analysis mode')
    
    # Web Directory Scanner
    dirscan_parser = subparsers.add_parser('dirscan', help='Web Directory Scanner')
    dirscan_parser.add_argument('url', help='Target website URL')
    dirscan_parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    dirscan_parser.add_argument('-t', '--threads', type=int, default=20,
                               help='Number of threads (default: 20)')
    
    # ARP Scanner
    arp_parser = subparsers.add_parser('arpscan', help='ARP Network Scanner')
    arp_parser.add_argument('network', help='Network range (e.g., 192.168.1.0/24)')
    
    return parser

def execute_command(args):
    """Execute the appropriate command based on arguments"""
    # Display CLI logo
    display_cli_logo()
    
    try:
        if args.command == 'portscan':
            print(f"{GREEN}[+] Starting port scan on {args.target}{RESET}")
            print(f"{BLUE}[+] Port range: {args.ports}{RESET}")
            print(f"{BLUE}[+] Threads: {args.threads}{RESET}")
            from port_scanner import run_cli
            run_cli(args.target, args.ports, args.threads)
            
        elif args.command == 'xss':
            print(f"{GREEN}[+] Starting XSS scan on {args.url}{RESET}")
            from xss_vulnerability_scanner import run_cli
            run_cli(args.url, args.payloads, args.forms)
            
        elif args.command == 'hashcrack':
            print(f"{GREEN}[+] Starting hash cracking: {args.hash}{RESET}")
            print(f"{BLUE}[+] Algorithm: {args.algorithm}{RESET}")
            from hash_cracker import run_cli
            run_cli(args.hash, args.wordlist, args.algorithm)
            
        elif args.command == 'sqli':
            print(f"{GREEN}[+] Starting SQL injection test on {args.url}{RESET}")
            from sql_injection_tester import run_cli
            run_cli(args.url, args.forms, args.param)
            
        elif args.command == 'phishing':
            print(f"{GREEN}[+] Checking URL for phishing: {args.url}{RESET}")
            from phishing_checker import run_cli
            run_cli(args.url)
            
        elif args.command == 'wordlist':
            print(f"{GREEN}[+] Generating custom wordlist{RESET}")
            from password_generator import run_cli
            run_cli(args.name, args.surname, args.birthdate, args.pet, 
                   args.team, args.hometown, args.profession)
            
        elif args.command == 'password':
            print(f"{GREEN}[+] Analyzing password security{RESET}")
            from password_checker import run_cli
            run_cli(args.password, args.mode)
            
        elif args.command == 'dirscan':
            print(f"{GREEN}[+] Starting directory scan on {args.url}{RESET}")
            from web_directory_scanner import run_cli
            run_cli(args.url, args.wordlist, args.threads)
            
        elif args.command == 'arpscan':
            print(f"{GREEN}[+] Starting ARP scan on {args.network}{RESET}")
            from arp_scanner import run_cli
            run_cli(args.network)
            
    except ImportError as e:
        print(f"{RED}❌ Error: Module not found - {e}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}❌ Error executing command: {e}{RESET}")
        sys.exit(1)

def main():
    """Main entry point for CyberNest"""
    # Check if help is requested
    if '--help' in sys.argv or '-h' in sys.argv:
        display_cli_logo()
        detailed_parser = setup_detailed_help_parser()
        detailed_parser.print_help()
        return
    
    # If no arguments provided, show basic help with logo
    if len(sys.argv) == 1:
        display_cli_logo()
        parser = setup_command_line_parser()
        parser.print_help()
        return
    
    # Parse command line arguments
    parser = setup_command_line_parser()
    args = parser.parse_args()
    
    # Check for menu mode
    if args.menu:
        display_interactive_menu()
    elif args.command:
        execute_command(args)
    else:
        display_cli_logo()
        parser.print_help()

if __name__ == "__main__":
    main()
