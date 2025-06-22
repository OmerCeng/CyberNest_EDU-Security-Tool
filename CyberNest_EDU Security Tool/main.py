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
{MAGENTA}{BOLD}{'CyberNest v1.0'.center(78)}{RESET}
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
            from port_scanner import run
            run()  

        elif choice == '2':
            print(f"\n {CYAN}======== Phishing Checker ========{RESET}")
            from phishing_checker import run
            run()  

        elif choice == '3':
            print(f"\n {MAGENTA}======== Hash Cracker ========{RESET}")
            from hash_cracker import run
            run()  

        elif choice == '4':
            print(f"\n {GREEN}======== Password Security Testing Tools ========{RESET}")
            print(f"{YELLOW}======== Loading libraries... ========{RESET}")
            from password_checker import run 
            run()  
        elif choice == '5':
            print(f"\n {YELLOW}======== Create Custom Wordlist ========{RESET}")
            from password_generator import run 
            run()  

        elif choice == '6':
            print(f"\n {WHITE}======== Help ========{RESET}")
            print(f"""{BOLD}
{YELLOW}1. Port (TCP) Scanner:{RESET} {WHITE}Scans the specified IP address and port range for open ports.{RESET}
{CYAN}2. Phishing Checker:{RESET} {WHITE}Checks if a given URL is a phishing site.{RESET}
{MAGENTA}3. Hash Cracker:{RESET} {WHITE}Attempts to crack MD5, SHA1, and similar hashes using a wordlist.{RESET}
{GREEN}4. Password Security Testing Tools:{RESET} {WHITE}Tests password strength and detects weak passwords.{RESET}
{YELLOW}5. Social Engineering-Based Custom Wordlist Generator:{RESET} {WHITE}Generates a custom wordlist based on personal information.{RESET}
{RED}0. Exit:{RESET} {WHITE}Exits the program.{RESET}

{CYAN}Her modülde herhangi bir giriş ekranında 'exit' yazarak ana menüye dönebilirsiniz.{RESET}
""")
            input(f"\n{BOLD}{CYAN}Press Enter to return to the menu...{RESET}")
            continue  

        elif choice == '0':
            print(f"{RED}Exiting...{RESET}")
            break
        # else:
        #     print("Invalid selection!")

if __name__ == "__main__":
    main()
