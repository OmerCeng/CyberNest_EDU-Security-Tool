
def main(): 
    while True:
        print("\n \n ============ CyberNest_EDU Security Tool ============")
        print("1. Port(tcp) Scanner")
        print("2. Phishing Checker")
        print("3. Hash Cracker")
        print("4. Password Security Testing Tools")
        print("5. Social Engineering-Based Custom Wordlist Generator")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            print("\n ========Port Scanner========")
            from port_scanner import run
            run()

        if choice == '2':
            print("\n ========Phishing Checker========")
            from phishing_checker import run
            run()

        if choice == '3':
            print("\n ========Hash Cracker========")
            from hash_cracker import run
            run()

        if choice == '4':
            print("\n ========Password Security Testing Tools========")
            print("========Loading libraries...========")
            from password_checker import run 
            run()

        if choice == '5':
            print("\n ========Create Custom Wordlist========")
            from password_generator import run 
            run()    
        elif choice == '0':
            print("Exiting...")
            break
       # else:
        #    print("Invalid selection!")

if __name__ == "__main__":
    main()
