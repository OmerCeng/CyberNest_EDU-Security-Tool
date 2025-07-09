import hashlib
import os

def crack_hash(hash_value, wordlist_path, algorithm='md5'):
    # Get the current directory of the script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    full_wordlist_path = os.path.join(current_dir, wordlist_path)
    
    try:
        with open(full_wordlist_path, 'r', encoding='utf-8') as file:
            for word in file:
                word = word.strip()
                if algorithm == 'md5':
                    hashed = hashlib.md5(word.encode()).hexdigest()
                elif algorithm == 'sha1':
                    hashed = hashlib.sha1(word.encode()).hexdigest()
                elif algorithm == 'sha256':
                    hashed = hashlib.sha256(word.encode()).hexdigest()
                elif algorithm == 'sha512':
                    hashed = hashlib.sha512(word.encode()).hexdigest()
                else:
                    return False, "Unsupported algorithm"

                if hashed == hash_value:
                    return True, word
        return False, None
    except FileNotFoundError:
        return False, f"Wordlist file not found at: {full_wordlist_path}"


def detect_algorithm_by_length(hash_value):
    length = len(hash_value)
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    elif length == 128:
        return 'sha512'
    else:
        return None


def run():
    wordlist_path = "wordlist/wordlist.txt"
    
    print("""
==== Hash Cracker Menu ====
1. Select Algorithm Manually
2. Automatically Detect Algorithm Based on Hash
0. Return to Menu
""")
    mode = input("Enter a choice: ")

    if mode == '0':
        return


    if mode == '1':
        print("""
    1. MD5
    2. SHA1
    3. SHA256
    4. SHA512
    """)
        algo_choice = input("Select Algorithm: ")
        algorithms = {'1': 'md5', '2': 'sha1', '3': 'sha256', '4': 'sha512'}
        hash_value = input("Enter target hash ")

        algorithm = algorithms.get(algo_choice)


        if not algorithm:
            print("Invalid algorithm selection!")
            return
        
    elif mode == '2':
        hash_value = input("Enter target hash: ")

        algorithm = detect_algorithm_by_length(hash_value)
        if not algorithm:
            print("Algorithm could not be detected. Please select manually.")
            return
        print(f"Algorithm detected: {algorithm.upper()}")

    else:
        print("Invalid Selection!")
        return

    found, result = crack_hash(hash_value, wordlist_path, algorithm)
    print(f"\n{'='*50}")
    if found:
        print(f"✅ Hash cracked successfully!")
        print(f"🔓 Plaintext: {result}")
        print(f"🔍 Algorithm: {algorithm.upper()}")
    else:
        print(f"❌ Hash could not be cracked.")
        print(f"ℹ️  {result if result else 'Try using a different wordlist or algorithm.'}")
    print(f"{'='*50}\n")
