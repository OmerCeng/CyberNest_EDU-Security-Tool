import hashlib
import os
wordlist_path = "wordlist/wordlist.txt"

def crack_hash(hash_value, wordlist_path, algorithm='md5'):
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as file:
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
                    return False, "Desteklenmeyen algoritma"

                if hashed == hash_value:
                    return True, word
        return False, None
    except FileNotFoundError:
        return False, "Wordlist dosyası bulunamadı!"


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
        print(f"Algorithm deteted: {algorithm.upper()}")

    else:
        print("Invalid Selection!")
        return

    found, result = crack_hash(hash_value, wordlist_path, algorithm)
    if found:
        print(f"Hash match found! Plaintext: {result}")
    else:
        print(f"Hash could not be cracked. {result if result else ''}")
