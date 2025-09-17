import itertools
import os

def get_user_info():
    print("Please enter the following information (you can leave it blank):")
    name = input("Name: ").strip()
    surname = input("Surname: ").strip()
    birth_year = input("Birth Year: ").strip()
    pet_name = input("Pet Name: ").strip()
    fav_team = input("Favorite Team: ").strip()
    hometown = input("Place of Birth: ").strip()
    profession = input("Occupation: ").strip()

    base_words = [name, surname, birth_year, pet_name, fav_team, hometown, profession]
    return [word for word in base_words if word]

def generate_combinations(words, max_length=3):
    combinations = set()
    for i in range(1, max_length + 1):
        for combo in itertools.permutations(words, i):
            base = ''.join(combo)
            combinations.update([
                base,
                base + "123",
                base + "!",
                base.capitalize(),
                base.upper()
            ])
    return combinations

def save_to_file(wordlist, filepath="wordlist/custom_wordlist.txt"):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        for word in sorted(wordlist):
            f.write(word + "\n")
    print(f"\n✔ Wordlist successfully saved to'{filepath}'! ({len(wordlist)} words)")

def run():
    user_words = get_user_info()
    if not user_words:
        print("⚠ Not enough information entered. Exiting...")
        return

    wordlist = generate_combinations(user_words)
    save_to_file(wordlist)

def run_cli(name=None, surname=None, birthdate=None, pet=None, team=None, hometown=None, profession=None):
    """CLI version for command line usage"""
    try:
        print(f"[+] Generating custom wordlist...")
        
        # Collect provided information
        user_words = []
        if name:
            user_words.append(name)
            print(f"[+] Name: {name}")
        if surname:
            user_words.append(surname)
            print(f"[+] Surname: {surname}")
        if birthdate:
            user_words.append(birthdate)
            print(f"[+] Birth year: {birthdate}")
        if pet:
            user_words.append(pet)
            print(f"[+] Pet name: {pet}")
        if team:
            user_words.append(team)
            print(f"[+] Favorite team: {team}")
        if hometown:
            user_words.append(hometown)
            print(f"[+] Hometown: {hometown}")
        if profession:
            user_words.append(profession)
            print(f"[+] Profession: {profession}")
        
        if not user_words:
            print(f"[-] No information provided. Need at least one parameter.")
            print(f"[+] Usage: cybernest wordlist -n John -s Doe -b 1990")
            import sys
            sys.exit(1)
        
        print(f"[+] Base words: {len(user_words)}")
        print("-" * 50)
        
        # Generate combinations
        wordlist = generate_combinations(user_words)
        
        # Save to file
        filepath = "wordlist/custom_wordlist.txt"
        save_to_file(wordlist, filepath)
        
        print(f"[+] Generated {len(wordlist)} password combinations")
        print(f"[+] Wordlist saved to: {filepath}")
        
        # Show some examples
        sample_words = list(sorted(wordlist))[:10]
        print(f"[+] Sample passwords:")
        for word in sample_words:
            print(f"  • {word}")
        
        if len(wordlist) > 10:
            print(f"  ... and {len(wordlist) - 10} more")
            
    except Exception as e:
        print(f"[-] Error: {e}")
        import sys
        sys.exit(1)

if __name__ == "__main__":
    run()
