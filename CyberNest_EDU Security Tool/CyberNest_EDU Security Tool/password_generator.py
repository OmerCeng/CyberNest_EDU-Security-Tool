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
