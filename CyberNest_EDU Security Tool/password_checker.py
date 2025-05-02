import time
import itertools
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from joblib import dump, load
import os

def brute_force_crack(password, charset):
    start_time = time.time()
    max_length = 4
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            attempt_password = ''.join(attempt)
            if attempt_password == password:
                end_time = time.time()
                return True, end_time - start_time
    end_time = time.time()
    return False, end_time - start_time

def password_strength(password):
    score = 0
    recommendations = []

    if len(password) >= 8:
        score += 1
    else:
        recommendations.append("Make your password at least 8 characters long.")

    if any(c.islower() for c in password):
        score += 1
    else:
        recommendations.append("Add lowercase letters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        recommendations.append("Add uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        recommendations.append("Add numbers.")

    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        score += 1
    else:
        recommendations.append("Use special characters (e.g., !, @, #).")

    return score, recommendations

def extract_features(password):
    features = []
    features.append(len(password))
    features.append(any(c.islower() for c in password))
    features.append(any(c.isupper() for c in password))
    features.append(any(c.isdigit() for c in password))
    features.append(any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password))
    return features


MODEL_PATH = "models/model.joblib"
ENCODER_PATH = "models/encoder.joblib"
def train_or_load_model():
  if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
        model = load(MODEL_PATH)
        label_encoder = load(ENCODER_PATH)
        return model, label_encoder

  else: # Eğitim verisi ve modeli oluştur
        data = {
            'password': [
                '12345', 'password', 'admin', 'P@ssw0rd', 'hello123', 'StrongPass!2',
                'letmein', 'qwerty', 'SuperSecret99!', 'simple', 'complexPASS#123'
            ],
            'strength': [
                'Weak', 'Weak', 'Weak', 'Strong', 'Medium', 'Strong',
                'Weak', 'Weak', 'Strong', 'Weak', 'Strong'
            ]
        }

        df = pd.DataFrame(data)
        X = [extract_features(pw) for pw in df['password']]
        y = df['strength']

        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)

        X_train, _, y_train, _ = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

        model = RandomForestClassifier()
        model.fit(X_train, y_train)
        os.makedirs("models", exist_ok=True)

        # MODELİ KAYDET
        dump(model, "model.joblib")
        dump(label_encoder, "encoder.joblib")
        return model, label_encoder

def run():  # <-- BU VAR
    model, label_encoder = train_or_load_model()

    print("""
    ==== Password Tools ====
    1. Crack the Password via Brute Force
    2. Analyze Password Strength (Heuristic)
    3. Password Strength Estimation (Machine Learning)
    0. Return to Menu
    """)

    choice = input("Select an option: ")

    if choice == '1':
        password = input("Enter the password to be cracked (up to 4 characters): ")
        charset = input("Enter the character set to be used (e.g., abc123): ")
        success, duration = brute_force_crack(password, charset)
        if success:
            print(f"Password found successfully! Duration:: {duration:.2f} seconds.")
        else:
            print("Password not found.")
    elif choice == '2':
        password = input("Enter the password to be analyze: ")
        score, recommendations = password_strength(password)
        print(f"Password Strength Score: {score}/5")
        if recommendations:
            print("Suggestions:")
            for rec in recommendations:
                print(f"- {rec}")
    elif choice == '3':
        password = input("Enter the password to be guessed: ")
        features = [extract_features(password)]
        prediction = model.predict(features)
        strength = label_encoder.inverse_transform(prediction)
        print(f"Machine Learning Prediction {strength[0]}")
    elif choice == '0':
        return
    else:
        print("Invalid Selection!")
