import hashlib
import os
import string
import time

# Chemin vers le dictionnaire partagé du projet (data/dictionnaire.txt)
CHEMIN_DICTIONNAIRE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "dictionnaire.txt"
)

# Liste noire de base de mots de passe courants (Cas Standard)
COMMON_PASSWORDS_BLACKLIST = {
    "password", "123456", "12345678", "123456789", "qwerty", "admin",
    "welcome", "P@ssword", "P@ssword123", "P@ssw0rd2026", "azerty", "superman",
    "root", "monkey", "letmein", "trustno1", "admin123"
}

# Dictionnaire pour la simulation de blocage temporaire (Rate Limiting / Force brute en ligne)
ATTEMPT_TRACKER = {}

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 30  # secondes


def charger_blacklist_dictionnaire():
    """
    Charge et combine la liste noire de base avec tous les mots 
    présents dans le fichier 'dictionnaire.txt' du projet.
    """
    blacklist = set(COMMON_PASSWORDS_BLACKLIST)
    if os.path.exists(CHEMIN_DICTIONNAIRE):
        try:
            with open(CHEMIN_DICTIONNAIRE, encoding="utf-8") as fichier:
                for ligne in fichier:
                    mot = ligne.strip().lower()
                    if mot:
                        blacklist.add(mot)
        except Exception:
            pass  # En cas de souci de lecture, on garde la liste de base
    return blacklist


def check_password_policy_cas3(password, min_length=12):
    """
    Politique de sécurité stricte pour le Cas 3 :
    - Exige une longueur minimale (défaut : 12 caractères).
    - Exige la présence de minuscules, majuscules, chiffres et symboles.
    - Rejette automatiquement tout mot de passe présent dans la blacklist ou le dictionnaire.
    """
    errors = []
    
    # 1. Vérification de la longueur minimale (Minimum length of 12)
    if len(password) < min_length:
        errors.append(f"❌ Longueur insuffisante : {len(password)}/{min_length} caractères requis minimum.")
        
    # 2. Vérification de la diversité des caractères
    if not any(c.islower() for c in password):
        errors.append("❌ Doit contenir au moins une lettre minuscule (a-z).")
    if not any(c.isupper() for c in password):
        errors.append("❌ Doit contenir au moins une lettre majuscule (A-Z).")
    if not any(c.isdigit() for c in password):
        errors.append("❌ Doit contenir au moins un chiffre (0-9).")
    if not any(c in string.punctuation for c in password):
        errors.append("❌ Doit contenir au moins un symbole (+, *, @, !, etc.).")
        
    # 3. Rejet des mots de passe courants (Blacklist dynamique via dictionnaire)
    blacklist_totale = charger_blacklist_dictionnaire()
    if password.lower() in blacklist_totale:
        errors.append("❌ Rejeté par la politique : Ce mot de passe est trop courant ou présent dans le dictionnaire d'attaque.")
        
    return errors


def verify_login_with_lockout(username, password_attempt, stored_salt_hex, stored_hash_hex):
    """
    Simule une tentative de connexion sécurisée avec limitation du nombre d'essais (Rate Limiting).
    Contre efficacement la Force Brute en ligne.
    """
    now = time.time()
    user_state = ATTEMPT_TRACKER.setdefault(username, {"attempts": 0, "lockout_until": 0})
    
    # Vérification du verrouillage temporaire
    if now < user_state["lockout_until"]:
        remaining = int(user_state["lockout_until"] - now)
        return False, f"🔒 Compte temporairement verrouillé ! Réessayez dans {remaining} secondes."
        
    # Vérification du mot de passe via hachage PBKDF2
    salt_bytes = bytes.fromhex(stored_salt_hex)
    computed_hash = hashlib.pbkdf2_hmac('sha256', password_attempt.encode('utf-8'), salt_bytes, 100000).hex()
    
    if computed_hash == stored_hash_hex:
        # Réinitialisation en cas de succès
        user_state["attempts"] = 0
        user_state["lockout_until"] = 0
        return True, "✅ Connexion réussie !"
    else:
        user_state["attempts"] += 1
        if user_state["attempts"] >= MAX_ATTEMPTS:
            user_state["lockout_until"] = now + LOCKOUT_TIME
            return False, f"🚨 Trop d'échecs ({MAX_ATTEMPTS}/{MAX_ATTEMPTS}). Compte bloqué pour {LOCKOUT_TIME}s !"
        else:
            remaining_attempts = MAX_ATTEMPTS - user_state["attempts"]
            return False, f"❌ Mot de passe incorrect. Tentatives restantes : {remaining_attempts}."


def proteger_mot_de_passe(password):
    """
    Hachage sécurisé PBKDF2-HMAC-SHA256 avec sel aléatoire de 16 octets.
    """
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex(), pwd_hash.hex()


def evaluer_complexite_cas3(password):
    """
    Analyse globale de la robustesse pour l'affichage.
    """
    policy_errors = check_password_policy_cas3(password, min_length=12)
    if not policy_errors:
        return "Très Fort 🟢 (Conforme aux exigences de sécurité et politique stricte)"
    elif len(password) >= 8:
        return "Moyen 🟠 (Ne respecte pas la règle des 12 caractères min. ou blacklisté)"
    else:
        return "Faible 🔴"