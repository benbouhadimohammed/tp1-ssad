"""Partie 3 - Protection des mots de passe.

Trois protections, une par type d'attaque :
  - force brute en ligne  -> limitation des tentatives (rate limiting)
  - dictionnaire          -> politique de mot de passe (refus des mots de passe courants)
  - vol de la base        -> hachage lent avec sel (PBKDF2)
"""
import hashlib
import hmac
import os
import time

# --- Paramètres ---
ITERATIONS = 100_000          # nombre d'itérations de PBKDF2 (plus il est grand, plus chaque essai coûte cher)
MAX_ATTEMPTS = 3              # échecs autorisés avant blocage
LOCKOUT_SECONDS = 30          # durée du blocage
MIN_LENGTH = 8                # longueur minimale exigée par la politique

# Mots de passe très courants : ceux qu'un dictionnaire d'attaque essaie en premier
COMMON_PASSWORDS = {
    "1234", "12345", "123456", "12345678", "0000", "1111", "2222", "3333", "4444",
    "4321", "1212", "2121", "abcd", "azerty", "qwerty", "password", "admin", "pass",
    "test", "love", "root", "user",
}

_failed_attempts = {}         # {identifiant: (nombre d'échecs, heure du dernier échec)}


# --- 1. Hachage avec sel (protection contre le vol de la base) ---
def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Retourne (empreinte, sel).

    Le sel est une valeur aléatoire ajoutée au mot de passe avant le hachage :
      - deux utilisateurs ayant le même mot de passe ont des empreintes différentes ;
      - les tables précalculées (rainbow tables) deviennent inutilisables.
    Ce qui RALENTIT chaque essai d'un attaquant, c'est le hachage lent (ITERATIONS),
    pas le sel : l'attaquant peut toujours essayer chaque candidat contre une empreinte précise.
    """
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return hashed, salt


def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    new_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)


# --- 2. Limitation des tentatives (protection contre la force brute en ligne) ---
def check_rate_limit(user_id: str) -> bool:
    """True si une tentative de connexion est autorisée, False si le compte est verrouillé."""
    count, last_time = _failed_attempts.get(user_id, (0, 0.0))
    if count < MAX_ATTEMPTS:
        return True
    if time.time() - last_time >= LOCKOUT_SECONDS:
        _failed_attempts.pop(user_id, None)       # le délai est écoulé : on repart de zéro
        return True
    return False


def seconds_until_unlock(user_id: str) -> float:
    count, last_time = _failed_attempts.get(user_id, (0, 0.0))
    if count < MAX_ATTEMPTS:
        return 0.0
    return max(0.0, LOCKOUT_SECONDS - (time.time() - last_time))


def register_failed_attempt(user_id: str):
    count, _ = _failed_attempts.get(user_id, (0, 0.0))
    _failed_attempts[user_id] = (count + 1, time.time())


def reset_attempts(user_id: str):
    """À appeler après une connexion réussie (ou pour réinitialiser la démo)."""
    _failed_attempts.pop(user_id, None)


def login(user_id: str, password: str, stored_hash: bytes, salt: bytes) -> tuple[bool, str]:
    """Tentative de connexion protégée. Retourne (succès, message)."""
    if not check_rate_limit(user_id):
        return False, f"Compte verrouillé : réessayez dans {seconds_until_unlock(user_id):.0f} s."
    if verify_password(password, stored_hash, salt):
        reset_attempts(user_id)
        return True, "Connexion réussie."
    register_failed_attempt(user_id)
    restants = MAX_ATTEMPTS - _failed_attempts[user_id][0]
    if restants <= 0:
        return False, f"Mot de passe incorrect. Compte verrouillé pendant {LOCKOUT_SECONDS} s."
    return False, f"Mot de passe incorrect. Il reste {restants} tentative(s)."


# --- 3. Politique de mot de passe (protection contre le dictionnaire) ---
def check_password_policy(password: str, min_length: int = MIN_LENGTH) -> list:
    """Retourne la liste des problèmes. Liste vide = mot de passe accepté."""
    problems = []
    if len(password) < min_length:
        problems.append(f"Trop court : {min_length} caractères minimum.")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("Mot de passe trop courant : il figure dans les dictionnaires d'attaque.")
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        problems.append("Pas assez varié : mélanger au moins 3 types (minuscules, majuscules, chiffres, symboles).")
    return problems