"""
Protection du cas 1. Avec seulement 8 possibilités, AUCUN hash ne protège à lui seul :
l'attaquant teste les 8 combinaisons en moins d'une seconde, même avec un hash lent.
Les vraies protections sont : limiter les essais, allonger/diversifier le mot de passe, MFA.
"""
import hashlib
import hmac
import os
import time

from .charsets import SPACE_SIZE, all_passwords

ITERATIONS = 200_000


# ── 1. Stockage : hash lent + sel aléatoire ──
def hash_password(pwd: str, salt: bytes = None, iterations: int = ITERATIONS) -> str:
    salt = salt or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, iterations)
    return f"{iterations}${salt.hex()}${h.hex()}"


def verify_password(pwd: str, stored: str) -> bool:
    iterations, salt, h = stored.split("$")
    test = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), int(iterations))
    return hmac.compare_digest(test.hex(), h)


def offline_attack_time(stored: str) -> float:
    """Temps (s) pour casser un hash PBKDF2 en testant les 8 possibilités : reste très faible."""
    start = time.perf_counter()
    for pwd in all_passwords():
        if verify_password(pwd, stored):
            break
    return time.perf_counter() - start


# ── 2. Limitation des tentatives (verrouillage) ──
class LoginGuard:
    """Verrouille le compte après `max_attempts` échecs consécutifs."""

    def __init__(self, secret: str, max_attempts: int = 3):
        self.stored = hash_password(secret, iterations=1000)  # peu d'itérations : démo rapide
        self.max_attempts = max_attempts
        self.failures = 0
        self.locked = False

    def login(self, pwd: str) -> str:
        if self.locked:
            return "verrouillé"
        if verify_password(pwd, self.stored):
            self.failures = 0
            return "accès accordé"
        self.failures += 1
        if self.failures >= self.max_attempts:
            self.locked = True
            return "verrouillé"
        return "refusé"


def attack_with_guard(secret: str, max_attempts: int = 3) -> dict:
    """Simule un attaquant qui essaie les combinaisons en ligne face à un LoginGuard."""
    guard = LoginGuard(secret, max_attempts)
    log = []
    for pwd in all_passwords():
        res = guard.login(pwd)
        log.append((pwd, res))
        if res in ("accès accordé", "verrouillé"):
            break
    return {"succès": log[-1][1] == "accès accordé", "essais": len(log), "journal": log}


# ── 3. Allonger / diversifier : effet sur l'espace de recherche ──
def strength_table():
    cases = [("Cas 1 actuel : {0,1}, 3 car.", 2, 3), ("{0,1}, 8 car.", 2, 8), ("{0,1}, 16 car.", 2, 16),
             ("chiffres, 8 car.", 10, 8), ("a-z A-Z 0-9, 8 car.", 62, 8), ("a-z A-Z 0-9, 12 car.", 62, 12)]
    return [{"Mot de passe": n, "Possibilités": f"{b ** l:,}".replace(",", " ")} for n, b, l in cases]


RECOMMANDATIONS = [
    "Verrouiller le compte (ou ralentir) après 3 échecs : limite l'attaque en ligne.",
    "Stocker un hash lent avec sel (PBKDF2, bcrypt, Argon2) : empêche les tables pré-calculées.",
    "Allonger le mot de passe et élargir le jeu de caractères : 8 combinaisons est trivial à casser.",
    "Ajouter une authentification multi-facteurs (MFA).",
    "Refuser les mots de passe trop simples (000, 111, ...).",
]
