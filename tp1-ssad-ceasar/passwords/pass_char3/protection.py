
import hashlib
import hmac
import os


def evaluer_complexite_cas1(password):
    """Évalue la robustesse du mot de passe Type 1."""

    if len(password) == 3 and all(c in "01" for c in password):
        return (
            "Faible : le mot de passe contient seulement 3 bits, "
            "soit 2^3 = 8 combinaisons possibles."
        )

    return "Invalide : utilisez exactement 3 caractères, 0 ou 1."


def proteger_mot_de_passe(password):
    """
    Génère un sel aléatoire et une empreinte PBKDF2-HMAC-SHA256.
    Retourne le sel et l'empreinte en hexadécimal.
    """

    salt = os.urandom(16)

    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )

    return salt.hex(), pwd_hash.hex()


def verifier_mot_de_passe(password, salt_hex, hash_hex):
    """Vérifie un mot de passe à partir du sel et de l'empreinte enregistrés."""

    salt = bytes.fromhex(salt_hex)

    hash_calcule = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )

    return hmac.compare_digest(hash_calcule.hex(), hash_hex)
