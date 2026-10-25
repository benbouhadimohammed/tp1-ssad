import hashlib
import os
import string

def proteger_mot_de_passe(password):
    """
    Protège le mot de passe du Cas 3 en générant un sel aléatoire 
    et un hachage fort (PBKDF2-HMAC-SHA256 avec 100 000 itérations).
    """
    salt = os.urandom(16)  # Sel cryptographique
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return salt.hex(), pwd_hash.hex()

def evaluer_complexite_cas3(password):
    """
    Évalue la robustesse d'un mot de passe standard (Cas 3).
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    
    score = sum([has_lower, has_upper, has_digit, has_symbol])
    
    if len(password) >= 8 and score >= 3:
        return "Fort 🟢"
    elif len(password) >= 6 and score >= 2:
        return "Moyen 🟠"
    else:
        return "Faible 🔴 (Recommandé : min. 8 caractères avec majuscules, chiffres et symboles)"