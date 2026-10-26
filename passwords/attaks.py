"""
Attaques sur le cas 1 (3 caractères dans {0,1} -> 8 possibilités).
Le mot de passe est stocké sous forme de hash SHA-256 ; l'attaquant connaît le hash
et cherche le mot de passe en clair.

Test rapide (depuis la racine du projet) :
    python -m passwords.pass_type1.attaks
"""
import hashlib
import time

from .charsets import all_passwords, is_valid

# Dictionnaire des mots de passe "faibles" que les utilisateurs choisissent le plus souvent
# (motifs simples et répétitifs), classés du plus probable au moins probable.
DICT_COMMON = ["000", "111", "101", "010"]


def sha256(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


def _result(found, attempts, start):
    return {"found": found, "attempts": attempts,
            "time_us": (time.perf_counter() - start) * 1e6}


def brute_force(target_hash: str) -> dict:
    """Teste les 8 combinaisons dans l'ordre. Au pire 8 essais, en moyenne 4.5."""
    start, attempts = time.perf_counter(), 0
    for pwd in all_passwords():
        attempts += 1
        if sha256(pwd) == target_hash:
            return _result(pwd, attempts, start)
    return _result(None, attempts, start)


def dictionary_attack(target_hash: str, wordlist=None) -> dict:
    """Teste uniquement les mots du dictionnaire. Échoue si le mot de passe n'y figure pas."""
    wordlist = DICT_COMMON if wordlist is None else wordlist
    start, attempts = time.perf_counter(), 0
    for w in wordlist:
        attempts += 1
        if sha256(w) == target_hash:
            return _result(w, attempts, start)
    return _result(None, attempts, start)


def smart_attack(target_hash: str) -> dict:
    """Attaque optimisée (temps minimal) : dictionnaire d'abord, puis force brute
    sur les combinaisons restantes uniquement (aucun essai n'est répété)."""
    start, attempts = time.perf_counter(), 0
    for w in DICT_COMMON + [p for p in all_passwords() if p not in DICT_COMMON]:
        attempts += 1
        if sha256(w) == target_hash:
            return _result(w, attempts, start)
    return _result(None, attempts, start)


ATTACKS = {"Force brute": brute_force, "Dictionnaire": dictionary_attack,
           "Attaque optimisée (dico + brute)": smart_attack}


def evaluate(repeats: int = 2000) -> list:
    """Évaluation des performances : lance chaque attaque sur les 8 mots de passe possibles.
    Le temps est moyenné sur `repeats` répétitions (un seul essai dure quelques microsecondes)."""
    rows = []
    for name, fn in ATTACKS.items():
        attempts, times, hits = [], [], 0
        for pwd in all_passwords():
            h = sha256(pwd)
            tot = 0.0
            for _ in range(repeats):
                r = fn(h)
                tot += r["time_us"]
            attempts.append(r["attempts"])
            times.append(tot / repeats)
            hits += r["found"] is not None
        rows.append({
            "Attaque": name,
            "Succès": f"{hits}/8",
            "Essais min": min(attempts),
            "Essais moyen": round(sum(attempts) / 8, 2),
            "Essais max": max(attempts),
            "Temps moyen (µs)": round(sum(times) / 8, 2),
        })
    return rows


if __name__ == "__main__":
    secret = "101"
    assert is_valid(secret)
    h = sha256(secret)
    print("Hash cible :", h)
    for name, fn in ATTACKS.items():
        print(f"{name:35s}", fn(h))
    print("\nÉvaluation sur les 8 mots de passe :")
    for row in evaluate(500):
        print(row)
