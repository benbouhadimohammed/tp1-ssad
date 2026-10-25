"""Attaques sur le cas 2 (4 caractères parmi {1,2,3,4}).

  - force brute            : on essaie les 256 combinaisons
  - dictionnaire           : on essaie d'abord les mots de passe probables
  - force brute sur hash   : chaque essai coûte un PBKDF2 (vol de base)
  - attaque combinée       : dictionnaire puis force brute en repli
"""
import itertools
import math
import time

try:
    from . import charsets, protection
except ImportError:              # fichier lancé directement depuis le dossier
    import charsets
    import protection


def brute_force_attack(target_password: str) -> dict:
    start = time.perf_counter()
    attempts = 0
    found = None
    for combo in itertools.product(charsets.CHARSET, repeat=charsets.LENGTH):
        attempts += 1
        candidate = "".join(combo)
        if candidate == target_password:
            found = candidate
            break
    return {
        "method": "Force brute",
        "found": found,
        "attempts": attempts,
        "time_seconds": time.perf_counter() - start,
        "search_space": charsets.search_space(),
    }


def dictionary_attack(target_password: str, dictionary: list = None) -> dict:
    if dictionary is None:
        dictionary = charsets.DICTIONARY
    candidates = [w for w in dict.fromkeys(dictionary) if charsets.is_valid_candidate(w)]

    start = time.perf_counter()
    attempts = 0
    found = None
    for candidate in candidates:
        attempts += 1
        if candidate == target_password:
            found = candidate
            break
    return {
        "method": "Dictionnaire",
        "found": found,
        "attempts": attempts,
        "time_seconds": time.perf_counter() - start,
        "dictionary_size": len(candidates),
    }


def combined_attack(target_password: str) -> dict:
    """Dictionnaire d'abord (rapide), puis force brute si le dictionnaire échoue."""
    d = dictionary_attack(target_password)
    if d["found"] is not None:
        d["method"] = "Dictionnaire + force brute (trouvé par le dictionnaire)"
        return d
    b = brute_force_attack(target_password)
    return {
        "method": "Dictionnaire + force brute (repli)",
        "found": b["found"],
        "attempts": d["attempts"] + b["attempts"],
        "time_seconds": d["time_seconds"] + b["time_seconds"],
        "search_space": b["search_space"],
    }


def brute_force_on_hash(target_password: str, max_attempts: int = None) -> dict:
    """Force brute sur l'empreinte PBKDF2 + sel (comme après le vol d'une base)."""
    stored_hash, salt = protection.hash_password(target_password)

    start = time.perf_counter()
    attempts = 0
    found = None
    stopped = False
    for combo in itertools.product(charsets.CHARSET, repeat=charsets.LENGTH):
        if max_attempts is not None and attempts >= max_attempts:
            stopped = True
            break
        attempts += 1
        candidate = "".join(combo)
        if protection.verify_password(candidate, stored_hash, salt):
            found = candidate
            break
    return {
        "method": "Force brute sur empreinte (PBKDF2 + sel)",
        "found": found,
        "attempts": attempts,
        "time_seconds": time.perf_counter() - start,
        "search_space": charsets.search_space(),
        "stopped": stopped,
    }


def estimate_online_time() -> float:
    """Pire cas d'une force brute EN LIGNE avec blocage : (86-1) x 30 s = 2550 s."""
    blocks = math.ceil(charsets.search_space() / protection.MAX_ATTEMPTS)
    return (blocks - 1) * protection.LOCKOUT_SECONDS


def average_time(attack, target_password: str, repeats: int = 1000) -> float:
    """Temps moyen sur plusieurs répétitions (un seul essai est trop court à mesurer)."""
    total = 0.0
    for _ in range(repeats):
        total += attack(target_password)["time_seconds"]
    return total / repeats


if __name__ == "__main__":
    # Vérification à la main
    attendus = {"1111": 1, "1234": 28, "2222": 86, "4321": 229, "4444": 256}
    for cible, attendu in attendus.items():
        r = brute_force_attack(cible)
        print(f"{cible} : {r['attempts']} essais (attendu {attendu}) "
              f"[{'OK' if r['attempts'] == attendu else 'ERREUR'}]")