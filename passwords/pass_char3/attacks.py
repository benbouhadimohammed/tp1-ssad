import itertools
import time


def brute_force_cas1(target_password, alphabet="01"):
    """Attaque par force brute pour un mot de passe binaire de 3 caractères."""

    if len(target_password) != 3 or any(c not in "01" for c in target_password):
        raise ValueError(
            "Le mot de passe doit contenir 3 caractères : 0 ou 1."
        )

    start_time = time.perf_counter()
    attempts = 0

    for combination in itertools.product(alphabet, repeat=3):
        attempts += 1
        guess = "".join(combination)

        if guess == target_password:
            duration = time.perf_counter() - start_time
            return True, guess, attempts, duration

    duration = time.perf_counter() - start_time
    return False, None, attempts, duration


def dictionary_attack_cas1(target_password, dictionary_list):
    """Attaque par dictionnaire pour un mot de passe binaire de 3 caractères."""

    if len(target_password) != 3 or any(c not in "01" for c in target_password):
        raise ValueError(
            "Le mot de passe doit contenir 3 caractères : 0 ou 1."
        )

    start_time = time.perf_counter()
    attempts = 0

    for word in dictionary_list:
        guess = word.strip()

        if not guess:
            continue

        attempts += 1

        if guess == target_password:
            duration = time.perf_counter() - start_time
            return True, guess, attempts, duration

    duration = time.perf_counter() - start_time
    return False, None, attempts, duration
