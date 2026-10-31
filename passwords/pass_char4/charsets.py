"""Cas 2 : mot de passe de 4 caractères, chacun parmi {1, 2, 3, 4}."""
import random

CASE_NAME = "Cas 2: 4 caractères {1, 2, 3, 4}"
CHARSET = ["1", "2", "3", "4"]
LENGTH = 4
import itertools

DICTIONARY = ["".join(p) for p in itertools.product(CHARSET, repeat=LENGTH)]


def search_space() -> int:
    """Nombre total de mots de passe possibles : 4^4 = 256."""
    return len(CHARSET) ** LENGTH


def generate_target_password() -> str:
    return "".join(random.choice(CHARSET) for _ in range(LENGTH))


def is_valid_candidate(candidate: str) -> bool:
    return len(candidate) == LENGTH and all(c in CHARSET for c in candidate)