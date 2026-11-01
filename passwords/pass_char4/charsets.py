"""Cas 2 : mot de passe de 4 caractères, chacun parmi {1, 2, 3, 4}."""
import random

CASE_NAME = "Cas 2: 4 caractères {1, 2, 3, 4}"
CHARSET = ["1", "2", "3", "4"]
LENGTH = 4

# Dictionnaire FIXE (reproductible), du plus probable au moins probable
DICTIONARY = ["1234", "1111", "4321", "2222", "3333", "4444", "1212", "2121",
              "1122", "3344", "1221", "2112", "1313", "2424", "4141"]


def search_space() -> int:
    """Nombre total de mots de passe possibles : 4^4 = 256."""
    return len(CHARSET) ** LENGTH


def generate_target_password() -> str:
    return "".join(random.choice(CHARSET) for _ in range(LENGTH))


def is_valid_candidate(candidate: str) -> bool:
    return len(candidate) == LENGTH and all(c in CHARSET for c in candidate)