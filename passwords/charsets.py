"""
Cas 1 : mot de passe de 3 caractères, chaque caractère appartient à {0, 1}.
Espace de recherche : 2^3 = 8 mots de passe possibles (3 bits d'entropie).
"""
import itertools

CHARSET = "01"
LENGTH = 3
SPACE_SIZE = len(CHARSET) ** LENGTH  # 8


def all_passwords():
    """Retourne les 8 mots de passe possibles : 000, 001, ..., 111."""
    return ["".join(p) for p in itertools.product(CHARSET, repeat=LENGTH)]


def is_valid(pwd: str) -> bool:
    """Vrai si pwd respecte la règle du cas 1 (3 caractères, uniquement 0 ou 1)."""
    return len(pwd) == LENGTH and all(c in CHARSET for c in pwd)
