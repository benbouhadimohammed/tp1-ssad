import itertools

# Configuration du Type 1
CAS1_ALPHABET = "01"
CAS1_LENGTH = 3


def get_cas1_config():
    """
    Retourne l'alphabet et la longueur
    du mot de passe pour le Type 1.
    """
    return CAS1_ALPHABET, CAS1_LENGTH


def valider_mot_de_passe_cas1(password):
    """Vérifie que le mot de passe contient exactement 3 bits."""
    return (
        len(password) == CAS1_LENGTH
        and all(c in CAS1_ALPHABET for c in password)
    )


def generer_combinaisons_cas1():
    """Génère les 8 combinaisons possibles."""
    return [
        "".join(combinaison)
        for combinaison in itertools.product(
            CAS1_ALPHABET, repeat=CAS1_LENGTH
        )
    ]
