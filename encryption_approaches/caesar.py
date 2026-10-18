import unicodedata


def normalize(texte):
    """Retire les accents"""
    decompose = unicodedata.normalize("NFD", texte)
    resultat = ""
    for c in decompose:
        if unicodedata.category(c) != "Mn":
            resultat = resultat + c
    return resultat


def decaler(texte, n):
   
    resultat = ""
    for c in texte:
        if "A" <= c <= "Z":
            resultat = resultat + chr((ord(c) - 65 + n) % 26 + 65)
        elif "a" <= c <= "z":
            resultat = resultat + chr((ord(c) - 97 + n) % 26 + 97)
        else:
            resultat = resultat + c
    return resultat


def verifier_cle(cle):
    try:
        n = int(cle)
    except (TypeError, ValueError):
        raise ValueError("La clé doit être un nombre entier.")
    if n % 26 == 0:
        raise ValueError("Clé faible : un décalage multiple de 26 ne change rien.")
    return n


def encrypt(texte, cle, sens="droite"):
    n = verifier_cle(cle)
    if sens == "gauche":
        n = -n
    return decaler(normalize(texte), n)


def decrypt(texte, cle, sens="droite"):
    n = verifier_cle(cle)
    if sens == "gauche":
        n = -n
    return decaler(texte, -n)
