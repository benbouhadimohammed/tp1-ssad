from collections import Counter

from encryption_approaches.caesar import decrypt


def brute_force(chiffre):
    """Essaie les 25 clés et retourne la liste de tous les résultats."""
    resultats = []
    for k in range(1, 26):
        texte = decrypt(chiffre, k)
        resultats.append((k, texte))
    return resultats


def attaque_lettre_frequente(chiffre):
    """Suppose que la lettre la plus fréquente du chiffré est un E."""
    lettres = []
    for c in chiffre.lower():
        if "a" <= c <= "z":
            lettres.append(c)
    if len(lettres) == 0:
        raise ValueError("Aucune lettre à analyser.")

    plus_frequente = Counter(lettres).most_common(1)[0][0]
    cle = (ord(plus_frequente) - ord("e")) % 26
    if cle == 0:                    
        return 0, chiffre
    return cle, decrypt(chiffre, cle)