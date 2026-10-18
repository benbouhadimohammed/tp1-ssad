from math import gcd

MOD = 26


def nettoyer(texte):
    """Met en majuscules et garde uniquement les lettres A-Z."""
    return "".join(c for c in texte.upper() if "A" <= c <= "Z")


def inverse_modulaire(a, m=MOD):
    """Inverse de a modulo m (si pgcd(a, m) = 1)."""
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"{a} n'est pas inversible modulo {m}")


def mineur(M, i, j):
    """Matrice M privée de la ligne i et de la colonne j."""
    return [ligne[:j] + ligne[j + 1 :] for k, ligne in enumerate(M) if k != i]


def determinant(M):
    """Déterminant (récursif, développement selon la première ligne)."""
    n = len(M)
    if n == 1:
        return M[0][0]
    if n == 2:
        return M[0][0] * M[1][1] - M[0][1] * M[1][0]
    return sum(
        (-1) ** j * M[0][j] * determinant(mineur(M, 0, j)) for j in range(n)
    )


def verifier_cle(K):
    """Vérifie que K est carrée et inversible modulo 26."""
    n = len(K)
    if any(len(ligne) != n for ligne in K):
        raise ValueError("La matrice clé doit être carrée.")
    d = determinant(K) % MOD
    if gcd(d, MOD) != 1:
        raise ValueError(
            f"Clé invalide : det = {d}, pgcd(det, 26) = {gcd(d, MOD)} != 1"
        )


def matrice_inverse(K):
    """Inverse de K modulo 26 : det^-1 * adjointe (mod 26)."""
    verifier_cle(K)
    n = len(K)
    d_inv = inverse_modulaire(determinant(K))
    if n == 1:
        return [[d_inv]]
    return [
        [
            (d_inv * (-1) ** (i + j) * determinant(mineur(K, j, i))) % MOD
            for j in range(n)
        ]
        for i in range(n)
    ]


def produit_matrice_vecteur(M, v):
    return [
        sum(M[i][j] * v[j] for j in range(len(v))) % MOD
        for i in range(len(M))
    ]


def transformer(texte, K):
    """Applique la matrice K à chaque bloc du texte (chiffrement ou déchiffrement)."""
    n = len(K)
    resultat = ""
    for i in range(0, len(texte), n):
        bloc = [ord(c) - ord("A") for c in texte[i : i + n]]
        for x in produit_matrice_vecteur(K, bloc):
            resultat += chr(x + ord("A"))
    return resultat


def chiffrer(message, K):
    verifier_cle(K)
    texte = nettoyer(message)
    while len(texte) % len(K) != 0:  # bourrage avec X
        texte += "X"
    return transformer(texte, K)


def dechiffrer(chiffre, K):
    return transformer(nettoyer(chiffre), matrice_inverse(K))