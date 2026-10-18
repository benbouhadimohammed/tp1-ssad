def creer_matrice(cle):
    """Crée une grille de 5x5 lettres à partir d'un mot-clé"""
    cle = cle.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grille = []
    
    # 1. Ajouter les lettres de la clé sans doublons
    for lettre in cle:
        if lettre in alphabet and lettre not in grille:
            grille.append(lettre)
            
    # 2. Ajouter le reste de l'alphabet
    for lettre in alphabet:
        if lettre not in grille:
            grille.append(lettre)
            
    # 3. Transformer la liste en une matrice (grille) de 5 lignes sur 5 colonnes
    matrice_5x5 = []
    for i in range(0, 25, 5):
        matrice_5x5.append(grille[i:i+5])
        
    return matrice_5x5


def trouver_position(matrice, lettre):
    """Cherche la ligne et la colonne d'une lettre dans la grille"""
    for lig in range(5):
        for col in range(5):
            if matrice[lig][col] == lettre:
                return lig, col
    return 0, 0


def playfair_encrypt(texte, cle):
    """Chiffre un message avec la méthode de Playfair"""
    # Nettoyer le texte (majuscules, remplacer J par I, enlever les espaces)
    texte = texte.upper().replace("J", "I").replace(" ", "")
    
    # Regrouper les lettres par paires
    paires = []
    i = 0
    while i < len(texte):
        a = texte[i]
        if i + 1 < len(texte):
            b = texte[i + 1]
            if a == b:  # Si deux lettres identiques, on sépare avec un 'X'
                paires.append(a + 'X')
                i += 1
            else:
                paires.append(a + b)
                i += 2
        else:  # S'il reste une seule lettre à la fin, on ajoute 'X'
            paires.append(a + 'X')
            i += 1
            
    matrice = creer_matrice(cle)
    resultat = ""
    
    # Appliquer les règles de chiffrement sur chaque paire
    for p in paires:
        l1, c1 = trouver_position(matrice, p[0])
        l2, c2 = trouver_position(matrice, p[1])
        
        if l1 == l2:  # Même ligne : on décale vers la droite
            resultat += matrice[l1][(c1 + 1) % 5] + matrice[l2][(c2 + 1) % 5]
        elif c1 == c2:  # Même colonne : on décale vers le bas
            resultat += matrice[(l1 + 1) % 5][c1] + matrice[(l2 + 1) % 5][c2]
        else:  # Rectangle : on croise les coins
            resultat += matrice[l1][c2] + matrice[l2][c1]
            
    return resultat