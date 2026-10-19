import secrets
import warnings

from encryption_approaches.caesar import normalize

try:
    import streamlit as st
except ImportError:
    st = None


def nettoyer(texte):
    """Retire les accents, met en majuscules, remplace J par I et garde uniquement A-Z."""
    texte = normalize(texte).upper().replace("J", "I")
    return "".join(c for c in texte if "A" <= c <= "Z")


def dans_streamlit():
    """Vrai si le code tourne dans l'application Streamlit."""
    return st is not None and st.runtime.exists()


def refuser(erreur):
    """Bloque l'opération avec une ValueError (comme César et Hill, app.py l'affiche)."""
    raise ValueError(erreur)


def nettoyer_message(texte):
    """Comme nettoyer, mais refuse un texte sans aucune lettre (validation de l'entrée)."""
    propre = nettoyer(texte)
    if not propre:
        refuser(
            "Message invalide : il doit contenir au moins une lettre (A-Z) "
            "pour pouvoir être chiffré avec Playfair."
        )
    return propre


def avertissements(texte):
    """Liste des limites de Playfair qui altèrent ce message (sans le modifier)."""
    alertes = []
    texte_normalise = normalize(texte)
    chiffres = [c for c in texte_normalise if c.isdigit()]
    ponctuation = [c for c in texte_normalise if not c.isalnum() and not c.isspace()]
    if chiffres or ponctuation:
        if chiffres and ponctuation:
            quoi = "les chiffres et la ponctuation ont été supprimés"
        elif chiffres:
            quoi = "les chiffres ont été supprimés"
        else:
            quoi = "la ponctuation a été supprimée"
        supprimes = " ".join(dict.fromkeys(chiffres + ponctuation))  # sans doublons
        alertes.append(
            "Limite de Playfair : la grille 5x5 ne contient que des lettres, "
            f"{quoi} ({supprimes}). B ne pourra pas les retrouver au déchiffrement."
        )
    if "J" in normalize(texte).upper():
        alertes.append(
            "Limite de Playfair : la grille 5x5 n'a que 25 cases, "
            "J a été remplacé par I, B lira I à la place de J."
        )
    return alertes


def afficher_avertissements(texte):
    """Affiche les avertissements dans l'interface Streamlit (ou via warnings sinon)."""
    for alerte in avertissements(texte):
        if dans_streamlit():
            st.warning(alerte)
        else:
            warnings.warn(alerte)


# --- Clé : validation, force et génération ---

ALPHABET_GRILLE = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 lettres, sans J

# Suites prévisibles : alphabet et rangées de clavier (AZERTY et QWERTY)
SUITES_PREVISIBLES = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "AZERTYUIOP", "QSDFGHJKLM", "WXCVBN",
    "QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM",
]

MIN_LETTRES_FAIBLE = 6   # en dessous : très faible
MIN_LETTRES_FORTE = 12   # à partir de là (sans défaut) : forte


def caracteres_invalides_cle(cle):
    """Caractères interdits dans une clé : tout sauf les lettres et les espaces."""
    return [c for c in normalize(cle) if not (c.isascii() and c.isalpha()) and not c.isspace()]


def verifier_cle(cle):
    """Refuse une clé avec des caractères interdits ou sans aucune lettre."""
    invalides = caracteres_invalides_cle(cle)
    if invalides:
        refuser(
            "Clé invalide : seules les lettres sont autorisées "
            f"(caractères refusés : {' '.join(dict.fromkeys(invalides))})."
        )
    if not nettoyer(cle):
        refuser("Clé invalide : elle doit contenir au moins une lettre.")


def contient_suite_previsible(cle, longueur=4):
    """Vrai si la clé contient une suite de 4 lettres de l'alphabet ou du clavier (dans un sens ou l'autre)."""
    lettres = "".join(c for c in normalize(cle).upper() if "A" <= c <= "Z")
    for i in range(len(lettres) - longueur + 1):
        morceau = lettres[i : i + longueur]
        for suite in SUITES_PREVISIBLES:
            if morceau in suite or morceau in suite[::-1]:
                return True
    return False


def evaluer_cle(cle):
    """
    Évalue la force d'une clé Playfair.
    Renvoie (niveau, score sur 100, conseils) avec niveau parmi
    "invalide", "tres_faible", "faible", "forte".
    """
    if caracteres_invalides_cle(cle):
        return "invalide", 0, ["Seules les lettres sont autorisées."]
    if not nettoyer(cle):
        return "invalide", 0, ["La clé est vide : saisissez au moins une lettre."]

    distinctes = list(dict.fromkeys(nettoyer(cle)))  # lettres différentes, dans l'ordre
    d = len(distinctes)
    score = round(d / 25 * 100)
    conseils = []

    if d < MIN_LETTRES_FORTE:
        conseils.append(f"Utilisez au moins {MIN_LETTRES_FORTE} lettres différentes (actuellement {d}).")
    if creer_matrice(cle) == creer_matrice(""):
        conseils.append("La clé donne la grille alphabétique de base : elle ne protège rien.")
        return "tres_faible", 0, conseils
    if d < MIN_LETTRES_FAIBLE:
        return "tres_faible", score, conseils

    defaut = False
    if contient_suite_previsible(cle):
        conseils.append("Évitez les suites prévisibles (ABCD, AZERTY, QWERTY...).")
        defaut = True
    if distinctes == sorted(distinctes):
        conseils.append("Évitez les lettres rangées dans l'ordre alphabétique.")
        defaut = True

    if d < MIN_LETTRES_FORTE or defaut:
        conseils.append("Un mot-clé court ou un mot du dictionnaire est vulnérable à une attaque par dictionnaire.")
        return "faible", min(score, 45), conseils
    return "forte", score, conseils


def generer_cle_aleatoire():
    """Clé aléatoire : les 25 lettres de la grille dans un ordre tiré au hasard (module secrets)."""
    while True:
        lettres = list(ALPHABET_GRILLE)
        for i in range(len(lettres) - 1, 0, -1):  # mélange de Fisher-Yates
            j = secrets.randbelow(i + 1)
            lettres[i], lettres[j] = lettres[j], lettres[i]
        cle = "".join(lettres)
        if evaluer_cle(cle)[0] == "forte":
            return cle


def afficher_force_cle(cle):
    """Affiche une barre de force (rouge / jaune / vert) sous le champ de la clé."""
    niveau, score, conseils = evaluer_cle(cle)
    libelles = {
        "invalide": ("Clé invalide", "#e5484d"),
        "tres_faible": ("Clé très faible", "#e5484d"),
        "faible": ("Clé faible", "#f5a524"),
        "forte": ("Clé forte", "#30a46c"),
    }
    libelle, couleur = libelles[niveau]
    largeur = max(score, 5)  # toujours un peu de barre visible
    st.markdown(
        f"""
        <div style="background:rgba(128,128,128,0.25);border-radius:4px;height:8px;width:100%;">
          <div style="background:{couleur};width:{largeur}%;height:8px;border-radius:4px;"></div>
        </div>
        <div style="color:{couleur};font-size:0.9rem;margin-top:4px;">{libelle}</div>
        """,
        unsafe_allow_html=True,
    )
    for conseil in conseils:
        st.caption(conseil)


def bouton_cle_aleatoire(cle_etat):
    """Bouton qui remplit le champ de clé (dont la clé Streamlit est cle_etat) avec une clé aléatoire."""
    def remplir():
        st.session_state[cle_etat] = generer_cle_aleatoire()

    st.button("Générer une clé aléatoire", key=f"{cle_etat}_generer", on_click=remplir)


def creer_matrice(cle):
    """Crée une grille de 5x5 lettres à partir d'un mot-clé"""
    cle = nettoyer(cle)
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
    verifier_cle(cle)
    # Nettoyer le texte (accents, majuscules, J -> I, uniquement A-Z)
    texte_original = texte
    texte = nettoyer_message(texte)
    afficher_avertissements(texte_original)
    
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

def playfair_decrypt(texte_chiffre, cle):
    """Déchiffre un message chiffré avec la méthode de Playfair"""
    verifier_cle(cle)
    # Comme Hill : on garde uniquement A-Z, sans erreur, et on complète un dernier bloc incomplet
    texte_chiffre = nettoyer(texte_chiffre)
    if len(texte_chiffre) % 2 != 0:
        texte_chiffre += "X"
    
    # Découper le texte chiffré par paires de 2 lettres
    paires = [texte_chiffre[i:i+2] for i in range(0, len(texte_chiffre), 2)]
    
    matrice = creer_matrice(cle)
    resultat = ""
    
    for p in paires:
        l1, c1 = trouver_position(matrice, p[0])
        l2, c2 = trouver_position(matrice, p[1])
        
        if l1 == l2:  # Même ligne : pour déchiffrer, on décale vers la GAUCHE (-1)
            resultat += matrice[l1][(c1 - 1) % 5] + matrice[l2][(c2 - 1) % 5]
        elif c1 == c2:  # Même colonne : pour déchiffrer, on décale vers le HAUT (-1)
            resultat += matrice[(l1 - 1) % 5][c1] + matrice[(l2 - 1) % 5][c2]
        else:  # Rectangle : inversion des coins (identique au chiffrement)
            resultat += matrice[l1][c2] + matrice[l2][c1]

    return resultat
