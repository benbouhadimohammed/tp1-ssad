import os
import secrets
import time
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
    if conseils:
        st.caption(" · ".join(conseils))


def bouton_cle_aleatoire(cle_etat):
    """Bouton qui remplit le champ de clé (dont la clé Streamlit est cle_etat) avec une clé aléatoire."""
    def remplir():
        st.session_state[cle_etat] = generer_cle_aleatoire()

    st.button("Générer une clé aléatoire", key=f"{cle_etat}_generer", on_click=remplir)


def afficher_grille(cle):
    """Affiche la grille 5x5 de la clé : lettres de la clé en vert, reste de l'alphabet en gris."""
    if caracteres_invalides_cle(cle) or not nettoyer(cle):
        st.caption("Saisissez une clé valide pour voir la grille.")
        return

    lettres_cle = set(nettoyer(cle))
    style_case = (
        "width:2.4em;height:2.4em;text-align:center;font-family:monospace;"
        "font-size:1.1rem;font-weight:600;border:1px solid rgba(128,128,128,0.4);"
    )
    lignes = []
    for ligne in creer_matrice(cle):
        cases = []
        for lettre in ligne:
            fond = "rgba(48,164,108,0.35)" if lettre in lettres_cle else "rgba(128,128,128,0.12)"
            cases.append(f'<td style="{style_case}background:{fond};">{lettre}</td>')
        lignes.append("<tr>" + "".join(cases) + "</tr>")
    st.markdown(
        '<table style="border-collapse:collapse;margin:0;">' + "".join(lignes) + "</table>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"En vert : les {len(lettres_cle)} lettres venant de la clé, sans doublons. "
        "En gris : le reste de l'alphabet, dans l'ordre (prévisible pour un attaquant). "
        "J est fusionné avec I."
    )


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


# --- Analyse : faiblesse des digrammes (paires de lettres) ---

def decouper_paires(texte_chiffre):
    """Découpe un message chiffré en paires de 2 lettres (comme au déchiffrement)."""
    texte_chiffre = nettoyer(texte_chiffre)
    return [texte_chiffre[i : i + 2] for i in range(0, len(texte_chiffre) - 1, 2)]


def paires_repetees(texte_chiffre):
    """
    Paires chiffrées qui apparaissent plusieurs fois.
    Avec Playfair, une même paire claire donne toujours la même paire chiffrée :
    les répétitions trahissent donc des répétitions du message clair.
    Renvoie une liste de (paire, nombre, positions), la plus fréquente en premier.
    Les positions sont les numéros des paires (à partir de 1).
    """
    positions = {}
    for numero, paire in enumerate(decouper_paires(texte_chiffre), start=1):
        positions.setdefault(paire, []).append(numero)
    repetees = [(paire, len(pos), pos) for paire, pos in positions.items() if len(pos) > 1]
    return sorted(repetees, key=lambda r: -r[1])


def paires_inversees(texte_chiffre):
    """
    Couples de paires chiffrées inverses l'une de l'autre (XY et YX).
    Avec Playfair, si AB donne XY alors BA donne YX : la présence des deux
    indique qu'une paire claire et son inverse (ex. ES et SE) sont dans le message.
    """
    paires = set(decouper_paires(texte_chiffre))
    return sorted({min(p, p[::-1]) for p in paires if p[::-1] in paires and p[0] != p[1]})


def afficher_analyse_paires(texte_chiffre):
    """Affiche ce qu'un attaquant voit dans le message chiffré, sans connaître la clé."""
    paires = decouper_paires(texte_chiffre)
    if not paires:
        return
    repetees = paires_repetees(texte_chiffre)
    inversees = paires_inversees(texte_chiffre)

    # Paires du message, les suspectes en gras
    suspectes = {p for p, _, _ in repetees} | {q for p in inversees for q in (p, p[::-1])}
    st.markdown(
        "Paires chiffrées : "
        + " ".join(f"**{p}**" if p in suspectes else p for p in paires)
    )

    if not repetees and not inversees:
        st.caption("Aucune paire répétée ou inversée détectée dans ce message.")
        return
    lignes = ["**Analyse des paires (visible sans la clé)**"]
    for paire, nombre, positions in repetees:
        lignes.append(
            f"- `{paire}` apparaît {nombre} fois (paires {', '.join(map(str, positions))}) : "
            "la même paire claire est répétée dans le message."
        )
    for paire in inversees:
        lignes.append(
            f"- `{paire}` et `{paire[::-1]}` sont inversées : "
            "le message clair contient une paire et son inverse (ex. ES / SE)."
        )
    lignes.append(
        "\nFaiblesse de Playfair : une même paire donne toujours la même paire chiffrée. "
        "Sur un long message, ces répétitions permettent une analyse de fréquence des digrammes."
    )
    st.info("\n".join(lignes))

# --- Attaque : dictionnaire sur la clé (Entité C intercepte le canal sans le modifier) ---

# Liste de mots partagée avec la partie 3 (un mot ou une expression par ligne)
CHEMIN_DICTIONNAIRE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "dictionnaire.txt"
)

# Nombre de grilles Playfair réellement différentes : 25! / 25
# (décaler toutes les lignes ou toutes les colonnes donne une grille équivalente)
NOMBRE_GRILLES = 620448401733239439360000


def charger_dictionnaire(chemin=CHEMIN_DICTIONNAIRE):
    """Lit la liste de mots (lignes vides ignorées)."""
    with open(chemin, encoding="utf-8") as fichier:
        return [ligne.strip() for ligne in fichier if ligne.strip()]


def attaque_dictionnaire(texte_chiffre, mots, indice):
    """
    Essaie chaque mot comme clé et garde ceux dont le déchiffrement contient l'indice
    (un mot que l'attaquant s'attend à trouver dans le message).
    Les X sont ignorés dans la comparaison, car un X de remplissage peut tomber au milieu de l'indice.
    Renvoie un dictionnaire : trouvees [(clé, message)], essais, duree, duree_premiere (secondes).
    """
    indice_propre = nettoyer(indice).replace("X", "")
    if not indice_propre:
        refuser("L'indice doit contenir au moins une lettre (autre que X).")

    debut = time.perf_counter()
    trouvees = []
    duree_premiere = None
    grilles_vues = set()
    for mot in mots:
        if caracteres_invalides_cle(mot) or not nettoyer(mot):
            continue  # pas une clé Playfair valide
        grille = tuple(tuple(ligne) for ligne in creer_matrice(mot))
        if grille in grilles_vues:
            continue  # même grille qu'un mot déjà essayé
        grilles_vues.add(grille)

        clair = playfair_decrypt(texte_chiffre, mot)
        if indice_propre in clair.replace("X", ""):
            trouvees.append((mot, clair))
            if duree_premiere is None:
                duree_premiere = time.perf_counter() - debut

    return {
        "trouvees": trouvees,
        "essais": len(grilles_vues),
        "duree": time.perf_counter() - debut,
        "duree_premiere": duree_premiere,
    }


def estimation_force_brute(cles_par_seconde):
    """Années nécessaires pour essayer toutes les grilles à cette vitesse."""
    return NOMBRE_GRILLES / cles_par_seconde / (3600 * 24 * 365.25)


def afficher_attaque_dictionnaire(texte_chiffre):
    """Section Entité C : intercepte le message du canal et lance l'attaque par dictionnaire."""
    st.caption(
        "C lit le message sur le canal sans le modifier (interception passive). "
        "C connaît l'algorithme et devine un mot présent dans le message, mais pas la clé."
    )
    if not nettoyer(texte_chiffre):
        st.caption("Aucun message intercepté pour l'instant.")
        return

    st.write("Message intercepté :", texte_chiffre)
    indice = st.text_input("Mot connu dans le message (indice) :", "ATTAQUE", key="indice_attaque_playfair")
    if not st.button("Lancer l'attaque par dictionnaire", key="attaque_playfair_btn"):
        return

    try:
        mots = charger_dictionnaire()
        resultat = attaque_dictionnaire(texte_chiffre, mots, indice)
    except (ValueError, OSError) as e:
        st.error(str(e))
        return

    essais, duree = resultat["essais"], resultat["duree"]
    vitesse = essais / duree if duree > 0 else 0
    stats = f"{essais} clés essayées en {duree * 1000:.1f} ms ({vitesse:,.0f} clés/s).".replace(",", " ")

    if resultat["trouvees"]:
        lignes = [
            f"**Attaque réussie : clé trouvée en {resultat['duree_premiere'] * 1000:.1f} ms.**",
        ]
        for mot, clair in resultat["trouvees"][:5]:
            lignes.append(f"- Clé `{mot}` → message : `{clair}`")
        if len(resultat["trouvees"]) > 5:
            lignes.append(f"- … et {len(resultat['trouvees']) - 5} autres : l'indice est trop court, essayez un mot plus long.")
        lignes.append("\n" + stats)
        lignes.append("\nUn mot-clé du dictionnaire ne protège pas le message : utilisez une clé aléatoire.")
        st.error("\n".join(lignes))
    else:
        message = f"**Attaque échouée : aucune clé du dictionnaire ne donne « {indice} ».**\n\n{stats}"
        if vitesse > 0:
            annees = estimation_force_brute(vitesse)
            message += (
                f"\n\nForce brute sur toutes les grilles possibles (≈ 6,2 × 10²³) à cette vitesse : "
                f"environ {annees:.1e} années."
            )
        st.success(message)


# --- Attaque : modification aveugle du message (Entité C modifie le canal sans la clé) ---

def paires_du_canal(texte_chiffre):
    """Paires du message chiffré, y compris une dernière lettre seule."""
    texte = nettoyer(texte_chiffre)
    return [texte[k : k + 2] for k in range(0, len(texte), 2)]


def echanger_paires(texte_chiffre, i, j):
    """Échange les paires n°i et n°j (à partir de 1)."""
    paires = paires_du_canal(texte_chiffre)
    paires[i - 1], paires[j - 1] = paires[j - 1], paires[i - 1]
    return "".join(paires)


def inverser_paire(texte_chiffre, i):
    """Inverse la paire n°i (XY devient YX) : B lira la paire claire inversée."""
    paires = paires_du_canal(texte_chiffre)
    paires[i - 1] = paires[i - 1][::-1]
    return "".join(paires)


def supprimer_paire(texte_chiffre, i):
    """Supprime la paire n°i."""
    paires = paires_du_canal(texte_chiffre)
    del paires[i - 1]
    return "".join(paires)


def afficher_modification_canal(cle_canal):
    """Section Entité C : modifie le message sur le canal (dont la clé Streamlit est cle_canal)."""
    st.caption(
        "C intercepte le message et le modifie avant que B le reçoive (attaque active). "
        "C ne connaît pas la clé et ne déchiffre rien."
    )
    canal = st.session_state.get(cle_canal, "")
    paires = paires_du_canal(canal)
    if not paires:
        st.caption("Aucun message à modifier pour l'instant.")
        return

    st.markdown("Paires sur le canal : " + " ".join(f"`{n}:{p}`" for n, p in enumerate(paires, start=1)))

    # Modifications rapides sur les paires (les clés des menus dépendent du nombre de paires)
    nombre = len(paires)
    numeros = list(range(1, nombre + 1))
    cle_a, cle_b = f"modif_a_{nombre}", f"modif_b_{nombre}"
    col_a, col_b = st.columns(2)
    with col_a:
        a = st.selectbox("Paire n° :", numeros, key=cle_a)
    with col_b:
        b = st.selectbox("Avec la paire n° (pour l'échange) :", numeros, index=min(1, nombre - 1), key=cle_b)

    def appliquer(fonction, *cles_numeros):
        numeros_choisis = [st.session_state[cle] for cle in cles_numeros]
        st.session_state[cle_canal] = fonction(st.session_state[cle_canal], *numeros_choisis)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.button(f"Échanger les paires {a} et {b}", key="modif_echanger", disabled=(a == b),
                  on_click=appliquer, args=(echanger_paires, cle_a, cle_b))
    with col2:
        st.button(f"Inverser la paire {a}", key="modif_inverser",
                  on_click=appliquer, args=(inverser_paire, cle_a))
    with col3:
        st.button(f"Supprimer la paire {a}", key="modif_supprimer", disabled=(nombre == 1),
                  on_click=appliquer, args=(supprimer_paire, cle_a))

    # Modification libre : le champ suit le contenu du canal quand celui-ci change
    if st.session_state.get("modif_source") != canal:
        st.session_state["modif_texte"] = canal
        st.session_state["modif_source"] = canal

    def remplacer():
        st.session_state[cle_canal] = st.session_state["modif_texte"].strip().upper()

    st.text_input("Ou modifier librement le message chiffré :", key="modif_texte")
    st.button("Remplacer sur le canal", key="modif_remplacer", on_click=remplacer)
