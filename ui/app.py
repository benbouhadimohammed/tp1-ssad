import sys
import os

# Permet de remonter à la racine du projet pour trouver les dossiers (encryption_approaches, passwords, integrity)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
from encryption_approaches import playfair
from encryption_approaches import caesar
from encryption_approaches import hill

# Import des modules pour les Mots de passe (Partie 3)
try:
    from passwords.pass_standard import charsets
    from passwords.pass_standard import attacks
    from passwords.pass_standard import protection
except ImportError:
    # Au cas où le dossier est nommé sans le 'a' (passwords)
    from passwords import charsets
    from passwords import attacks
    from passwords import protection

# === CAS 1 : imports (alias pour ne pas entrer en conflit) ===
from passwords.pass_char3 import charsets as charsets1
from passwords.pass_char3 import attacks as attacks1  
from passwords.pass_char3 import protection as protection1

# === CAS 2 : imports (alias pour ne pas entrer en conflit avec le Cas 3) ===
from passwords.pass_char4 import charsets as charsets4
from passwords.pass_char4 import attacks as attacks4
from passwords.pass_char4 import protection as protection4


# === CAS 2 : fonctions utilitaires ===
def format_duration(seconds):
    """Affiche une durée dans une unité lisible."""
    if seconds < 1:
        return f"{seconds * 1000:.3f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def nouveau_cible():
    """Appelée par le bouton « Tirer au hasard » (Cas 2)."""
    st.session_state["c4_target"] = charsets4.generate_target_password()


# Configuration de la page
st.set_page_config(
    page_title="TP SSAD - Encryption Framework",
    page_icon="🔒",
    layout="wide"
)

# === AUTHENTIFICATION (Partie 3) : page affichée avant tout le reste ===
from passwords import auth
if not auth.page_connexion():
    st.stop()
auth.sidebar_utilisateur()

st.title("🔒 Framework de Chiffrement et Sécurité (SSAD)")
st.write("Interface principale du projet - TP N°1")

# Création des 4 onglets correspondant aux parties de ton TP
tab1, tab2, tab3, tab4 = st.tabs([
    "📂 1. Accueil / Menu",
    "🔤 2. Chiffrement (César, Playfair, Hill)",
    "🔑 3. Mots de passe & Attaques",
    "🛡️ 4. Intégrité / Authenticité"
])

# --- ONGLET 1 : Accueil / Menu ---
with tab1:
    st.header("Bienvenue sur l'application du TP")
    st.info("Cette application regroupe les quatre parties demandées dans le sujet de SSAD.")
    st.write("Utilisez les onglets ci-dessus pour naviguer entre les différentes fonctionnalités.")

# --- ONGLET 2 : Chiffrement ---
with tab2:
    st.header("Partie 2 : Algorithmes de Chiffrement")
    cipher_choice = st.selectbox("Choisissez l'algorithme", ["Playfair", "César", "Hill"])
    
    if cipher_choice == "Playfair":
        st.subheader("Chiffrement de Playfair (Entité A ↔ Entité B)")

        # --- 1. Entité A : message, clé et chiffrement ---
        with st.container(border=True):
            st.markdown("**1. Entité A : chiffrement**")
            message_clair = st.text_input("Message clair :", "HELLO")

            st.session_state.setdefault("cle_playfair", "MONKEY")
            col_cle, col_bouton = st.columns([4, 1], vertical_alignment="bottom")
            with col_cle:
                cle_playfair = st.text_input("Mot-clé :", key="cle_playfair")
            with col_bouton:
                playfair.bouton_cle_aleatoire("cle_playfair")
            playfair.afficher_force_cle(cle_playfair)
            with st.expander("Voir la grille 5×5 de la clé"):
                playfair.afficher_grille(cle_playfair)

            if st.button("Chiffrer / Envoyer à B", key="playfair_encrypt_btn", type="primary"):
                for cle_etat in ("canal_playfair", "envoye_playfair", "attendu_playfair"):
                    st.session_state.pop(cle_etat, None)  # on efface le résultat précédent
                if message_clair and cle_playfair:
                    try:
                        resultat = playfair.playfair_encrypt(message_clair, cle_playfair)
                        st.session_state["canal_playfair"] = resultat
                        # Ce que A a réellement envoyé, pour montrer une éventuelle modification par C
                        st.session_state["envoye_playfair"] = resultat
                        st.session_state["attendu_playfair"] = playfair.playfair_decrypt(resultat, cle_playfair)
                        st.success("Message chiffré et transmis au canal !")
                    except ValueError as e:
                        st.error(str(e))
                else:
                    st.warning("Veuillez remplir le message et la clé.")

        # --- 2. Canal de transmission ---
        canal = st.session_state.get("canal_playfair", "")
        envoye = st.session_state.get("envoye_playfair", "")
        modifie = bool(envoye) and canal != envoye
        with st.container(border=True):
            st.markdown("**2. Canal de transmission**")
            if canal:
                st.code(canal, language=None)
            else:
                st.caption("Aucun message transmis pour l'instant.")
            if modifie:
                st.warning(f"Vue de l'observateur : message modifié par C. A avait envoyé `{envoye}`.")

        # --- 3. Entité B : déchiffrement ---
        with st.container(border=True):
            st.markdown("**3. Entité B : déchiffrement**")
            if st.button("Déchiffrer", key="playfair_decrypt_btn"):
                if canal and cle_playfair:
                    try:
                        clair = playfair.playfair_decrypt(canal, cle_playfair)
                        st.success(f"Message lu par B : `{clair}`")
                        if modifie:
                            st.info(
                                f"Vue de l'observateur : A avait écrit `{st.session_state['attendu_playfair']}`. "
                                "B a déchiffré sans aucune erreur et ne peut pas savoir que le message a été modifié : "
                                "Playfair ne garantit pas l'intégrité (voir partie 4)."
                            )
                    except ValueError as e:
                        st.error(str(e))
                else:
                    st.error("Aucun message transmis ou clé manquante.")

        # --- Sécurité : analyse et attaque (repliées par défaut) ---
        with st.expander("🔍 Analyse des paires chiffrées (faiblesse de Playfair)"):
            if canal:
                playfair.afficher_analyse_paires(canal)
            else:
                st.caption("Chiffrez un message pour analyser ses paires.")

        with st.expander("🕵️ Simulation d'attaque : Entité C (attaque par dictionnaire)"):
            playfair.afficher_attaque_dictionnaire(canal)

        with st.expander("✏️ Simulation d'attaque : Entité C (modification du message)"):
            playfair.afficher_modification_canal("canal_playfair")

    elif cipher_choice == "César":
        st.subheader("Chiffre de César")
        cle_cesar = st.text_input("Clé (nombre) :", "3")
        sens = st.radio("Sens :", ["droite", "gauche"], horizontal=True)
        message = st.text_input("Message de A :", "ATTAQUE DEMAIN A LAUBE")

        if st.button("Chiffrer / Envoyer à B"):
            try:
                st.session_state["canal"] = caesar.encrypt(message, cle_cesar, sens)
            except ValueError as e:
                st.error(str(e))

        st.write("Message transmis :", st.session_state.get("canal", ""))

        if st.button("Déchiffrer (entité B)"):
            try:
                clair = caesar.decrypt(st.session_state.get("canal", ""), cle_cesar, sens)
                st.success(f"Message lu par B : {clair}")
            except ValueError as e:
                st.error(str(e))
        
    else:
        st.subheader("Chiffre de Hill (Entité A ↔ Entité B)")
        message_hill = st.text_input("Message de l'entité A (Clair) :", "HELP")
        
        # Saisie de la matrice clé (ex: 3,3,2,5 pour du 2x2)
        str_matrice = st.text_input("Matrice clé (séparée par des virgules) :", "3,3,2,5")
        
        if st.button("Chiffrer / Envoyer à B", key="hill_encrypt_btn"):
            try:
                # Transformation de la chaîne en matrice 2D (ex: 4 éléments -> grille 2x2)
                valeurs = [int(x.strip()) for x in str_matrice.split(",")]
                n = int(len(valeurs) ** 0.5)
                K = [valeurs[i:i+n] for i in range(0, len(valeurs), n)]
                
                resultat_hill = hill.chiffrer(message_hill, K)
                st.session_state["canal_hill"] = resultat_hill
                st.success("Message chiffré et transmis au canal !")
            except Exception as e:
                st.error(f"Erreur (vérifie que la matrice est inversible et carrée) : {e}")

        st.write("Message transmis sur le canal :", st.session_state.get("canal_hill", ""))

        if st.button("Déchiffrer (entité B)", key="hill_decrypt_btn"):
            try:
                valeurs = [int(x.strip()) for x in str_matrice.split(",")]
                n = int(len(valeurs) ** 0.5)
                K = [valeurs[i:i+n] for i in range(0, len(valeurs), n)]
                
                message_recu = st.session_state.get("canal_hill", "")
                if message_recu:
                    clair_hill = hill.dechiffrer(message_recu, K)
                    st.success(f"Message lu par B : `{clair_hill}`")
                else:
                    st.error("Aucun message sur le canal.")
            except Exception as e:
                st.error(f"Erreur de déchiffrement : {e}")

# --- ONGLET 3 : Mots de passe & Attaques ---
with tab3:
    st.header("Partie 3 : Gestion des Mots de passe & Attaques")
    pwd_case = st.selectbox(
        "Cas de mot de passe :",
        ["Cas 1: 3 caractères {0, 1}", "Cas 2: 4 caractères {1, 2, 3, 4}", "Cas 3: Standard (a-z, A-Z, 0-9, symboles)"]
    )

    if "Cas 3" in pwd_case:
        st.subheader("🔑 Cas 3 : Mot de passe Standard (a..z, A..Z, 0..9, symboles)")

        # Saisie du mot de passe
        target_pwd = st.text_input("Mot de passe cible à tester :", value="P@ss*1", type="password")

        # --- Section 1 : Évaluation & Protection ---
        with st.container(border=True):
            st.markdown("**1. Évaluation de la robustesse & Solution de Protection**")
            if target_pwd:
                robustesse = protection.evaluer_complexite_cas3(target_pwd)
                st.write(f"**Robustesse du mot de passe :** {robustesse}")

                if st.button("🔐 Proposer la solution de protection (Hachage + Sel)"):
                    salt_hex, hash_hex = protection.proteger_mot_de_passe(target_pwd)
                    st.success("Le mot de passe a été sécurisé avec PBKDF2-HMAC-SHA256 (100 000 itérations) !")
                    st.code(f"Sel (Salt - 16 octets) : {salt_hex}\nEmpreinte (Hash)        : {hash_hex}", language=None)

        # --- Section 2 : Attaques ---
        with st.container(border=True):
            st.markdown("**2. Attaques (Minimal Time Execution)**")
            attack_type = st.radio("Méthode d'attaque :", ["Force Brute", "Dictionnaire"], horizontal=True)

            if attack_type == "Force Brute":
                st.caption("Attaque par force brute basée sur l'alphabet standard (a-z, A-Z, 0-9, symboles).")
                if st.button("Lancer l'attaque Force Brute", type="primary"):
                    if target_pwd:
                        alphabet, _ = charsets.get_cas3_config()
                        with st.spinner("Exécution de l'attaque par force brute..."):
                            success, guess, attempts, duration = attacks.brute_force_cas3(target_pwd, alphabet)

                        if success:
                            st.success("🎯 Mot de passe cassé avec succès !")
                            st.metric("Mot de passe trouvé", guess)
                            st.metric("Nombre d'essais", f"{attempts:,}")
                            st.metric("Temps écoulé", f"{duration:.5f} secondes")
                        else:
                            st.error(f"❌ Échec de l'attaque après {attempts:,} essais ({duration:.5f}s).")
                    else:
                        st.warning("Veuillez saisir un mot de passe.")

            else:  # Dictionnaire
                st.caption("Attaque par dictionnaire testant une liste de candidats.")
                dict_input = st.text_area(
                    "Dictionnaire de mots de passe (un par ligne) :",
                    "admin\npassword\n123456\nP@ss*1\nroot\nwelcome"
                )
                if st.button("Lancer l'attaque Dictionnaire", type="primary"):
                    if target_pwd:
                        dictionary_list = dict_input.split("\n")
                        with st.spinner("Recherche dans le dictionnaire..."):
                            success, guess, attempts, duration = attacks.dictionary_attack_cas3(target_pwd, dictionary_list)

                        if success:
                            st.success("🎯 Mot de passe trouvé dans le dictionnaire !")
                            st.metric("Mot de passe", guess)
                            st.metric("Position dans le dictionnaire", f"Essai N°{attempts}")
                            st.metric("Temps écoulé", f"{duration:.6f} secondes")
                        else:
                            st.error(f"❌ Aucune correspondance trouvée dans le dictionnaire ({attempts} mots testés en {duration:.6f}s).")
                    else:
                        st.warning("Veuillez saisir un mot de passe.")

    # === CAS 2 : 4 caractères parmi {1,2,3,4} ===
    elif "Cas 2" in pwd_case:
        st.subheader(charsets4.CASE_NAME)
        if "c4_target" not in st.session_state:
            nouveau_cible()

        col_cible, col_hasard = st.columns([3, 1])
        with col_cible:
            target = st.text_input("Mot de passe cible (modifiable) :", key="c4_target", type="password")
        with col_hasard:
            st.write("")
            st.button("Tirer au hasard", on_click=nouveau_cible, key="c4_random")

        st.caption(f"Espace de recherche : {charsets4.search_space()} mots de passe possibles")
        if not charsets4.is_valid_candidate(target):
            st.warning("Mot de passe hors du cas (4 caractères parmi 1, 2, 3, 4).")

        methode = st.radio("Méthode d'attaque :", ["Force brute", "Dictionnaire"], key="c4_method")

        if st.button("Lancer l'attaque", key="c4_launch"):
            if methode == "Force brute":
                r = attacks4.brute_force_attack(target)
            else:
                r = attacks4.dictionary_attack(target)

            if r["found"] is not None:
                st.success(f"Mot de passe trouvé : `{r['found']}`")
            else:
                st.error("Mot de passe non trouvé.")
            st.write(f"Méthode : {r['method']}")
            st.write(f"Nombre d'essais : {r['attempts']}")
            st.write(f"Temps écoulé : {format_duration(r['time_seconds'])}")
            if "dictionary_size" in r:
                st.write(f"Taille du dictionnaire : {r['dictionary_size']}")

        st.info(f"Attaque en ligne avec blocage ({protection4.MAX_ATTEMPTS} essais puis "
                f"{protection4.LOCKOUT_SECONDS} s) : au pire "
                f"{format_duration(attacks4.estimate_online_time())}.")

        st.success("Protection appliquée : politique de mot de passe (8 caractères ou plus, variés) à l'inscription, "
                   "délai croissant et blocage global à la connexion. Déconnectez-vous pour les tester sur la page d'authentification.")

        st.divider()
        st.subheader("Protection contre la force brute : limitation des tentatives")
        mdp_compte = st.text_input("Mot de passe du compte :", "1234", key="c4_acc_pwd", type="password")
        if st.button("Créer le compte", key="c4_acc_btn"):
            st.session_state["c4_compte"] = protection4.hash_password(mdp_compte)
            protection4.reset_attempts("demo_c4")
            st.success("Compte créé.")

        essai = st.text_input("Tentative de connexion :", key="c4_try", type="password")
        
        if st.button("Se connecter", key="c4_login"):
            if "c4_compte" not in st.session_state:
                st.error("Créez d'abord le compte.")
            else:
                h, s = st.session_state["c4_compte"]
                ok, msg = protection4.login("demo_c4", essai, h, s)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

        st.divider()
        st.subheader("Protection contre le dictionnaire : politique de mot de passe")
        cand = st.text_input("Mot de passe à tester :", "1234", key="c4_policy_in", type="password")
        
        if st.button("Vérifier la politique", key="c4_policy_btn"):
            problemes = protection4.check_password_policy(cand)
            if problemes:
                for p in problemes:
                    st.error(p)
            else:
                st.success("Mot de passe accepté.")

    else:
        import itertools
        import hashlib
        import hmac
        # === CAS 1 : 3 caractères parmi {0, 1} ===
        st.subheader("🔐 Cas 1 : Mot de passe binaire")
        st.info("Mot de passe de 3 caractères : 0 ou 1. Total : 8 combinaisons.")

        # 1. Saisie et validation du mot de passe
        target_pwd = st.text_input(
            "Mot de passe cible :",
            value="101",
            type="password",
            key="c1_target_pwd"
        )

        valide = (
            len(target_pwd) == 3
            and all(c in "01" for c in target_pwd)
        )

        if valide:
            st.success("Le mot de passe respecte le format demandé.")
            st.write(protection1.evaluer_complexite_cas1(target_pwd))
        else:
            st.warning("Entrez exactement 3 caractères : 0 ou 1.")

        # 2. Affichage des combinaisons possibles
        with st.expander("Afficher les 8 combinaisons possibles"):
            combinaisons = [
                "".join(c)
                for c in itertools.product("01", repeat=3)
            ]
            st.code("\n".join(combinaisons))

        # 3. Attaques
        st.subheader("1. Attaques")

        methode = st.radio(
            "Choisir une attaque :",
            ["Force brute", "Dictionnaire"],
            key="c1_attack_method",
            horizontal=True
        )

        if methode == "Force brute":

            if st.button("Lancer la force brute", key="c1_brute_btn"):

                if valide:
                    try:
                        success, guess, attempts, duration = (
                            attacks1.brute_force_cas1(target_pwd, "01")
                        )

                        if success:
                            st.success(f"Mot de passe trouvé : {guess}")
                        else:
                            st.error("Mot de passe non trouvé.")

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric("Nombre d'essais", attempts)

                        with col2:
                            st.metric(
                                "Temps d'exécution",
                                f"{duration:.8f} s"
                            )

                    except AttributeError:
                        st.error(
                            "La fonction brute_force_cas1 est introuvable "
                            "dans passwords/pass_char3/attacks.py."
                        )
                else:
                    st.error(
                        "Saisissez un mot de passe valide de 3 caractères : "
                        "0 ou 1."
                    )

        else:
            dictionnaire = st.text_area(
                "Dictionnaire (un mot de passe par ligne) :",
                value="000\n001\n101\n111",
                key="c1_dictionary"
            )

            if st.button(
                "Lancer l'attaque par dictionnaire",
                key="c1_dict_btn"
            ):

                if valide:
                    try:
                        liste = [
                            mot.strip()
                            for mot in dictionnaire.splitlines()
                            if mot.strip()
                        ]

                        success, guess, attempts, duration = (
                            attacks1.dictionary_attack_cas1(
                                target_pwd,
                                liste
                            )
                        )

                        if success:
                            st.success(f"Mot de passe trouvé : {guess}")
                        else:
                            st.warning(
                                "Mot de passe absent du dictionnaire."
                            )

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric("Nombre d'essais", attempts)

                        with col2:
                            st.metric(
                                "Temps d'exécution",
                                f"{duration:.8f} s"
                            )

                    except AttributeError:
                        st.error(
                            "La fonction dictionary_attack_cas1 est "
                            "introuvable dans passwords/pass_char3/attacks.py."
                        )
                else:
                    st.error(
                        "Saisissez un mot de passe valide de 3 caractères : "
                        "0 ou 1."
                    )

        # ==============================
        # 4. PROTECTION DU MOT DE PASSE
        # ==============================
        st.subheader("2. Protection du mot de passe")

        if valide:
            # Génération d'un hash avec sel et PBKDF2
            if st.button(
                "Protéger le mot de passe",
                key="c1_protect_btn"
            ):
                salt_hex, hash_hex = (
                    protection1.proteger_mot_de_passe(target_pwd)
                )

                st.session_state["c1_salt"] = salt_hex
                st.session_state["c1_hash"] = hash_hex

            if (
                "c1_salt" in st.session_state
                and "c1_hash" in st.session_state
            ):
                st.write("**Sel généré :**")
                st.code(st.session_state["c1_salt"])

                st.write("**Hash du mot de passe :**")
                st.code(st.session_state["c1_hash"])

                st.caption(
                    "Le mot de passe est transformé avec PBKDF2-HMAC-SHA256 "
                    "et un sel aléatoire."
                )

                # Vérification du mot de passe
                st.markdown("#### Vérifier un mot de passe")

                pwd_test = st.text_input(
                    "Mot de passe à vérifier :",
                    type="password",
                    key="c1_verify_pwd"
                )

                if st.button(
                    "Vérifier le mot de passe",
                    key="c1_verify_btn"
                ):
                    verification = (
                        protection1.verifier_mot_de_passe(
                            pwd_test,
                            st.session_state["c1_salt"],
                            st.session_state["c1_hash"]
                        )
                    )

                    if verification:
                        st.success("Mot de passe correct.")
                    else:
                        st.error("Mot de passe incorrect.")
        else:
            st.info(
                "Saisissez d'abord un mot de passe valide pour tester "
                "la protection."
            )

                   

# --- ONGLET 4 : Intégrité ---
with tab4:
    st.header("Partie 4 : Intégrité et Authenticité")
    msg_integrity = st.text_input("Message à vérifier :", "Données sensibles")

    if st.button("Calculer l'empreinte (Hash)"):
        st.code("Empreinte SHA-256 : [En attente d'implémentation]")