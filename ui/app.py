import sys
import os

# Permet de remonter à la racine du projet pour trouver les dossiers (encryption_approaches, passwords, integrity)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
from encryption_approaches import playfair
from encryption_approaches import caesar
from encryption_approaches import hill
from integrity import integrity

# Import des modules pour les Mots de passe (Partie 3 - Cas 3)
try:
    from passwords.pass_standard import charsets
    from passwords.pass_standard import attaks
    from passwords.pass_standard import protection
except ImportError:
    from passwords import password as charsets
    from passwords import attaks
    from passwords import protection

# === CAS 2 : imports (alias pour ne pas entrer en conflit avec le Cas 3) ===
from passwords.pass_char4 import charsets as charsets4
from passwords.pass_char4 import attaks as attacks4
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
            message_clair = st.text_input("Message clair (Playfair) :", "HELLO", key="msg_playfair")

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
                    st.session_state.pop(cle_etat, None)
                if message_clair and cle_playfair:
                    try:
                        resultat = playfair.playfair_encrypt(message_clair, cle_playfair)
                        st.session_state["canal_playfair"] = resultat
                        st.session_state["envoye_playfair"] = resultat
                        st.session_state["attendu_playfair"] = playfair.playfair_decrypt(resultat, cle_playfair)
                        st.session_state["algo_canal"] = "Playfair"  # 🔒 Enregistrement de l'algorithme source
                        st.success("Message chiffré et transmis au canal via Playfair !")
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

        # --- 3. Entité B : déchiffrement avec validation stricte de l'algorithme ---
        with st.container(border=True):
            st.markdown("**3. Entité B : déchiffrement**")
            if st.button("Déchiffrer", key="playfair_decrypt_btn"):
                algo_actuel = st.session_state.get("algo_canal")
                if algo_actuel and algo_actuel != "Playfair":
                    st.error(f"❌ Erreur critique : Le canal contient un message chiffré avec **{algo_actuel}**, impossible de déchiffrer avec **Playfair** !")
                elif canal and cle_playfair:
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
        cle_cesar = st.text_input("Clé (nombre) :", "3", key="cle_cesar")
        sens = st.radio("Sens :", ["droite", "gauche"], horizontal=True, key="sens_cesar")
        message = st.text_input("Message de A :", "ATTAQUE DEMAIN A LAUBE", key="msg_cesar")

        if st.button("Chiffrer / Envoyer à B", key="cesar_encrypt_btn"):
            try:
                st.session_state["canal_cesar"] = caesar.encrypt(message, cle_cesar, sens)
                st.session_state["algo_canal"] = "César"  # 🔒 Enregistrement de l'algorithme source
                st.success("Message chiffré et transmis via César !")
            except ValueError as e:
                st.error(str(e))

        canal = st.session_state.get("canal_cesar", "")
        st.write("Message transmis :", canal)

        if st.button("Déchiffrer (entité B)", key="cesar_decrypt_btn"):
            algo_actuel = st.session_state.get("algo_canal")
            if algo_actuel and algo_actuel != "César":
                st.error(f"❌ Erreur : Ce message provient de l'algorithme **{algo_actuel}**. Changement d'algorithme interdit au déchiffrement !")
            else:
                try:
                    clair = caesar.decrypt(canal, cle_cesar, sens)
                    st.success(f"Message lu par B : {clair}")
                except ValueError as e:
                    st.error(str(e))
        
    else:
        st.subheader("Chiffre de Hill (Entité A ↔ Entité B)")
        message_hill = st.text_input("Message de l'entité A (Clair) :", "HELP", key="msg_hill")
        str_matrice = st.text_input("Matrice clé (séparée par des virgules) :", "3,3,2,5", key="matrice_hill")
        
        if st.button("Chiffrer / Envoyer à B", key="hill_encrypt_btn"):
            try:
                valeurs = [int(x.strip()) for x in str_matrice.split(",")]
                n = int(len(valeurs) ** 0.5)
                K = [valeurs[i:i+n] for i in range(0, len(valeurs), n)]
                
                resultat_hill = hill.chiffrer(message_hill, K)
                st.session_state["canal_hill"] = resultat_hill
                st.session_state["algo_canal"] = "Hill"  # 🔒 Enregistrement de l'algorithme source
                st.success("Message chiffré et transmis via Hill !")
            except Exception as e:
                st.error(f"Erreur (vérifie que la matrice est inversible et carrée) : {e}")

        canal = st.session_state.get("canal_hill", "")
        st.write("Message transmis sur le canal :", canal)

        if st.button("Déchiffrer (entité B)", key="hill_decrypt_btn"):
            algo_actuel = st.session_state.get("algo_canal")
            if algo_actuel and algo_actuel != "Hill":
                st.error(f"❌ Erreur : Tentative de déchiffrement avec Hill alors que le canal utilise **{algo_actuel}** !")
            else:
                try:
                    valeurs = [int(x.strip()) for x in str_matrice.split(",")]
                    n = int(len(valeurs) ** 0.5)
                    K = [valeurs[i:i+n] for i in range(0, len(valeurs), n)]
                    
                    if canal:
                        clair_hill = hill.dechiffrer(canal, K)
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
        st.subheader("🔑 Cas 3 : Mot de passe Standard (a..z, A..Z, 0-9, symboles)")

        target_pwd = st.text_input("Mot de passe cible à tester :", value="P@ssword2026!", type="password")

        # --- Section 1 : Vérification de la Politique de Sécurité (Password Policy) ---
        with st.container(border=True):
            st.markdown("**1. Politique de Sécurité & Validation du Mot de passe**")
            st.caption("Règles d'acceptation : Longueur min. 12 car., Majuscule, Minuscule, Chiffre, Symbole, non-blacklisté.")
            
            if st.button("Vérifier le mot de passe (Politique Cas 3)"):
                erreurs = protection.check_password_policy_cas3(target_pwd, min_length=12)
                if erreurs:
                    for err in erreurs:
                        st.error(err)
                else:
                    st.success("✅ Mot de passe conforme et accepté par la politique de sécurité !")

        # --- Section 2 : Protection contre la Force Brute en ligne (Rate Limiting & Lockout) ---
        with st.container(border=True):
            st.markdown("**2. Protection contre la Force Brute en Ligne (Account Lockout)**")
            st.caption("Après 3 échecs consécutifs, le compte est verrouillé pendant 30 secondes.")

            if st.button("Initialiser un compte sécurisé"):
                salt_hex, hash_hex = protection.proteger_mot_de_passe(target_pwd)
                st.session_state["compte_cas3"] = (salt_hex, hash_hex)
                st.success("Compte créé avec mot de passe haché (PBKDF2) !")

            essai_login = st.text_input("Saisir un mot de passe pour vous connecter :", key="login_try_cas3", type="password")
            
            if st.button("Se connecter"):
                if "compte_cas3" not in st.session_state:
                    st.warning("Veuillez d'abord initialiser le compte sécurisé.")
                else:
                    salt_hex, hash_hex = st.session_state["compte_cas3"]
                    succes, message = protection.verify_login_with_lockout("utilisateur_demo", essai_login, salt_hex, hash_hex)
                    if succes:
                        st.success(message)
                    else:
                        st.error(message)

        # --- Section 3 : Simulation des Attaques ---
        with st.container(border=True):
            st.markdown("**3. Attaques (Force Brute & Dictionnaire)**")
            attack_type = st.radio("Méthode d'attaque :", ["Force Brute", "Dictionnaire"], horizontal=True)

            if attack_type == "Force Brute":
                st.caption("Attaque par force brute basée sur l'alphabet standard.")
                if st.button("Lancer l'attaque Force Brute", type="primary"):
                    if target_pwd:
                        alphabet, _ = charsets.get_cas3_config()
                        with st.spinner("Exécution de l'attaque par force brute..."):
                            success, guess, attempts, duration = attaks.brute_force_cas3(target_pwd, alphabet)

                        if success:
                            st.success("🎯 Mot de passe cassé avec succès !")
                            st.metric("Mot de passe trouvé", guess)
                            st.metric("Nombre d'essais", f"{attempts:,}")
                            st.metric("Temps écoulé", f"{duration:.5f} secondes")
                        else:
                            st.error(f"❌ Échec de l'attaque après {attempts:,} essais ({duration:.5f}s).")
            else:
                dict_input = st.text_area(
                    "Dictionnaire de mots de passe :",
                    "admin\npassword\n123456\nP@ssword2026!\nroot\nwelcome"
                )
                if st.button("Lancer l'attaque Dictionnaire", type="primary"):
                    dictionary_list = dict_input.split("\n")
                    with st.spinner("Recherche..."):
                        success, guess, attempts, duration = attaks.dictionary_attack_cas3(target_pwd, dictionary_list)

                    if success:
                        st.success("🎯 Mot de passe trouvé dans le dictionnaire !")
                        st.metric("Mot de passe", guess)
                        st.metric("Position", f"Essai N°{attempts}")
                        st.metric("Temps", f"{duration:.6f} secondes")
                    else:
                        st.error(f"❌ Aucune correspondance dans le dictionnaire.")

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
        st.info("Cas 1 : à venir.")

# --- ONGLET 4 : Intégrité ---
# --- ONGLET 4 : Intégrité / Authenticité ---
with tab4:
    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        st.header("Partie 4 : Intégrité et Authenticité des Données")
        st.info("Objectif : Garantir qu'un message transmis sur le canal n'a pas été altéré par un tiers (Entité C).")

    with st.container(border=True):
        st.markdown("**1. Émission par l'Entité A (Génération de l'empreinte / Hash)**")
        
        # Récupération automatique du dernier message du canal ou saisie libre
        message_origine = st.text_input("Message clair envoyé par A :", value="Données sensibles du TP SSAD")
        
        # Calcul du hash SHA-256 du message original
        hash_origine = integrity.calculer_hash_sha256(message_origine)
        st.text_input("Empreinte SHA-256 générée (à joindre au message) :", value=hash_origine, disabled=True)

    with st.container(border=True):
        st.markdown("**2. Réception par l'Entité B (Vérification d'intégrité)**")
        st.caption("L'entité C a pu intercepter et modifier le message sur le canal de transmission.")
        
        # Simulation d'un message potentiellement modifié par l'attaquant C
        message_recu_par_b = st.text_input("Message réellement reçu par B :", value=message_origine)
        
        if st.button("Vérifier l'intégrité du message", type="primary"):
            hash_du_message_recu = integrity.calculer_hash_sha256(message_recu_par_b)
            
            st.write(f"Hash d'origine joint : `{hash_origine}`")
            st.write(f"Hash recalculé sur le message reçu : `{hash_du_message_recu}`")
            
            if message_recu_par_b == message_origine:
                st.success("✅ **Intégrité Validée !** Le message reçu est rigoureusement identique à celui envoyé par A (aucune modification par C).")
            else:
                st.error("🚨 **ALERTE INTÉGRITÉ COMPROMMISE !** Le message a été modifié en transit (Attaque active détectée : les empreintes ne correspondent pas).")