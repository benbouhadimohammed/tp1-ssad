import sys
import os

# Permet de remonter à la racine du projet pour trouver les dossiers (encryption_approaches, passwoards, integrity)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
from encryption_approaches import playfair
from encryption_approaches import caesar
from encryption_approaches import hill

# Import des modules pour les Mots de passe (Partie 3)
try:
    from passwords.pass_standard import charsets
    from passwords.pass_standard import attaks
    from passwords.pass_standard import protection
except ImportError:
    # Au cas où le dossier est nommé sans le 'a' (passwords)
    from passwords import password
    from passwords import attaks
    from passwords import protection

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
                            success, guess, attempts, duration = attaks.brute_force_cas3(target_pwd, alphabet)
                        
                        if success:
                            st.success("🎯 Mot de passe cassé avec succès !")
                            st.metric("Mot de passe trouvé", guess)
                            st.metric("Nombre d'essais", f"{attempts:,}")
                            st.metric("Temps écoulé", f"{duration:.5f} secondes")
                        else:
                            st.error(f"❌ Échec de l'attaque après {attempts:,} essais ({duration:.5f}s).")
                    else:
                        st.warning("Veuillez saisir un mot de passe.")
                        
            else: # Dictionnaire
                st.caption("Attaque par dictionnaire testant une liste de candidats.")
                dict_input = st.text_area(
                    "Dictionnaire de mots de passe (un par ligne) :", 
                    "admin\npassword\n123456\nP@ss*1\nroot\nwelcome"
                )
                if st.button("Lancer l'attaque Dictionnaire", type="primary"):
                    if target_pwd:
                        dictionary_list = dict_input.split("\n")
                        with st.spinner("Recherche dans le dictionnaire..."):
                            success, guess, attempts, duration = attaks.dictionary_attack_cas3(target_pwd, dictionary_list)
                        
                        if success:
                            st.success("🎯 Mot de passe trouvé dans le dictionnaire !")
                            st.metric("Mot de passe", guess)
                            st.metric("Position dans le dictionnaire", f"Essai N°{attempts}")
                            st.metric("Temps écoulé", f"{duration:.6f} secondes")
                        else:
                            st.error(f"❌ Aucune correspondance trouvée dans le dictionnaire ({attempts} mots testés en {duration:.6f}s).")
                    else:
                        st.warning("Veuillez saisir un mot de passe.")
    else:
        st.info("Sélectionnez le **Cas 3: Standard** dans le menu déroulant ci-dessus.")

# --- ONGLET 4 : Intégrité ---
with tab4:
    st.header("Partie 4 : Intégrité et Authenticité")
    msg_integrity = st.text_input("Message à vérifier :", "Données sensibles")
    
    if st.button("Calculer l'empreinte (Hash)"):
        st.code("Empreinte SHA-256 : [En attente d'implémentation]")