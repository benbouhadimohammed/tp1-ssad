import sys
import os

# Permet de remonter à la racine du projet pour trouver les dossiers (encryption_approaches, passwoards, integrity)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
from encryption_approaches import playfair
from encryption_approaches import caesar
from encryption_approaches import hill

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
        message_clair = st.text_input("Message de l'entité A (Clair) :", "HELLO")
        cle_playfair = st.text_input("Mot-clé Playfair :", "MONKEY")
        
        # --- Chiffrement et Transmission ---
        if st.button("Chiffrer / Envoyer à B", key="playfair_encrypt_btn"):
            if message_clair and cle_playfair:
                try:
                    resultat = playfair.playfair_encrypt(message_clair, cle_playfair)
                    st.session_state["canal_playfair"] = resultat
                    st.success("Message chiffré et transmis au canal !")
                except ValueError as e:
                    st.error(str(e))
            else:
                st.warning("Veuillez remplir le message et la clé.")
        
        # Affichage du message sur le canal de transmission
        st.write("Message transmis sur le canal :", st.session_state.get("canal_playfair", ""))
        
        # --- Déchiffrement ---
        if st.button("Déchiffrer (entité B)", key="playfair_decrypt_btn"):
            message_recu = st.session_state.get("canal_playfair", "")
            if message_recu and cle_playfair:
                try:
                    clair = playfair.playfair_decrypt(message_recu, cle_playfair)
                    st.success(f"Message lu par B : `{clair}`")
                except ValueError as e:
                    st.error(str(e))
            else:
                st.error("Aucun message transmis ou clé manquante.")
                
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
    
    attack_type = st.radio("Méthode d'attaque :", ["Force Brute", "Dictionnaire"])
    
    if st.button("Lancer l'attaque"):
        st.warning(f"Exécution de l'attaque ({attack_type}) sur le {pwd_case}... [En attente d'implémentation]")

# --- ONGLET 4 : Intégrité ---
with tab4:
    st.header("Partie 4 : Intégrité et Authenticité")
    msg_integrity = st.text_input("Message à vérifier :", "Données sensibles")
    
    if st.button("Calculer l'empreinte (Hash)"):
        st.code("Empreinte SHA-256 : [En attente d'implémentation]")
