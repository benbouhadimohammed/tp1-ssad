import sys
import os

# Permet de remonter à la racine du projet pour trouver les dossiers (encryption_approaches, passwoards, integrity)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
from encryption_approaches.playfair import playfair_encrypt

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
        st.subheader("Chiffrement de Playfair")
        message_clair = st.text_input("Message de l'entité A (Clair) :", "HELLO")
        cle = st.text_input("Mot-clé Playfair :", "MONKEY")
        
        if st.button("Chiffrer / Envoyer à B"):
            if message_clair and cle:
                resultat = playfair_encrypt(message_clair, cle)
                st.success("Message chiffré avec succès !")
                st.write(f"**Message chiffré reçu par l'entité B :** `{resultat}`")
            else:
                st.warning("Veuillez remplir le message et la clé.")
                
    elif cipher_choice == "César":
        st.subheader("Chiffre de César")
        st.info("Bientôt implémenté !")
        
    else:
        st.subheader("Chiffre de Hill")
        st.info("Bientôt implémenté !")

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