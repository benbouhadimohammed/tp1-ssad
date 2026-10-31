"""Partie 3 : authentification (page de connexion affichée avant l'application).

Protections combinées (une seule limitation par machine ne suffit pas) :
  1. Stockage : seule l'empreinte PBKDF2 + sel est enregistrée (vol de base).
  2. Délai CROISSANT par compte : 3 essais, puis 30 s, 60 s, 120 s... (force brute en ligne).
  3. Compteur GLOBAL : trop d'échecs sur tous les comptes => blocage général
     (attaque répartie sur plusieurs machines / plusieurs comptes).
  4. Message d'erreur identique que le compte existe ou non (pas de fuite d'information).
  5. Politique de mot de passe à l'inscription (dictionnaire).
L'état des blocages est gardé côté serveur (variables du module) : un simple
rafraîchissement de la page ne le remet pas à zéro.
"""
import itertools
import json
import os
import string
import time

import streamlit as st

from passwords.pass_char4 import protection as prot

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

MAX_ATTEMPTS = 3        # échecs autorisés avant le premier blocage
BASE_LOCK = 30          # durée du premier blocage (s), doublée à chaque échec suivant
MAX_LOCK = 3600         # plafond du blocage (s)
GLOBAL_LIMIT = 10       # échecs (tous comptes) tolérés dans la fenêtre
GLOBAL_WINDOW = 60      # taille de la fenêtre (s)
GLOBAL_LOCK = 60        # durée du blocage général (s)

_failures = {}          # {identifiant: (nombre d'échecs, heure du dernier échec)}
_global_failures = []   # heures des derniers échecs, tous comptes confondus
_global_lock_until = 0.0

MSG_ECHEC = "Identifiant ou mot de passe incorrect."

# Les 3 cas de mots de passe du TP (alphabet, longueur) ; longueur None = aucune restriction
CAS = {
    "Cas 1 : 3 caractères {0, 1}": ("01", 3),
    "Cas 2 : 4 caractères {1, 2, 3, 4}": ("1234", 4),
    "Cas 3 : standard (lettres, chiffres, symboles)": (string.ascii_letters + string.digits + "!@#$%^&*", None),   # longueur libre
}


# ---------- Stockage des comptes (empreinte + sel, jamais le mot de passe) ----------
def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_users(users: dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def register(username: str, password: str, confirm: str) -> tuple:
    """Crée un compte. Retourne (succès, liste de messages)."""
    username = username.strip()
    if not username:
        return False, ["Identifiant obligatoire."]
    if password != confirm:
        return False, ["Les deux mots de passe sont différents."]
    problems = prot.check_password_policy(password)
    if problems:
        return False, problems
    users = _load_users()
    if username in users:
        return False, ["Cet identifiant existe déjà."]
    h, s = prot.hash_password(password)
    users[username] = {"hash": h.hex(), "salt": s.hex()}
    _save_users(users)
    return True, ["Compte créé. Vous pouvez vous connecter."]


# ---------- Limitation des tentatives ----------
def _lock_duration(count: int) -> float:
    """Durée du blocage après `count` échecs : 30, 60, 120... plafonné."""
    if count < MAX_ATTEMPTS:
        return 0.0
    return min(BASE_LOCK * 2 ** (count - MAX_ATTEMPTS), MAX_LOCK)


def lock_remaining(username: str) -> float:
    count, last = _failures.get(username, (0, 0.0))
    return max(0.0, _lock_duration(count) - (time.time() - last))


def global_lock_remaining() -> float:
    return max(0.0, _global_lock_until - time.time())


def _record_failure(username: str):
    global _global_lock_until
    now = time.time()
    count, _ = _failures.get(username, (0, 0.0))
    _failures[username] = (count + 1, now)
    _global_failures[:] = [t for t in _global_failures if now - t < GLOBAL_WINDOW] + [now]
    if len(_global_failures) >= GLOBAL_LIMIT:
        _global_lock_until = now + GLOBAL_LOCK
        _global_failures.clear()


def reset_locks():
    """Pour la démonstration uniquement."""
    global _global_lock_until
    _failures.clear()
    _global_failures.clear()
    _global_lock_until = 0.0


def login(username: str, password: str) -> tuple:
    """Tentative de connexion protégée. Retourne (succès, message)."""
    username = username.strip()
    g = global_lock_remaining()
    if g > 0:
        return False, f"Trop d'échecs sur le système : toutes les connexions sont suspendues {g:.0f} s."
    r = lock_remaining(username)
    if r > 0:
        return False, f"Trop d'échecs : réessayez dans {r:.0f} s."

    rec = _load_users().get(username)
    if rec:
        ok = prot.verify_password(password, bytes.fromhex(rec["hash"]), bytes.fromhex(rec["salt"]))
    else:
        prot.hash_password(password)   # même temps de calcul : on ne révèle pas si le compte existe
        ok = False

    if ok:
        _failures.pop(username, None)
        return True, "Connexion réussie."

    _record_failure(username)
    wait = lock_remaining(username)
    if wait > 0:
        return False, f"{MSG_ECHEC} Accès bloqué pendant {wait:.0f} s."
    restants = MAX_ATTEMPTS - _failures[username][0]
    return False, f"{MSG_ECHEC} Il reste {restants} tentative(s) avant blocage."


# ---------- Attaque et estimation (pour la démonstration) ----------
def estimate_online_time(space: int = 256) -> float:
    """Pire cas d'une force brute en ligne sur `space` mots de passe avec le délai croissant."""
    total, k = 0.0, MAX_ATTEMPTS
    while k < space:
        d = _lock_duration(k)
        if d >= MAX_LOCK:                     # plafond atteint : le reste est un produit
            total += (space - k) * MAX_LOCK
            break
        total += d
        k += 1
    return total


def simulate_online_attack(username: str, candidates, max_tries: int = 20) -> list:
    """L'attaquant essaie des mots de passe à travers la vraie page de connexion."""
    log = []
    for i, cand in enumerate(candidates):
        if i >= max_tries:
            break
        ok, msg = login(username, cand)
        log.append((cand, ok, msg))
        if ok:
            break
    return log


def _fmt(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} h"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} jours"
    return f"{seconds / (86400 * 365):.1f} ans"


def afficher_base_comptes():
    """Montre ce qui est réellement stocké : des empreintes salées, jamais les mots de passe."""
    users = _load_users()
    if not users:
        st.caption("Aucun compte enregistré pour l'instant.")
        return
    for nom, rec in users.items():
        st.write(f"**{nom}**")
        st.code(f"sel     : {rec['salt']}\nempreinte : {rec['hash']}", language=None)
    st.caption("Même si ce fichier est volé, l'attaquant ne voit aucun mot de passe : "
               "il doit tester chaque candidat avec PBKDF2 (100 000 itérations), ce qui est lent.")


# ---------- Interface ----------
def page_connexion() -> bool:
    """Affiche la page d'authentification. Retourne True si l'utilisateur est connecté."""
    if st.session_state.get("auth_user"):
        return True

    st.title("🔐 Authentification")
    st.write("Connectez-vous pour accéder au framework de chiffrement et de sécurité (SSAD).")

    tab_login, tab_register = st.tabs(["Se connecter", "Créer un compte"])

    with tab_login:
        with st.form("auth_login_form"):
            u = st.text_input("Identifiant", key="auth_login_user")
            p = st.text_input("Mot de passe", type="password", key="auth_login_pwd")
            submit = st.form_submit_button("Se connecter", type="primary")
        if submit:
            ok, msg = login(u, p)
            if ok:
                st.session_state["auth_user"] = u.strip()
                st.rerun()
            else:
                st.error(msg)

    with tab_register:
        with st.form("auth_register_form"):
            u = st.text_input("Identifiant", key="auth_reg_user")
            p = st.text_input("Mot de passe", type="password", key="auth_reg_pwd")
            c = st.text_input("Confirmer le mot de passe", type="password", key="auth_reg_conf")
            submit = st.form_submit_button("Créer le compte")
        st.caption("Politique : 8 caractères minimum, au moins 3 types de caractères "
                   "(minuscules, majuscules, chiffres, symboles), pas de mot de passe courant.")
        if submit:
            ok, msgs = register(u, p, c)
            for m in msgs:
                (st.success if ok else st.error)(m)

    with st.expander("🕵️ Simulation d'attaque en ligne sur la connexion (démo)"):
        st.write("L'attaquant teste les combinaisons d'un des 3 cas à travers cette page de connexion.")
        nom_cas = st.selectbox("Cas de mot de passe visé :", list(CAS.keys()), key="auth_attack_case")
        alphabet, longueur = CAS[nom_cas]
        if longueur is None:
            # Cas 3 : longueur libre => l'attaquant essaie les longueurs 1, 2, 3... successivement
            lmax = st.number_input("Longueur maximale supposée du mot de passe :", 1, 12, 8,
                                   key="auth_attack_lmax")
            espace = sum(len(alphabet) ** l for l in range(1, lmax + 1))
        else:
            lmax = longueur
            espace = len(alphabet) ** longueur
        cible = st.text_input("Compte attaqué :", key="auth_attack_user")
        if st.button("Lancer l'attaque par force brute", key="auth_attack_btn"):
            longueurs = range(1, lmax + 1) if longueur is None else [longueur]
            candidats = ("".join(c) for l in longueurs
                         for c in itertools.product(alphabet, repeat=l))
            log = simulate_online_attack(cible, candidats, max_tries=20)
            acceptes = sum(1 for _, _, m in log if "réessayez" not in m and "suspendues" not in m)
            bloques = len(log) - acceptes
            if any(ok for _, ok, _ in log):
                st.error(f"Mot de passe trouvé : {[c for c, ok, _ in log if ok][0]}")
            else:
                st.success("Attaque stoppée : mot de passe non trouvé.")
            st.write(f"Essais réellement évalués : {acceptes} | essais refusés (blocage) : {bloques}")
            st.code("\n".join(f"{c} -> {m}" for c, _, m in log[:8]), language=None)
        st.info(f"Espace de recherche : {espace:,} mots de passe".replace(",", " ")
                + (f" (longueurs 1 à {lmax})" if longueur is None else "")
                + f" | pire cas en ligne avec délai croissant : {_fmt(estimate_online_time(espace))}"
                + f" | avec un blocage fixe de {BASE_LOCK} s : "
                + _fmt((-(-espace // MAX_ATTEMPTS) - 1) * BASE_LOCK))
        if st.button("Réinitialiser les blocages (démo)", key="auth_reset_btn"):
            reset_locks()
            st.success("Blocages réinitialisés.")

    with st.expander("🗄️ Contenu de la base des comptes (users.json)"):
        afficher_base_comptes()

    return False


def sidebar_utilisateur():
    """Affiche l'utilisateur connecté et le bouton de déconnexion."""
    with st.sidebar:
        st.write(f"👤 Connecté : **{st.session_state.get('auth_user', '')}**")
        if st.button("Se déconnecter", key="auth_logout_btn"):
            st.session_state.pop("auth_user", None)
            st.rerun()