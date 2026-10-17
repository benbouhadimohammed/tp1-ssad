import tkinter as tk
from tkinter import ttk


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TP1 - Encryption Framework")
        self.geometry("760x560")

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True)

        self.tab_crypto = ttk.Frame(tabs)
        self.tab_pwd = ttk.Frame(tabs)
        self.tab_attacks = ttk.Frame(tabs)
        self.tab_integrity = ttk.Frame(tabs)

        tabs.add(self.tab_crypto, text="Chiffrement")
        tabs.add(self.tab_pwd, text="Mots de passe")
        tabs.add(self.tab_attacks, text="Attaques")
        tabs.add(self.tab_integrity, text="Intégrité")

        self.build_crypto_tab()
        self.build_password_tab()
        self.build_attacks_tab()
        self.build_integrity_tab()

    # ---------- Onglet 1 : Chiffrement ----------
    def build_crypto_tab(self):
        f = self.tab_crypto

        opt = ttk.LabelFrame(f, text="Paramètres")
        opt.pack(fill="x", padx=10, pady=8)
        ttk.Label(opt, text="Algorithme :").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.algo = ttk.Combobox(opt, values=["César", "Playfair", "Hill"], state="readonly", width=15)
        self.algo.current(0)
        self.algo.grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(opt, text="Clé :").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.key = ttk.Entry(opt, width=30)
        self.key.grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(opt, text="Sens (César) :").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.direction = ttk.Combobox(opt, values=["Droite", "Gauche"], state="readonly", width=15)
        self.direction.current(0)
        self.direction.grid(row=2, column=1, sticky="w", padx=5)

        a = ttk.LabelFrame(f, text="Entité A (émetteur)")
        a.pack(fill="x", padx=10, pady=8)
        ttk.Label(a, text="Message :").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.msg = ttk.Entry(a, width=60)
        self.msg.grid(row=0, column=1, padx=5)
        ttk.Button(a, text="Chiffrer et envoyer").grid(row=1, column=1, sticky="w", padx=5, pady=5)

        c = ttk.LabelFrame(f, text="Canal (message transmis)")
        c.pack(fill="x", padx=10, pady=8)
        self.cipher_var = tk.StringVar()
        ttk.Entry(c, textvariable=self.cipher_var, width=75).pack(padx=5, pady=5)

        b = ttk.LabelFrame(f, text="Entité B (récepteur)")
        b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Déchiffrer").pack(anchor="w", padx=5, pady=5)
        self.result_var = tk.StringVar()
        ttk.Label(b, textvariable=self.result_var, font=("Arial", 12, "bold")).pack(anchor="w", padx=5)

    # ---------- Onglet 2 : Mots de passe ----------
    def build_password_tab(self):
        f = self.tab_pwd

        case = ttk.LabelFrame(f, text="Cas de mot de passe")
        case.pack(fill="x", padx=10, pady=8)
        self.pwd_case = tk.IntVar(value=1)
        ttk.Radiobutton(case, text="Cas 1 : 3 caractères dans {0,1}", variable=self.pwd_case, value=1).pack(anchor="w", padx=5)
        ttk.Radiobutton(case, text="Cas 2 : 4 caractères dans {1,2,3,4}", variable=self.pwd_case, value=2).pack(anchor="w", padx=5)
        ttk.Radiobutton(case, text="Cas 3 : a-z, A-Z, 0-9, symboles", variable=self.pwd_case, value=3).pack(anchor="w", padx=5)

        gen = ttk.LabelFrame(f, text="Mot de passe")
        gen.pack(fill="x", padx=10, pady=8)
        ttk.Label(gen, text="Mot de passe :").grid(row=0, column=0, padx=5, pady=5)
        self.pwd_entry = ttk.Entry(gen, width=30)
        self.pwd_entry.grid(row=0, column=1, padx=5)
        ttk.Button(gen, text="Générer").grid(row=0, column=2, padx=5)

        prot = ttk.LabelFrame(f, text="Protection")
        prot.pack(fill="x", padx=10, pady=8)
        ttk.Button(prot, text="Hacher avec sel").pack(side="left", padx=5, pady=5)
        self.hash_var = tk.StringVar()
        ttk.Entry(prot, textvariable=self.hash_var, width=60).pack(side="left", padx=5)

    # ---------- Onglet 3 : Attaques ----------
    def build_attacks_tab(self):
        f = self.tab_attacks

        top = ttk.LabelFrame(f, text="Attaque sur mot de passe")
        top.pack(fill="x", padx=10, pady=8)
        ttk.Button(top, text="Force brute").pack(side="left", padx=5, pady=5)
        ttk.Button(top, text="Dictionnaire").pack(side="left", padx=5)
        ttk.Label(top, text="Temps :").pack(side="left", padx=(20, 2))
        self.time_var = tk.StringVar(value="-")
        ttk.Label(top, textvariable=self.time_var).pack(side="left")

        mid = ttk.LabelFrame(f, text="Attaque sur les chiffrements (failles)")
        mid.pack(fill="x", padx=10, pady=8)
        ttk.Button(mid, text="Casser César").pack(side="left", padx=5, pady=5)
        ttk.Button(mid, text="Casser Playfair").pack(side="left", padx=5)
        ttk.Button(mid, text="Casser Hill").pack(side="left", padx=5)

        out = ttk.LabelFrame(f, text="Résultats")
        out.pack(fill="both", expand=True, padx=10, pady=8)
        self.attack_out = tk.Text(out, height=12)
        self.attack_out.pack(fill="both", expand=True, padx=5, pady=5)

    # ---------- Onglet 4 : Intégrité ----------
    def build_integrity_tab(self):
        f = self.tab_integrity

        a = ttk.LabelFrame(f, text="Entité A")
        a.pack(fill="x", padx=10, pady=8)
        ttk.Label(a, text="Message :").grid(row=0, column=0, padx=5, pady=3, sticky="w")
        self.int_msg = ttk.Entry(a, width=60)
        self.int_msg.grid(row=0, column=1, padx=5)
        ttk.Button(a, text="Calculer l'empreinte").grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.int_hash = tk.StringVar()
        ttk.Entry(a, textvariable=self.int_hash, width=60).grid(row=2, column=1, padx=5, pady=3)

        c = ttk.LabelFrame(f, text="Canal (modifiable pour simuler une attaque)")
        c.pack(fill="x", padx=10, pady=8)
        self.int_channel = tk.StringVar()
        ttk.Entry(c, textvariable=self.int_channel, width=75).pack(padx=5, pady=5)

        b = ttk.LabelFrame(f, text="Entité B")
        b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Vérifier").pack(anchor="w", padx=5, pady=5)
        self.int_result = tk.StringVar(value="-")
        ttk.Label(b, textvariable=self.int_result, font=("Arial", 12, "bold")).pack(anchor="w", padx=5)


def run():
    App().mainloop()