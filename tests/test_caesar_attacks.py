from encryption_approaches import caesar, caesar_attacks


def test_force_brute_trouve_le_clair():
    chiffre = caesar.encrypt("bonjour", 5)
    resultats = caesar_attacks.brute_force(chiffre)
    assert len(resultats) == 25
    assert (5, "bonjour") in resultats


def test_attaque_lettre_frequente():
    clair = "le chiffrement de cesar est tres facile a casser car il n y a que vingt cinq cles possibles"
    chiffre = caesar.encrypt(clair, 7)
    cle, texte = caesar_attacks.attaque_lettre_frequente(chiffre)
    assert cle == 7
    assert texte == clair