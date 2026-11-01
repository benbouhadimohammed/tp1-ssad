import pytest
from encryption_approaches import caesar


def test_exemple_du_cours():
    assert caesar.encrypt("ATTAQUE DEMAIN A LAUBE", 3) == "DWWDTXH GHPDLQ D ODXEH"


def test_aller_retour():
    m = "Bonjour le monde, 2026 !"
    assert caesar.decrypt(caesar.encrypt(m, 7), 7) == m


def test_bouclage():
    assert caesar.encrypt("xyz", 3) == "abc"


def test_sens_gauche():
    assert caesar.encrypt("abc", 1, sens="gauche") == "zab"
    assert caesar.decrypt("zab", 1, sens="gauche") == "abc"


def test_accents():
    assert caesar.encrypt("Été", 3) == "Hwh"


def test_cle_faible():
    with pytest.raises(ValueError):
        caesar.encrypt("abc", 26)
    with pytest.raises(ValueError):
        caesar.encrypt("abc", "abc")


def test_cryptogramme_du_cours():
    assert caesar.decrypt("ATRWXUUGTBTCI", 15) == "LECHIFFREMENT"