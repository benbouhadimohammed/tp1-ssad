def get_cas1_config():
    """
    Configuration pour le Cas 1 :
    Mot de passe composé de 3 caractères (valeurs 0 et 1 uniquement).
    """
    charset = ['0', '1']
    default_length = 3
    return charset, default_length