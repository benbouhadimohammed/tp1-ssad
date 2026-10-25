import string

def get_cas3_config():
    """
    Configuration pour le Cas 3 (Standard) :
    Combine minuscules, majuscules, chiffres et caractères spéciaux/symboles.
    """
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    default_length = 8  
    return charset, default_length