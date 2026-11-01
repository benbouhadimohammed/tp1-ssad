import hashlib

def calculer_hash_sha256(message):
    """
    Calcule l'empreinte cryptographique (Hash SHA-256) d'un message.
    Garantit l'intégrité : si un seul caractère change, le hash est totalement différent.
    """
    if not message:
        return ""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def verifier_integrite(message_recu, hash_original):
    """
    Vérifie si le message reçu correspond bien au hash d'origine.
    Renvoie True si l'intégrité est intacte, False sinon.
    """
    hash_actuel = calculer_hash_sha256(message_recu)
    return hash_actuel == hash_original