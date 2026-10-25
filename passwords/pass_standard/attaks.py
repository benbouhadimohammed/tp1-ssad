import itertools
import time

def brute_force_cas3(target_password, alphabet):
    """
    Attaque par Force Brute optimisée pour le Cas 3 
    (teste les combinaisons pour la longueur exacte du mot de passe).
    """
    start_time = time.time()
    attempts = 0
    length = len(target_password)
    
    # Utilisation d'itertools pour une recherche rapide en arrière-plan
    for combination in itertools.product(alphabet, repeat=length):
        attempts += 1
        guess = "".join(combination)
        
        if guess == target_password:
            return True, guess, attempts, time.time() - start_time
            
    return False, None, attempts, time.time() - start_time

def dictionary_attack_cas3(target_password, dictionary_list):
    """
    Attaque par Dictionnaire rapide pour tester des mots de passe courants.
    """
    start_time = time.time()
    for attempts, word in enumerate(dictionary_list, start=1):
        clean_word = word.strip()
        if clean_word == target_password:
            return True, clean_word, attempts, time.time() - start_time
            
    return False, None, len(dictionary_list), time.time() - start_time