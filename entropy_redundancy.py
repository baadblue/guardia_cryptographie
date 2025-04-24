import math
from zxcvbn import zxcvbn
import string

def calculate_redundancy(password):
    """
    Calculate the redundancy of a password based on its entropy.
    The redundancy is calculated as 1 - (H(X) / Hmax). H(X) is the entropy of the password and Hmax is the maximum entropy.
    
    :param password: password to analyze
    :return: redundancy value (0 to 1)"""
    validate_password(password)
    entropy = calculate_entropy(password)
    max_entropy = calculate_max_entropy(password)
    return 1 - (entropy/max_entropy)

def calculate_entropy(password):
    """
    Calculate the entropy of a password using the zxcvbn library.
    The entropy is calculated as log2(guesses).
    
    :param password: password to analyze
    :return: entropy value (in bits)"""
    validate_password(password)
    try:
        result = zxcvbn(password)
        return math.log2(result['guesses'])
    except Exception as e:
        raise RuntimeError(f"Erreur lors du calcul de l'entropie : {str(e)}")

def calculate_max_entropy(password, length_alphabet=95):
    """
    Calculate the maximum entropy of a password based on its length and character set.
    The maximum entropy is calculated as log2(alphabet_size) * length of the password.
    By default, the alphabet size is set to 95 (printable ASCII characters).
    
    :param password: password to analyze
    :return: maximum entropy value (in bits)"""
    validate_password(password)
    return (math.log2(length_alphabet)*len(password))

def calculate_max_relative_entropy(password):
    """
    Calculate the maximum relative entropy of a password based on its length and character set.
    
    :param password: password to analyze
    :return: maximum relative entropy value (in bits)"""
    validate_password(password)
    length_alphabet = 0
    has_upper, has_lower, has_digit, has_special = False, False, False, False

    for c in password:
        if c.isupper():
            has_upper = True
        elif c.islower():
            has_lower = True
        elif c.isdigit():
            has_digit = True
        elif c in string.punctuation or c.isspace():
            has_special = True

    if has_upper:
        length_alphabet += 26
    if has_lower:
        length_alphabet += 26
    if has_digit:
        length_alphabet += 10
    if has_special:
        length_alphabet += 33

    return calculate_max_entropy(password, length_alphabet)

def is_password_secure(password):
    validate_password(password)
    entropy = calculate_max_entropy(password)
    return entropy >= 80

def validate_password(password):
    if not password or not isinstance(password, str):
        raise ValueError("Le mot de passe doit être une chaîne de caractères non vide.")

if __name__ == "__main__":
    password = "H€ll_Yeah!99"
    print("Mot de passe : ", password)
    print("Approximate entropy :", calculate_entropy(password))
    print("Redondance : ", calculate_redundancy(password))
    print("Max entropy : ", calculate_max_entropy(password))

'''
Recommandations de la CNIL pour des niveaux de sécurité équivalent par rapport aux systèmes de vérifications en parallèle du mot de passe : 

- Pour un mot de passe seul : min. 80 d'entropie maximum théorique
    Exemple : p'tite_d0uc€ur!
- Avec mécanisme de captcha, protection contre le brute force, ... : min. 50 d'entropie maximum théorique
    Exemple : H€ll_Yeah!95
- Avec un dispositif d'authentification matériel et personnel : min. 13 d'entropie maximum théorique
    Exemple : l0l 

Dans tous les cas, il est préférable d'avoir un mot de passe ayant une entropie minimum de 80.
'''