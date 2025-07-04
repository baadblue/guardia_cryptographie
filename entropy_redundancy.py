import math
from zxcvbn import zxcvbn
import string
import logging

logger = logging.getLogger(__name__)
# Ensure a handler is available if the application doesn't configure one,
# to make warnings visible during development/testing of this module directly.
# A NullHandler is often preferred in libraries to avoid output if not configured.
if not logging.getLogger().hasHandlers(): # Check root logger
    # If no handlers are configured on the root logger, add a basic one for this module's logger.
    # This is mostly for making sure warnings from this module are visible if run standalone or tested.
    # Application should ideally set up its own comprehensive logging.
    # For library code, often a logging.NullHandler() is added to the library's top-level logger
    # to prevent "No handlers could be found" warnings, e.g., logger.addHandler(logging.NullHandler()).
    # Given the project structure, a simple default might be okay for now if not run as part of larger app.
    # Let's assume basicConfig might be called at entry point of a script using this.
    # For now, no specific basicConfig here to avoid overriding app-level config.
    pass


def calculate_redundancy(password, use_relative_max_entropy=False):
    """
    Calculate the redundancy of a password based on its entropy.
    The redundancy is calculated as 1 - (H(X) / H_max).
    H(X) is the entropy of the password (from zxcvbn).
    H_max can be either the theoretical maximum based on a fixed alphabet (default 95 chars)
    or a "relative" maximum based on the character types present in the password.
    
    :param password: password to analyze
    :param use_relative_max_entropy: If True, uses `calculate_max_relative_entropy` for H_max.
                                     Otherwise, uses `calculate_max_entropy` (fixed alphabet of 95).
    :return: redundancy value (0 to 1). Can be negative if entropy > max_entropy (e.g. zxcvbn is optimistic).
    """
    validate_password(password)
    entropy = calculate_entropy(password)

    if use_relative_max_entropy:
        max_entropy_val = calculate_max_relative_entropy(password)
    else:
        max_entropy_val = calculate_max_entropy(password) # Defaults to alphabet size 95

    if max_entropy_val == 0: # Avoid division by zero if password length is 0 (though validation should prevent)
        return 1.0 if entropy == 0 else 0.0 # Or handle as an error/undefined

    return 1 - (entropy / max_entropy_val)

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
    This version assumes a fixed-size alphabet (defaulting to 95, representing common printable ASCII characters)
    for calculating a theoretical maximum entropy if any of those characters *could* be used at each position.
    
    :param password: password to analyze (used for its length)
    :param length_alphabet: The total number of unique characters assumed to be in the possible alphabet.
                            Defaults to 95 (approximating printable ASCII: 26 upper, 26 lower, 10 digits, 33 special).
    :return: maximum theoretical entropy value (in bits) for the given length and alphabet size.
    """
    validate_password(password)
    return (math.log2(length_alphabet)*len(password))

def calculate_max_relative_entropy(password):
    """
    Calculate the maximum entropy for a password based *only* on the character sets
    (uppercase, lowercase, digits, special) actually present in the password string.
    This provides a "tighter" theoretical maximum if we assume the character choices
    were limited to only those types observed in the password.

    The special character set size is assumed to be 33 (string.punctuation + space).
    
    :param password: password to analyze (used for its length and character composition)
    :return: maximum entropy value (in bits) relative to the character sets used in the password.
    """
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
        length_alphabet += 10 # 0-9
    if has_special:
        length_alphabet += 33 # Based on standard US keyboard: string.punctuation (32) + space (1)
                              # Note: string.punctuation is '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

    # If no character types were found (e.g., empty string, though validate_password should prevent this),
    # length_alphabet would be 0, leading to math.log2(0) error.
    # However, validate_password ensures password is not empty.
    # If a password somehow passed validation but had no recognizable characters for these sets,
    # length_alphabet could be 0. Default to 1 to avoid log(0) error, resulting in 0 entropy.
    if length_alphabet == 0 and len(password) > 0: # Should not happen with current validation
        logger.warning("Password '%s' resulted in a zero-size alphabet for relative entropy.", password)
        length_alphabet = 1 # Avoid math error, effectively results in 0 entropy.
    elif length_alphabet == 0 and len(password) == 0: # Also should not happen
        return 0.0


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