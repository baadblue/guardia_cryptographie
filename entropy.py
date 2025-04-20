import math

def calculate_entropy(password):
    lenght_alphabet = 0

    if any(c.isupper() for c in password):
        lenght_alphabet += 26
    if any(c.islower() for c in password):
        lenght_alphabet += 26
    if any(c.isdigit() for c in password):
        lenght_alphabet += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/ " for c in password):
        lenght_alphabet += 28
    
    return math.log2(lenght_alphabet)*len(password)

if __name__ == "__main__":
    print(calculate_entropy("l0l"))

'''
Recommandations de la CNIL pour des niveaux de sécurité équivalent par rapport aux systèmes de vérifications en parallèle du mot de passe : 

- Pour un mot de passe seul : min. 80 d'entropie
    Exemple : p'tite_d0uc€ur!
- Avec mécanisme de captcha, protection contre le brute force, ... : min. 50 d'entropie
    Exemple : H€ll_Yeah!95
- Avec un dispositif d'authentification matériel et personnel : min. 13 d'entropie
    Exemple : l0l 

Dans tous les cas, il est préférable d'avoir un mot de passe ayant une entropie minimum de 80.
'''