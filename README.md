# Guardia Cryptographie

Ce projet implémente plusieurs algorithmes de cryptographie, notamment les chiffrements de César, Vigenère et Hill, ainsi que des outils pour analyser l'entropie et la redondance des mots de passe.
Ce projet a été réalisé dans le cadre du module *Techniques de sécurisation cryptographique* de la première année du Bachelor *Développeur Informatique, option Cybersécurité* à l'école Guardia Cybersecurity School.

## Fonctionnalités

- **César Cipher** :
  - Chiffrement et déchiffrement avec une clé donnée.
  - Déchiffrement par force brute.
  - Analyse de fréquence pour estimer la clé.

- **Vigenère Cipher** :
  - Chiffrement et déchiffrement avec une clé alphabétique.
  - Gestion des caractères non alphabétiques.

- **Hill Cipher** :
  - Chiffrement et déchiffrement basé sur des matrices carrées.
  - Génération automatique de matrices de clé et de clé inverse.
  - Validation des matrices (carrées, inversibles, etc.).

- **Analyse d'entropie et de redondance** :
  - Calcul de l'entropie d'un mot de passe.
  - Calcul de la redondance.
  - Vérification de la sécurité des mots de passe selon les recommandations de la CNIL.

## Prérequis

- Python 3.8 ou supérieur
- Bibliothèques Python :
  - `numpy`
  - `python-dotenv`
  - `zxcvbn`
  - `pytest` (pour les tests)

## Installation

1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/votre-utilisateur/guardia_cryptographie.git
   cd guardia_cryptographie
   ```
2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

3. Configurez les variables d'environnement pour le Hill Cipher dans un fichier `.env` :
   ```properties
   HILL_KEY=[[16,24,20,21],[15,1,12,3],[3,4,7,18],[22,22,5,13]]
   # HILL_KEY_INVERSE is optional. If not provided or invalid, it will be calculated from HILL_KEY.
   # Example: HILL_KEY_INVERSE=[[7,14,9,9],[14,5,11,5],[9,10,16,1],[11,10,0,10]]
   ```

## Utilisation

### Exemple : Chiffrement de César
```python
from cesar import CesarCipher

cipher = CesarCipher()
encrypted = cipher.cesar_encryption("HELLO", 3)
print("Message chiffré :", encrypted)

decrypted = cipher.cesar_decryption(encrypted, 3)
print("Message déchiffré :", decrypted)
```

### Exemple : Chiffrement de Vigenère
```python
from vigenere import VigenereCipher

cipher = VigenereCipher()
encrypted = cipher.vigenere_encryption("HELLO WORLD!", "KEY")
print("Message chiffré :", encrypted)
```

### Exemple : Chiffrement de Hill
```python
from hillcipher import HillCipher

cipher = HillCipher(load_from_env=True)
encrypted = cipher.hill_encryption("HELLO")
print("Message chiffré :", encrypted)

decrypted = cipher.hill_decryption(encrypted)
print("Message déchiffré :", decrypted)
```

### Exemple : Analyse d'entropie
```python
from entropy_redundancy import calculate_entropy, calculate_redundancy

password = "H€ll_Yeah!99"
entropy = calculate_entropy(password)
redundancy = calculate_redundancy(password)

print("Entropie :", entropy)
print("Redondance :", redundancy)
```

## Tests

Pour exécuter les tests unitaires, utilisez la commande suivante :
```bash
pytest
```

## Recommandations de sécurité (CNIL)

- **Mot de passe seul** : Minimum 80 bits d'entropie.
- **Avec protection (captcha, anti-brute force)** : Minimum 50 bits d'entropie.
- **Avec dispositif d'authentification matériel** : Minimum 13 bits d'entropie.

*Ce document a été écrit avec Copilot.*