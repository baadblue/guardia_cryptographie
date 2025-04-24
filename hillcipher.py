from dotenv import load_dotenv
import os
import numpy as np
from math import gcd
import secrets
import json
import logging

logger = logging.getLogger("HillCipher")

class HillCipher():
    def __init__(self, load_from_env=True):
        """
        Initialise la classe HillCipher. Charge les matrices de clé et inverse depuis les variables d'environnement
        
        :param load_from_env: si True, charge les matrices depuis les variables d'environnement
        """
        logger.debug("Initialisation de la classe HillCipher.")

        self.key_matrix = None
        self.key_matrix_inverse = None
        if load_from_env:
            self.load_key_matrix()
        else:
            self.key_matrix = self.generate_key_matrix()
            self.key_matrix_inverse = self.generate_key_matrix_inverse(self.key_matrix)
        logger.debug("Clé et matrice inverse initialisées.")


    def load_key_matrix(self):
        """
        Charge la matrice de la clé et la matrice inverse de la clé à partir des variables d'environnement.
        Si elles ne sont pas définies, génère une nouvelle matrice de clé et sa matrice inverse.
                
        Code erreur :
        1 : Matrice de clé mal formée dans le fichier .env
        2 : Matrice vide
        3 : Matrice non carrée
        4 : Matrice de clé non inversible
        5 : Erreur inattendue
        """
        logger.debug("Chargement des matrices de clé depuis les variables d'environnement.")
        if not os.getenv("HILL_KEY") or not os.getenv("HILL_KEY_INVERSE"):
            logger.debug("Variables d'environnement non définies.")
            raise ValueError("Erreur : variables d'environnement non définies.", 1)
            
        load_dotenv()

        try:
            self.key_matrix = json.loads(os.getenv("HILL_KEY", "[]"))
            self.key_matrix_inverse = json.loads(os.getenv("HILL_KEY_INVERSE", "[]"))
            logger.debug("Matrices de clé chargées depuis les variables d'environnement.")
        except json.JSONDecodeError as e:
            logger.error("Erreur lors du chargement des matrices de clé : %s", str(e))
            raise ValueError("Erreur : matrices de clé mal formées.", 1)
        except Exception as e:
            logger.exception("Erreur inattendue lors du chargement des matrices de clé : %s", str(e))
            raise ValueError("Erreur inattendue lors du chargement des matrices de clé.", 5)

        if not self.key_matrix or not self.key_matrix_inverse:
            logger.error("Les matrices de clé ou inverse sont vides.")
            raise ValueError("Erreur : matrice de clé vide.", 2)

        if not self.validate_matrix(self.key_matrix) or not self.validate_matrix(self.key_matrix_inverse):
            logger.error("Les matrices de clé ou inverse ne sont pas carrées.")
            raise ValueError("Erreur : matrice de clé non carrée.", 3)

        if not self.is_invertible(self.key_matrix)[0] or not self.is_invertible(self.key_matrix_inverse)[0]:
            logger.error("Les matrices de clé ou inverse ne sont pas inversibles.")
            raise ValueError("Erreur : matrice de clé non inversible.", 4)

        logger.debug("Matrices de clé et inverse chargées avec succès.")

    def validate_matrix(self, matrix):
        """
        Vérifie si la matrice est carrée et contient uniquement des entiers.

        :param matrix: matrice à valider
        :return: True si la matrice est valide, sinon lève une exception
        """
        logger.debug("Validation de la matrice : %s", matrix)

        if isinstance(matrix, np.ndarray):
            matrix = matrix.tolist()

        if not isinstance(matrix, list) or not all(isinstance(row, list) for row in matrix):
            logger.error("La clé doit être une liste de listes.")
            raise ValueError("La clé doit être une liste de listes.")
        if len(matrix) != len(matrix[0]):
            logger.error("La clé doit être une matrice carrée.")
            raise ValueError("La clé doit être une matrice carrée.")
        if not all(isinstance(num, int) for row in matrix for num in row):
            logger.error("La clé doit contenir uniquement des entiers.")
            raise ValueError("La clé doit contenir uniquement des entiers.")
        logger.debug("Validation de la matrice réussie.")
        return True

    def generate_key_matrix(self, size=4, max_attempts=1000):
        """
        Génère une matrice de clé aléatoire de taille size x size.

        :param size: taille de la matrice
        :param max_attempts: nombre maximum de tentatives pour générer une matrice inversible
        :return: matrice de clé générée 
        """
        logger.debug("Génération d'une matrice de clé de taille %dx%d.", size, size)
        if size < 1:
            logger.error("La taille de la matrice doit être supérieure à 0.")
            raise ValueError("La taille de la matrice doit être supérieure à 0.")
        attempts = 0
        while attempts < max_attempts:
            matrix = [[secrets.randbelow(26) for _ in range(size)] for _ in range(size)]
            if self.is_invertible(matrix)[0]:
                try:
                    self.validate_matrix(matrix)
                    logger.debug("Matrice de clé générée après %d tentatives.", attempts + 1)
                    return matrix
                except ValueError:
                    logger.debug("Matrice générée invalide, nouvelle tentative.")
                    continue
            attempts += 1
        logger.error("Impossible de générer une matrice inversible après %d tentatives.", max_attempts)
        raise RuntimeError(f"Impossible de générer une matrice inversible après {max_attempts} tentatives.")

    def is_invertible(self, matrix, mod=26):
        """
        Vérifie si la matrice est inversible modulo mod.
        :param matrix: matrice à vérifier
        :param mod: modulo
        :return: True si la matrice est inversible, False sinon
        :return: déterminant de la matrice
        """
        logger.debug("Vérification de l'inversibilité de la matrice : %s", matrix)
        if not self.validate_matrix(matrix):
            logger.error("La matrice fournie n'est pas valide.")
            raise ValueError("La matrice fournie n'est pas valide.")
        det = int(np.round(np.linalg.det(matrix))) % mod
        logger.debug("Déterminant calculé : %d", det)
        return gcd(det, mod) == 1, det

    def modinv(self, a, m):
        """
        Trouve l'inverse modulaire de a modulo m.

        :param a: entier dont on veut l'inverse modulaire
        :param m: modulo
        :return: inverse modulaire de a modulo m
        """
        logger.debug("Calcul de l'inverse modulaire de %d modulo %d.", a, m)
        if gcd(a, m) != 1:
            logger.error("Pas d'inverse modulaire pour %d modulo %d.", a, m)
            raise ValueError(f"Pas d'inverse modulaire pour {a} modulo {m}.")
        for x in range(1, m):
            if (a * x) % m == 1:
                logger.debug("Inverse modulaire trouvé : %d", x)
                return x
        logger.error("Erreur inattendue lors du calcul de l'inverse modulaire.")
        raise RuntimeError("Erreur inattendue lors du calcul de l'inverse modulaire.")

    def generate_key_matrix_inverse(self, matrix, mod=26):
        """
        Calcule la matrice inverse de la matrice fournie modulo mod.

        :param matrix: matrice à inverser
        :param mod: modulo
        :return: matrice inverse de la matrice fournie
        """
        logger.debug("Calcul de la matrice inverse modulo %d.", mod)
        if not self.validate_matrix(matrix):
            logger.error("La matrice fournie n'est pas valide.")
            raise ValueError("La matrice fournie n'est pas valide.")

        matrix = np.array(matrix, dtype=int)

        is_invertible, det = self.is_invertible(matrix, mod)
        if not is_invertible:
            logger.error("Matrice non inversible modulo %d.", mod)
            raise ValueError("Matrice non inversible modulo {}.".format(mod))

        cofactors = np.zeros_like(matrix, dtype=int)
        for r in range(matrix.shape[0]):
            for c in range(matrix.shape[1]):
                minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
                cofactors[r, c] = ((-1) ** (r + c)) * int(round(np.linalg.det(minor)))

        det_inv = self.modinv(det, mod)
        adjugate = np.transpose(cofactors) % mod
        inverse = (det_inv * adjugate) % mod
        logger.debug("Matrice inverse calculée avec succès.")
        return inverse.tolist()

    def split_text(self, text, size=4):
        """
        Divise le texte en blocs de taille size. Les caractères non alphabétiques sont ignorés.
        Si le dernier bloc est plus court que size, il est complété avec 'X'.
        
        :param text: texte à diviser
        :param size: taille des blocs
        :return: liste de blocs de texte
        """
        logger.debug("Division du texte en blocs de taille %d.", size)
        splited_text = [""]
        index = 0
        for car in text:
            if car.isalpha():
                if index == size:
                    splited_text.append("")
                    index = 0
                splited_text[-1] += car.upper()
                index += 1
        while len(splited_text[-1]) != size:
            splited_text[-1] += 'X'
        logger.debug("Texte divisé en blocs : %s", splited_text)
        return splited_text

    def hill_encryption(self, text, mod=0):
        """
        Chiffre ou déchiffre le texte en utilisant la matrice de clé.

        :param text: texte à chiffrer ou déchiffrer
        :param mod: 0 pour le chiffrement, 1 pour le déchiffrement
        :return: texte chiffré ou déchiffré
        """
        logger.debug("Début du chiffrement/déchiffrement du texte.")
        matrix = self.key_matrix if mod == 0 else self.key_matrix_inverse
        block_size = len(matrix)
        text = self.split_text(text, block_size)
        encrypted_text = ""
        for block in text:
            if len(block) != block_size:
                logger.error("La taille du bloc ne correspond pas à la taille de la matrice.")
                raise ValueError("La taille du bloc ne correspond pas à la taille de la matrice.")
            for i in range(len(block)):
                somme = 0
                for j in range(len(block)):
                    letter_nbr = ord(block[j]) - 65
                    somme += letter_nbr * matrix[i][j]
                encrypted_text += chr((somme % 26) + 65)
        logger.debug("Chiffrement/déchiffrement terminé.")
        return encrypted_text

    def hill_decryption(self, text):
        """
        Déchiffre le texte en utilisant la matrice de clé inverse.

        :param text: texte à déchiffrer
        :return: texte déchiffré
        """
        logger.debug("Début du déchiffrement du texte.")
        if not self.key_matrix_inverse:
            logger.error("La matrice inverse n'est pas définie.")
            raise ValueError("La matrice inverse n'est pas définie.")
        result = self.hill_encryption(text, 1)
        logger.debug("Déchiffrement terminé.")
        return result
