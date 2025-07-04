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
        
        load_dotenv()
        env_key = os.getenv("HILL_KEY")
        env_key_inverse = os.getenv("HILL_KEY_INVERSE")

        if not env_key:
            logger.error("Variable d'environnement HILL_KEY non définie.")
            raise ValueError("Erreur : HILL_KEY non définie.", 1)

        try:
            self.key_matrix = json.loads(env_key)
            logger.debug("Matrice de clé HILL_KEY chargée depuis les variables d'environnement.")
        except json.JSONDecodeError as e:
            logger.error("Erreur lors du chargement de HILL_KEY : %s", str(e))
            raise ValueError("Erreur : HILL_KEY mal formée.", 1)

        if not self.key_matrix:
            logger.error("HILL_KEY est vide.")
            raise ValueError("Erreur : HILL_KEY est vide.", 2)
        if not self.validate_matrix(self.key_matrix): # validate_matrix raises its own errors
             # Error already logged by validate_matrix if it returns False implicitly (though it raises)
            raise ValueError("Erreur : HILL_KEY n'est pas une matrice valide.", 3) # Should be caught by validate_matrix
        if not self.is_invertible(self.key_matrix)[0]:
            logger.error("HILL_KEY n'est pas inversible.")
            raise ValueError("Erreur : HILL_KEY non inversible.", 4)

        if env_key_inverse:
            try:
                self.key_matrix_inverse = json.loads(env_key_inverse)
                logger.debug("Matrice de clé inverse HILL_KEY_INVERSE chargée.")
                if not self.key_matrix_inverse: # check if empty list after load
                    logger.warn("HILL_KEY_INVERSE est définie mais vide dans .env. Tentative de calcul à partir de HILL_KEY.")
                    self.key_matrix_inverse = None # Force recalculation
                elif not self.validate_matrix(self.key_matrix_inverse):
                    raise ValueError("Erreur : HILL_KEY_INVERSE n'est pas une matrice valide.", 3)
                elif not self.is_invertible(self.key_matrix_inverse)[0]: # Should be an inverse, so also invertible
                    logger.warn("HILL_KEY_INVERSE chargée n'est pas inversible. Tentative de calcul à partir de HILL_KEY.")
                    self.key_matrix_inverse = None # Force recalculation
            except json.JSONDecodeError as e:
                logger.warn("Erreur lors du chargement de HILL_KEY_INVERSE : %s. Tentative de calcul à partir de HILL_KEY.", str(e))
                self.key_matrix_inverse = None # Force recalculation
            except ValueError as e: # Catch validation errors for inverse
                logger.warn(f"Erreur de validation pour HILL_KEY_INVERSE: {e}. Tentative de calcul à partir de HILL_KEY.")
                self.key_matrix_inverse = None # Force recalculation

        if not self.key_matrix_inverse:
            logger.info("HILL_KEY_INVERSE non chargée ou invalide, tentative de calcul à partir de HILL_KEY.")
            try:
                self.key_matrix_inverse = self.generate_key_matrix_inverse(self.key_matrix)
                logger.info("Matrice de clé inverse calculée avec succès à partir de HILL_KEY.")
            except Exception as e:
                logger.error("Impossible de calculer HILL_KEY_INVERSE à partir de HILL_KEY : %s", str(e))
                raise ValueError("Erreur : Impossible de calculer HILL_KEY_INVERSE.", 5)

        # Final check for the inverse matrix (either loaded or generated)
        if not self.key_matrix_inverse: # Should not happen if generation was successful
             logger.error("La matrice inverse n'a pas pu être définie.")
             raise ValueError("Erreur : La matrice inverse n'a pas pu être définie.", 2)
        # Validation for the determined key_matrix_inverse is implicitly done if generated.
        # If loaded, it was validated or generation was attempted.

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
        processed_chars = [c.upper() for c in text if c.isalpha()]

        # Pad with 'X' if necessary
        while len(processed_chars) % size != 0:
            processed_chars.append('X')

        if not processed_chars and size > 0: # Handle empty text case after filtering
            processed_chars = ['X'] * size

        splitted_text = []
        for i in range(0, len(processed_chars), size):
            splitted_text.append("".join(processed_chars[i:i+size]))

        # Ensure that if the original text was empty and size > 0,
        # we still return a block of 'X's of the correct size.
        # This also handles the case where text might become empty after filtering non-alpha chars.
        if not splitted_text and size > 0:
             splitted_text.append('X' * size)
        elif splitted_text and len(splitted_text[-1]) == 0 and size > 0 : # if last block is empty string
            splitted_text[-1] = 'X' * size


        logger.debug("Texte divisé en blocs : %s", splitted_text)
        return splitted_text

    def hill_encryption(self, text, mod=0):
        """
        Chiffre ou déchiffre le texte en utilisant la matrice de clé.

        :param text: texte à chiffrer ou déchiffrer
        :param mod: 0 pour le chiffrement, 1 pour le déchiffrement
        :return: texte chiffré ou déchiffré
        """
        logger.debug("Début du chiffrement/déchiffrement du texte.")
        current_key_matrix = self.key_matrix if mod == 0 else self.key_matrix_inverse

        if not current_key_matrix:
            err_msg = "Matrice de clé non disponible pour le chiffrement." if mod == 0 else "Matrice de clé inverse non disponible pour le déchiffrement."
            logger.error(err_msg)
            raise ValueError(err_msg)

        block_size = len(current_key_matrix)
        text_blocks = self.split_text(text, block_size) # Renamed to avoid conflict

        # Ensure the key matrix is a NumPy array for np.dot()
        np_key_matrix = np.array(current_key_matrix, dtype=int)

        result_chars = []
        for block in text_blocks:
            if len(block) != block_size:
                # This should ideally not happen if split_text works correctly
                logger.error("La taille du bloc (%d) ne correspond pas à la taille de la matrice (%d). Bloc: '%s'", len(block), block_size, block)
                raise ValueError("La taille du bloc ne correspond pas à la taille de la matrice.")

            # Convert block characters to numerical vector (0-25)
            block_vector = np.array([ord(char) - 65 for char in block], dtype=int)

            # Perform matrix multiplication: result_vector = key_matrix * block_vector (mod 26)
            encrypted_vector = np.dot(np_key_matrix, block_vector) % 26

            # Convert numerical vector back to characters
            for num in encrypted_vector:
                result_chars.append(chr(num + 65))

        encrypted_text = "".join(result_chars)
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
