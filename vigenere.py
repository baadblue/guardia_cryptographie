from cesar import CesarCipher
import logging

logging.basicConfig(
        filename="app.log",  # Fichier de log
        filemode="a",             # Mode d'écriture : "a" pour ajouter, "w" pour écraser
        level=logging.DEBUG,      # Niveau de log
        format="[%(asctime)s] - %(name)s - %(levelname)s - %(message)s",  # Format des messages
        encoding="utf-8"          # Encodage
    )

logger = logging.getLogger("VigenereCipher")

class VigenereCipher:
    def __init__(self):
        pass

    def vigenere_encryption(self, chain, key):
        """
        Encrypts a string using the Vigenère cipher with a given key.

        Non-alphabetic characters in the input string are ignored.
        
        :param chain: the string to encrypt
        :param key: the key to use for encryption
        :return: the encrypted string
        """
        logger.debug("Début du chiffrement avec la chaîne : '%s' et la clé : '%s'.", chain, key)

        if not isinstance(chain, str):
            logger.error("TypeError : La chaîne à chiffrer doit être une chaîne de caractères.")
            raise TypeError("La chaîne à chiffrer doit être une chaîne de caractères.")
        if not isinstance(key, str):
            logger.error("TypeError : La clé doit être une chaîne de caractères.")
            raise TypeError("La clé doit être une chaîne de caractères.")
        if not chain:
            logger.error("ValueError : La chaîne à chiffrer ne peut pas être vide.")
            raise ValueError("La chaîne à chiffrer ne peut pas être vide.")
        if not key:
            logger.error("ValueError : La clé ne peut pas être vide.")
            raise ValueError("La clé ne peut pas être vide.")
        if not key.isalpha():
            logger.error("ValueError : La clé doit contenir uniquement des lettres.")
            raise ValueError("La clé doit contenir uniquement des lettres.")

        keyIndex = 0
        key = key.upper()
        chain = chain.upper()

        newChain = []
        for elt in chain:
            if elt.isalpha():
                newChain.append(CesarCipher().cesar_encryption(elt, ord(key[keyIndex]) - 65))
                keyIndex = (keyIndex + 1) % len(key)

        encrypted_chain = "".join(newChain)
        logger.debug("Chiffrement terminé. Résultat : '%s'.", encrypted_chain)
        return encrypted_chain
 
if __name__ == "__main__":
    print(VigenereCipher().vigenere_encryption("Hello world!", "test"))