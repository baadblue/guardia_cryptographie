import logging

logging.basicConfig(
        filename="app.log",  # Fichier de log
        filemode="a",             # Mode d'écriture : "a" pour ajouter, "w" pour écraser
        level=logging.DEBUG,      # Niveau de log
        format="[%(asctime)s] - %(name)s - %(levelname)s - %(message)s",  # Format des messages
        encoding="utf-8"          # Encodage
    )
logger = logging.getLogger("CesarCipher")

class CesarCipher:
    def __init__(self):
        pass

    def cesar_encryption(self, chain, key, reverse=False):
        """
        Chiffre une chaîne de caractères en utilisant le chiffrement de César.
        Le résultat est une nouvelle chaîne de caractères en majuscule et sans caractères spéciaux.
        
        :param chain: chaîne à chiffrer
        :param key: clé de chiffrement (décalage)
        :return: chaîne chiffrée
        """
        if not isinstance(chain, str):
            logger.error("TypeError : La chaîne à chiffrer doit être une chaîne de caractères.")
            raise TypeError("La chaîne à chiffrer doit être une chaîne de caractères.")
        if not isinstance(key, int):
            logger.error("TypeError : La clé doit être un entier.")
            raise TypeError("La clé doit être un entier.")
        if not chain:
            logger.error("ValueError : La chaîne à chiffrer ne peut pas être vide.")
            raise ValueError("La chaîne à chiffrer ne peut pas être vide.")
        if not key:
            logger.error("ValueError : La clé ne peut pas être vide.")
            raise ValueError("La clé ne peut pas être vide.")
        
        logger.debug("Début du chiffrement avec la clé : %d", key)
        if reverse:
            key = -key
        encoded_chain = ""
        for letter in chain:
            car = ord(letter)
            if 65 <= car <= 90:
                encoded_chain += chr((car - 65 + key) % 26 + 65)
            elif 97 <= car <= 122:
                encoded_chain += chr((car - 97 + key) % 26 + 65)
        logger.debug("Chiffrement terminé.")
        return encoded_chain
    
    def cesar_decryption(self, chain, key):
        logger.debug("Début du déchiffrement avec la clé : %d", key)
        return self.cesar_encryption(chain, key, reverse=True)

if __name__ == "__main__":
    print(CesarCipher().cesar_encryption("Hello World!", 0))
    print(CesarCipher().cesar_decryption("KHOORZRUOG", 3))