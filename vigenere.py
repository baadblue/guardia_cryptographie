from cesar import CesarCipher
import logging

# logging.basicConfig should ideally be called by the application using this module,
# not within the module itself, to avoid conflicts if other modules also use logging.
# We will still define a logger for use within this class.
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
        cesar_cipher_instance = CesarCipher() # Instantiate once
        for elt in chain:
            if elt.isalpha():
                newChain.append(cesar_cipher_instance.cesar_encryption(elt, ord(key[keyIndex]) - 65))
                keyIndex = (keyIndex + 1) % len(key)

        encrypted_chain = "".join(newChain)
        logger.debug("Chiffrement terminé. Résultat : '%s'.", encrypted_chain)
        return encrypted_chain

    def vigenere_decryption(self, chain, key):
        """
        Decrypts a string using the Vigenère cipher with a given key.

        Non-alphabetic characters in the input string are ignored.

        :param chain: the string to decrypt
        :param key: the key to use for decryption
        :return: the decrypted string
        """
        logger.debug("Début du déchiffrement avec la chaîne : '%s' et la clé : '%s'.", chain, key)

        if not isinstance(chain, str):
            logger.error("TypeError : La chaîne à déchiffrer doit être une chaîne de caractères.")
            raise TypeError("La chaîne à déchiffrer doit être une chaîne de caractères.")
        if not isinstance(key, str):
            logger.error("TypeError : La clé doit être une chaîne de caractères.")
            raise TypeError("La clé doit être une chaîne de caractères.")
        if not chain:
            logger.error("ValueError : La chaîne à déchiffrer ne peut pas être vide.")
            raise ValueError("La chaîne à déchiffrer ne peut pas être vide.")
        if not key:
            logger.error("ValueError : La clé ne peut pas être vide.")
            raise ValueError("La clé ne peut pas être vide.")
        if not key.isalpha():
            logger.error("ValueError : La clé doit contenir uniquement des lettres.")
            raise ValueError("La clé doit contenir uniquement des lettres.")

        keyIndex = 0
        key = key.upper()
        # Chain is already expected to be uppercase from encryption, but good to ensure
        chain = chain.upper()

        decrypted_chars = []
        cesar_cipher_instance = CesarCipher() # Instantiate once
        for elt in chain:
            if elt.isalpha():
                # For decryption, the shift is reversed
                shift = ord(key[keyIndex]) - 65
                decrypted_chars.append(cesar_cipher_instance.cesar_decryption(elt, shift))
                keyIndex = (keyIndex + 1) % len(key)
            # Non-alpha characters from the encrypted string are typically kept as is or ignored.
            # Current CesarCipher().cesar_decryption will ignore non-alpha, so they won't appear.
            # If they were preserved during encryption, this part might need adjustment.
            # However, current vigenere_encryption only outputs alpha characters.

        decrypted_chain = "".join(decrypted_chars)
        logger.debug("Déchiffrement terminé. Résultat : '%s'.", decrypted_chain)
        return decrypted_chain

if __name__ == "__main__":
    cipher = VigenereCipher()
    encrypted = cipher.vigenere_encryption("Hello world!", "test")
    print(f"Encrypted: {encrypted}")
    decrypted = cipher.vigenere_decryption(encrypted, "test")
    print(f"Decrypted: {decrypted}")

    encrypted_long = cipher.vigenere_encryption("This is a longer test message to see how the Vigenere cipher handles it with a repeating key.", "PYTHON")
    print(f"Encrypted Long: {encrypted_long}")
    decrypted_long = cipher.vigenere_decryption(encrypted_long, "PYTHON")
    print(f"Decrypted Long: {decrypted_long}")