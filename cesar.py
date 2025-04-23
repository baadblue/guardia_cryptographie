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
    
    def brute_force_decryption(self, chain):
        """
        Déchiffre une chaîne de caractères en utilisant le chiffrement de César avec toutes les clés possibles.
        
        :param chain: chaîne à déchiffrer
        :return: liste des chaînes déchiffrées
        """
        logger.debug("Début du déchiffrement par force brute.")
        decrypted_chains = []
        for i in range(1, 26):
            decrypted_chains.append(self.cesar_decryption(chain, i))
        logger.debug("Déchiffrement par force brute terminé.")
        return decrypted_chains
    
    def frequency_analysis(self, chain):
        """
        Analyse la fréquence des lettres dans une chaîne de caractères et estime la clé de chiffrement.

        :param chain: chaîne à analyser
        :return: clé estimée
        """
        logger.debug("Début de l'analyse de fréquence.")
        frequency = {}
        for letter in chain:
            if letter.isalpha():
                letter = letter.upper()
                frequency[letter] = frequency.get(letter, 0) + 1

        most_common = sorted(frequency.items(), key=lambda x: x[1], reverse=True)[0]
        logger.debug("Lettre la plus fréquente : %s avec une fréquence de %d", most_common[0], most_common[1])
        key = ord(most_common[0]) - ord('E')
        logger.debug("Clé estimée : %d", key)
        
        logger.debug("Analyse de fréquence terminée.")
        return key

if __name__ == "__main__":
    print(CesarCipher().cesar_encryption("Hello World!", 3))
    print(CesarCipher().cesar_decryption("KHOORZRUOG", 3))
    print(CesarCipher().brute_force_decryption("KHOORZRUOG"))
    text = "GHPDLQ, GHV O'DXEH, D O'KHXUH RX EODQFKLW OD FDPSDJQH, MH SDUWLUDL. YRLV-WX, MH VDLV TXH WX P'DWWHQGV.M'LUDL SDU OD IRUHW, M'LUDL SDU OD PRQWDJQH.MH QH SXLV GHPHXUHU ORLQ GH WRL SOXV ORQJWHPSV.MH PDUFKHUDL OHV BHXA ILAHV VXU PHV SHQVHHV,VDQV ULHQ YRLU DX GHKRUV, VDQV HQWHQGUH DXFXQ EUXLW,VHXO, LQFRQQX, OH GRV FRXUEH, OHV PDLQV FURLVHHV,WULVWH, HW OH MRXU SRXU PRL VHUD FRPPH OD QXLW.MH QH UHJDUGHUDL QL O'RU GX VRLU TXL WRPEH,QL OHV YRLOHV DX ORLQ GHVFHQGDQW YHUV KDUIOHXU,HW TXDQG M'DUULYHUDL, MH PHWWUDL VXU WD WRPEHXQ ERXTXHW GH KRXA YHUW HW GH EUXBHUH HQ IOHXU.GHPDLQ, GHV O'DXEH..."
    key = CesarCipher().frequency_analysis(text)
    print(f"Estimated key: {key}")
    print(CesarCipher().cesar_decryption(text, key))
