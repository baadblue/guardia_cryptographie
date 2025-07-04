import pytest
from cesar import CesarCipher

@pytest.fixture
def cipher():
    """Fixture pour initialiser une instance de CesarCipher."""
    return CesarCipher()

def test_encryption_standard(cipher):
    assert cipher.cesar_encryption("HELLO", 3) == "KHOOR"
    assert cipher.cesar_encryption("hello", 3) == "KHOOR"

def test_decryption_standard(cipher):
    assert cipher.cesar_decryption("KHOOR", 3) == "HELLO"
    assert cipher.cesar_decryption("khoor", 3) == "HELLO"

def test_non_alphabetic_characters(cipher):
    assert cipher.cesar_encryption("HELLO WORLD!", 3) == "KHOORZRUOG"
    assert cipher.cesar_decryption("KHOOR ZRUOG!", 3) == "HELLOWORLD"

def test_negative_key(cipher):
    assert cipher.cesar_encryption("HELLO", -3) == "EBIIL"
    assert cipher.cesar_decryption("EBIIL", -3) == "HELLO"

def test_large_key(cipher):
    assert cipher.cesar_encryption("HELLO", 29) == "KHOOR"  # 29 % 26 = 3
    assert cipher.cesar_decryption("KHOOR", 29) == "HELLO"

def test_key_zero(cipher):
    # Encryption with key 0 should return the original string (uppercase, alpha-only)
    assert cipher.cesar_encryption("HELLO", 0) == "HELLO"
    assert cipher.cesar_encryption("Hello World!", 0) == "HELLOWORLD"
    # Decryption with key 0 should also return the original string (uppercase, alpha-only)
    assert cipher.cesar_decryption("HELLO", 0) == "HELLO"
    assert cipher.cesar_decryption("Hello World!", 0) == "HELLOWORLD"

def test_key_none(cipher):
    # None is not an int, so it should be caught by `isinstance(key, int)` check first.
    with pytest.raises(TypeError, match="La clé doit être un entier."):
        cipher.cesar_encryption("HELLO", None)
    with pytest.raises(TypeError, match="La clé doit être un entier."):
        cipher.cesar_decryption("HELLO", None)

def test_empty_string(cipher):
    with pytest.raises(ValueError, match="La chaîne à chiffrer ne peut pas être vide."):
        cipher.cesar_encryption("", 3)
    with pytest.raises(ValueError, match="La chaîne à chiffrer ne peut pas être vide."):
        cipher.cesar_decryption("", 3)

def test_invalid_key(cipher):
    with pytest.raises(TypeError, match="La clé doit être un entier."):
        cipher.cesar_encryption("HELLO", "a")
    with pytest.raises(TypeError, match="La clé doit être un entier."):
        cipher.cesar_decryption("HELLO", "a")

def test_mixed_case(cipher):
    assert cipher.cesar_encryption("Hello World!", 3) == "KHOORZRUOG"
    assert cipher.cesar_decryption("Khoor Zruog!", 3) == "HELLOWORLD"

def test_special_characters(cipher):
    assert cipher.cesar_encryption("!@#$%^&*", 3) == ""
    assert cipher.cesar_decryption("!@#$%^&*", 3) == ""

def test_long_text(cipher):
    long_text = "HELLO" * 1000
    encrypted = cipher.cesar_encryption(long_text, 3)
    decrypted = cipher.cesar_decryption(encrypted, 3)
    assert decrypted == long_text

def test_brute_force_decryption(cipher):
    encrypted = cipher.cesar_encryption("HELLO", 3)
    possible_decryptions = cipher.brute_force_decryption(encrypted)
    assert "HELLO" in possible_decryptions  
    assert len(possible_decryptions) == 25  

def test_frequency_analysis(cipher):
    text = "GHPDLQ, GHV O'DXEH, D O'KHXUH RX EODQFKLW OD FDPSDJQH, MH SDUWLUDL. YRLV-WX, MH VDLV TXH WX P'DWWHQGV.M'LUDL SDU OD IRUHW, M'LUDL SDU OD PRQWDJQH.MH QH SXLV GHPHXUHU ORLQ GH WRL SOXV ORQJWHPSV.MH PDUFKHUDL OHV BHXA ILAHV VXU PHV SHQVHHV,VDQV ULHQ YRLU DX GHKRUV, VDQV HQWHQGUH DXFXQ EUXLW,VHXO, LQFRQQX, OH GRV FRXUEH, OHV PDLQV FURLVHHV,WULVWH, HW OH MRXU SRXU PRL VHUD FRPPH OD QXLW.MH QH UHJDUGHUDL QL O'RU GX VRLU TXL WRPEH,QL OHV YRLOHV DX ORLQ GHVFHQGDQW YHUV KDUIOHXU,HW TXDQG M'DUULYHUDL, MH PHWWUDL VXU WD WRPEHXQ ERXTXHW GH KRXA YHUW HW GH EUXBHUH HQ IOHXU.GHPDLQ, GHV O'DXEH..."  
    estimated_key = cipher.frequency_analysis(text)
    assert estimated_key == 3 
    decrypted = cipher.cesar_decryption(text, estimated_key)
    assert decrypted == "DEMAINDESLAUBEALHEUREOUBLANCHITLACAMPAGNEJEPARTIRAIVOISTUJESAISQUETUMATTENDSJIRAIPARLAFORETJIRAIPARLAMONTAGNEJENEPUISDEMEURERLOINDETOIPLUSLONGTEMPSJEMARCHERAILESYEUXFIXESSURMESPENSEESSANSRIENVOIRAUDEHORSSANSENTENDREAUCUNBRUITSEULINCONNULEDOSCOURBELESMAINSCROISEESTRISTEETLEJOURPOURMOISERACOMMELANUITJENEREGARDERAINILORDUSOIRQUITOMBENILESVOILESAULOINDESCENDANTVERSHARFLEURETQUANDJARRIVERAIJEMETTRAISURTATOMBEUNBOUQUETDEHOUXVERTETDEBRUYEREENFLEURDEMAINDESLAUBE" 