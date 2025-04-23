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
    with pytest.raises(ValueError, match="La clé ne peut pas être vide."):
        cipher.cesar_encryption("HELLO", 0)
    with pytest.raises(ValueError, match="La clé ne peut pas être vide."):
        cipher.cesar_decryption("HELLO", 0) == "HELLO"

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