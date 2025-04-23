import pytest
from vigenere import VigenereCipher

@pytest.fixture
def cipher():
    """Fixture pour initialiser une instance de VigenereCipher."""
    return VigenereCipher()

def test_vigenere_encryption(cipher):
    assert cipher.vigenere_encryption("HELLO", "KEY") == "RIJVS"
    assert cipher.vigenere_encryption("HELLO WORLD!", "KEY") == "RIJVSUYVJN"

    with pytest.raises(ValueError, match="La chaîne à chiffrer ne peut pas être vide."):
        cipher.vigenere_encryption("", "KEY")
    with pytest.raises(ValueError, match="La clé ne peut pas être vide."):
        cipher.vigenere_encryption("HELLO", "")
    with pytest.raises(ValueError, match="La clé doit contenir uniquement des lettres."):
        cipher.vigenere_encryption("HELLO", "K3Y!")
    with pytest.raises(TypeError, match="La chaîne à chiffrer doit être une chaîne de caractères."):
        cipher.vigenere_encryption(12345, "KEY")
    with pytest.raises(TypeError, match="La clé doit être une chaîne de caractères."):
        cipher.vigenere_encryption("HELLO", 12345)