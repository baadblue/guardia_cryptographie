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

def test_vigenere_decryption(cipher):
    # Basic test
    assert cipher.vigenere_decryption("RIJVS", "KEY") == "HELLO"
    # Test with spaces and mixed content (encryption output is only alpha)
    assert cipher.vigenere_decryption("RIJVSUYVJN", "KEY") == "HELLOWORLD"

    # Test case from the __main__ in vigenere.py
    text = "HELLOWORLD"
    key = "TEST"
    encrypted = cipher.vigenere_encryption(text, key) # AXEEHPEXMA
    assert cipher.vigenere_decryption(encrypted, key) == text.upper()

    long_text = "THISISALONGERTESTMESSAGETOSEEHOWTHEVIGENERECIPHERHANDLEITWITHAREPEATINGKEY"
    long_key = "PYTHON"
    encrypted_long = cipher.vigenere_encryption(long_text, long_key)
    assert cipher.vigenere_decryption(encrypted_long, long_key) == long_text.upper()

    # Error conditions for decryption
    with pytest.raises(ValueError, match="La chaîne à déchiffrer ne peut pas être vide."):
        cipher.vigenere_decryption("", "KEY")
    with pytest.raises(ValueError, match="La clé ne peut pas être vide."):
        cipher.vigenere_decryption("RIJVS", "")
    with pytest.raises(ValueError, match="La clé doit contenir uniquement des lettres."):
        cipher.vigenere_decryption("RIJVS", "K3Y!")
    with pytest.raises(TypeError, match="La chaîne à déchiffrer doit être une chaîne de caractères."):
        cipher.vigenere_decryption(12345, "KEY")
    with pytest.raises(TypeError, match="La clé doit être une chaîne de caractères."):
        cipher.vigenere_decryption("RIJVS", 12345)

def test_vigenere_encryption_decryption_roundtrip(cipher):
    plaintexts = ["HELLO", "HELLOWORLD", "THISISALONGTEST", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    keys = ["KEY", "PYTHON", "GUARDIA"]

    for text in plaintexts:
        for key in keys:
            encrypted = cipher.vigenere_encryption(text, key)
            decrypted = cipher.vigenere_decryption(encrypted, key)
            assert decrypted == text.upper(), f"Failed for text='{text}', key='{key}'"

    # Test with non-alphabetic characters in original plaintext
    text_with_non_alpha = "Hello, World 123!"
    key = "SECRET"
    # Encryption will strip non-alpha, so we test against the alpha-only version
    expected_alpha_only_plaintext = "HELLOWORLD"
    encrypted = cipher.vigenere_encryption(text_with_non_alpha, key)
    decrypted = cipher.vigenere_decryption(encrypted, key)
    assert decrypted == expected_alpha_only_plaintext