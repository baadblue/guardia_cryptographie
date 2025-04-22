import pytest
from hillcipher import HillCipher

@pytest.fixture
def cipher():
    """Fixture pour initialiser une instance de HillCipher."""
    return HillCipher()

def test_split_text(cipher):
    """Test de la méthode split_text."""
    assert cipher.split_text("Hello, world!", 4) == ["HELL", "OWOR", "LDXX"]
    assert cipher.split_text("ABC", 4) == ["ABCX"]
    assert cipher.split_text("", 4) == ["XXXX"]
    assert cipher.split_text("HELLO", 3) == ["HEL", "LOX"]

def test_validate_matrix(cipher):
    """Test de la méthode validate_matrix."""
    valid_matrix = [[1, 2], [3, 4]]
    assert cipher.validate_matrix(valid_matrix) is True

    with pytest.raises(ValueError, match="La clé doit être une liste de listes."):
        cipher.validate_matrix("not a matrix")

    with pytest.raises(ValueError, match="La clé doit être une matrice carrée."):
        cipher.validate_matrix([[1, 2, 3], [4, 5]])

    with pytest.raises(ValueError, match="La clé doit contenir uniquement des entiers."):
        cipher.validate_matrix([[1, 2], [3, "a"]])

def test_generate_key_matrix(cipher):
    """Test de la méthode generate_key_matrix."""
    matrix = cipher.generate_key_matrix(size=3)
    assert len(matrix) == 3
    assert len(matrix[0]) == 3
    assert all(isinstance(num, int) for row in matrix for num in row)

    with pytest.raises(ValueError, match="La taille de la matrice doit être supérieure à 0."):
        cipher.generate_key_matrix(size=0)

def test_is_invertible(cipher):
    """Test de la méthode is_invertible."""
    invertible_matrix = [[1, 2], [3, 5]]
    non_invertible_matrix = [[1, 2], [2, 4]]

    assert cipher.is_invertible(invertible_matrix)[0] is True
    assert cipher.is_invertible(non_invertible_matrix)[0] is False

def test_modinv(cipher):
    """Test de la méthode modinv."""
    assert cipher.modinv(3, 26) == 9

    with pytest.raises(ValueError, match="Pas d'inverse modulaire pour 2 modulo 4."):
        cipher.modinv(2, 4)

def test_generate_key_matrix_inverse(cipher):
    """Test de la méthode generate_key_matrix_inverse."""
    matrix = [[1, 2], [3, 5]]
    inverse = cipher.generate_key_matrix_inverse(matrix)
    assert len(inverse) == 2
    assert len(inverse[0]) == 2

    with pytest.raises(ValueError, match="La clé doit être une liste de listes."):
        cipher.generate_key_matrix_inverse("not a matrix")

    with pytest.raises(ValueError, match="Matrice non inversible modulo 26."):
        cipher.generate_key_matrix_inverse([[1, 2], [2, 4]])

def test_hill_encryption(cipher):
    """Test de la méthode hill_encryption."""
    encrypted = cipher.hill_encryption("HELLO")
    assert isinstance(encrypted, str)
    assert len(encrypted) > 0

    encrypted = cipher.hill_encryption("A")
    assert isinstance(encrypted, str)
    assert len(encrypted) > 0

    decrypted = cipher.hill_decryption(encrypted)
    assert decrypted.startswith("A")

def test_hill_decryption(cipher):
    """Test de la méthode hill_decryption."""
    encrypted = cipher.hill_encryption("HELLO")
    decrypted = cipher.hill_decryption(encrypted)
    assert decrypted.startswith("HELLO")

    with pytest.raises(ValueError, match="La matrice inverse n'est pas définie."):
        cipher.key_matrix_inverse = None
        cipher.hill_decryption("HELLO")