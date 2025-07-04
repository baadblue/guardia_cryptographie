import pytest
from hillcipher import HillCipher
from unittest.mock import patch # For mocking split_text

# --- Fixtures ---

@pytest.fixture
def default_env_cipher():
    """Fixture for HillCipher using .env (default behavior)."""
    try:
        # Attempt to initialize. This might fail if .env is not configured.
        return HillCipher(load_from_env=True)
    except ValueError as e:
        pytest.skip(f"Skipping .env dependent tests: HillCipher init failed during setup: {e}")
        return None # Should not be reached due to pytest.skip

@pytest.fixture
def fixed_key_cipher_2x2():
    """Cipher with a fixed, known 2x2 key, not loaded from .env."""
    cipher = HillCipher(load_from_env=False) # Prevents .env loading, might generate random keys initially
    # Override generated keys with fixed ones for testing
    cipher.key_matrix = [[3, 3], [2, 5]]
    # Inverse for [[3,3],[2,5]] is [[15,17],[20,9]] mod 26
    cipher.key_matrix_inverse = cipher.generate_key_matrix_inverse(cipher.key_matrix)
    # Sanity check the inverse calculation for the fixture itself
    assert cipher.key_matrix_inverse == [[15, 17], [20, 9]]
    return cipher

@pytest.fixture
def fixed_key_cipher_3x3():
    """Cipher with a fixed, known 3x3 key, not loaded from .env."""
    cipher = HillCipher(load_from_env=False)
    # Key: [[17, 17, 5], [21, 18, 21], [2, 2, 19]] (Invertible, det=25 mod 26)
    cipher.key_matrix = [[17, 17, 5], [21, 18, 21], [2, 2, 19]]
    # Corresponding inverse (Verified using online calculators and manual checks)
    # For [[17,17,5],[21,18,21],[2,2,19]], inverse is [[4,9,15],[15,17,6],[24,0,17]]
    cipher.key_matrix_inverse = cipher.generate_key_matrix_inverse(cipher.key_matrix)
    assert cipher.key_matrix_inverse == [[4, 9, 15], [15, 17, 6], [24, 0, 17]]
    return cipher

# --- Generic Method Tests (using any valid cipher instance) ---
# These methods don't depend on specific key values, just on having an instance.

def test_split_text(fixed_key_cipher_2x2): # Instance needed to call method
    cipher_instance = fixed_key_cipher_2x2
    assert cipher_instance.split_text("Hello, world!", 4) == ["HELL", "OWOR", "LDXX"]
    assert cipher_instance.split_text("ABC", 4) == ["ABCX"]
    assert cipher_instance.split_text("", 4) == ["XXXX"]
    assert cipher_instance.split_text("HELLO", 3) == ["HEL", "LOX"]
    # Test with block size matching the fixture's key, if split_text were dependent (it's not currently)
    assert cipher_instance.split_text("H", 2) == ["HX"] # block size 2
    assert cipher_instance.split_text("", 2) == ["XX"]  # block size 2

def test_validate_matrix(fixed_key_cipher_2x2):
    cipher_instance = fixed_key_cipher_2x2
    valid_matrix = [[1, 2], [3, 4]]
    assert cipher_instance.validate_matrix(valid_matrix) is True

    with pytest.raises(ValueError, match="La clé doit être une liste de listes."):
        cipher_instance.validate_matrix("not a matrix")
    with pytest.raises(ValueError, match="La clé doit être une matrice carrée."):
        cipher_instance.validate_matrix([[1, 2, 3], [4, 5]])
    with pytest.raises(ValueError, match="La clé doit contenir uniquement des entiers."):
        cipher_instance.validate_matrix([[1, 2], [3, "a"]])

def test_generate_key_matrix(fixed_key_cipher_2x2):
    cipher_instance = fixed_key_cipher_2x2
    matrix = cipher_instance.generate_key_matrix(size=3) # Test generating a 3x3
    assert len(matrix) == 3
    assert len(matrix[0]) == 3
    assert all(isinstance(num, int) for row in matrix for num in row)
    assert cipher_instance.is_invertible(matrix)[0] is True # Generated key must be invertible

    with pytest.raises(ValueError, match="La taille de la matrice doit être supérieure à 0."):
        cipher_instance.generate_key_matrix(size=0)

def test_is_invertible(fixed_key_cipher_2x2):
    cipher_instance = fixed_key_cipher_2x2
    invertible_matrix = [[1, 2], [3, 5]] # det = -1 = 25 (mod 26). gcd(25, 26) = 1
    non_invertible_matrix = [[1, 2], [2, 4]] # det = 0. gcd(0, 26) = 26
    assert cipher_instance.is_invertible(invertible_matrix)[0] is True
    assert cipher_instance.is_invertible(non_invertible_matrix)[0] is False

def test_modinv(fixed_key_cipher_2x2):
    cipher_instance = fixed_key_cipher_2x2
    assert cipher_instance.modinv(3, 26) == 9
    assert cipher_instance.modinv(25, 26) == 25 # modInverse of -1

    with pytest.raises(ValueError, match="Pas d'inverse modulaire pour 2 modulo 4."):
        cipher_instance.modinv(2, 4)

def test_generate_key_matrix_inverse(fixed_key_cipher_2x2):
    cipher_instance = fixed_key_cipher_2x2
    matrix = [[1, 2], [3, 5]]
    expected_inverse = [[21, 2], [3, 25]]
    inverse = cipher_instance.generate_key_matrix_inverse(matrix)
    assert inverse == expected_inverse

    with pytest.raises(ValueError, match="La clé doit être une liste de listes."):
        cipher_instance.generate_key_matrix_inverse("not a matrix")
    with pytest.raises(ValueError, match="Matrice non inversible modulo 26."):
        cipher_instance.generate_key_matrix_inverse([[1, 2], [2, 4]])

# --- Tests for .env dependent cipher ---

def test_hill_encryption_decryption_default_env(default_env_cipher):
    if default_env_cipher is None: # Fixture skipped test
        return

    original_text = "HELLOWORLD"
    # Key matrix might not be loaded if .env is faulty, but fixture handles skip.
    block_size = len(default_env_cipher.key_matrix)

    encrypted = default_env_cipher.hill_encryption(original_text)
    decrypted = default_env_cipher.hill_decryption(encrypted)

    expected_padded_len = len(original_text)
    if expected_padded_len % block_size != 0:
        expected_padded_len = (expected_padded_len // block_size + 1) * block_size

    assert len(encrypted) == expected_padded_len
    assert decrypted.startswith(original_text.upper())

    if len(original_text) % block_size != 0:
        assert len(decrypted) == expected_padded_len
        padding_char = 'X' # Assuming 'X' is the padding char from split_text
        expected_decrypted_text = original_text.upper() + padding_char * (expected_padded_len - len(original_text))
        assert decrypted == expected_decrypted_text
    else:
        assert decrypted == original_text.upper()

def test_hill_decryption_error_if_inverse_unavailable_manual_unset(fixed_key_cipher_2x2):
    # Test the error raised by hill_decryption if inverse is None
    cipher = fixed_key_cipher_2x2
    cipher.key_matrix_inverse = None # Manually unset the inverse
    # This error comes directly from hill_decryption's check
    with pytest.raises(ValueError, match="La matrice inverse n'est pas définie."):
        cipher.hill_decryption("TEST")


# --- Tests with Fixed Keys (Isolated from .env) ---

def test_hill_encryption_decryption_fixed_2x2(fixed_key_cipher_2x2):
    cipher = fixed_key_cipher_2x2 # Key: [[3,3],[2,5]], Inv: [[15,17],[20,9]]

    # X (23) X (23) -> (3*23+3*23, 2*23+5*23) = (69+69, 46+115) = (138, 161) = (8,5) -> IF
    test_cases = [
        ("HELP", "HIAT", "HELP"),       # HELP -> HIAT
        ("TEST", "RGHB", "TEST"),       # TEST -> RGHB
        ("HELLOWORLD", "HIOZEIPJQL", "HELLOWORLD"), # HELLOWORLD -> HIOZEIPJQL
        ("A", "RL", "AX"),              # A (padded to AX) -> RL, decrypts to AX
        ("", "IF", "XX")                # Empty (padded to XX) encrypts to IF, decrypts to XX
    ]

    for plaintext, expected_ciphertext, expected_decrypted in test_cases:
        encrypted = cipher.hill_encryption(plaintext)
        assert encrypted == expected_ciphertext, f"Encryption failed for '{plaintext}' with 2x2 key"
        decrypted = cipher.hill_decryption(encrypted)
        assert decrypted == expected_decrypted, f"Decryption failed for '{encrypted}' with 2x2 key"

def test_hill_encryption_decryption_fixed_3x3(fixed_key_cipher_3x3):
    cipher = fixed_key_cipher_3x3 # Key: [[17,17,5],[21,18,21],[2,2,19]]
                                  # Inv: [[4,9,15],[15,17,6],[24,0,17]]
    # CAT (2,0,19) -> ZZB (25,25,1)
    # XXX (23,23,23) -> (17*23+17*23+5*23, 21*23+18*23+21*23, 2*23+2*23+19*23)
    # = (391+391+115, 483+414+483, 46+46+437) = (897, 1380, 529) mod 26
    # 897 = 34*26 + 13 (N)
    # 1380 = 53*26 + 2 (C)
    # 529 = 20*26 + 9 (J)
    # "" (XXX) -> NCJ
    test_cases = [
        ("CAT", "ZZB", "CAT"),    # CAT -> ZZB
        ("ACT", "ZTB", "ACT"),    # ACT -> ZTB
        ("HELLOWORLD", "IIXPJAKZLLYV", "HELLOWORLDXX"), # Corrected expected ciphertext
        ("", "NCJ", "XXX")        # Empty (padded to XXX) encrypts to NCJ, decrypts to XXX
    ]

    for plaintext, expected_ciphertext, expected_decrypted in test_cases:
        encrypted = cipher.hill_encryption(plaintext)
        assert encrypted == expected_ciphertext, f"Encryption failed for '{plaintext}' with 3x3 key"
        decrypted = cipher.hill_decryption(encrypted)
        assert decrypted == expected_decrypted, f"Decryption failed for '{encrypted}' with 3x3 key"

def test_hill_encryption_invalid_block_size_mocked(fixed_key_cipher_2x2):
    cipher = fixed_key_cipher_2x2 # Operates with block_size = 2

    # Mock split_text to return a block of incorrect size
    with patch.object(HillCipher, 'split_text', return_value=["ABC"]): # Block of 3 for 2x2 matrix
        with pytest.raises(ValueError, match="La taille du bloc ne correspond pas à la taille de la matrice."):
            cipher.hill_encryption("TEXT DOESNT MATTER DUE TO MOCK")

    # Ensure original split_text is restored for other tests (pytest fixtures handle this)
    # Verify normal operation after mock
    assert cipher.split_text("HI", 2) == ["HI"]