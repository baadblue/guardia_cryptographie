import pytest
import math
from unittest.mock import patch, MagicMock

# Assuming entropy_redundancy.py is in the same directory or accessible via PYTHONPATH
from entropy_redundancy import (
    validate_password,
    calculate_entropy,
    calculate_max_entropy,
    calculate_max_relative_entropy,
    calculate_redundancy,
    is_password_secure
)

# Test validate_password
def test_validate_password_valid():
    assert validate_password("password123") is None  # Should not raise

def test_validate_password_empty():
    with pytest.raises(ValueError, match="Le mot de passe doit être une chaîne de caractères non vide."):
        validate_password("")

def test_validate_password_none():
    with pytest.raises(ValueError, match="Le mot de passe doit être une chaîne de caractères non vide."):
        validate_password(None)

def test_validate_password_not_string():
    with pytest.raises(ValueError, match="Le mot de passe doit être une chaîne de caractères non vide."):
        validate_password(12345)

# Test calculate_entropy (mocking zxcvbn)
@patch('entropy_redundancy.zxcvbn')
def test_calculate_entropy_basic(mock_zxcvbn):
    mock_zxcvbn.return_value = {'guesses': 1024} # 2^10
    assert calculate_entropy("password") == 10.0

@patch('entropy_redundancy.zxcvbn')
def test_calculate_entropy_error(mock_zxcvbn):
    mock_zxcvbn.side_effect = Exception("ZXCVBN Error")
    with pytest.raises(RuntimeError, match="Erreur lors du calcul de l'entropie : ZXCVBN Error"):
        calculate_entropy("password")

def test_calculate_entropy_invalid_input():
    with pytest.raises(ValueError): # From validate_password
        calculate_entropy("")

# Test calculate_max_entropy
def test_calculate_max_entropy_default_alphabet():
    password = "abc" # length 3
    # Default alphabet size 95
    # log2(95) * 3
    expected = math.log2(95) * 3
    assert math.isclose(calculate_max_entropy(password), expected)

def test_calculate_max_entropy_custom_alphabet():
    password = "abcd" # length 4
    alphabet_size = 10
    expected = math.log2(alphabet_size) * 4
    assert math.isclose(calculate_max_entropy(password, length_alphabet=alphabet_size), expected)

def test_calculate_max_entropy_zero_length():
    # validate_password will raise error for empty string
    with pytest.raises(ValueError):
        calculate_max_entropy("")

# Test calculate_max_relative_entropy
def test_calculate_max_relative_entropy_all_types():
    password = "aB1!" # upper, lower, digit, special
    # 26 (lower) + 26 (upper) + 10 (digit) + 33 (special) = 95
    expected_alphabet_size = 95
    expected_entropy = math.log2(expected_alphabet_size) * len(password)
    assert math.isclose(calculate_max_relative_entropy(password), expected_entropy)

def test_calculate_max_relative_entropy_only_lower():
    password = "abc"
    expected_alphabet_size = 26
    expected_entropy = math.log2(expected_alphabet_size) * len(password)
    assert math.isclose(calculate_max_relative_entropy(password), expected_entropy)

def test_calculate_max_relative_entropy_only_upper_digits():
    password = "AB12"
    expected_alphabet_size = 26 + 10 # 36
    expected_entropy = math.log2(expected_alphabet_size) * len(password)
    assert math.isclose(calculate_max_relative_entropy(password), expected_entropy)

def test_calculate_max_relative_entropy_only_special_with_space():
    password = "!@ #" # string.punctuation often includes space, but our code adds it if not.
                      # Our code explicitly counts 33 for "has_special" if any special is found.
    expected_alphabet_size = 33
    expected_entropy = math.log2(expected_alphabet_size) * len(password)
    assert math.isclose(calculate_max_relative_entropy(password), expected_entropy)

def test_calculate_max_relative_entropy_no_recognized_chars():
    # This case is tricky as it depends on what `isalpha`, `isdigit`, etc. recognize
    # If a string has chars not in these, alphabet_size could be 0.
    # The function now handles length_alphabet=0 by setting it to 1 to avoid log(0) error,
    # resulting in 0 entropy.
    # Example: A password made of only control characters (if they could pass validation)
    # For now, assuming validate_password ensures non-empty.
    # If password was "漢字" (Chinese characters), it would currently result in alphabet_size = 0
    # Let's use a mock for `validate_password` for this specific sub-test if needed,
    # or test with characters that are not latin letters/numbers/string.punctuation
    # The current implementation of `calculate_max_relative_entropy` would result in alphabet_size=1 (to avoid log(0))
    # if no standard types are found. Entropy = log2(1) * len = 0.
    assert calculate_max_relative_entropy("漢字") == 0.0


# Test calculate_redundancy
@patch('entropy_redundancy.calculate_entropy')
def test_calculate_redundancy_default_max(mock_calculate_entropy):
    password = "password"
    mock_calculate_entropy.return_value = 30.0 # Mocked entropy H(X)

    # H_max = log2(95) * len(password)
    expected_max_entropy = math.log2(95) * len(password)
    expected_redundancy = 1 - (30.0 / expected_max_entropy)

    assert math.isclose(calculate_redundancy(password, use_relative_max_entropy=False), expected_redundancy)

@patch('entropy_redundancy.calculate_entropy')
@patch('entropy_redundancy.calculate_max_relative_entropy')
def test_calculate_redundancy_relative_max(mock_calculate_max_relative_entropy, mock_calculate_entropy):
    password = "Pwd1"
    mock_calculate_entropy.return_value = 25.0 # Mocked H(X)
    mock_calculate_max_relative_entropy.return_value = 50.0 # Mocked relative H_max

    expected_redundancy = 1 - (25.0 / 50.0) # 1 - 0.5 = 0.5

    assert math.isclose(calculate_redundancy(password, use_relative_max_entropy=True), expected_redundancy)

@patch('entropy_redundancy.calculate_entropy', return_value=10)
def test_calculate_redundancy_zero_max_entropy(mock_calc_entropy):
    # This would happen if password length is 0 and max_entropy is calculated (log2(X)*0 = 0)
    # validate_password should prevent empty strings.
    # If max_entropy is 0, redundancy should be handled:
    # If entropy is also 0, redundancy is 1.0 (no info, max no info)
    # If entropy > 0, redundancy is 0.0 (some info, but max no info - implies infinite info needed to break)
    # The function currently returns 1.0 if entropy is 0, else 0.0 if max_entropy_val is 0.

    # Mocking calculate_max_entropy to return 0 for a non-empty password (artificial scenario)
    with patch('entropy_redundancy.calculate_max_entropy', return_value=0.0):
        assert calculate_redundancy("a") == 0.0 # entropy 10 / max_entropy 0 -> handled

    with patch('entropy_redundancy.calculate_max_entropy', return_value=0.0):
        with patch('entropy_redundancy.calculate_entropy', return_value=0.0) as mock_ent_zero:
             assert calculate_redundancy("a") == 1.0 # entropy 0 / max_entropy 0 -> handled


# Test is_password_secure
# This function uses calculate_max_entropy, not zxcvbn's entropy
def test_is_password_secure_strong():
    # Needs len * log2(95) >= 80
    # log2(95) is approx 6.5698
    # 80 / 6.5698 approx 12.17
    # So, a password of length 13 should be "secure" by this function's logic
    assert is_password_secure("a" * 13) is True

def test_is_password_secure_weak():
    assert is_password_secure("a" * 12) is False

def test_is_password_secure_boundary():
    # Exact boundary might depend on float precision
    # Length 12: 12 * log2(95) = 78.83... < 80 -> False
    # Length 13: 13 * log2(95) = 85.40... > 80 -> True
    assert is_password_secure("longenough123") is True # len 13
    assert is_password_secure("shortenough1") is False   # len 12

def test_is_password_secure_empty():
     with pytest.raises(ValueError): # from validate_password
        is_password_secure("")

# Example of testing the __main__ part if desired (optional)
@patch('builtins.print')
def test_main_block_runs(mock_print):
    # This is more of an integration test for the main block
    # It requires careful mocking if __main__ does complex things
    # For now, just ensure it can be imported and run without error
    # by temporarily tricking the __name__

    import sys
    # Store original argv
    original_argv = sys.argv

    # To run __main__ block, we typically execute the script directly.
    # Here, we can simulate it by importing and then calling a main function if it existed,
    # or by re-importing/running parts if necessary.
    # For this simple __main__, just ensuring it doesn't crash on import is often enough
    # as it prints directly. We can capture print.

    # If entropy_redundancy.py was imported as a module, its __main__ doesn't run.
    # To test it, one might use subprocess or exec.
    # For now, this test is more a placeholder if __main__ was complex.
    # The current __main__ just prints, testing print calls could be done.

    # Example: If __main__ called a main() function:
    # import entropy_redundancy
    # entropy_redundancy.main() # if main existed
    # mock_print.assert_any_call(...)
    pass # Simple __main__ does not require extensive testing here beyond module importability
