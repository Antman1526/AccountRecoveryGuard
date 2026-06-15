from account_recovery_guard.passwords import PasswordPolicy, generate_passphrase, generate_password


def test_generate_password_honors_required_character_classes():
    password = generate_password(
        PasswordPolicy(length=28, uppercase=True, lowercase=True, digits=True, symbols=True)
    )

    assert len(password) == 28
    assert any(char.isupper() for char in password)
    assert any(char.islower() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in PasswordPolicy().symbol_alphabet for char in password)


def test_generate_passphrase_uses_requested_word_count_and_separator():
    phrase = generate_passphrase(word_count=5, separator="-")

    assert len(phrase.split("-")) == 5
    assert phrase.count("-") == 4
