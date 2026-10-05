import pytest

from utils.validators import ValidationError, normalize_username, validate_domain, validate_ip_address, validate_url, validate_username


def test_valid_domain():
    assert validate_domain("example.com") == "example.com"


def test_domain_rejects_shell_metacharacters():
    with pytest.raises(ValidationError):
        validate_domain("example.com; rm -rf /")


def test_domain_rejects_invalid_format():
    with pytest.raises(ValidationError):
        validate_domain("not a domain")


def test_valid_ip():
    assert validate_ip_address("192.168.1.1") == "192.168.1.1"


def test_invalid_ip():
    with pytest.raises(ValidationError):
        validate_ip_address("999.999.999.999")


def test_valid_url():
    assert validate_url("https://example.com/path") == "https://example.com/path"


def test_url_rejects_shell_metacharacters():
    with pytest.raises(ValidationError):
        validate_url("https://example.com/$(whoami)")


# ------------------------------------------------------------------ usernames
@pytest.mark.parametrize("name", ["a", "ab", "Hazig Haikal", "hazig.haikal", "hazig_haikal-99", "Ahmad bin Ali", "nur@home", "x" * 80, "Zoë Müller", "山田太郎", "o'brien"])
def test_a_username_can_be_any_name_up_to_eighty_characters(name):
    assert validate_username(name) == name


def test_a_username_is_trimmed_and_repeated_spaces_are_squeezed():
    assert validate_username("  hazig    haikal  ") == "hazig haikal"
    assert normalize_username("  a   b ") == "a b"


@pytest.mark.parametrize("name,message", [
    ("", "Enter a username"), ("    ", "Enter a username"), (None, "Enter a username"),
    ("x" * 81, "at most 80 characters"),
    ("line\nbreak", "line breaks"), ("tab\there", "line breaks"), ("carriage\rreturn", "line breaks"),
    ("zero\u200bwidth", "invisible"), ("right\u202eto-left", "invisible"), ("non\u00a0breaking", "invisible"), ("null\x00byte", "invisible"),
])
def test_only_empty_overlong_or_invisible_usernames_are_refused(name, message):
    with pytest.raises(ValidationError, match=message):
        validate_username(name)


def test_normalising_something_that_is_not_text_gives_nothing():
    assert normalize_username(123) == "" and normalize_username(None) == "" and normalize_username(["a"]) == ""
