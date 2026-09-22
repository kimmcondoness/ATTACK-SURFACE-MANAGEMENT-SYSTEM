import pytest

from utils.validators import ValidationError, validate_domain, validate_ip_address, validate_url


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
