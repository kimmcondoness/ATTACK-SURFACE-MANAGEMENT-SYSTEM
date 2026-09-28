import ipaddress
import re
from urllib.parse import urlsplit

# Reject anything that could be used for shell/command injection if it
# ever leaked into a subprocess argument list.
_SHELL_METACHARACTERS = re.compile(r"[;&|`$(){}<>\\\"'\n\r]")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ValidationError(ValueError):
    pass


def validate_username(value: str) -> str:
    value = (value or "").strip()
    if not USERNAME_RE.match(value):
        raise ValidationError("Username must be 3-30 characters (letters, numbers, dots, underscores, hyphens).")
    return value


def validate_email(value: str) -> str:
    value = (value or "").strip().lower()
    if not EMAIL_RE.match(value) or len(value) > 120:
        raise ValidationError("Enter a valid email address.")
    return value


def contains_shell_metacharacters(value: str) -> bool:
    return bool(_SHELL_METACHARACTERS.search(value or ""))


def validate_domain(value: str) -> str:
    if not value or not isinstance(value, str):
        raise ValidationError("Domain is required.")
    value = value.strip()
    if contains_shell_metacharacters(value):
        raise ValidationError("Domain contains invalid characters.")
    if not _DOMAIN_RE.match(value):
        raise ValidationError(f"'{value}' is not a valid domain.")
    return value.lower()


def validate_ip_address(value: str) -> str:
    if not value or not isinstance(value, str):
        raise ValidationError("IP address is required.")
    value = value.strip()
    if contains_shell_metacharacters(value):
        raise ValidationError("IP address contains invalid characters.")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid IP address.") from exc
    return value


def validate_url(value: str) -> str:
    if not value or not isinstance(value, str):
        raise ValidationError("URL is required.")
    value = value.strip()
    if contains_shell_metacharacters(value):
        raise ValidationError("URL contains invalid characters.")
    if not _URL_RE.match(value):
        raise ValidationError(f"'{value}' is not a valid URL.")
    return value


def extract_domain(value: str) -> str:
    """Accept a bare domain or a full URL (https://host/path) and return
    just the host, so users can paste either into the scan input.
    """
    if not value or not isinstance(value, str):
        raise ValidationError("Domain is required.")
    value = value.strip()
    if contains_shell_metacharacters(value):
        raise ValidationError("Domain contains invalid characters.")
    if "//" in value:
        host = urlsplit(value).netloc
    else:
        host = urlsplit(f"//{value}").netloc
    host = host.split("@")[-1].split(":")[0]
    return validate_domain(host)


# Password policy. The same four rules are mirrored in static/js/password-rules.js
# for the live checklist, but this is the one that is actually enforced.
_PASSWORD_RULES = (
    ("more than 8 characters", lambda p: len(p) > 8),
    ("an uppercase letter", lambda p: any(c.isupper() for c in p)),
    ("a number", lambda p: re.search(r"[0-9]", p) is not None),
    ("a special character", lambda p: any(not c.isalnum() and not c.isspace() for c in p)),
)


def password_problems(password: str) -> list:
    """The password rules this password does not meet (empty list = acceptable)."""
    return [rule for rule, is_met in _PASSWORD_RULES if not is_met(password or "")]


def validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValidationError("Password is required.")
    missing = password_problems(password)
    if missing:
        listed = missing[0] if len(missing) == 1 else ", ".join(missing[:-1]) + " and " + missing[-1]
        raise ValidationError(f"Password must have {listed}.")
    return password


def validate_role(value: str, allowed_roles) -> str:
    if value not in allowed_roles:
        raise ValidationError(
            f"'{value}' is not a valid role. Allowed: {', '.join(allowed_roles)}"
        )
    return value
