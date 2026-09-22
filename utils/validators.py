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


class ValidationError(ValueError):
    pass


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


def validate_role(value: str, allowed_roles) -> str:
    if value not in allowed_roles:
        raise ValidationError(
            f"'{value}' is not a valid role. Allowed: {', '.join(allowed_roles)}"
        )
    return value
