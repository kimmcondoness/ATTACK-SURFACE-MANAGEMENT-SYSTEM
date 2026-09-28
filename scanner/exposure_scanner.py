"""Exposure checks that confirm what the Google dork catalog only suggests.

A dork tells you where to look; it does not tell you whether the file is
really there. Each Check below maps to a query in services/dork_service.py
and requests the matching path on the target's own host, then decides from
the response *content* (not just a 200) whether the exposure is real. That
keeps catch-all pages, login redirects and custom 404s from becoming false
findings, and needs no search-engine API or Google scraping.

Safety rules:
  * GET requests only, no exploitation, no login attempts.
  * Redirects are not followed, so a bounce to a login page is a miss.
  * Only the first 64 KB of a response is read, and archives are only
    checked by their first bytes, never downloaded.
  * Exposed secrets are never copied out: evidence is a status code, a
    size and, for env files, the variable *names*, never their values.
"""

import functools
import http.client
import random
import re
import ssl
import string
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from scanner.base import ScanControl, ScannerResult
from services.dork_service import query_for

USER_AGENT = "ASM-ExposureCheck/1.0 (authorized security assessment)"
TIMEOUT_SECONDS = 6
MAX_BYTES = 64 * 1024
WORKERS = 8
NONCE_PATH = "/asm-check-{nonce}"
TITLE_PREFIX = "[Dork] "

# Scanners routinely meet self-signed or expired certificates on the hosts
# they assess, and an expired cert must not hide an exposed .env file.
_INSECURE_TLS = ssl.create_default_context()
_INSECURE_TLS.check_hostname = False
_INSECURE_TLS.verify_mode = ssl.CERT_NONE


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes

    @functools.cached_property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


Fetch = Callable[[str], Optional[Response]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_get(url: str) -> Optional[Response]:
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_INSECURE_TLS))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as resp:
            return Response(url, resp.status, _lower(resp.headers), resp.read(MAX_BYTES))
    except urllib.error.HTTPError as err:
        try:
            body = err.read(MAX_BYTES)
        except (OSError, http.client.HTTPException):
            body = b""
        return Response(url, err.code, _lower(err.headers), body)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return None


def _lower(headers) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


# ---------------------------------------------------------------- matchers
# A matcher takes a Response and returns a short evidence string when the
# exposure is confirmed, otherwise None.

Matcher = Callable[[Response], Optional[str]]


def _size(r: Response) -> str:
    n = len(r.body)
    return f"{n} bytes" if n < MAX_BYTES else f"at least {MAX_BYTES // 1024} KB"


def _looks_like_html(text: str) -> bool:
    return bool(re.match(r"\s*(<!doctype html|<html|<head|<body)", text[:400], re.I))


def _content(*patterns: str, min_hits: int = 1, html_ok: bool = False, statuses: Optional[Tuple[int, ...]] = (200,)) -> Matcher:
    regexes = [re.compile(p, re.I | re.M) for p in patterns]

    def match(r: Response) -> Optional[str]:
        if statuses is not None and r.status not in statuses:
            return None
        if not html_ok and _looks_like_html(r.text):
            return None
        if sum(1 for rx in regexes if rx.search(r.text)) >= min_hits:
            return f"HTTP {r.status}, {_size(r)}, content matches the expected signature"
        return None

    return match


def _magic(*signatures: bytes) -> Matcher:
    def match(r: Response) -> Optional[str]:
        if r.status not in (200, 206) or "text/html" in r.headers.get("content-type", ""):
            return None
        if any(r.body.startswith(sig) for sig in signatures):
            return f"HTTP {r.status}, file header matches the expected format"
        return None

    return match


def _header_present(name: str, statuses: Tuple[int, ...] = (200, 302, 401, 403)) -> Matcher:
    def match(r: Response) -> Optional[str]:
        if r.status in statuses and name in r.headers:
            return f"HTTP {r.status}, response carries the {name} header"
        return None

    return match


def _basic_auth_realm(text: str) -> Matcher:
    def match(r: Response) -> Optional[str]:
        if r.status == 401 and text in r.headers.get("www-authenticate", "").lower():
            return f"HTTP 401 asking for {text} credentials, so the console is reachable"
        return None

    return match


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=", re.M)


def _env_file(r: Response) -> Optional[str]:
    if r.status != 200 or _looks_like_html(r.text):
        return None
    names = list(dict.fromkeys(_ENV_LINE.findall(r.text)))
    if len(names) < 2:
        return None
    return f"HTTP 200, {_size(r)}, {len(names)} variables including {', '.join(names[:6])} (values are not stored)"


def _any(*matchers: Matcher) -> Matcher:
    def match(r: Response) -> Optional[str]:
        for matcher in matchers:
            evidence = matcher(r)
            if evidence:
                return evidence
        return None

    return match


# ------------------------------------------------------------------ checks


@dataclass(frozen=True)
class Check:
    key: str
    label: str  # must equal a query label in services/dork_service.py
    severity: str
    title: str
    paths: Tuple[str, ...]
    match: Matcher
    impact: str
    steps: Tuple[str, ...]
    per_path_title: bool = True


_ROTATE = "Treat everything in the file as exposed and rotate every password, API key and token it contained."
_CHECK_LOGS = "Search the access logs for earlier requests to this path to see whether it was already downloaded."
_BLOCK_DOTFILES = (
    "Deny the path at the web server (nginx: a location block for /. with deny all; Apache: deny access to dotfiles) "
    "and keep files like this out of the web root."
)
_REMOVE_FILE = "Delete the file from the web root, or move it somewhere the web server does not serve."
_RESTRICT = "Restrict access with an IP allowlist, VPN or authenticating reverse proxy so it is not reachable from the internet."
_RERUN = "Re-run the scan to confirm the exposure is gone."

CHECKS: List[Check] = [
    Check("env-file", "Laravel .env files", "critical", "Exposed environment file",
          ("/.env", "/.env.backup", "/.env.bak", "/.env.local", "/.env.production"), _env_file,
          "Environment files usually hold database, mail and cloud credentials plus the application key.",
          (_REMOVE_FILE, _ROTATE, _BLOCK_DOTFILES, _CHECK_LOGS)),
    Check("docker-compose", "Docker Compose secrets", "high", "Exposed Docker Compose file",
          ("/docker-compose.yml", "/docker-compose.yaml", "/docker-compose.override.yml"),
          _content(r"^\s*services\s*:", r"^\s*(image|build|environment)\s*:", min_hits=2),
          "Compose files describe the internal stack and often embed database passwords.",
          (_REMOVE_FILE, _ROTATE, "Pass secrets through a secrets manager or environment injection instead of committing them to the file.")),
    Check("web-config", "web.config credentials", "high", "Exposed web.config",
          ("/web.config",), _content(r"<configuration", r"connectionStrings|password=|<appSettings", min_hits=2),
          "web.config can contain connection strings and machine keys.",
          ("Configure IIS request filtering so web.config is never served.", _ROTATE, _CHECK_LOGS)),
    Check("wp-config-copy", "wp-config saved as text", "critical", "Readable wp-config backup",
          ("/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~", "/wp-config.txt", "/wp-config.php.save", "/wp-config.php.orig"),
          _content(r"define\s*\(\s*['\"]DB_(NAME|PASSWORD|USER)['\"]"),
          "A served copy of wp-config.php exposes the database credentials and the authentication salts.",
          (_REMOVE_FILE, "Change the database password and regenerate the WordPress salts and keys.", _CHECK_LOGS)),
    Check("git-repo", "Exposed .git repository", "high", "Exposed .git repository",
          ("/.git/config", "/.git/HEAD"), _content(r"^\[core\]", r"^ref:\s*refs/"),
          "A reachable .git folder lets anyone rebuild the full source code and its history, including old secrets.",
          ("Deny access to /.git at the web server and remove the folder from the deployed web root.",
           "Rotate any credential that was ever committed, because it stays in the history.", _CHECK_LOGS)),
    Check("svn-metadata", "Exposed .svn metadata", "high", "Exposed .svn metadata",
          ("/.svn/wc.db", "/.svn/entries"),
          _any(_magic(b"SQLite format 3"), _content(r"^dir\s*$", r"^\d+\s*$", min_hits=2)),
          "Subversion metadata reveals file lists and can be used to fetch source code.",
          (_BLOCK_DOTFILES, "Deploy with an export (no .svn folder) rather than a working copy.")),
    Check("ssh-key", "SSH private keys in listings", "critical", "Exposed private key",
          ("/id_rsa", "/.ssh/id_rsa", "/id_dsa", "/.ssh/id_ed25519"),
          _content(r"-----BEGIN (RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----"),
          "A private key can grant direct login to servers or repositories.",
          (_REMOVE_FILE, "Revoke the key everywhere it is authorized and issue a new one.", _CHECK_LOGS)),
    Check("sftp-config", "SFTP editor configs", "high", "Exposed SFTP editor config",
          ("/sftp-config.json", "/.vscode/sftp.json"),
          _content(r'"host"\s*:', r'"(password|user|username|ssh_key_file)"\s*:', min_hits=2),
          "Editor SFTP settings store server addresses and, often, the login password.",
          (_REMOVE_FILE, _ROTATE, _BLOCK_DOTFILES)),
    Check("cloud-state", "Terraform state / cloud credentials", "critical", "Exposed Terraform state or cloud credentials",
          ("/terraform.tfstate", "/terraform.tfstate.backup", "/.terraform/terraform.tfstate", "/.aws/credentials"),
          _content(r'"terraform_version"\s*:', r"^aws_access_key_id\s*="),
          "State files list infrastructure and frequently contain live secrets; AWS credential files are usable keys.",
          (_REMOVE_FILE, "Revoke and reissue any cloud access keys, then move Terraform state to a private remote backend.", _CHECK_LOGS)),
    Check("backup-source", "Backup file extensions", "high", "Readable backup of a script",
          ("/index.php.bak", "/index.php~", "/config.php.bak", "/config.php.old", "/config.php~"),
          _content(r"<\?php", html_ok=True),
          "A backup copy is served as plain text, so its source code and any embedded credentials are readable.",
          (_REMOVE_FILE, "Block backup extensions (.bak, .old, ~, .orig) at the web server.", _ROTATE)),
    Check("htpasswd", ".htpasswd files", "high", "Exposed .htpasswd",
          ("/.htpasswd",), _content(r"^[\w.@-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13})"),
          "Password hashes for basic-auth users can be cracked offline.",
          (_BLOCK_DOTFILES, "Change the passwords of every user in the file.")),
    Check("backup-archive", "Backup archives", "high", "Downloadable backup archive",
          ("/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip", "/www.zip", "/wwwroot.zip", "/website.zip", "/db.zip", "/database.zip", "/backup.sql.gz"),
          _magic(b"PK\x03\x04", b"\x1f\x8b", b"Rar!", b"7z\xbc\xaf\x27\x1c"),
          "A site or database backup contains source code and data that were never meant to be public.",
          (_REMOVE_FILE, "Keep backups outside the web root or in private storage.", _ROTATE, _CHECK_LOGS)),
    Check("sql-dump", "phpMyAdmin dump text", "critical", "Exposed database dump",
          ("/dump.sql", "/backup.sql", "/database.sql", "/db.sql", "/site.sql", "/data.sql", "/mysql.sql", "/backup/backup.sql"),
          _content(r"^(CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS|-- (MySQL dump|Dumping data for table|PostgreSQL database dump))"),
          "A SQL dump contains the application's data, often including user records and password hashes.",
          (_REMOVE_FILE, "Assess what personal data the dump held and whether it must be reported as a breach.", _ROTATE, _CHECK_LOGS)),
    Check("server-logs", "Web server logs", "medium", "Exposed log file",
          ("/access.log", "/error.log", "/logs/access.log", "/logs/error.log", "/log/error.log", "/storage/logs/laravel.log"),
          _content(r'\b(GET|POST|HEAD) \S+ HTTP/1\.[01]"', r"\[(error|warn|notice)\]", r"PHP (Warning|Notice|Fatal error|Deprecated)",
                   r"^\[\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d[^\]]*\]\s+\w+\.(ERROR|WARNING|INFO)"),
          "Logs reveal internal paths, visitor IPs, request parameters and sometimes session tokens or errors with secrets.",
          ("Move logs outside the web root and deny direct access to *.log files.", "Rotate any session token or credential visible in the log.")),
    Check("wp-debug-log", "WordPress debug log", "medium", "Exposed WordPress debug log",
          ("/wp-content/debug.log",), _content(r"PHP (Warning|Notice|Fatal error|Deprecated)", r"^\[\d\d-\w{3}-\d{4}"),
          "The WP_DEBUG log lists file paths, plugin errors and sometimes query details.",
          ("Turn off WP_DEBUG_LOG on production, or point it outside the web root.", _REMOVE_FILE)),
    Check("django-debug", "Django debug page", "high", "Django running with DEBUG enabled",
          (NONCE_PATH,), _content(r"DEBUG = True", r"Django", min_hits=2, statuses=None, html_ok=True),
          "The debug error page prints settings, installed apps and code paths to anyone who triggers an error.",
          ("Set DEBUG = False and configure ALLOWED_HOSTS in production settings.", "Rotate SECRET_KEY and any credential shown in past error pages.", _RERUN),
          per_path_title=False),
    Check("laravel-debug", "Laravel debug page", "high", "Laravel debug mode enabled",
          (NONCE_PATH,), _content(r"Whoops! There was an error|facade/ignition|window\.ignition", statuses=None, html_ok=True),
          "Debug mode exposes stack traces and environment values, and older Ignition versions allow remote code execution.",
          ("Set APP_DEBUG=false in production and clear the config cache.", "Rotate APP_KEY and any secret shown in past error pages.", _RERUN),
          per_path_title=False),
    Check("stack-trace", "Application stack traces", "medium", "Verbose error output",
          (NONCE_PATH,),
          _content(r"Traceback \(most recent call last\)", r"Fatal error:.{0,200} on line \d+", r"you have an error in your SQL syntax",
                   r"at [\w.$]+\(\w+\.java:\d+\)", statuses=None, html_ok=True),
          "Error pages that print stack traces or SQL errors tell an attacker the framework, file paths and query structure.",
          ("Show a generic error page in production and log the details server-side only.", _RERUN),
          per_path_title=False),
    Check("actuator-env", "Spring Boot actuator", "high", "Spring Boot actuator exposed",
          ("/actuator/env", "/env"), _content(r'"propertySources"', r'"activeProfiles"'),
          "The env endpoint lists configuration properties and can leak credentials.",
          ("Expose only health and info endpoints, and secure the rest with authentication.", _ROTATE)),
    Check("actuator-heapdump", "Spring Boot actuator", "critical", "Spring Boot heap dump downloadable",
          ("/actuator/heapdump", "/heapdump"), _magic(b"JAVA PROFILE"),
          "A heap dump contains the application's memory, including secrets and session data.",
          ("Disable the heapdump endpoint and secure the actuator behind authentication.", "Rotate every secret the application held in memory.", _CHECK_LOGS)),
    Check("server-status", "Apache server-status", "medium", "Apache status page exposed",
          ("/server-status", "/server-info"), _content(r"Apache Server Status for", r"Apache Server Information", html_ok=True),
          "Live status pages show client IPs and the URLs being requested.",
          ("Restrict server-status and server-info to localhost or an admin IP allowlist.",)),
    Check("jenkins-console", "Jenkins dashboards", "critical", "Jenkins script console reachable",
          ("/script",), _content(r"Script Console", r"Jenkins", min_hits=2, html_ok=True),
          "An open script console allows arbitrary code execution on the Jenkins server.",
          ("Require login for all Jenkins access and disable anonymous read.", _RESTRICT, "Rotate credentials stored in Jenkins.")),
    Check("jenkins-login", "Jenkins dashboards", "medium", "Jenkins exposed to the internet",
          ("/login",), _header_present("x-jenkins", statuses=(200,)),
          "A public CI server is a high-value target and often has weak or default credentials.",
          (_RESTRICT, "Keep Jenkins and its plugins patched.")),
    Check("grafana", "Grafana logins", "low", "Grafana login exposed",
          ("/login",), _content(r"<title>\s*Grafana\s*</title>", r"grafana-app", html_ok=True),
          "Older Grafana versions have known authentication bypasses and file-read bugs.",
          (_RESTRICT, "Keep Grafana patched and disable anonymous access.")),
    Check("kibana", "Kibana consoles", "medium", "Kibana console exposed",
          ("/app/kibana", "/app/home"),
          _any(_header_present("kbn-name"), _content(r"kbn-injected-metadata", r"<title>\s*Elastic\s*</title>", html_ok=True)),
          "A public Kibana can expose indexed logs and business data.",
          (_RESTRICT, "Enable authentication and role-based access on the Elastic stack.")),
    Check("elasticsearch", "Elasticsearch nodes", "high", "Elasticsearch node answering publicly",
          ("/",), _content(r'"tagline"\s*:\s*"You Know, for Search"', html_ok=True),
          "An open Elasticsearch node can usually be read, and sometimes written, by anyone.",
          ("Bind the node to a private interface and require authentication (security features or a proxy).", _RESTRICT)),
    Check("elasticsearch-indices", "Elasticsearch nodes", "critical", "Elasticsearch indices listable without login",
          ("/_cat/indices",), _content(r"^(green|yellow|red)\s+(open|close)\s"),
          "Unauthenticated access to the index list means the stored data can be read.",
          ("Enable authentication immediately and block public access to port 9200.", "Review which indexes held personal or sensitive data.")),
    Check("swagger", "Swagger / API docs", "low", "Public API documentation",
          ("/swagger-ui.html", "/swagger-ui/index.html", "/swagger/index.html", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json"),
          _content(r"swagger-ui", r'"swagger"\s*:', r'"openapi"\s*:', html_ok=True),
          "Public API docs list every endpoint and parameter, including internal ones.",
          ("Disable or require login for API documentation outside development.", "Make sure each documented endpoint enforces authentication itself.")),
    Check("tomcat-manager", "Tomcat manager", "medium", "Tomcat manager reachable",
          ("/manager/html",), _any(_basic_auth_realm("tomcat manager"), _content(r"Tomcat Web Application Manager", html_ok=True)),
          "A reachable manager lets anyone with weak credentials deploy code.",
          (_RESTRICT, "Remove default manager accounts and use strong, unique passwords.")),
    Check("gitlab", "GitLab sign-in pages", "low", "GitLab instance exposed",
          ("/users/sign_in",), _content(r"GitLab", r"sign_in|Sign in", min_hits=2, html_ok=True),
          "A public GitLab is a target for credential attacks and may allow open sign-up.",
          ("Disable public sign-up and set project visibility to private by default.", "Keep GitLab patched.")),
    Check("webmail", "Webmail portals", "low", "Webmail login exposed",
          ("/webmail", "/roundcube/", "/mail/"), _content(r"Roundcube Webmail|SquirrelMail|rcmloginuser|Horde", html_ok=True),
          "Mail logins are common phishing and password-spray targets.",
          ("Enforce multi-factor authentication and rate limiting on the mail login.", "Restrict the portal by VPN if it is only for staff.")),
    Check("wp-users", "WordPress user listing", "medium", "WordPress user list exposed",
          ("/wp-json/wp/v2/users",), _content(r'"slug"\s*:', r'"link"\s*:', min_hits=2),
          "The REST API discloses real usernames, which makes password attacks easier.",
          ("Restrict the users REST route to logged-in users (security plugin or a small filter).", "Use unique display names and enforce strong passwords with MFA.")),
    Check("wp-readme", "WordPress readme version", "low", "WordPress version disclosed",
          ("/readme.html",), _content(r"WordPress", r"Version\s+\d", min_hits=2, html_ok=True),
          "The default readme names the exact WordPress version, which points attackers at known bugs.",
          ("Delete readme.html and keep WordPress core and plugins updated.",)),
    Check("wp-xmlrpc", "WordPress XML-RPC", "low", "WordPress XML-RPC enabled",
          ("/xmlrpc.php",), _content(r"XML-RPC server accepts POST requests only", statuses=(200, 405), html_ok=True),
          "XML-RPC is used for brute-force amplification and pingback abuse.",
          ("Disable XML-RPC unless a client needs it, or block /xmlrpc.php at the web server.",)),
    Check("joomla-config", "Joomla config backups", "critical", "Readable Joomla config backup",
          ("/configuration.php-dist", "/configuration.php.bak", "/configuration.php~", "/configuration.php.old"),
          _content(r"class\s+JConfig"),
          "Joomla's config holds the database credentials and secret.",
          (_REMOVE_FILE, "Change the database password and the Joomla secret.", _CHECK_LOGS)),
    Check("drupal-changelog", "Drupal changelog", "low", "Drupal version disclosed",
          ("/CHANGELOG.txt",), _content(r"^Drupal\s+\d+\.\d+"),
          "The changelog states the exact Drupal version.",
          ("Remove CHANGELOG.txt from the public web root and keep Drupal updated.",)),
    Check("directory-listing", "Open directory listings", "medium", "Open directory listing",
          ("/", "/uploads/", "/backup/", "/backups/", "/files/", "/wp-content/uploads/", "/admin/", "/images/", "/logs/", "/tmp/", "/old/"),
          _content(r"<title>\s*Index of /", r"<h1>\s*Index of /", html_ok=True),
          "A directory index shows every file in the folder, including ones never linked from the site.",
          ("Turn off automatic indexes (nginx: autoindex off; Apache: Options -Indexes).", "Review what the folder held and move anything sensitive out of the web root.")),
    Check("phpinfo", "Exposed phpinfo()", "medium", "phpinfo() page exposed",
          ("/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php"), _content(r"phpinfo\(\)", r"PHP Version\s+\d", html_ok=True),
          "phpinfo() prints the full server configuration, paths, modules and environment variables.",
          (_REMOVE_FILE, "Rotate any secret that appears in the environment section.")),
    Check("db-admin", "Database admin tools", "medium", "Database admin tool reachable",
          ("/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/adminer.php", "/adminer/"),
          _content(r"pma_username|<title>phpMyAdmin", r'name="auth\[driver\]"|<title>Login - Adminer', html_ok=True),
          "A public database console invites password guessing and exploits against the tool itself.",
          (_RESTRICT, "Use strong unique database credentials and remove the tool if it is not needed.")),
    Check("default-page", "Default web server pages", "low", "Default web server page",
          ("/",), _content(r"Apache2 (Ubuntu|Debian) Default Page|Welcome to nginx!|IIS Windows Server|Test Page for the (Apache|Nginx)", html_ok=True),
          "A default page usually means the server was never hardened or the site is not deployed.",
          ("Deploy the real site or take the host off the internet.", "Review the server against a hardening baseline.")),
]

_BUCKET_MATCH = _content(r"<ListBucketResult", statuses=(200,), html_ok=True)
_BUCKETS = (
    ("Open S3 buckets", "Amazon S3", "https://s3.amazonaws.com/{name}/"),
    ("Open Google Cloud Storage", "Google Cloud Storage", "https://storage.googleapis.com/{name}/"),
)
_BUCKET_STEPS = (
    "Turn off public listing and public read access on the bucket (block public access settings).",
    "Review the bucket contents and rotate any credential or personal data that was reachable.",
)


def bucket_names(domain: str) -> List[str]:
    """Names built from the *full* domain only. A bare label like "example"
    is almost certainly some other organization's bucket, so it is not tried."""
    bare = domain[4:] if domain.startswith("www.") else domain
    return list(dict.fromkeys([bare, bare.replace(".", "-")]))


# ----------------------------------------------------------------- scanner


def _finding(check_label: str, severity: str, title: str, url: str, evidence: str, impact: str, steps, host: str) -> dict:
    query = query_for(check_label, host)
    lead = f'Google dork "{check_label}"' + (f": {query}. " if query else ". ")
    return {
        "severity": severity,
        "cve": None,
        "title": title,
        "description": f"{lead}Confirmed by requesting {url} ({evidence}). {impact}",
        "recommendation": "\n".join(steps),
    }


class ExposureScanner:
    source = "real"

    def __init__(self, fetch: Fetch = http_get, workers: int = WORKERS):
        self._fetch = fetch
        self._workers = workers

    def run(self, host: str, control: ScanControl = None, bucket_domain: Optional[str] = None) -> ScannerResult:
        base = self._base_url(host)
        if base is None:
            return ScannerResult(success=True, source=self.source, raw_output="unreachable")

        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        nonce_path = NONCE_PATH.format(nonce=nonce)
        paths = list(dict.fromkeys(nonce_path if p == NONCE_PATH else p for c in CHECKS for p in c.paths))

        responses = self._fetch_all(base, paths, control)
        if responses is None:
            return ScannerResult(success=True, source=self.source, stopped=True)

        bare_host = urlparse(base).netloc
        baseline = responses.get(nonce_path)
        catch_all_body = baseline.body if baseline is not None and baseline.status == 200 else None

        findings = []
        for check in CHECKS:
            for path in check.paths:
                resolved = nonce_path if path == NONCE_PATH else path
                response = responses.get(resolved)
                if response is None or (catch_all_body is not None and response.body == catch_all_body):
                    continue
                evidence = check.match(response)
                if not evidence:
                    continue
                title = TITLE_PREFIX + check.title + (f": {path}" if check.per_path_title else "")
                findings.append(_finding(check.label, check.severity, title, response.url, evidence, check.impact, check.steps, bare_host))

        checks_run = len(responses)
        if bucket_domain:
            bucket_findings, bucket_requests = self._bucket_findings(bucket_domain, bare_host, control)
            findings.extend(bucket_findings)
            checks_run += bucket_requests

        return ScannerResult(success=True, source=self.source, data=findings, raw_output=f"{checks_run} requests")

    def _base_url(self, host: str) -> Optional[str]:
        # An asset is often stored as https:// even when the site only serves
        # plain HTTP, so the stored scheme is tried first and the other second.
        if host.startswith(("http://", "https://")):
            parsed = urlparse(host)
            netloc, schemes = parsed.netloc, [parsed.scheme, "http" if parsed.scheme == "https" else "https"]
        else:
            netloc, schemes = host, ["https", "http"]
        for scheme in schemes:
            if self._fetch(f"{scheme}://{netloc}/"):
                return f"{scheme}://{netloc}"
        return None

    def _fetch_all(self, base: str, paths: List[str], control: Optional[ScanControl]) -> Optional[Dict[str, Response]]:
        """Fetch every path in parallel. Returns None if the scan was stopped."""
        responses: Dict[str, Response] = {}
        pool = ThreadPoolExecutor(max_workers=self._workers)
        try:
            futures = {pool.submit(self._fetch, base + path): path for path in paths}
            for future in as_completed(futures):
                if control:
                    control.wait_if_paused()
                    if control.stop_requested():
                        return None
                response = future.result()
                if response is not None:
                    responses[futures[future]] = response
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return responses

    def _bucket_findings(self, domain: str, host: str, control: Optional[ScanControl]):
        findings, requests = [], 0
        for name in bucket_names(domain):
            for label, provider, template in _BUCKETS:
                if control and control.stop_requested():
                    return findings, requests
                url = template.format(name=name)
                requests += 1
                response = self._fetch(url)
                evidence = _BUCKET_MATCH(response) if response else None
                if evidence:
                    findings.append(_finding(label, "critical", f"{TITLE_PREFIX}Publicly listable {provider} bucket: {name}",
                                             url, evidence, "Anyone can list, and usually read, every object in the bucket. The name only matches this domain, so confirm the bucket belongs to this organization.", _BUCKET_STEPS, host))
        return findings, requests
