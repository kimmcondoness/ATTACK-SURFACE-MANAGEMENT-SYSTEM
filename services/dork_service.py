"""Google dorking helper -- generates curated, categorized Google search
queries (site:, filetype:, inurl:, intitle:, intext:) for a specific
authorized target, as links to open in Google directly.

Categorized to match the Exploit-DB Google Hacking Database (GHDB)
taxonomy -- https://www.exploit-db.com/google-hacking-database -- the
long-standing reference catalog for this recon technique, with queries
drawn from well-documented public dork patterns for each category and
scoped to the target with `site:{domain}`.

The later categories (secrets, backups, debug endpoints, dev tools, CMS
fingerprints, third-party leak sources) are hand-picked and rewritten from
patterns that also appear in the open-source X-osint project's
google_Dorks.txt (https://github.com/TermuxHackz/X-osint, GPL-3.0, itself a
dump of GHDB entries). Only individual query patterns were adapted; each is
re-scoped to the target domain and no X-osint code is included.

There is no ToS-compliant way to scrape Google's results programmatically
(scraping search result pages violates Google's Terms of Service and gets
IPs rate-limited/blocked quickly), so this deliberately stays a "generate
the queries, a human reviews the real results in their own browser" tool
rather than an automated scanner -- the same way the GHDB itself is just
a catalog of queries, not a scraper.
"""

import re
from urllib.parse import quote_plus

# Each entry's `query` is a template with {domain} substituted in. Group
# names match GHDB's own category names so results map 1:1 onto that
# reference catalog; "Cloud storage exposure" is the one addition beyond
# GHDB's original 14, covering a modern OSINT surface (S3/Blob buckets)
# the 2010s-era GHDB categories predate.
_DORK_TEMPLATES = [
    {
        "category": "Footholds",
        "queries": [
            ("Exposed phpinfo()", 'site:{domain} intitle:"phpinfo()" "PHP Version"', "phpinfo() pages leak the full server configuration, paths and loaded modules -- a common first foothold."),
            ("Default install/setup pages", "site:{domain} intitle:\"Setup Configuration Page\" OR inurl:setup.php OR inurl:install.php", "Unremoved installer scripts can allow full re-configuration or a fresh admin account to be created."),
            ("Exposed web shells", "site:{domain} intitle:\"phpshell\" OR intitle:\"c99shell\" OR intitle:\"WSO Shell\"", "Known web-shell interfaces left behind by a prior compromise or careless testing."),
        ],
    },
    {
        "category": "Files Containing Usernames",
        "queries": [
            ("Password/credential logs", "site:{domain} filetype:log intext:\"username\" intext:\"password\"", "Application logs that recorded credentials in plain text."),
            ("Exported user lists", "site:{domain} filetype:xls OR filetype:csv intext:\"username\" intext:\"email\"", "Exported user/contact lists that were never meant to be public."),
            (".htpasswd files", "site:{domain} intitle:\"index of\" \".htpasswd\"", "Apache basic-auth credential files, sometimes crackable if indexed."),
        ],
    },
    {
        "category": "Sensitive Directories",
        "queries": [
            ("Open directory listings", "site:{domain} intitle:\"index of\" \"parent directory\"", "Misconfigured web servers exposing raw directory contents."),
            ("Exposed uploads folder", "site:{domain} intitle:\"index of\" inurl:uploads", "Unrestricted upload directories, often browsable without authentication."),
            ("Exposed .ssh / backup folders", "site:{domain} intitle:\"index of\" (\".ssh\" OR \"backup\" OR \"old\")", "Directories that should never be reachable from the public internet."),
        ],
    },
    {
        "category": "Web Server Detection",
        "queries": [
            ("Default web server pages", "site:{domain} intitle:\"Apache2 Ubuntu Default Page\" OR intitle:\"Welcome to nginx\" OR intitle:\"IIS Windows Server\"", "A default landing page usually means the server was never hardened after install."),
            ("Server self-test pages", "site:{domain} intitle:\"Test Page for Apache Installation\"", "Leftover test pages that confirm software/version and are unnecessary attack surface."),
        ],
    },
    {
        "category": "Vulnerable Files",
        "queries": [
            ("Common LFI/RFI-prone parameters", "site:{domain} inurl:\"page=\" OR inurl:\"file=\" OR inurl:\"include=\"", "URL parameters historically associated with local/remote file inclusion bugs -- verify input handling."),
            ("Exposed upload handlers", "site:{domain} inurl:\"upload.php\" OR inurl:\"file_upload.php\"", "Upload endpoints are common targets for unrestricted file-upload vulnerabilities."),
        ],
    },
    {
        "category": "Vulnerable Servers",
        "queries": [
            ("Exposed WS_FTP / FTP logs", "site:{domain} intitle:\"index of\" \"WS_FTP.log\"", "Historic FTP client logs that can reveal internal file paths and hosts."),
            ("Outdated CMS version fingerprint", "site:{domain} intext:\"Powered by WordPress\" OR intext:\"Powered by Joomla!\" intext:\"version\"", "A publicly disclosed CMS version makes it trivial to look up known CVEs for that exact build."),
        ],
    },
    {
        "category": "Error Messages",
        "queries": [
            ("Database error output", "site:{domain} intext:\"Warning: mysql_connect()\" OR intext:\"ORA-00921\" OR intext:\"you have an error in your SQL syntax\"", "Verbose database errors can leak table/column names, paths and driver/version details."),
            ("Application stack traces", "site:{domain} intext:\"stack trace\" OR intext:\"fatal error\" intext:\"on line\"", "Unhandled exceptions revealing internal file paths, frameworks and versions."),
        ],
    },
    {
        "category": "Files Containing Juicy Info",
        "queries": [
            ("Private keys", "site:{domain} intext:\"BEGIN RSA PRIVATE KEY\" OR intext:\"BEGIN OPENSSH PRIVATE KEY\" OR filetype:pem", "A leaked private key can be a full-compromise-severity finding on its own."),
            ("Config / env files", "site:{domain} filetype:env OR filetype:conf OR filetype:config OR filetype:yml OR filetype:ini", "Configuration files that can contain secrets or connection strings."),
            ("Database dumps", "site:{domain} filetype:sql OR filetype:db OR filetype:sqlite", "Raw database exports -- a critical finding if indexed."),
        ],
    },
    {
        "category": "Files Containing Passwords",
        "queries": [
            ("Credentials/API keys in page text", "site:{domain} intext:\"api_key\" OR intext:\"apikey\" OR intext:\"secret_key\" OR intext:\"password\"", "Pages that mention secrets in plain text -- verify context before treating as a real leak."),
            ("Password dumps in SQL exports", "site:{domain} filetype:sql intext:\"INSERT INTO\" intext:\"password\"", "SQL export files that embed hashed or plaintext user passwords."),
            ("Backed-up config with credentials", "site:{domain} intitle:\"index of\" (\"wp-config.php.bak\" OR \".env.bak\")", "Backup copies of config files often bypass the access rules that protect the original."),
        ],
    },
    {
        "category": "Sensitive Online Shopping Info",
        "queries": [
            ("Payment data in exports/logs", "site:{domain} filetype:sql OR filetype:log intext:\"credit_card\" OR intext:\"cc_number\" OR intext:\"card number\"", "Any indexed payment-card data is a severe, often regulatory-reportable exposure."),
        ],
    },
    {
        "category": "Network or Vulnerability Data",
        "queries": [
            ("Leaked scan reports", "site:{domain} intitle:\"Nessus Scan Report\" OR intext:\"Nikto\" OR filetype:xml intext:\"nmap\"", "Published scan output from Nessus/Nikto/Nmap runs against this target -- a roadmap of its own weaknesses if exposed."),
        ],
    },
    {
        "category": "Pages Containing Login Portals",
        "queries": [
            ("Admin panels", "site:{domain} inurl:admin", "Administrative interfaces that shouldn't be publicly discoverable."),
            ("Login pages", "site:{domain} inurl:login OR inurl:signin", "Authentication endpoints -- confirm they're intended to be public."),
            ("Database admin tools", "site:{domain} inurl:phpmyadmin OR inurl:adminer", "Database management tools that should never be internet-facing."),
        ],
    },
    {
        "category": "Various Online Devices",
        "queries": [
            ("Exposed cameras/IoT panels", "site:{domain} intitle:\"Network Camera\" OR intitle:\"webcamXP\" OR intitle:\"VOIP\" intext:\"login\"", "Internet-facing cameras or embedded-device panels tied to this organization."),
            ("Exposed router/printer admin", "site:{domain} intitle:\"Router Login\" OR intitle:\"Printer\" intext:\"login\"", "Network hardware admin panels that are easy to overlook during asset inventory."),
        ],
    },
    {
        "category": "Advisories and Vulnerabilities",
        "queries": [
            ("Version-disclosing banners", "site:{domain} intext:\"Powered by\" intext:\"version\"", "Any explicit software/version string is a direct lookup key for known CVEs (cross-reference with the Findings panel's NVD lookups)."),
        ],
    },
    {
        "category": "Secrets and config exposure",
        "queries": [
            ("Laravel .env files", 'site:{domain} ext:env intext:"APP_KEY=" OR intext:"APP_DEBUG="', "A Laravel .env holds the app key and usually database and mail credentials."),
            ("Database passwords in .env", 'site:{domain} ext:env intext:"DB_PASSWORD"', "Environment files carrying database credentials in plain text."),
            ("Docker Compose secrets", 'site:{domain} ext:yml intext:"MYSQL_ROOT_PASSWORD" OR intext:"POSTGRES_PASSWORD"', "docker-compose files with database passwords baked in."),
            ("web.config credentials", 'site:{domain} inurl:web.config ext:config intext:"password"', "IIS/ASP.NET config files with connection strings or credentials."),
            ("wp-config saved as text", 'site:{domain} inurl:wp-config (ext:txt OR ext:bak OR ext:old)', "Copies of wp-config.php that the server hands out as plain text, exposing DB credentials and salts."),
            ("Jenkins config hashes", 'site:{domain} inurl:config.xml ext:xml intext:"passwordHash"', "Jenkins configuration files containing user password hashes."),
            ("Exposed .git repository", 'site:{domain} inurl:".git" intitle:"index of"', "A reachable .git folder lets anyone download the full source and its history."),
            ("Exposed .svn metadata", 'site:{domain} inurl:".svn" intitle:"index of"', "Subversion metadata that can be used to rebuild source code."),
            ("SSH private keys in listings", 'site:{domain} intitle:"index of" "id_rsa" -"id_rsa.pub"', "Private keys sitting in a browsable directory."),
            ("SFTP editor configs", "site:{domain} inurl:sftp-config.json", "Sublime SFTP settings files that store server hostnames and passwords."),
            ("Terraform state / cloud credentials", 'site:{domain} ext:tfstate OR inurl:".aws/credentials"', "Terraform state and AWS credential files contain resource details and often live secrets."),
        ],
    },
    {
        "category": "Backups and database dumps",
        "queries": [
            ("Backup file extensions", "site:{domain} ext:bak OR ext:old OR ext:backup OR ext:orig OR ext:save", "Leftover copies of scripts and configs are often served as plain text."),
            ("Backup archives", "site:{domain} inurl:backup (ext:zip OR ext:tar OR ext:gz OR ext:7z OR ext:rar)", "Compressed site or database backups reachable by URL."),
            ("phpMyAdmin dump text", 'site:{domain} intext:"-- Dumping data for table" OR intext:"phpMyAdmin MySQL-Dump"', "Pasted or uploaded SQL dumps that include table contents."),
            ("BackupBuddy archives", 'site:{domain} intitle:"index of" inurl:backupbuddy_backups', "WordPress BackupBuddy backups stored in a browsable folder."),
        ],
    },
    {
        "category": "Logs and debug endpoints",
        "queries": [
            ("Web server logs", "site:{domain} inurl:access.log OR inurl:error.log ext:log", "Access and error logs reveal internal paths, IPs and sometimes session tokens."),
            ("WordPress debug log", "site:{domain} inurl:wp-content/debug.log", "WP_DEBUG output written to a public file, leaking paths and plugin errors."),
            ("Laravel debug page", 'site:{domain} intext:"Whoops! There was an error"', "Laravel/Whoops error pages that expose environment variables and stack traces."),
            ("Django debug page", 'site:{domain} intext:"You\'re seeing this error because you have DEBUG = True"', "Django running with DEBUG on, which prints settings and code paths."),
            ("Spring Boot actuator", "site:{domain} inurl:/actuator/env OR inurl:/actuator/heapdump", "Actuator endpoints can disclose configuration values and even memory dumps."),
            ("Apache server-status", 'site:{domain} inurl:server-status intitle:"Apache Status"', "Live server status pages show client IPs and requested URLs."),
        ],
    },
    {
        "category": "Admin and developer tools",
        "queries": [
            ("Jenkins dashboards", 'site:{domain} intitle:"Dashboard [Jenkins]"', "CI servers reachable from the internet, sometimes without authentication."),
            ("Grafana logins", 'site:{domain} intitle:"Grafana" inurl:/login', "Monitoring dashboards; older versions have known auth bypasses."),
            ("Kibana consoles", 'site:{domain} intitle:"Kibana" OR inurl:app/kibana', "Log/analytics consoles that can expose large amounts of internal data."),
            ("Elasticsearch nodes", 'site:{domain} intext:"You Know, for Search"', "An Elasticsearch node answering publicly, often with no authentication."),
            ("Swagger / API docs", "site:{domain} inurl:swagger-ui OR inurl:/swagger/index.html OR inurl:api-docs", "Public API documentation lists every endpoint, including internal ones."),
            ("Tomcat manager", 'site:{domain} intitle:"Apache Tomcat" inurl:manager', "Tomcat manager consoles allow deploying code if credentials are weak."),
            ("GitLab sign-in pages", 'site:{domain} intitle:"GitLab" inurl:users/sign_in', "Self-hosted GitLab instances; confirm registration and visibility settings."),
            ("Webmail portals", "site:{domain} inurl:webmail intitle:login", "Mail login portals are frequent phishing and password-spray targets."),
        ],
    },
    {
        "category": "CMS fingerprints",
        "queries": [
            ("WordPress user listing", 'site:{domain} inurl:"wp-json/wp/v2/users"', "The REST API reveals real usernames unless it is restricted."),
            ("WordPress readme version", 'site:{domain} inurl:readme.html intext:"WordPress"', "The default readme states the installed version."),
            ("WordPress XML-RPC", "site:{domain} inurl:xmlrpc.php", "An enabled XML-RPC endpoint is used for brute-force and pingback abuse."),
            ("Joomla config backups", "site:{domain} inurl:configuration.php-dist OR inurl:configuration.php.bak", "Backups of the Joomla config expose database credentials."),
            ("Drupal changelog", 'site:{domain} inurl:CHANGELOG.txt intext:"Drupal"', "The changelog file states the exact Drupal version."),
        ],
    },
    {
        "category": "Sensitive documents",
        "queries": [
            ("Confidential documents", 'site:{domain} (ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:pdf) intext:"confidential" OR intext:"internal use only"', "Internal documents that ended up indexed by search engines."),
            ("Internal spreadsheets", 'site:{domain} (ext:xls OR ext:xlsx OR ext:csv) intext:"employee" OR intext:"salary" OR intext:"invoice"', "Spreadsheets with staff or financial data that were never meant to be public."),
        ],
    },
    {
        "category": "Pre-production hosts",
        "queries": [
            ("Staging / dev / test sites", "site:{domain} inurl:staging OR inurl:dev OR inurl:test OR inurl:uat", "Pre-production copies are usually less hardened and may hold real data."),
        ],
    },
    {
        "category": "Third-party leak sources",
        "queries": [
            ("GitHub mentions with secrets", 'site:github.com "{domain}" (password OR secret OR api_key OR token)', "Public repositories that reference this domain next to a credential."),
            ("GitLab mentions", 'site:gitlab.com "{domain}" (password OR secret OR token)', "Public GitLab projects referencing this domain."),
            ("Pastebin mentions", 'site:pastebin.com "{domain}"', "Pastes that mention this domain, often credential or data dumps."),
            ("Trello boards", 'site:trello.com "{domain}"', "Public Trello boards where staff sometimes pin credentials or internal notes."),
            ("Public Google Docs and Sheets", 'site:docs.google.com "{domain}" (password OR credentials OR internal)', "Shared Docs or Sheets that mention this domain."),
        ],
    },
    {
        "category": "Cloud storage exposure",
        "queries": [
            ("Open S3 buckets", "site:s3.amazonaws.com \"{domain}\"", "Amazon S3 buckets referencing this domain that Google has indexed."),
            ("Open Azure blobs", "site:blob.core.windows.net \"{domain}\"", "Azure Blob Storage containers referencing this domain."),
            ("Open Google Cloud Storage", 'site:storage.googleapis.com "{domain}"', "Google Cloud Storage buckets referencing this domain."),
        ],
    },
]


def exposed_dork_labels(target_id: int) -> dict:
    """{dork label: number of confirmed exposures} for one target, read from
    the "[Dork]" findings the exposure scan stored (each one names its label)."""
    from models import Asset, Vulnerability

    rows = (
        Vulnerability.query.join(Asset)
        .filter(Asset.target_id == target_id, Vulnerability.title.like("[Dork]%"), Vulnerability.status.in_(("open", "in_progress")))
        .with_entities(Vulnerability.description)
        .all()
    )
    counts = {}
    for (description,) in rows:
        match = re.match(r'Google dork "([^"]+)"', description or "")
        if match:
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    return counts


def dork_categories_for_domain(domain: str, exposed: dict = None):
    """Return the dork catalog with each query rendered for `domain`, a
    ready-to-open Google search URL, and how many confirmed exposures the
    exposure scan found for it (`exposed` maps label -> count).
    """
    exposed = exposed or {}
    categories = []
    for group in _DORK_TEMPLATES:
        queries = []
        for label, query_template, description in group["queries"]:
            query = query_template.format(domain=domain)
            queries.append(
                {
                    "label": label,
                    "query": query,
                    "description": description,
                    "url": f"https://www.google.com/search?q={quote_plus(query)}",
                    "exposed": exposed.get(label, 0),
                }
            )
        categories.append({"category": group["category"], "queries": queries})
    return categories


def query_for(label: str, domain: str):
    """The rendered dork query for a catalog label, or None if there is no such label."""
    for group in _DORK_TEMPLATES:
        for item_label, query_template, _description in group["queries"]:
            if item_label == label:
                return query_template.format(domain=domain)
    return None


def total_dork_count() -> int:
    return sum(len(group["queries"]) for group in _DORK_TEMPLATES)
