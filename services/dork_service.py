"""Google dorking helper -- generates curated, categorized Google search
queries (site:, filetype:, inurl:, intitle:, intext:) for a specific
authorized target, as links to open in Google directly.

Categorized to match the Exploit-DB Google Hacking Database (GHDB)
taxonomy -- https://www.exploit-db.com/google-hacking-database -- the
long-standing reference catalog for this recon technique, with queries
drawn from well-documented public dork patterns for each category and
scoped to the target with `site:{domain}`.

There is no ToS-compliant way to scrape Google's results programmatically
(scraping search result pages violates Google's Terms of Service and gets
IPs rate-limited/blocked quickly), so this deliberately stays a "generate
the queries, a human reviews the real results in their own browser" tool
rather than an automated scanner -- the same way the GHDB itself is just
a catalog of queries, not a scraper.
"""

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
        "category": "Cloud storage exposure",
        "queries": [
            ("Open S3 buckets", "site:s3.amazonaws.com \"{domain}\"", "Amazon S3 buckets referencing this domain that Google has indexed."),
            ("Open Azure blobs", "site:blob.core.windows.net \"{domain}\"", "Azure Blob Storage containers referencing this domain."),
        ],
    },
]


def dork_categories_for_domain(domain: str):
    """Return the dork catalog with each query rendered for `domain` and
    a ready-to-open Google search URL.
    """
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
                }
            )
        categories.append({"category": group["category"], "queries": queries})
    return categories


def total_dork_count() -> int:
    return sum(len(group["queries"]) for group in _DORK_TEMPLATES)
