# Deployment Guide

The application code itself is OS-agnostic (pure Python/Flask, `os.path.join`
throughout, `shutil.which()` for scanner discovery, `psutil` for cross-platform
process suspend/resume). Both a Linux and a Windows/IIS deployment path are
documented below and are equally supported -- pick whichever fits your
infrastructure.

## Important: this app must run as a single process

Live scan control (Run/Pause/Stop) is tracked in an in-memory registry
(`services/job_registry.py`) inside the worker process that started the scan.
If requests are load-balanced across multiple **processes** (e.g. Gunicorn
with `--workers > 1`), a Pause/Stop click can land on a worker that never
started that scan and silently do nothing.

- Run **one process**, multiple **threads**, for both dev and production.
- Waitress does this by default (`threads=N` in one process) -- the simplest
  correct option on either OS.
- If you use Gunicorn on Linux, pin `--workers 1 --threads 8` (or similar) --
  never `--workers > 1` for this app as it's currently built.
- The rate limiter (`Flask-Limiter`) also defaults to in-memory storage
  (`RATELIMIT_STORAGE_URI=memory://`), which has the same single-process
  requirement. If you later need multiple processes/machines, move both the
  job registry design and the rate limiter to a shared backend (Redis) first.

## Continuous monitoring (the scheduler)

Monitored targets are re-scanned by a background thread inside the same single process
(`services/monitor_service.py`), so it needs the same one-process deployment described
above and nothing else: no cron job, no extra service.

- It starts with the app (under `flask run --debug` it starts in the serving process, on
  first request). Targets are claimed with one atomic database update, so even an
  accidental second process cannot scan the same target twice.
- Existing databases are upgraded in place at start-up (`AUTO_UPGRADE_SCHEMA`): new columns
  and the `monitor_events` table are added, nothing is removed. Back up the database first
  as you would before any release.
- To send alert emails set `MAIL_SERVER`, `MAIL_USERNAME`, `MAIL_PASSWORD` (see `.env`);
  without them alerts are only written to the application log.
- Optional, to add template-based scanning: install Nuclei (see below). The built-in
  configuration checks run either way.
- To remove the sample findings that older versions stored when Nuclei was missing:
  `python database/seed.py --remove-sample-findings` (only exact matches are deleted).

## Prerequisites (both OSes)

- Python 3.11+
- MySQL 8+ (schema in `database/mysql_schema.sql`)
- A `.env` file (copy `.env.example` if present, or set the variables listed
  in `config.py`: `SECRET_KEY`, `DATABASE_URL`, `MAIL_*`, `FLASK_ENV`)
- Optional, for real (non-mock) scanning: Subfinder, Nmap and Nuclei
  reachable on `PATH`. Without them the app automatically falls back to
  clearly-labeled mock scan data (see `scanner/base.py`) -- nothing breaks,
  it just isn't live.
- Outbound HTTPS access to `services.nvd.nist.gov`, `cve.circl.lu` and
  `www.cisa.gov` for the CVE/KEV threat-intelligence lookups
  (`services/cve_lookup.py`, `services/kev_service.py`).

---

## Linux (recommended: systemd + Waitress or Gunicorn, behind Nginx)

```bash
# 1. System packages
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv nmap mysql-server nginx

# 2. App + venv
cd /opt/attack-surface-management
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Scanner tools (Subfinder / Nuclei -- Go binaries, not in apt)
curl -sL -o /tmp/subfinder.zip \
  "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(uname -s)_amd64.zip"
curl -sL -o /tmp/nuclei.zip \
  "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_amd64.zip"
# unzip both into /usr/local/bin (check the actual release asset names on
# each project's GitHub Releases page; they change per version)

# 4. Database
mysql -u root -p < database/mysql_schema.sql
.venv/bin/python database/seed.py   # creates the initial IT Admin account

# 5. Config
cp .env.example .env   # then edit SECRET_KEY, DATABASE_URL, MAIL_*, FLASK_ENV=production
```

**systemd unit** (`/etc/systemd/system/asm.service`):

```ini
[Unit]
Description=Attack Surface Management
After=network.target mysql.service

[Service]
Type=simple
User=asm
WorkingDirectory=/opt/attack-surface-management
EnvironmentFile=/opt/attack-surface-management/.env
ExecStart=/opt/attack-surface-management/.venv/bin/python wsgi.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`wsgi.py` (already in the repo root) runs the app under Waitress on
`127.0.0.1:5050`. If you prefer Gunicorn instead, remember the single-process
constraint above:

```bash
.venv/bin/gunicorn --workers 1 --threads 8 --bind 127.0.0.1:5050 "app:create_app()"
```

**Nginx reverse proxy** (`/etc/nginx/sites-available/asm`):

```nginx
server {
    listen 80;
    server_name asm.your-domain.example;

    location / {
        proxy_pass http://127.0.0.1:5050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Put TLS in front with `certbot --nginx` once the domain resolves.

```bash
sudo systemctl enable --now asm
sudo ln -s /etc/nginx/sites-available/asm /etc/nginx/sites-enabled/
sudo systemctl reload nginx
```

---

## Windows (IIS as a reverse proxy in front of Waitress)

Modern IIS Python hosting doesn't need the old `wfastcgi` WSGI bridge --
run the app under Waitress as a Windows service and let IIS (or
`Application Request Routing`) reverse-proxy to it, the same pattern as the
Nginx setup above.

```powershell
# 1. Prerequisites
winget install Python.Python.3.11
winget install Insecure.Nmap
# Subfinder / Nuclei: download the *_windows_amd64.zip from each project's
# GitHub Releases page and put the .exe files on PATH.

# 2. App + venv
cd C:\inetpub\attack-surface-management
py -3.11 -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# 3. Database (MySQL Community Server or Laragon for local/dev)
mysql -u root -p < database\mysql_schema.sql
.venv\Scripts\python database\seed.py

# 4. Config
copy .env.example .env   # edit SECRET_KEY, DATABASE_URL, MAIL_*, FLASK_ENV=production
```

**Run as a Windows service** with NSSM (the Non-Sucking Service Manager) so
it survives reboots without a logged-in session:

```powershell
choco install nssm    # or download nssm.exe directly
nssm install AttackSurfaceManagement "C:\inetpub\attack-surface-management\.venv\Scripts\python.exe" "C:\inetpub\attack-surface-management\wsgi.py"
nssm set AttackSurfaceManagement AppDirectory "C:\inetpub\attack-surface-management"
nssm start AttackSurfaceManagement
```

This serves the app on `127.0.0.1:5050` (edit `wsgi.py`'s `serve(...)` call
to change the port).

**IIS reverse proxy**: install `Application Request Routing` (ARR) and
`URL Rewrite` from the IIS extensions, enable ARR's proxy, then add this to
the site's `web.config`:

```xml
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="ReverseProxyToWaitress" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="http://127.0.0.1:5050/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
```

Bind the IIS site to your domain/port 443 with a certificate the normal IIS
way; IIS handles TLS termination and forwards plain HTTP to Waitress
internally, same division of labor as the Nginx setup.

---

## Either OS: verifying the deployment

```bash
curl -I http://127.0.0.1:5050/login   # direct to the app process
curl -I https://asm.your-domain.example/login   # through the reverse proxy
```

Then log in with the seeded IT Admin account and confirm:
- `/admin/dashboard` loads and shows the seeded user.
- Running a scan against an authorized test target (or `scanme.nmap.org`,
  which exists specifically for this) produces real (not mock) results if
  Subfinder/Nmap/Nuclei are installed and on `PATH` for the account the
  service runs as -- `PATH` for a Windows service or systemd unit is **not**
  the same as your interactive shell's `PATH`, so this is the most common
  thing to re-check after moving from dev to a service.
