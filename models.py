from datetime import datetime

from flask_login import UserMixin

from extensions import bcrypt, db

# Roles
ROLE_IT_ADMIN = "it_admin"
ROLE_ANALYST = "cybersecurity_analyst"
ROLE_SECURITY_TEAM = "security_team"
ROLE_THREAT_INTEL = "threat_intel_analyst"
ROLES = (ROLE_IT_ADMIN, ROLE_ANALYST, ROLE_SECURITY_TEAM, ROLE_THREAT_INTEL)

# Severities
SEVERITIES = ("critical", "high", "medium", "low")

# Scan types / status
SCAN_TYPES = ("asset_discovery", "port_discovery", "vulnerability_scan")
SCAN_STATUSES = ("pending", "running", "paused", "completed", "failed", "stopped")

# Report types
REPORT_TYPES = ("pdf", "csv")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(30), nullable=False, default=ROLE_ANALYST)
    is_active_flag = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    targets = db.relationship("AuthorizedTarget", backref="owner", lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_flag

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "is_active": self.is_active_flag,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuthorizedTarget(db.Model):
    __tablename__ = "authorized_targets"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    authorized = db.Column(db.Boolean, nullable=False, default=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    assets = db.relationship(
        "Asset", backref="target", lazy=True, cascade="all, delete-orphan"
    )
    scans = db.relationship(
        "Scan", backref="target", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "domain": self.domain,
            "description": self.description,
            "authorized": self.authorized,
            "owner_id": self.owner_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(
        db.Integer, db.ForeignKey("authorized_targets.id"), nullable=False
    )
    subdomain = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    url = db.Column(db.String(500))
    technologies = db.Column(db.String(500))
    discovery_date = db.Column(db.DateTime, default=datetime.utcnow)

    ports_services = db.relationship(
        "PortService", backref="asset", lazy=True, cascade="all, delete-orphan"
    )
    vulnerabilities = db.relationship(
        "Vulnerability", backref="asset", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "subdomain": self.subdomain,
            "ip_address": self.ip_address,
            "url": self.url,
            "technologies": self.technologies,
            "discovery_date": self.discovery_date.isoformat()
            if self.discovery_date
            else None,
        }


class PortService(db.Model):
    __tablename__ = "ports_services"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    service_name = db.Column(db.String(100))
    service_version = db.Column(db.String(100))
    state = db.Column(db.String(20), default="open")
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "state": self.state,
            "discovered_at": self.discovered_at.isoformat()
            if self.discovered_at
            else None,
        }


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cve = db.Column(db.String(50))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    status = db.Column(db.String(20), default="open")
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Threat-intelligence enrichment (services/kev_service.py, services/cve_lookup.py):
    # cvss_score is the real NVD CVSS base score when known, kev/exploit_available
    # flag whether CISA's Known Exploited Vulnerabilities catalog lists this CVE as
    # actively weaponized -- used to prioritize risk beyond a bare severity bucket.
    cvss_score = db.Column(db.Float)
    kev = db.Column(db.Boolean, nullable=False, default=False)
    exploit_available = db.Column(db.Boolean, nullable=False, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "cve": self.cve,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "status": self.status,
            "discovered_at": self.discovered_at.isoformat()
            if self.discovered_at
            else None,
            "cvss_score": self.cvss_score,
            "kev": self.kev,
            "exploit_available": self.exploit_available,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(
        db.Integer, db.ForeignKey("authorized_targets.id"), nullable=False
    )
    scan_type = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    started_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    result_summary = db.Column(db.Text)
    source = db.Column(db.String(10), default="mock")

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "started_by": self.started_by,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "result_summary": self.result_summary,
            "source": self.source,
        }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(
        db.Integer, db.ForeignKey("authorized_targets.id"), nullable=False
    )
    report_type = db.Column(db.String(10), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "report_type": self.report_type,
            "file_path": self.file_path,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at.isoformat()
            if self.generated_at
            else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
