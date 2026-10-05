import csv
import io
import re
import time
from datetime import datetime

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from extensions import bcrypt, db, limiter
from models import (
    MONITOR_INTERVALS,
    Asset,
    AuthorizedTarget,
    ROLE_ANALYST,
    ROLE_IT_ADMIN,
    ROLE_THREAT_INTEL,
    ROLES,
    Scan,
    User,
    VULN_STATUSES,
    Vulnerability,
)
from services.chart_service import RANGES as CHART_RANGES, normalize_range, scan_status_totals, severity_totals
from services import inventory_service, monitor_service, radar_service, user_admin_service
from services.dork_service import dork_categories_for_domain, exposed_dork_labels, total_dork_count
from services.report_service import list_reports_for_target
from services.risk_service import risk_score
from services.vulnerability_service import findings_for_targets
from utils.audit import log_action
from utils.captcha import generate_captcha, verify_captcha
from utils.device_trust import COOKIE_NAME as DEVICE_TRUST_COOKIE, set_device_trust_cookie, verify_device_trust_token
from utils.mailer import send_otp_email
from utils.otp import generate_otp, verify_otp
from utils.validators import EMAIL_RE, ValidationError, normalize_username, validate_password, validate_role, validate_username

auth_pages_bp = Blueprint("auth_pages", __name__)

_CAPTCHA_KEYS = ("captcha_question", "captcha_answer_hash", "captcha_expires_at")
_PENDING_MFA_KEYS = ("pending_user_id", "otp_hash", "otp_expires_at", "otp_attempts", "otp_last_sent_at")
_PENDING_SIGNUP_KEYS = (
    "pending_signup",
    "signup_otp_hash",
    "signup_otp_expires_at",
    "signup_otp_attempts",
    "signup_otp_last_sent_at",
)
_PENDING_RESET_KEYS = (
    "reset_user_id",
    "reset_email",
    "reset_otp_hash",
    "reset_otp_expires_at",
    "reset_otp_attempts",
    "reset_otp_last_sent_at",
    "reset_verified",
)
_OTP_MAX_ATTEMPTS = 5
_OTP_RESEND_COOLDOWN_SECONDS = 60
# IT Administrators are never self-registered; an existing admin assigns that role.
_SIGNUP_ROLES = (ROLE_ANALYST, ROLE_THREAT_INTEL)

_EMAIL_RE = EMAIL_RE


def _new_captcha():
    question, answer_hash, expires_at = generate_captcha()
    session["captcha_question"] = question
    session["captcha_answer_hash"] = answer_hash
    session["captcha_expires_at"] = expires_at
    return question


def _clear(*keys):
    for key in keys:
        session.pop(key, None)


def _email_code(to_email, code, purpose="login"):
    """Email a one-time code and return whether it went out. When it did not, say so on the page the
    user is sent to, instead of leaving them waiting for an email that is not coming (the reason is
    in the server log: see utils/mailer.py)."""
    sent = send_otp_email(to_email, code, purpose=purpose)
    session["otp_email_failed"] = not sent   # the verify page words itself by this, so it never claims an email it did not send
    if not sent:
        message = "We could not send the verification email right now. Try Resend code in a minute, or contact an administrator."
        if current_app.debug:
            message += " (Development mode: the code was written to the server console.)"
        flash(message, "error")
    return sent


def _send_login_otp(user):
    code, code_hash, expires_at = generate_otp()
    session["pending_user_id"] = user.id
    session["otp_hash"] = code_hash
    session["otp_expires_at"] = expires_at
    session["otp_attempts"] = 0
    session["otp_last_sent_at"] = time.time()
    return _email_code(user.email, code)


def _send_signup_otp(email):
    code, code_hash, expires_at = generate_otp()
    session["signup_otp_hash"] = code_hash
    session["signup_otp_expires_at"] = expires_at
    session["signup_otp_attempts"] = 0
    session["signup_otp_last_sent_at"] = time.time()
    return _email_code(email, code)


def _send_reset_otp(user):
    code, code_hash, expires_at = generate_otp()
    session["reset_user_id"] = user.id
    session["reset_email"] = user.email
    session["reset_otp_hash"] = code_hash
    session["reset_otp_expires_at"] = expires_at
    session["reset_otp_attempts"] = 0
    session["reset_otp_last_sent_at"] = time.time()
    return _email_code(user.email, code, purpose="password reset")


def _resend_available_at(session_key):
    last_sent = session.get(session_key, 0)
    return last_sent + _OTP_RESEND_COOLDOWN_SECONDS if last_sent else 0


@auth_pages_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    if request.method == "GET":
        question = _new_captcha()
        return render_template("login.html", captcha_question=question)

    username = normalize_username(request.form.get("username", ""))
    password = request.form.get("password", "")
    captcha_answer = request.form.get("captcha_answer", "")

    captcha_ok = verify_captcha(
        captcha_answer,
        session.get("captcha_answer_hash"),
        session.get("captcha_expires_at"),
    )
    _clear(*_CAPTCHA_KEYS)

    if not captcha_ok:
        flash("Incorrect or expired CAPTCHA answer. Please try again.", "error")
        question = _new_captcha()
        return render_template("login.html", captcha_question=question, username=username), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        log_action(None, "login_failed", detail=f"username={username}")
        flash("Invalid username or password.", "error")
        question = _new_captcha()
        return render_template("login.html", captcha_question=question, username=username), 401

    if not user.is_active_flag:
        log_action(user.id, "login_failed_deactivated")
        flash("Your account has been deactivated. Please contact an administrator.", "error")
        question = _new_captcha()
        return render_template("login.html", captcha_question=question, username=username), 403

    if user.role == ROLE_IT_ADMIN:
        login_user(user)
        session.permanent = True
        log_action(user.id, "login_success", detail="admin, MFA skipped")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    if verify_device_trust_token(request.cookies.get(DEVICE_TRUST_COOKIE), user.id):
        login_user(user)
        session.permanent = True
        log_action(user.id, "login_success", detail="trusted device, MFA skipped")
        # The trust cookie is deliberately not renewed here: the week runs from the
        # last time the code was entered, not from the last sign-in.
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    _send_login_otp(user)
    log_action(user.id, "login_password_verified", detail="awaiting MFA code")

    return redirect(url_for("auth_pages.verify_otp_page"))


@auth_pages_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def signup_page():
    if current_user.is_authenticated:
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    if request.method == "GET":
        question = _new_captcha()
        return render_template("signup.html", captcha_question=question)

    form = {
        "first_name": request.form.get("first_name", "").strip(),
        "last_name": request.form.get("last_name", "").strip(),
        "username": request.form.get("username", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
        "role": request.form.get("role", ROLE_ANALYST),
    }
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    captcha_answer = request.form.get("captcha_answer", "")

    def reject(message, status=400):
        flash(message, "error")
        question = _new_captcha()
        return render_template("signup.html", captcha_question=question, **form), status

    captcha_ok = verify_captcha(
        captcha_answer,
        session.get("captcha_answer_hash"),
        session.get("captcha_expires_at"),
    )
    _clear(*_CAPTCHA_KEYS)
    if not captcha_ok:
        return reject("Incorrect or expired CAPTCHA answer. Please try again.")

    if not form["first_name"] or not form["last_name"]:
        return reject("First and last name are required.")
    if form["role"] not in _SIGNUP_ROLES:
        return reject("Choose a valid role.")
    try:
        form["username"] = validate_username(form["username"])
    except ValidationError as exc:
        return reject(str(exc))
    if not _EMAIL_RE.match(form["email"]):
        return reject("Enter a valid email address.")
    try:
        validate_password(password)
    except ValidationError as exc:
        return reject(str(exc))
    if password != confirm_password:
        return reject("Passwords do not match.")
    if User.query.filter_by(username=form["username"]).first():
        return reject("That username is already taken.")
    if User.query.filter_by(email=form["email"]).first():
        return reject("An account with that email already exists.")

    session["pending_signup"] = {
        **form,
        "password_hash": bcrypt.generate_password_hash(password).decode("utf-8"),
    }

    _send_signup_otp(form["email"])
    log_action(None, "signup_started", detail=f"username={form['username']}")

    return redirect(url_for("auth_pages.signup_verify_page"))


@auth_pages_bp.route("/signup/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def signup_verify_page():
    pending = session.get("pending_signup")
    if not pending:
        flash("Please fill in the sign up form first.", "error")
        return redirect(url_for("auth_pages.signup_page"))

    if request.method == "GET":
        return render_template(
            "verify_otp.html",
            pending_email=pending["email"],
            mode="signup",
            resend_available_at=_resend_available_at("signup_otp_last_sent_at"),
        )

    submitted_code = request.form.get("otp_code", "")
    attempts = session.get("signup_otp_attempts", 0)

    ok = verify_otp(submitted_code, session.get("signup_otp_hash"), session.get("signup_otp_expires_at"))
    if not ok:
        attempts += 1
        session["signup_otp_attempts"] = attempts
        if attempts >= _OTP_MAX_ATTEMPTS:
            log_action(None, "signup_verify_locked", detail=f"username={pending['username']}")
            _clear(*_PENDING_SIGNUP_KEYS)
            flash("Too many incorrect codes. Please sign up again.", "error")
            return redirect(url_for("auth_pages.signup_page"))

        log_action(None, "signup_verify_failed", detail=f"username={pending['username']}")
        flash(f"Incorrect or expired code. {_OTP_MAX_ATTEMPTS - attempts} attempt(s) remaining.", "error")
        return render_template(
            "verify_otp.html",
            pending_email=pending["email"],
            mode="signup",
            resend_available_at=_resend_available_at("signup_otp_last_sent_at"),
        ), 401

    if User.query.filter_by(username=pending["username"]).first() or User.query.filter_by(email=pending["email"]).first():
        _clear(*_PENDING_SIGNUP_KEYS)
        flash("That username or email was just registered by someone else. Please sign up again.", "error")
        return redirect(url_for("auth_pages.signup_page"))

    user = User(
        username=pending["username"],
        email=pending["email"],
        first_name=pending["first_name"],
        last_name=pending["last_name"],
        role=pending.get("role", ROLE_ANALYST) if pending.get("role") in _SIGNUP_ROLES else ROLE_ANALYST,
    )
    user.password_hash = pending["password_hash"]
    db.session.add(user)
    db.session.commit()
    _clear(*_PENDING_SIGNUP_KEYS)

    log_action(user.id, "signup_verified", detail=f"username={user.username}")
    flash("Account created and email verified. You can now sign in.", "success")
    return redirect(url_for("auth_pages.login_page"))


@auth_pages_bp.route("/signup/verify/resend", methods=["POST"])
@limiter.limit("5 per minute")
def resend_signup_otp():
    pending = session.get("pending_signup")
    if not pending:
        flash("Please fill in the sign up form first.", "error")
        return redirect(url_for("auth_pages.signup_page"))

    remaining = _resend_available_at("signup_otp_last_sent_at") - time.time()
    if remaining > 0:
        flash(f"Please wait {int(remaining) + 1}s before requesting another code.", "error")
        return redirect(url_for("auth_pages.signup_verify_page"))

    sent = _send_signup_otp(pending["email"])
    log_action(None, "signup_code_resent", detail=f"username={pending['username']}")
    if sent:
        flash("A new verification code has been sent.", "success")
    return redirect(url_for("auth_pages.signup_verify_page"))


@auth_pages_bp.route("/login/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp_page():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("auth_pages.login_page"))

    if request.method == "GET":
        user = User.query.get(pending_user_id)
        return render_template(
            "verify_otp.html",
            pending_email=user.email if user else None,
            mode="login",
            resend_available_at=_resend_available_at("otp_last_sent_at"),
        )

    submitted_code = request.form.get("otp_code", "")
    attempts = session.get("otp_attempts", 0)

    ok = verify_otp(submitted_code, session.get("otp_hash"), session.get("otp_expires_at"))
    if not ok:
        attempts += 1
        session["otp_attempts"] = attempts
        max_attempts = 5
        if attempts >= max_attempts:
            log_action(pending_user_id, "mfa_failed_locked", detail=f"attempts={attempts}")
            _clear(*_PENDING_MFA_KEYS)
            flash("Too many incorrect codes. Please log in again.", "error")
            return redirect(url_for("auth_pages.login_page"))

        log_action(pending_user_id, "mfa_failed", detail=f"attempts={attempts}")
        flash(f"Incorrect or expired code. {max_attempts - attempts} attempt(s) remaining.", "error")
        user = User.query.get(pending_user_id)
        return render_template(
            "verify_otp.html",
            pending_email=user.email if user else None,
            mode="login",
            resend_available_at=_resend_available_at("otp_last_sent_at"),
        ), 401

    user = User.query.get(pending_user_id)
    _clear(*_PENDING_MFA_KEYS)

    if not user or not user.is_active_flag:
        flash("Account is no longer active.", "error")
        return redirect(url_for("auth_pages.login_page"))

    login_user(user)
    session.permanent = True
    log_action(user.id, "login_success", detail="mfa verified")
    resp = redirect(url_for("auth_pages.dashboard_placeholder"))
    return set_device_trust_cookie(resp, user.id)


@auth_pages_bp.route("/login/verify/resend", methods=["POST"])
@limiter.limit("5 per minute")
def resend_login_otp():
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("auth_pages.login_page"))

    remaining = _resend_available_at("otp_last_sent_at") - time.time()
    if remaining > 0:
        flash(f"Please wait {int(remaining) + 1}s before requesting another code.", "error")
        return redirect(url_for("auth_pages.verify_otp_page"))

    user = User.query.get(pending_user_id)
    if not user:
        flash("Please log in first.", "error")
        return redirect(url_for("auth_pages.login_page"))

    sent = _send_login_otp(user)
    log_action(user.id, "mfa_code_resent")
    if sent:
        flash("A new verification code has been sent.", "success")
    return redirect(url_for("auth_pages.verify_otp_page"))


@auth_pages_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password_page():
    if current_user.is_authenticated:
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()

    if user and user.is_active_flag:
        _send_reset_otp(user)
        log_action(user.id, "password_reset_requested")
        return redirect(url_for("auth_pages.forgot_password_verify_page"))

    log_action(None, "password_reset_requested_unknown", detail=f"email={email}")
    flash("If an account exists for that email, a verification code has been sent.", "success")
    return redirect(url_for("auth_pages.login_page"))


@auth_pages_bp.route("/forgot-password/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def forgot_password_verify_page():
    pending_user_id = session.get("reset_user_id")
    if not pending_user_id:
        flash("Please request a password reset code first.", "error")
        return redirect(url_for("auth_pages.forgot_password_page"))

    if request.method == "GET":
        return render_template(
            "verify_otp.html",
            pending_email=session.get("reset_email"),
            mode="reset",
            resend_available_at=_resend_available_at("reset_otp_last_sent_at"),
        )

    submitted_code = request.form.get("otp_code", "")
    attempts = session.get("reset_otp_attempts", 0)

    ok = verify_otp(submitted_code, session.get("reset_otp_hash"), session.get("reset_otp_expires_at"))
    if not ok:
        attempts += 1
        session["reset_otp_attempts"] = attempts
        if attempts >= _OTP_MAX_ATTEMPTS:
            log_action(pending_user_id, "password_reset_verify_locked")
            _clear(*_PENDING_RESET_KEYS)
            flash("Too many incorrect codes. Please request a new reset code.", "error")
            return redirect(url_for("auth_pages.forgot_password_page"))

        log_action(pending_user_id, "password_reset_verify_failed", detail=f"attempts={attempts}")
        flash(f"Incorrect or expired code. {_OTP_MAX_ATTEMPTS - attempts} attempt(s) remaining.", "error")
        return render_template(
            "verify_otp.html",
            pending_email=session.get("reset_email"),
            mode="reset",
            resend_available_at=_resend_available_at("reset_otp_last_sent_at"),
        ), 401

    session["reset_verified"] = True
    log_action(pending_user_id, "password_reset_verified")
    return redirect(url_for("auth_pages.reset_password_page"))


@auth_pages_bp.route("/forgot-password/verify/resend", methods=["POST"])
@limiter.limit("5 per minute")
def resend_reset_otp():
    pending_user_id = session.get("reset_user_id")
    if not pending_user_id:
        flash("Please request a password reset code first.", "error")
        return redirect(url_for("auth_pages.forgot_password_page"))

    remaining = _resend_available_at("reset_otp_last_sent_at") - time.time()
    if remaining > 0:
        flash(f"Please wait {int(remaining) + 1}s before requesting another code.", "error")
        return redirect(url_for("auth_pages.forgot_password_verify_page"))

    user = User.query.get(pending_user_id)
    if not user:
        _clear(*_PENDING_RESET_KEYS)
        flash("Please request a password reset code first.", "error")
        return redirect(url_for("auth_pages.forgot_password_page"))

    sent = _send_reset_otp(user)
    log_action(user.id, "password_reset_code_resent")
    if sent:
        flash("A new verification code has been sent.", "success")
    return redirect(url_for("auth_pages.forgot_password_verify_page"))


@auth_pages_bp.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def reset_password_page():
    pending_user_id = session.get("reset_user_id")
    if not pending_user_id or not session.get("reset_verified"):
        flash("Please verify your identity first.", "error")
        return redirect(url_for("auth_pages.forgot_password_page"))

    if request.method == "GET":
        return render_template("reset_password.html")

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    try:
        validate_password(password)
    except ValidationError as exc:
        flash(str(exc), "error")
        return render_template("reset_password.html"), 400
    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return render_template("reset_password.html"), 400

    user = User.query.get(pending_user_id)
    if not user:
        _clear(*_PENDING_RESET_KEYS)
        flash("Something went wrong. Please try again.", "error")
        return redirect(url_for("auth_pages.forgot_password_page"))

    user.set_password(password)
    db.session.commit()
    _clear(*_PENDING_RESET_KEYS)
    log_action(user.id, "password_reset_completed")
    flash("Your password has been reset. You can now sign in.", "success")
    resp = redirect(url_for("auth_pages.login_page"))
    resp.delete_cookie(DEVICE_TRUST_COOKIE)
    return resp


def _my_target_ids():
    return [
        row.id
        for row in AuthorizedTarget.query.filter_by(owner_id=current_user.id).with_entities(AuthorizedTarget.id).all()
    ]


def _my_findings(target_ids):
    return findings_for_targets(target_ids)


def _selected_target_id(my_target_ids):
    raw = request.args.get("target_id", type=int)
    return raw if raw in my_target_ids else None


def _monitoring_context(my_targets, scoped_target_ids):
    """Everything the monitoring panels show: whether the engine is alive, what it has done, what it
    did while this user was signed out, and when it next runs."""
    now = monitor_service.utcnow()
    try:
        away_since = datetime.fromisoformat(session["monitor_away_since"]) if session.get("monitor_away_since") else None
    except ValueError:
        away_since = None
    monitored = [t for t in my_targets if t.id in scoped_target_ids and t.authorized and t.monitor_interval_days]
    due = [monitor_service.next_run_at(t) for t in monitored]
    return {
        "monitor_engine": monitor_service.engine_status(current_app, now),
        "monitor_activity": monitor_service.activity_totals(scoped_target_ids, now=now),
        "monitor_runs": monitor_service.recent_runs(scoped_target_ids, 50),
        "monitor_away": monitor_service.away_summary([t.id for t in my_targets], away_since),
        "monitor_monitored_count": len(monitored),
        "monitor_next_due": min(due) if due else None,
        "monitor_now": now,
    }


def _workspace_context():
    my_targets = AuthorizedTarget.query.filter_by(owner_id=current_user.id).order_by(
        AuthorizedTarget.created_at.desc()
    ).all()
    my_target_ids = [t.id for t in my_targets]
    target_map = {t.id: t.domain for t in my_targets}
    target_risk = {t.id: risk_score(t.id) for t in my_targets}
    summary = {
        "total_targets": len(my_targets),
        "authorized_targets": sum(1 for t in my_targets if t.authorized),
        "total_assets": sum(len(t.assets) for t in my_targets),
        "total_vulnerabilities": sum(len(a.vulnerabilities) for t in my_targets for a in t.assets),
        "risk_score": sum(target_risk.values()),
    }

    # Sidebar counts always reflect the whole inventory; everything below
    # (assets/network/findings/scan history/charts) is scoped to whichever
    # single target is selected, so a freshly scanned site shows up in its
    # own clean view instead of blending into every other target's rows.
    nav_counts = inventory_service.nav_counts(my_targets)

    selected_target_id = _selected_target_id(my_target_ids)
    scoped_target_ids = [selected_target_id] if selected_target_id else my_target_ids
    scoped_targets = [t for t in my_targets if t.id in scoped_target_ids]

    scan_history = (
        Scan.query.filter(Scan.target_id.in_(scoped_target_ids)).order_by(Scan.started_at.desc()).limit(200).all()
        if scoped_target_ids
        else []
    )
    findings = _my_findings(scoped_target_ids)
    chart_range = normalize_range(request.args.get("range"))
    scan_totals = scan_status_totals(scoped_target_ids, chart_range)
    severity_counts = severity_totals(scoped_target_ids, chart_range)

    vulnerable_count = sum(1 for f in findings if f.status == "open")
    needs_review_count = sum(1 for f in findings if f.status == "in_progress")
    scoped_asset_total = sum(len(t.assets) for t in scoped_targets)
    scoped_risk_score = sum(risk_score(t.id) for t in scoped_targets)
    stat_values = {
        "targets": len(scoped_targets),
        "assets": scoped_asset_total,
        "vulnerable": vulnerable_count,
        "needsreview": needs_review_count,
        "risk": scoped_risk_score,
    }
    max_stat = max(stat_values.values()) if any(stat_values.values()) else 0
    stat_bar_pct = {
        key: (round(value * 100 / max_stat) if max_stat else 0) for key, value in stat_values.items()
    }

    target_reports = list_reports_for_target(selected_target_id) if selected_target_id else []
    exposed_dorks = exposed_dork_labels(selected_target_id) if selected_target_id else {}
    dork_categories = (
        dork_categories_for_domain(target_map[selected_target_id], exposed_dorks) if selected_target_id else []
    )

    return {
        **_monitoring_context(my_targets, scoped_target_ids),
        "user": current_user,
        "targets": my_targets,
        "selected_target_id": selected_target_id,
        "scoped_stat_values": stat_values,
        "target_reports": target_reports,
        "dork_categories": dork_categories,
        "exposed_dork_total": sum(exposed_dorks.values()),
        "dork_count": total_dork_count(),
        "recent_scans": scan_history,
        "summary": summary,
        "target_map": target_map,
        "target_risk": target_risk,
        "findings": findings,
        "nav_counts": nav_counts,
        "vulnerable_count": vulnerable_count,
        "needs_review_count": needs_review_count,
        "scan_totals": scan_totals,
        "severity_totals": severity_counts,
        "stat_bar_pct": stat_bar_pct,
        "chart_range": chart_range,
        "chart_ranges": CHART_RANGES,
    }


@auth_pages_bp.route("/dashboard")
def dashboard_placeholder():
    if not current_user.is_authenticated:
        return redirect(url_for("auth_pages.login_page"))
    if current_user.role == ROLE_IT_ADMIN:
        return redirect(url_for("auth_pages.admin_dashboard"))
    if current_user.role == ROLE_THREAT_INTEL:
        return redirect(url_for("threat_intel.threat_intel_page"))

    return render_template("workspace_overview.html", active_nav="overview", **_workspace_context())


@auth_pages_bp.route("/dashboard/details")
@login_required
def workspace_dashboard():
    if current_user.role == ROLE_IT_ADMIN:
        return redirect(url_for("auth_pages.admin_dashboard"))
    if current_user.role == ROLE_THREAT_INTEL:
        return redirect(url_for("threat_intel.threat_intel_page"))

    context = _workspace_context()
    radar = radar_service.radar_snapshot(current_user.id, context["selected_target_id"])
    scoped_ids = [context["selected_target_id"]] if context["selected_target_id"] else [t.id for t in context["targets"]]
    return render_template(
        "dashboard_user.html",
        active_nav="dashboard",
        radar=radar,
        events=monitor_service.recent_events(scoped_ids, 100),
        monitor_choices=[(key, key.capitalize()) for key in MONITOR_INTERVALS],
        monitor_choice=lambda target: next((k for k, d in MONITOR_INTERVALS.items() if d == target.monitor_interval_days), "off"),
        monitor_next=monitor_service.next_run_at,
        **context,
    )


def _export_target_ids():
    my_target_ids = _my_target_ids()
    selected = _selected_target_id(my_target_ids)
    return [selected] if selected else my_target_ids


@auth_pages_bp.route("/workspace/findings/export.json")
@login_required
def export_findings_json():
    findings = _my_findings(_export_target_ids())
    return jsonify({"findings": [f.to_dict() for f in findings]})


@auth_pages_bp.route("/workspace/findings/export.csv")
@login_required
def export_findings_csv():
    findings = _my_findings(_export_target_ids())
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["CVE", "Severity", "Title", "Status", "Discovered"])
    for f in findings:
        writer.writerow([
            f.cve or "-",
            f.severity,
            f.title,
            f.status,
            f.discovered_at.strftime("%Y-%m-%d") if f.discovered_at else "-",
        ])

    log_action(current_user.id, "findings_exported", detail="format=csv")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@auth_pages_bp.route("/workspace/findings/export.md")
@login_required
def export_findings_markdown():
    findings = _my_findings(_export_target_ids())
    lines = ["# Findings export", "", "| CVE | Severity | Title | Status | Discovered |", "| --- | --- | --- | --- | --- |"]
    for f in findings:
        discovered = f.discovered_at.strftime("%Y-%m-%d") if f.discovered_at else "-"
        lines.append(f"| {f.cve or '-'} | {f.severity} | {f.title} | {f.status} | {discovered} |")

    log_action(current_user.id, "findings_exported", detail="format=markdown")
    return Response(
        "\n".join(lines) + "\n",
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=findings.md"},
    )


@auth_pages_bp.route("/workspace/findings/<int:vuln_id>/status", methods=["POST"])
@login_required
def update_finding_status(vuln_id):
    if current_user.role not in (ROLE_ANALYST, ROLE_IT_ADMIN):
        flash("You do not have permission to change finding status.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    back = url_for("findings.findings_page", target_id=request.form.get("target_id", type=int))
    vuln = Vulnerability.query.get(vuln_id)
    target = vuln.asset.target if vuln else None
    if not target or (target.owner_id != current_user.id and current_user.role != ROLE_IT_ADMIN):
        flash("Finding not found.", "error")
        return redirect(back)

    status = request.form.get("status", "")
    if status not in VULN_STATUSES:
        flash("Invalid status.", "error")
        return redirect(back)

    vuln.status = status
    db.session.commit()
    log_action(current_user.id, "vulnerability_status_updated", detail=f"vuln_id={vuln_id} status={status}")
    return redirect(back)


@auth_pages_bp.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != ROLE_IT_ADMIN:
        flash("You do not have permission to view that page.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    users = User.query.order_by(User.created_at.desc()).all()
    role_counts = {
        "total": len(users),
        "it_admin": sum(1 for u in users if u.role == ROLE_IT_ADMIN),
        "analyst": sum(1 for u in users if u.role == ROLE_ANALYST),
        "threat_intel": sum(1 for u in users if u.role == ROLE_THREAT_INTEL),
        "deactivated": sum(1 for u in users if not u.is_active_flag),
    }

    return render_template(
        "dashboard_admin.html",
        user=current_user,
        users=users,
        role_counts=role_counts,
        roles=ROLES,
        recent_activity=user_admin_service.recent_activity(10),
        display_name=user_admin_service.display_name,
    )


@auth_pages_bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
def admin_update_user_role(user_id):
    if current_user.role != ROLE_IT_ADMIN:
        flash("You do not have permission to do that.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "")
    try:
        validate_role(new_role, ROLES)
    except ValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("auth_pages.admin_dashboard"))

    user.role = new_role
    db.session.commit()
    log_action(current_user.id, "user_role_updated", detail=f"user_id={user.id} role={new_role}")
    flash(f"Updated role for {user.username}.", "success")
    return redirect(url_for("auth_pages.admin_dashboard"))


@auth_pages_bp.route("/admin/users/<int:user_id>/status", methods=["POST"])
@login_required
def admin_toggle_user_status(user_id):
    if current_user.role != ROLE_IT_ADMIN:
        flash("You do not have permission to do that.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot change the status of your own account.", "error")
        return redirect(url_for("auth_pages.admin_dashboard"))

    user.is_active_flag = not user.is_active_flag
    db.session.commit()
    log_action(
        current_user.id,
        "user_status_updated",
        detail=f"user_id={user.id} active={user.is_active_flag}",
    )
    flash(f"{'Activated' if user.is_active_flag else 'Deactivated'} {user.username}.", "success")
    return redirect(url_for("auth_pages.admin_dashboard"))


@auth_pages_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if current_user.role != ROLE_IT_ADMIN:
        flash("You do not have permission to do that.", "error")
        return redirect(url_for("auth_pages.dashboard_placeholder"))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("auth_pages.admin_dashboard"))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action(current_user.id, "user_deleted", detail=f"deleted user_id={user_id}")
    flash(f"Deleted user {username}.", "success")
    return redirect(url_for("auth_pages.admin_dashboard"))


@auth_pages_bp.route("/logout", methods=["POST"])
@login_required
def logout_page():
    user_id = current_user.id
    logout_user()
    log_action(user_id, "logout")
    return redirect(url_for("auth_pages.login_page"))
