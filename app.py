import os

from flask import Flask, jsonify, redirect, request, session, url_for
from flask_login import current_user, user_logged_in
from sqlalchemy.engine import make_url

from config import BASE_DIR, get_config
from extensions import bcrypt, csrf, db, limiter, login_manager
from utils.security import apply_secure_headers


def create_app(config_object=None):
    # instance_path is pinned to the project root so a relative
    # DATABASE_URL (e.g. "sqlite:///asm.db") resolves next to this file --
    # Flask-SQLAlchemy otherwise resolves it under ./instance/, silently
    # pointing the app at a second, empty database.
    app = Flask(__name__, template_folder="login/templates", instance_path=BASE_DIR, instance_relative_config=False)
    app.config.from_object(config_object or get_config())

    db.init_app(app)

    # Two machines running this app (e.g. a Windows dev box and a Linux server) each talk
    # to their OWN local MySQL by default -- nothing here replicates or syncs data between
    # them (see DEPLOYMENT.md). Different users/roles or a missing account on one machine
    # almost always means its DATABASE_URL points at a different, independently seeded
    # database. This line makes that visible in the startup log instead of only showing up
    # as "I can log in here but not there".
    db_url = make_url(app.config["SQLALCHEMY_DATABASE_URI"])
    app.logger.info("Database: %s", db_url.render_as_string(hide_password=True))
    if not os.environ.get("DATABASE_URL"):
        app.logger.warning(
            "DATABASE_URL is not set in the environment, so this process fell back to the "
            "built-in default above. If this machine is meant to share data with another one, "
            "set DATABASE_URL in its .env to the exact same value as the other machine's."
        )

    if app.config.get("AUTO_UPGRADE_SCHEMA"):
        from database.upgrade import upgrade_schema

        with app.app_context():
            try:
                for change in upgrade_schema(db):
                    app.logger.info("Database upgrade: %s", change)
            except Exception:   # noqa: BLE001 - never stop the app from starting over an upgrade
                app.logger.exception("Database upgrade failed; new features may be unavailable until it is fixed.")
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        from models import User

        user = User.query.get(int(user_id))
        # A deactivated ("locked") account must stop working immediately, not
        # only at its next sign-in.
        return user if user and user.is_active_flag else None

    from routes.admin_users import admin_users_bp
    from routes.assets import assets_bp
    from routes.auth import auth_bp
    from routes.auth_pages import auth_pages_bp
    from routes.dashboard import dashboard_bp
    from routes.findings import findings_bp
    from routes.graphql_api import graphql_bp
    from routes.inventory import inventory_bp
    from routes.legal import legal_bp
    from routes.monitoring import monitoring_bp
    from routes.radar import radar_bp
    from routes.reports import reports_bp
    from routes.scans import scans_bp
    from routes.targets import targets_bp
    from routes.threat_intel import threat_intel_bp
    from routes.users import users_bp
    from routes.vulnerabilities import vulnerabilities_bp
    from routes.workspace_reports import workspace_reports_bp
    from routes.workspace_scans import workspace_scans_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(auth_pages_bp)
    app.register_blueprint(legal_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(workspace_scans_bp)
    app.register_blueprint(workspace_reports_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(graphql_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(radar_bp)
    app.register_blueprint(admin_users_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(monitoring_bp)

    app.after_request(apply_secure_headers)

    # Continuous monitoring. Started here when this is certainly the serving process; under the
    # debug reloader the first request starts it instead (see monitor_service.start_scheduler).
    from services import monitor_service

    monitor_service.start_scheduler(app)

    @app.before_request
    def _start_monitoring_scheduler():
        if not app.extensions.get("monitor_scheduler_started"):
            app.extensions["monitor_scheduler_started"] = True
            monitor_service.start_scheduler(app, force=True)

    # Monitoring carries on while people are signed out. So that the next sign-in can say what it did
    # meanwhile, remember when each user was last here, and what that was at the moment they sign in.
    @user_logged_in.connect_via(app)
    def _remember_previous_visit(_sender, user):
        previous = user.last_seen_at
        session["monitor_away_since"] = previous.isoformat() if previous else None
        _mark_seen(user)

    @app.before_request
    def _remember_this_visit():
        if request.endpoint in (None, "static") or not current_user.is_authenticated:
            return
        _mark_seen(current_user)

    def _mark_seen(user):
        try:
            monitor_service.mark_seen(user)
        except Exception:   # noqa: BLE001 - bookkeeping must never fail a request
            db.session.rollback()
            app.logger.exception("Could not record when %s was last seen", user.username)

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("auth_pages.login_page"))

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(500)
    def server_error(error):
        app.logger.error("Unhandled server error: %s", error)
        return jsonify({"error": "Internal server error."}), 500

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/health/monitoring", methods=["GET"])
    def monitoring_health():
        """For an uptime checker: 200 while the monitoring engine is reporting in (or is switched off
        on purpose), 503 when it has gone quiet. No sign-in needed; it reveals only timestamps."""
        status = monitor_service.engine_status(app)
        body = {key: status[key] for key in ("state", "label", "last_check_at", "age_seconds", "started_at", "monitored_targets")}
        return jsonify({"monitoring": monitor_service.public_status(body)}), (200 if status["state"] in ("active", "disabled") else 503)

    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("auth_pages.login_page"))

    print(app.static_folder)
    
    return app

    

if __name__ == "__main__":
    application = create_app()
    application.run(debug=application.config.get("DEBUG", False))
