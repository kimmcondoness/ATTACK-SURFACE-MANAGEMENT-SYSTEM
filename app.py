from flask import Flask, jsonify, redirect, request, url_for

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

    @app.route("/", methods=["GET"])
    def index():
        return redirect(url_for("auth_pages.login_page"))

    print(app.static_folder)
    
    return app

    

if __name__ == "__main__":
    application = create_app()
    application.run(debug=application.config.get("DEBUG", False))
