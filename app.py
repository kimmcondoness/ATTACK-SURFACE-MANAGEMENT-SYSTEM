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
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        from models import User

        return User.query.get(int(user_id))

    from routes.assets import assets_bp
    from routes.auth import auth_bp
    from routes.auth_pages import auth_pages_bp
    from routes.dashboard import dashboard_bp
    from routes.graphql_api import graphql_bp
    from routes.legal import legal_bp
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

    app.after_request(apply_secure_headers)

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
