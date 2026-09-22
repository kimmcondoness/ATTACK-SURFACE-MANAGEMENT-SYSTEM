import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from extensions import db
from models import ROLE_IT_ADMIN, User


def seed():
    app = create_app()
    with app.app_context():
        db.create_all()

        username = os.environ.get("SEED_ADMIN_USERNAME", "admin")
        email = os.environ.get("SEED_ADMIN_EMAIL", "admin@example.com")
        password = os.environ.get("SEED_ADMIN_PASSWORD", "ChangeMe123!")

        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists. Skipping seed.")
            return

        admin = User(username=username, email=email, role=ROLE_IT_ADMIN)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Seeded IT Admin user '{username}'.")


if __name__ == "__main__":
    seed()
