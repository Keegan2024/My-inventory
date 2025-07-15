"""
Inventory Management System for Healthcare Facilities

Features:
- User authentication and role-based access control
- Commodity tracking with usage reporting
- Facility management
- Data export functionality
- Administrative controls

Security Note: This version includes security improvements but still requires
proper deployment configuration (HTTPS, secret management, etc.) for production use.
"""

import os
from datetime import datetime
from io import BytesIO

import pandas as pd
from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Configuration
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///inventory.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
    DATA_DIR = "data"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB upload limit


# Application Factory
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from app.auth import auth_bp
    from app.main import main_bp
    from app.admin import admin_bp
    from app.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(reports_bp, url_prefix="/reports")

    # CLI commands
    @app.cli.command("init-db")
    def init_db():
        """Initialize the database with sample data"""
        db.create_all()
        load_sample_data()
        print("Database initialized successfully.")

    return app


# Extensions
db = SQLAlchemy()

# Models
class Facility(db.Model):
    """Healthcare facility model"""

    __tablename__ = "facilities"

    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False, default="Zambia")
    province = db.Column(db.String(100), nullable=False, index=True)
    district = db.Column(db.String(100), nullable=False, index=True)
    hub = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    users = db.relationship("User", backref="facility", lazy=True)
    reports = db.relationship("Report", backref="facility", lazy=True)

    def __repr__(self):
        return f"<Facility {self.name}>"


class Commodity(db.Model):
    """Medical commodity model"""

    __tablename__ = "commodities"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.String(200))
    category = db.Column(db.String(100), index=True)
    reports = db.relationship("Report", backref="commodity", lazy=True)

    def __repr__(self):
        return f"<Commodity {self.name}>"


class User(db.Model):
    """System user model"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user", index=True)
    approved = db.Column(db.Boolean, default=False, index=True)
    facility_id = db.Column(db.Integer, db.ForeignKey("facilities.id"))
    last_login = db.Column(db.DateTime)
    reports = db.relationship("Report", backref="user", lazy=True)

    ROLES = ["user", "facility_admin", "system_admin"]

    def __repr__(self):
        return f"<User {self.username}>"

    def has_role(self, role_name):
        """Check if user has specified role"""
        return self.role == role_name

    def can_access_facility(self, facility_id):
        """Check if user can access a specific facility"""
        if self.has_role("system_admin"):
            return True
        return self.facility_id == facility_id


class Report(db.Model):
    """Inventory report model"""

    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey("facilities.id"), nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey("commodities.id"), nullable=False)
    quantity_used = db.Column(db.Integer, nullable=False)
    quantity_received = db.Column(db.Integer, nullable=False)
    balance = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f"<Report {self.id} for {self.commodity.name}>"


# Helper Functions
def load_sample_data():
    """Load initial sample data into the database"""
    try:
        # Create default admin user
        if not User.query.filter_by(username=Config.ADMIN_USERNAME).first():
            admin = User(
                username=Config.ADMIN_USERNAME,
                password=generate_password_hash(Config.ADMIN_PASSWORD),
                role="system_admin",
                approved=True,
            )
            db.session.add(admin)

        # Load facilities from CSV if none exist
        if Facility.query.count() == 0:
            facilities_path = os.path.join(Config.DATA_DIR, "zambia_facilities.csv")
            if os.path.exists(facilities_path):
                df = pd.read_csv(facilities_path)
                for _, row in df.iterrows():
                    facility = Facility(
                        country=row.get("Country", "Zambia"),
                        province=row["Province"],
                        district=row["District"],
                        hub=row.get("Hub"),
                        name=row["FacilityName"],
                    )
                    db.session.add(facility)

        # Load commodities from CSV if none exist
        if Commodity.query.count() == 0:
            commodities_path = os.path.join(Config.DATA_DIR, "commodities.csv")
            if os.path.exists(commodities_path):
                df = pd.read_csv(commodities_path)
                for _, row in df.iterrows():
                    commodity = Commodity(
                        name=row["Name"],
                        description=row.get("Description"),
                        category=row.get("Category"),
                    )
                    db.session.add(commodity)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error loading sample data: {str(e)}")


# Create application
app = create_app()


# Error Handlers
@app.errorhandler(403)
def forbidden(error):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
