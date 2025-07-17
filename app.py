import os
import csv
import io
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from xhtml2pdf import pisa

# ---------------------- Logging Setup (MOVED TO TOP) ----------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------- Flask App Initialization ----------------------
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", "mysecret")

# ---------------------- Configuration ----------------------
# Fix PostgreSQL URI if needed
db_uri = os.environ.get("DATABASE_URL", "sqlite:///inventory.db")
if db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CACHE_TYPE"] = "simple"

# ---------------------- Extensions ----------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)

# Redis for Rate Limiting
try:
    redis_url = os.environ.get('REDIS_URL')
    if redis_url:
        app.config['RATELIMIT_STORAGE_URL'] = redis_url
    else:
        app.config['RATELIMIT_STORAGE_URL'] = "memory://"
except Exception as e:
    logger.error("Failed to load Redis configuration: %s", str(e))
    app.config['RATELIMIT_STORAGE_URL'] = "memory://"

limiter = Limiter(get_remote_address, app=app)

# ---------------------- Login Manager ----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------------- Database Models ----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False)
    opening_balance = db.Column(db.Integer, default=0)
    received = db.Column(db.Integer, default=0)
    used = db.Column(db.Integer, default=0)
    closing_balance = db.Column(db.Integer, default=0)

# ---------------------- Forms ----------------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=100)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=100)])
    submit = SubmitField("Login")

# ---------------------- User Loader ----------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------- Routes ----------------------
@app.route("/")
@login_required
def dashboard():
    facilities = Facility.query.all()
    commodities = Commodity.query.all()
    return render_template("dashboard.html", facilities=facilities, commodities=commodities)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/add_inventory", methods=["POST"])
@login_required
def add_inventory():
    facility_id = request.form["facility_id"]
    commodity_id = request.form["commodity_id"]
    date = datetime.strptime(request.form["date"], "%Y-%m-%d")
    received = int(request.form["received"])
    used = int(request.form["used"])

    latest = Inventory.query.filter_by(facility_id=facility_id, commodity_id=commodity_id)\
        .order_by(Inventory.date.desc()).first()

    opening = latest.closing_balance if latest else 0
    closing = opening + received - used

    new_entry = Inventory(
        facility_id=facility_id,
        commodity_id=commodity_id,
        date=date,
        opening_balance=opening,
        received=received,
        used=used,
        closing_balance=closing
    )
    db.session.add(new_entry)
    db.session.commit()
    flash("Inventory added successfully", "success")
    return redirect(url_for("dashboard"))

@app.route("/export/csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Facility", "Commodity", "Opening", "Received", "Used", "Closing"])

    data = Inventory.query.all()
    for entry in data:
        writer.writerow([
            entry.date,
            Facility.query.get(entry.facility_id).name,
            Commodity.query.get(entry.commodity_id).name,
            entry.opening_balance,
            entry.received,
            entry.used,
            entry.closing_balance
        ])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True, download_name="inventory.csv")

@app.route("/export/pdf")
@login_required
def export_pdf():
    data = Inventory.query.all()
    html = render_template("report.html", data=data)
    pdf = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html), dest=pdf)
    pdf.seek(0)
    return send_file(pdf, mimetype="application/pdf", as_attachment=True, download_name="inventory.pdf")

# ---------------------- Run Server ----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
