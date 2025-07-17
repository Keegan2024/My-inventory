import os
import io
import csv
import json
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SelectField, IntegerField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, NumberRange, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
import openpyxl
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging

# Initialize Flask app
app = Flask(__name__)

# Configure app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secure-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///zambia_supply_chain.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['RATELIMIT_STORAGE_URL'] = os.environ.get('REDIS_URL', 'memory://')  # Use Redis URL directly or fallback to memory

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URL'],
    default_limits=["200 per day", "50 per hour"]  # Add reasonable default limits
)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user, admin, facility_manager, auditor
    approved = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20))
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    facility = db.relationship('Facility', backref='users')
    reports = db.relationship('Report', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

class Province(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    hubs = db.relationship('Hub', backref='province', lazy=True)

class Hub(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    province_id = db.Column(db.Integer, db.ForeignKey('province.id'), nullable=False)
    districts = db.relationship('District', backref='hub', lazy=True)

class District(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hub_id = db.Column(db.Integer, db.ForeignKey('hub.id'), nullable=False)
    facilities = db.relationship('Facility', backref='district', lazy=True)

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    district_id = db.Column(db.Integer, db.ForeignKey('district.id'), nullable=False)
    reports = db.relationship('Report', backref='facility', lazy=True)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=True)
    items = db.relationship('ReportItem', backref='commodity', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_date = db.Column(db.Date, nullable=False, index=True)
    report_period = db.Column(db.String(20), nullable=False, default='weekly')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('ReportItem', backref='report', lazy=True, cascade='all, delete-orphan')

class ReportItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False, index=True)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False, index=True)
    opening_balance = db.Column(db.Integer, nullable=False)
    received = db.Column(db.Integer, nullable=False)
    used = db.Column(db.Integer, nullable=False)
    closing_balance = db.Column(db.Integer, nullable=False)
    exp_date = db.Column(db.String(20))
    remarks = db.Column(db.Text)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=20)])
    province_id = SelectField('Province', coerce=int, validators=[DataRequired()])
    hub_id = SelectField('Hub', coerce=int, validators=[DataRequired()])
    district_id = SelectField('District', coerce=int, validators=[DataRequired()])
    facility_id = SelectField('Facility', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=20)])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ReportForm(FlaskForm):
    province_id = SelectField('Province', coerce=int, validators=[DataRequired()])
    hub_id = SelectField('Hub', coerce=int, validators=[DataRequired()])
    district_id = SelectField('District', coerce=int, validators=[DataRequired()])
    facility_id = SelectField('Facility', coerce=int, validators=[DataRequired()])
    report_date = DateField('Report Date', validators=[DataRequired()], format='%Y-%m-%d')
    commodity_id = SelectField('Commodity', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Submit Report')

class ReportItemForm(FlaskForm):
    commodity_id = IntegerField('Commodity ID', validators=[DataRequired()])
    opening_balance = IntegerField('Opening Balance', validators=[DataRequired(), NumberRange(min=0)])
    received = IntegerField('Received', validators=[DataRequired(), NumberRange(min=0)])
    used = IntegerField('Used', validators=[DataRequired(), NumberRange(min=0)])
    closing_balance = IntegerField('Closing Balance', validators=[DataRequired(), NumberRange(min=0)])
    exp_date = StringField('Expiration Date', validators=[Length(max=20)])
    remarks = TextAreaField('Remarks', validators=[Length(max=500)])

    def validate_closing_balance(self, field):
        if 'opening_balance' in self.data and 'received' in self.data and 'used' in self.data:
            expected = self.data['opening_balance'] + self.data['received'] - self.data['used']
            if field.data != expected:
                raise ValidationError('Closing balance must equal Opening Balance + Received - Used')

class CommodityForm(FlaskForm):
    name = StringField('Commodity Name', validators=[DataRequired(), Length(min=1, max=100)])
    description = TextAreaField('Description', validators=[Length(max=200)])
    submit = SubmitField('Add Commodity')

class FacilityForm(FlaskForm):
    province_id = SelectField('Province', coerce=int, validators=[DataRequired()])
    hub_id = SelectField('Hub', coerce=int, validators=[DataRequired()])
    district_id = SelectField('District', coerce=int, validators=[DataRequired()])
    name = StringField('Facility Name', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Add Facility')

class ImportForm(FlaskForm):
    file = FileField('Upload Excel File', validators=[DataRequired()])
    submit = SubmitField('Import')

# Database Initialization
def initialize_database():
    with app.app_context():
        db.create_all()

        # Initialize Provinces, Hubs, and Districts
        if not Province.query.first():
            provinces_data = {
                'Central': {'Kabwe Hub': ['Kabwe', 'Kapiri Mposhi'], 'Chibombo Hub': ['Chibombo']},
                'Copperbelt': {'Ndola Hub': ['Ndola', 'Kitwe'], 'Luanshya Hub': ['Luanshya']},
                'Eastern': {'Chipata Hub': ['Chipata', 'Petauke'], 'Katete Hub': ['Katete']},
                'Luapula': {'Mansa Hub': ['Mansa', 'Samfya'], 'Kawambwa Hub': ['Kawambwa']},
                'Lusaka': {'Lusaka Hub': ['Lusaka', 'Chongwe'], 'Kafue Hub': ['Kafue']},
                'Muchinga': {'Chinsali Hub': ['Chinsali', 'Mpika'], 'Nakonde Hub': ['Nakonde']},
                'Northern': {'Kasama Hub': ['Kasama', 'Mbala'], 'Mporokoso Hub': ['Mporokoso']},
                'North-Western': {'Solwezi Hub': ['Solwezi', 'Mwinilunga'], 'Kasempa Hub': ['Kasempa']},
                'Southern': {'Livingstone Hub': ['Livingstone', 'Choma'], 'Kalomo Hub': ['Kalomo']},
                'Western': {'Mongu Hub': ['Mongu', 'Kaoma'], 'Senanga Hub': ['Senanga']}
            }
            for province_name, hubs in provinces_data.items():
                province = Province(name=province_name)
                db.session.add(province)
                db.session.flush()
                for hub_name, districts in hubs.items():
                    hub = Hub(name=hub_name, province_id=province.id)
                    db.session.add(hub)
                    db.session.flush()
                    for district_name in districts:
                        db.session.add(District(name=district_name, hub_id=hub.id))
                db.session.commit()

        # Initialize Facilities
        if not Facility.query.first():
            facilities_data = {
                'Mansa': ['Mansa General Hospital', 'Kabuta RHC', 'Chembe RHC'],
                'Samfya': ['Samfya District Hospital', 'Mambilima Mission Hospital'],
                'Kawambwa': ['Kawambwa District Hospital', 'St. Paul\'s Mission Hospital'],
                'Lusaka': ['University Teaching Hospital', 'Levy Mwanawasa Hospital'],
                'Ndola': ['Ndola Teaching Hospital', 'Arthur Davison Hospital'],
            }
            for district_name, facilities in facilities_data.items():
                district = District.query.filter_by(name=district_name).first()
                if district:
                    for facility_name in facilities:
                        db.session.add(Facility(name=facility_name, district_id=district.id))
            db.session.commit()

        # Initialize Admin
        if not User.query.filter_by(username='admin').first():
            try:
                province = Province.query.filter_by(name='Lusaka').first()
                hub = Hub.query.filter_by(name='Lusaka Hub', province_id=province.id).first()
                district = District.query.filter_by(name='Lusaka', hub_id=hub.id).first()
                admin_facility = Facility.query.filter_by(name='Provincial Health Office').first()
                if not admin_facility:
                    admin_facility = Facility(name='Provincial Health Office', district_id=district.id)
                    db.session.add(admin_facility)
                    db.session.commit()

                admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
                admin = User(
                    username='admin',
                    password=generate_password_hash(admin_password),
                    facility_id=admin_facility.id,
                    role='admin',
                    approved=True,
                    phone_number='0972511451'
                )
                db.session.add(admin)
                db.session.commit()  # Commit admin user to assign ID
                db.session.add(AuditLog(user_id=admin.id, action='create_admin', details='Admin user created'))
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Admin creation failed: {str(e)}")
                raise

        # Initialize Commodities
        if not Commodity.query.first():
            try:
                commodities = [
                    {"name": "TLD 30", "description": "Tenofovir/Lamivudine/Dolutegravir 30 tablets"},
                    {"name": "TLD90", "description": "Tenofovir/Lamivudine/Dolutegravir 90 tablets"},
                    {"name": "TLD 180s", "description": "Tenofovir/Lamivudine/Dolutegravir 180 tablets"},
                    {"name": "PALD", "description": "Pediatric Antiretroviral"},
                    {"name": "TAFED(KOCITAF)", "description": "Tenofovir/Alafenamide/Emtricitabine"},
                    {"name": "ABC/3TC Pdtg10mg", "description": "Abacavir/Lamivudine Pediatric 10mg"},
                    {"name": "DTG50mg", "description": "Dolutegravir 50mg tablets"},
                    {"name": "Pdtg10mg", "description": "Pediatric Dolutegravir 10mg"},
                    {"name": "INH 300mg", "description": "Isoniazid 300mg"},
                    {"name": "NVP", "description": "Nevirapine"},
                    {"name": "BENZATHINE", "description": "Benzathine Penicillin"},
                    {"name": "LIGNOCAIN", "description": "Lignocaine"},
                    {"name": "ORAL QUICKS", "description": "Oral HIV Testing Kits"},
                    {"name": "DETERMINE", "description": "HIV Determine Test Kits"},
                    {"name": "SD BIOLINE", "description": "SD Bioline Test Kits"},
                    {"name": "HIV/SYPHILIS DUO", "description": "HIV/Syphilis Duo Test Kits"},
                    {"name": "TDF/FTC (PrEP)", "description": "Tenofovir/Emtricitabine for PrEP"},
                    {"name": "DBS CARDS", "description": "Dried Blood Spot Cards"},
                    {"name": "EDTA BOTTLES", "description": "EDTA Blood Collection Bottles"},
                    {"name": "AZT/3TC peads", "description": "Zidovudine/Lamivudine Pediatric"}
                ]
                for item in commodities:
                    db.session.add(Commodity(name=item['name'], description=item['description']))
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Commodity creation failed: {str(e)}")
                raise

# Helpers
@cache.memoize(timeout=300)
def get_previous_report(facility_id, commodity_id):
    return ReportItem.query.join(Report).filter(
        Report.facility_id == facility_id,
        ReportItem.commodity_id == commodity_id
    ).order_by(Report.report_date.desc()).first()

def validate_report_items(items, facility_id):
    errors = []
    for item in items:
        try:
            commodity_id = item['commodity_id']
            opening_balance = item['opening_balance']
            received = item['received']
            used = item['used']
            closing_balance = item['closing_balance']
            exp_date = item['exp_date']

            if not all(isinstance(x, int) and x >= 0 for x in [opening_balance, received, used, closing_balance]):
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Invalid values for {commodity.name}: All quantities must be non-negative integers.")
                continue

            if closing_balance != (opening_balance + received - used):
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Closing balance for {commodity.name} doesn't match calculation.")

            prev = get_previous_report(facility_id, commodity_id)
            if prev and opening_balance != prev.closing_balance:
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Opening balance for {commodity.name} doesn't match previous closing balance of {prev.closing_balance}.")

            if exp_date and not isinstance(exp_date, str):
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Expiration date for {commodity.name} must be a string.")
        except Exception as e:
            errors.append(f"Validation error for commodity ID {commodity_id}: {str(e)}")
    return errors

def check_permission(user, required_role):
    if user.role not in [required_role, 'admin']:
        flash('Insufficient permissions.', 'danger')
        return False
    return True

def parse_excel(file):
    wb = openpyxl.load_workbook(file, read_only=True)  # Use read_only mode to reduce memory
    sheet = wb['WEEK 1']
    data = []
    commodities = Commodity.query.all()
    commodity_map = {c.name: c.id for c in commodities}

    for row in sheet.iter_rows(min_row=9, max_row=28, min_col=1, max_col=7, values_only=True):
        item_desc = str(row[0]) if pd.notna(row[0]) else ''
        if item_desc in commodity_map:
            exp_date = str(row[5]) if pd.notna(row[5]) else ''
            data.append({
                'commodity_id': commodity_map[item_desc],
                'opening_balance': int(row[1]) if pd.notna(row[1]) else 0,
                'received': int(row[2]) if pd.notna(row[2]) else 0,
                'used': int(row[3]) if pd.notna(row[3]) else 0,
                'closing_balance': int(row[4]) if pd.notna(row[4]) else 0,
                'exp_date': exp_date,
                'remarks': str(row[6]) if pd.notna(row[6]) else ''
            })
    wb.close()  # Explicitly close to free memory
    return data

def generate_reset_token():
    return str(uuid.uuid4())

# Routes
@app.route('/')
def home():
    try:
        if 'user_id' not in session:
            logger.info("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Home route error: {str(e)}", exc_info=True)
        return "Internal Server Error", 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, form.password.data):
            if not user.approved:
                flash('Your account is pending approval.', 'warning')
                return render_template('login.html', form=form)
            session['user_id'] = user.id
            session['user_role'] = user.role
            db.session.add(AuditLog(user_id=user.id, action='login', details=f'User {username} logged in'))
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    form.province_id.choices = [(p.id, p.name) for p in Province.query.all()]
    form.hub_id.choices = [(h.id, h.name) for h in Hub.query.filter_by(province_id=form.province_id.data or Province.query.first().id).all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.filter_by(hub_id=form.hub_id.data or Hub.query.first().id).all()]
    form.facility_id.choices = [(f.id, f.name) for f in Facility.query.filter_by(district_id=form.district_id.data or District.query.first().id).all()]

    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data.strip(),
                password=generate_password_hash(form.password.data),
                phone_number=form.phone_number.data.strip(),
                facility_id=form.facility_id.data,
                role='user',
                approved=False
            )
            db.session.add(user)
            db.session.add(AuditLog(user_id=user.id, action='signup', details=f'User {user.username} requested account'))
            db.session.commit()
            flash('Sign-up request submitted. Awaiting auditor approval.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Signup error: {str(e)}")
            flash(f'Failed to sign up: {str(e)}', 'danger')
    return render_template('signup.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        try:
            username = form.username.data.strip()
            phone_number = form.phone_number.data.strip()
            user = User.query.filter_by(username=username, phone_number=phone_number).first()
            if user:
                token = generate_reset_token()
                user.reset_token = token
                user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
                db.session.add(AuditLog(user_id=user.id, action='request_password_reset', details=f'Password reset requested for {username}'))
                db.session.commit()
                reset_link = url_for('reset_password', token=token, _external=True)
                flash(f'A password reset link has been sent to {phone_number}: {reset_link}', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid username or phone number.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Forgot password error: {str(e)}")
            flash(f'Failed to process request: {str(e)}', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            user.password = generate_password_hash(form.password.data)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.add(AuditLog(user_id=user.id, action='reset_password', details=f'Password reset for {user.username}'))
            db.session.commit()
            flash('Password reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Reset password error: {str(e)}")
            flash(f'Failed to reset password: {str(e)}', 'danger')
    return render_template('reset_password.html', form=form, token=token)

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id', type=int)
            action = request.form.get('action')
            target_user = User.query.get(user_id)
            if not target_user:
                flash('User not found.', 'danger')
                return redirect(url_for('admin_users'))

            if action == 'approve':
                target_user.approved = True
                db.session.add(AuditLog(user_id=user.id, action='approve_user', details=f'Approved user {target_user.username}'))
            elif action == 'reject':
                target_user.approved = False
                db.session.add(AuditLog(user_id=user.id, action='reject_user', details=f'Rejected user {target_user.username}'))
            elif action == 'delete':
                db.session.delete(target_user)
                db.session.add(AuditLog(user_id=user.id, action='delete_user', details=f'Deleted user {target_user.username}'))
            db.session.commit()
            flash(f'User {action}d successfully.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"User management error: {str(e)}")
            flash(f'Failed to process action: {str(e)}', 'danger')

    users = User.query.all()
    return render_template('admin_users.html', users=users, user=user)

@app.route('/dashboard')
def dashboard():
    try:
        if 'user_id' not in session:
            logger.info("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            logger.warning("User not found, clearing session")
            session.clear()
            flash('User not found. Please log in again.', 'warning')
            return redirect(url_for('login'))
        page = request.args.get('page', 1, type=int)
        logger.info(f"Fetching reports for user {user.username}, facility {user.facility_id}, page {page}")
        reports = Report.query.filter_by(facility_id=user.facility_id).order_by(Report.report_date.desc()).paginate(page=page, per_page=10)
        provinces = Province.query.all()
        logger.info(f"Rendering dashboard for user {user.username}")
        return render_template('dashboard.html', user=user, reports=reports, provinces=provinces)
    except Exception as e:
        logger.error(f"Dashboard route error: {str(e)}", exc_info=True)
        return "Internal Server Error", 500

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'user'):
        return redirect(url_for('dashboard'))

    form = ReportForm()
    form.province_id.choices = [(p.id, p.name) for p in Province.query.all()]
    form.hub_id.choices = [(h.id, h.name) for h in Hub.query.filter_by(province_id=form.province_id.data or Province.query.first().id).all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.filter_by(hub_id=form.hub_id.data or Hub.query.first().id).all()]
    form.facility_id.choices = [(f.id, f.name) for f in Facility.query.filter_by(district_id=form.district_id.data or District.query.first().id).all()]
    form.commodity_id.choices = [(c.id, c.name) for c in Commodity.query.filter_by(active=True).order_by(Commodity.name).all()]

    commodities = Commodity.query.filter_by(active=True).order_by(Commodity.name).all()
    item_forms = {c.id: ReportItemForm(prefix=str(c.id)) for c in commodities}

    if form.validate_on_submit() and all(f.validate() for f in item_forms.values()):
        try:
            facility_id = form.facility_id.data
            if user.role != 'admin' and user.facility_id != facility_id:
                flash('You can only submit reports for your assigned facility.', 'danger')
                return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user)

            report_date = form.report_date.data
            report = Report(facility_id=facility_id, user_id=user.id, report_date=report_date, report_period='weekly')
            db.session.add(report)
            db.session.flush()

            items = [
                {
                    'commodity_id': c.id,
                    'opening_balance': item_forms[c.id].opening_balance.data,
                    'received': item_forms[c.id].received.data,
                    'used': item_forms[c.id].used.data,
                    'closing_balance': item_forms[c.id].closing_balance.data,
                    'exp_date': item_forms[c.id].exp_date.data,
                    'remarks': item_forms[c.id].remarks.data
                } for c in commodities
            ]

            errors = validate_report_items(items, facility_id)
            if errors:
                for err in errors:
                    flash(err, 'danger')
                return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user)

            for item in items:
                report_item = ReportItem(
                    report_id=report.id,
                    commodity_id=item['commodity_id'],
                    opening_balance=item['opening_balance'],
                    received=item['received'],
                    used=item['used'],
                    closing_balance=item['closing_balance'],
                    exp_date=item['exp_date'],
                    remarks=item['remarks']
                )
                db.session.add(report_item)
            db.session.add(AuditLog(user_id=user.id, action='submit_report', details=f'Submitted report for facility {facility_id}'))
            db.session.commit()
            flash('Report submitted successfully.', 'success')
            return redirect(url_for('dashboard'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Submit report error: {str(e)}")
            flash(f'Failed to submit report: {str(e)}', 'danger')
    return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user)

@app.route('/import-reports', methods=['GET', 'POST'])
def import_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'admin'):
        return redirect(url_for('dashboard'))
    form = ImportForm()
    if form.validate_on_submit():
        try:
            file = form.file.data
            items = parse_excel(file)
            errors = validate_report_items(items, user.facility_id)
            if errors:
                for err in errors:
                    flash(err, 'danger')
            else:
                report = Report(facility_id=user.facility_id, user_id=user.id, report_date=datetime.utcnow().date(), report_period='weekly')
                db.session.add(report)
                db.session.flush()
                for item in items:
                    report_item = ReportItem(
                        report_id=report.id,
                        commodity_id=item['commodity_id'],
                        opening_balance=item['opening_balance'],
                        received=item['received'],
                        used=item['used'],
                        closing_balance=item['closing_balance'],
                        exp_date=item['exp_date'],
                        remarks=item['remarks']
                    )
                    db.session.add(report_item)
                db.session.add(AuditLog(user_id=user.id, action='import_report', details=f'Imported report for facility {user.facility_id}'))
                db.session.commit()
                flash('Report imported successfully.', 'success')
                return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Import report error: {str(e)}")
            flash(f'Failed to import report: {str(e)}', 'danger')
    return render_template('import_reports.html', form=form, user=user)

@app.route('/view-reports', methods=['GET', 'POST'])
def view_reports():
    try:
        if 'user_id' not in session:
            logger.info("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user:
            logger.warning("User not found, clearing session")
            session.clear()
            flash('User not found. Please log in again.', 'warning')
            return redirect(url_for('login'))

        facility_id = request.args.get('facility_id', type=int, default=user.facility_id)
        start_date = request.args.get('start_date')
        period = request.args.get('period', 'weekly')
        page = request.args.get('page', 1, type=int)

        if user.role != 'admin' and facility_id != user.facility_id:
            flash('You can only view reports for your assigned facility.', 'danger')
            facility_id = user.facility_id

        query = Report.query.filter_by(facility_id=facility_id)
        if start_date:
            try:
                query = query.filter(Report.report_date >= datetime.strptime(start_date, '%Y-%m-%d').date())
            except ValueError:
                flash('Invalid date format. Use YYYY-MM-DD.', 'danger')
        if period:
            query = query.filter_by(report_period=period)

        reports = query.order_by(Report.report_date.desc()).paginate(page=page, per_page=10)
        facilities = Facility.query.all() if user.role == 'admin' else [user.facility]
        return render_template('view_reports.html', user=user, reports=reports, facilities=facilities, selected_facility_id=facility_id, start_date=start_date, period=period)
    except Exception as e:
        logger.error(f"View reports route error: {str(e)}", exc_info=True)
        return "Internal Server Error", 500

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/health')
def health():
    return jsonify({"status": "healthy"}), 200

# Initialize database
initialize_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
