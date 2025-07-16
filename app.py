import os
import io
import csv
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SelectField, IntegerField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, NumberRange, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
import openpyxl
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging
from sqlalchemy import func

app = Flask(__name__)

# Secure configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secure-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///zambia_supply_chain.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user, admin, facility_manager, auditor
    approved = db.Column(db.Boolean, default=False)
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
                    approved=True
                )
                db.session.add(admin)
                db.session.add(AuditLog(user_id=admin.id, action='create_admin', details='Admin user created'))
                db.session.commit()
            except (SQLAlchemyError, ValueError) as e:
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
    wb = openpyxl.load_workbook(file)
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
    return data

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if not user.approved:
                flash('Your account is pending approval.', 'warning')
                return render_template('login.html', form=form)
            session['user_id'] = user.id
            db.session.add(AuditLog(user_id=user.id, action='login', details=f'User {username} logged in'))
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        db.session.add(AuditLog(user_id=user_id, action='logout', details='User logged out'))
        db.session.commit()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please log in again.', 'warning')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    reports = Report.query.filter_by(facility_id=user.facility_id).order_by(Report.report_date.desc()).paginate(page=page, per_page=10)
    provinces = Province.query.all()
    return render_template('dashboard.html', user=user, reports=reports, provinces=provinces)

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'))
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
            # Enforce weekly reports
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
                db.session.add(ReportItem(
                    report_id=report.id,
                    commodity_id=item['commodity_id'],
                    opening_balance=item['opening_balance'],
                    received=item['received'],
                    used=item['used'],
                    closing_balance=item['closing_balance'],
                    exp_date=item['exp_date'],
                    remarks=item['remarks']
                ))

            db.session.add(AuditLog(user_id=user.id, action='submit_report', details=f'Report ID {report.id} submitted'))
            db.session.commit()
            cache.delete_memoized(get_previous_report)
            flash('Report submitted successfully!', 'success')
            return redirect(url_for('dashboard'))

        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            logger.error(f"Submit error: {str(e)}")
            flash(f'Failed to submit report: {str(e)}', 'danger')

    # Pre-fill forms
    form_data = {}
    facility_id = user.facility_id if user.role != 'admin' else (form.facility_id.data or Facility.query.first().id)
    for commodity in commodities:
        cid = commodity.id
        prev = get_previous_report(facility_id, cid)
        form_data[f'opening_balance_{cid}'] = prev.closing_balance if prev else 0
        item_forms[cid].opening_balance.data = prev.closing_balance if prev else 0
        item_forms[cid].received.data = 0
        item_forms[cid].used.data = 0
        item_forms[cid].closing_balance.data = prev.closing_balance if prev else 0
        item_forms[cid].exp_date.data = ''
        item_forms[cid].remarks.data = ''

    return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user, form_data=form_data)

@app.route('/add-commodity', methods=['GET', 'POST'])
def add_commodity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'admin'):
        return redirect(url_for('dashboard'))

    form = CommodityForm()
    if form.validate_on_submit():
        try:
            commodity = Commodity(
                name=form.name.data.strip(),
                description=form.description.data.strip(),
                active=True
            )
            db.session.add(commodity)
            db.session.add(AuditLog(user_id=user.id, action='add_commodity', details=f'Commodity {commodity.name} added'))
            db.session.commit()
            flash('Commodity added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Commodity name already exists.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Add commodity error: {str(e)}")
            flash(f'Failed to add commodity: {str(e)}', 'danger')

    return render_template('add_commodity.html', form=form, user=user)

@app.route('/add-facility', methods=['GET', 'POST'])
def add_facility():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'admin'):
        return redirect(url_for('dashboard'))

    form = FacilityForm()
    form.province_id.choices = [(p.id, p.name) for p in Province.query.all()]
    form.hub_id.choices = [(h.id, h.name) for h in Hub.query.filter_by(province_id=form.province_id.data or Province.query.first().id).all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.filter_by(hub_id=form.hub_id.data or Hub.query.first().id).all()]

    if form.validate_on_submit():
        try:
            facility = Facility(
                name=form.name.data.strip(),
                district_id=form.district_id.data
            )
            db.session.add(facility)
            db.session.add(AuditLog(user_id=user.id, action='add_facility', details=f'Facility {facility.name} added'))
            db.session.commit()
            flash('Facility added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Facility name already exists.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Add facility error: {str(e)}")
            flash(f'Failed to add facility: {str(e)}', 'danger')

    return render_template('add_facility.html', form=form, user=user)

@app.route('/view-reports', methods=['GET'])
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    facility_id = request.args.get('facility_id', type=int)
    period = request.args.get('period', 'weekly')
    start_date = request.args.get('start_date', type=str)
    end_date = request.args.get('end_date', type=str)

    reports_query = Report.query
    if facility_id and user.role == 'admin':
        reports_query = reports_query.filter_by(facility_id=facility_id)
    elif user.role != 'admin':
        reports_query = reports_query.filter_by(facility_id=user.facility_id)

    if period == 'daily':
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date == start)
            except ValueError:
                flash('Invalid start date format.', 'danger')
    elif period == 'weekly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')
    elif period == 'quarterly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')

    reports = reports_query.order_by(Report.report_date.desc()).paginate(page=page, per_page=10)
    facilities = Facility.query.all() if user.role == 'admin' else [user.facility]
    return render_template('view_reports.html', reports=reports, user=user, facilities=facilities, period=period, start_date=start_date, end_date=end_date)

@app.route('/analytics', methods=['GET'])
def analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    commodity_id = request.args.get('commodity_id', type=int)
    facility_id = request.args.get('facility_id', type=int) if user.role == 'admin' else user.facility_id
    period = request.args.get('period', 'weekly')
    start_date = request.args.get('start_date', type=str)
    end_date = request.args.get('end_date', type=str)

    if not commodity_id:
        commodity = Commodity.query.first()
        if not commodity:
            flash('No commodities available.', 'warning')
            return redirect(url_for('dashboard'))
        commodity_id = commodity.id

    commodity = Commodity.query.get(commodity_id)
    if not commodity:
        flash('Selected commodity not found.', 'warning')
        return redirect(url_for('dashboard'))

    reports_query = ReportItem.query.join(Report).filter(
        ReportItem.commodity_id == commodity_id,
        Report.facility_id == (facility_id or user.facility_id)
    )

    if period == 'daily':
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date == start)
            except ValueError:
                flash('Invalid start date format.', 'danger')
    elif period == 'weekly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')
    elif period == 'quarterly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')

    reports = reports_query.order_by(Report.report_date.asc()).all()

    labels = [r.report.report_date.strftime('%Y-%m-%d') for r in reports] if reports else [datetime.utcnow().strftime('%Y-%m-%d')]
    data = [int(r.closing_balance) for r in reports] if reports else [0]

    ```chartjs
    {
        "type": "line",
        "data": {
            "labels": labels,
            "datasets": [{
                "label": commodity.name + " Closing Balance",
                "data": data,
                "borderColor": "#3B82F6",
                "backgroundColor": "rgba(59, 130, 246, 0.1)",
                "fill": true,
                "tension": 0.4
            }]
        },
        "options": {
            "responsive": true,
            "scales": {
                "y": {
                    "beginAtZero": true,
                    "title": {"display": true, "text": "Closing Balance"}
                },
                "x": {
                    "title": {"display": true, "text": "Report Date"}
                }
            },
            "plugins": {
                "legend": {"position": "top"},
                "title": {"display": true, "text": commodity.name + " Inventory Trend (" + period.capitalize() + ")"}
            }
        }
    }
    ```

    try:
        chart_data_json = json.dumps({"labels": labels, "data": data, "commodity_name": commodity.name, "period": period}, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.error(f"Failed to serialize chart_data: {str(e)}")
        flash('Error generating analytics chart.', 'danger')
        chart_data_json = json.dumps({
            "labels": [], "data": [], "commodity_name": "No Data", "period": period,
            "options": {"plugins": {"title": {"display": true, "text": "No Data Available"}}}
        })

    facilities = Facility.query.all() if user.role == 'admin' else [user.facility]
    return render_template('analytics.html', chart_data=chart_data_json, commodities=Commodity.query.all(), selected_commodity=commodity, user=user, facilities=facilities, period=period, start_date=start_date, end_date=end_date)

@app.route('/export-reports', methods=['GET'])
def export_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    facility_id = request.args.get('facility_id', type=int)
    period = request.args.get('period', 'weekly')
    start_date = request.args.get('start_date', type=str)
    end_date = request.args.get('end_date', type=str)

    reports_query = Report.query
    if facility_id and user.role == 'admin':
        reports_query = reports_query.filter_by(facility_id=facility_id)
    elif user.role != 'admin':
        reports_query = reports_query.filter_by(facility_id=user.facility_id)

    if period == 'daily':
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date == start)
            except ValueError:
                flash('Invalid start date format.', 'danger')
    elif period == 'weekly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')
    elif period == 'quarterly':
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                reports_query = reports_query.filter(Report.report_date.between(start, end))
            except ValueError:
                flash('Invalid date format.', 'danger')

    reports = reports_query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Report ID', 'Province', 'Hub', 'District', 'Facility', 'Report Date', 'Period', 'Commodity', 'Opening Balance', 'Received', 'Used', 'Closing Balance', 'Expiration Date', 'Remarks'])
    
    for report in reports:
        facility = report.facility
        district = facility.district
        hub = district.hub
        province = hub.province
        for item in report.items:
            writer.writerow([
                report.id, province.name, hub.name, district.name, facility.name, report.report_date, report.report_period,
                item.commodity.name, item.opening_balance, item.received, item.used,
                item.closing_balance, item.exp_date or '', item.remarks or ''
            ])

    db.session.add(AuditLog(user_id=user.id, action='export_reports', details='Exported reports to CSV'))
    db.session.commit()

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=reports.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/import-reports', methods=['GET', 'POST'])
def import_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'admin'):
        return redirect(url_for('dashboard'))

    form = ImportForm()
    if form.validate_on_submit():
        file = form.file.data
        if not file.filename.endswith(('.xlsx', '.xls')):
            flash('Please upload a valid Excel file (.xlsx or .xls).', 'danger')
            return redirect(url_for('import_reports'))

        try:
            data = parse_excel(file)
            for item in data:
                commodity = Commodity.query.get(item['commodity_id'])
                if not commodity:
                    flash(f"Invalid commodity: {item['commodity_id']}", 'danger')
                    continue

                facility = Facility.query.get(user.facility_id)
                if not facility:
                    flash(f"Invalid facility ID: {user.facility_id}", 'danger')
                    continue

                report = Report(
                    facility_id=facility.id,
                    user_id=user.id,
                    report_date=datetime.utcnow().date(),
                    report_period='weekly'
                )
                db.session.add(report)
                db.session.flush()

                db.session.add(ReportItem(
                    report_id=report.id,
                    commodity_id=item['commodity_id'],
                    opening_balance=item['opening_balance'],
                    received=item['received'],
                    used=item['used'],
                    closing_balance=item['closing_balance'],
                    exp_date=item['exp_date'],
                    remarks=item['remarks']
                ))

            db.session.add(AuditLog(user_id=user.id, action='import_reports', details='Imported reports from Excel'))
            db.session.commit()
            cache.delete_memoized(get_previous_report)
            flash('Reports imported successfully!', 'success')
        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            logger.error(f"Import error: {str(e)}")
            flash(f'Failed to import reports: {str(e)}', 'danger')

    return render_template('import_reports.html', form=form, user=user)

# API Endpoints for Dropdowns
@app.route('/get_hubs/<int:province_id>')
def get_hubs(province_id):
    hubs = Hub.query.filter_by(province_id=province_id).all()
    return jsonify([{'id': h.id, 'name': h.name} for h in hubs])

@app.route('/get_districts/<int:hub_id>')
def get_districts(hub_id):
    districts = District.query.filter_by(hub_id=hub_id).all()
    return jsonify([{'id': d.id, 'name': d.name} for d in districts])

@app.route('/get_facilities/<int:district_id>')
def get_facilities(district_id):
    facilities = Facility.query.filter_by(district_id=district_id).all()
    return jsonify([{'id': f.id, 'name': f.name} for f in facilities])

with app.app_context():
    initialize_database()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV', 'development') == 'development')
