```python
import os
import io
import csv
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SelectField, IntegerField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
import logging

app = Flask(__name__)

# Secure config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///luapula_supply_chain.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300

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

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    district = db.Column(db.String(50), nullable=False)
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
    report_period = db.Column(db.String(20), nullable=False)
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
    report_date = DateField('Report Date', validators=[DataRequired()], format='%Y-%m-%d')
    report_period = SelectField('Report Period', choices=[('weekly', 'Weekly'), ('monthly', 'Monthly')], validators=[DataRequired()])
    submit = SubmitField('Submit Report')

class ReportItemForm(FlaskForm):
    commodity_id = IntegerField('Commodity ID', validators=[DataRequired()])
    opening_balance = IntegerField('Opening Balance', validators=[DataRequired(), NumberRange(min=0)])
    received = IntegerField('Received', validators=[DataRequired(), NumberRange(min=0)])
    used = IntegerField('Used', validators=[DataRequired(), NumberRange(min=0)])
    closing_balance = IntegerField('Closing Balance', validators=[DataRequired(), NumberRange(min=0)])
    exp_date = StringField('Expiration Date', validators=[Length(max=20)])
    remarks = TextAreaField('Remarks', validators=[Length(max=500)])

# Database Init
def initialize_database():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            try:
                admin_facility = Facility(name='Provincial Health Office', district='Luapula')
                db.session.add(admin_facility)
                db.session.commit()

                admin_password = os.environ.get('ADMIN_PASSWORD')
                if not admin_password:
                    raise ValueError("No ADMIN_PASSWORD set")
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

        if not Facility.query.first():
            try:
                districts = {
                    'Mansa': ['Mansa General Hospital', 'St. Theresa Mission Hospital'],
                    'Samfya': ['Samfya District Hospital', 'Mambilima Mission Hospital'],
                    'Kawambwa': ['Kawambwa District Hospital', 'St. Paul\'s Mission Hospital']
                }
                for district, facilities in districts.items():
                    for facility_name in facilities:
                        db.session.add(Facility(name=facility_name, district=district))
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"Facility creation failed: {str(e)}")
                raise

        if not Commodity.query.first():
            try:
                commodities = [
                    {"name": "TLD 30", "description": "TLD 30 tablets"},
                    {"name": "TLD90", "description": "TLD 90 tablets"},
                    {"name": "TLD 180s", "description": "TLD 180 tablets"},
                    {"name": "PALD", "description": "PALD medication"},
                    {"name": "TAFED(KOCITAF)", "description": "TAFED combination"},
                    {"name": "ABC/3TC Pdtg10mg", "description": "Pediatric ABC/3TC"},
                    {"name": "DTG50mg", "description": "DTG 50mg tablets"},
                    {"name": "Pdtg10mg", "description": "Pediatric DTG 10mg"},
                    {"name": "INH 300mg", "description": "Isoniazid 300mg"}
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
                errors.append(f"Opening balance for {commodity.name} doesn't match previous closing balance.")
        except Exception as e:
            errors.append(f"Validation error for commodity ID {commodity_id}: {str(e)}")
    return errors

def check_permission(user, required_role):
    if user.role not in [required_role, 'admin']:
        flash('Insufficient permissions.', 'danger')
        return False
    return True

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
    return render_template('dashboard.html', user=user, reports=reports)

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'user'):
        return redirect(url_for('dashboard'))

    form = ReportForm()
    commodities = Commodity.query.filter_by(active=True).order_by(Commodity.name).all()
    item_forms = {c.id: ReportItemForm(prefix=str(c.id)) for c in commodities}

    if form.validate_on_submit() and all(f.validate() for f in item_forms.values()):
        try:
            report_date = form.report_date.data
            report_period = form.report_period.data

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

            errors = validate_report_items(items, user.facility_id)
            if errors:
                for err in errors:
                    flash(err, 'danger')
                return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user)

            report = Report(facility_id=user.facility_id, user_id=user.id, report_date=report_date, report_period=report_period)
            db.session.add(report)
            db.session.flush()

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
    for commodity in commodities:
        cid = commodity.id
        prev = get_previous_report(user.facility_id, cid)
        form_data[f'opening_balance_{cid}'] = prev.closing_balance if prev else 0
        item_forms[cid].opening_balance.data = prev.closing_balance if prev else 0
        item_forms[cid].received.data = 0
        item_forms[cid].used.data = 0
        item_forms[cid].closing_balance.data = 0
        item_forms[cid].exp_date.data = ''
        item_forms[cid].remarks.data = ''

    return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user, form_data=form_data)

@app.route('/view-reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    reports = Report.query.order_by(Report.report_date.desc()).paginate(page=page, per_page=10)
    return render_template('view_reports.html', reports=reports, user=user)

@app.route('/analytics')
def analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    commodity_id = request.args.get('commodity_id', type=int)
    if not commodity_id:
        commodity = Commodity.query.first()
        if not commodity:
            flash('No commodities available.', 'warning')
            return redirect(url_for('dashboard'))
        commodity_id = commodity.id

    commodity = Commodity.query.get(commodity_id)
    reports = ReportItem.query.join(Report).filter(
        ReportItem.commodity_id == commodity_id,
        Report.facility_id == user.facility_id
    ).order_by(Report.report_date.asc()).all()

    chart_data = {
        'type': 'line',
        'data': {
            'labels': [r.report.report_date.strftime('%Y-%m-%d') for r in reports],
            'datasets': [{
                'label': f'{commodity.name} Closing Balance',
                'data': [r.closing_balance for r in reports],
                'borderColor': '#007bff',
                'backgroundColor': 'rgba(0, 123, 255, 0.1)',
                'fill': True,
                'tension': 0.4
            }]
        },
        'options': {
            'responsive': True,
            'scales': {
                'y': {
                    'beginAtZero': True,
                    'title': {'display': True, 'text': 'Closing Balance'}
                },
                'x': {
                    'title': {'display': True, 'text': 'Report Date'}
                }
            },
            'plugins': {
                'legend': {'position': 'top'},
                'title': {'display': True, 'text': f'{commodity.name} Inventory Trend'}
            }
        }
    }
    return render_template('analytics.html', chart_data=json.dumps(chart_data), commodities=Commodity.query.all(), selected_commodity=commodity, user=user)

@app.route('/export-reports', methods=['GET'])
def export_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not check_permission(user, 'auditor'):
        return redirect(url_for('dashboard'))

    reports = Report.query.filter_by(facility_id=user.facility_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Report ID', 'Facility', 'Report Date', 'Period', 'Commodity', 'Opening Balance', 'Received', 'Used', 'Closing Balance', 'Expiration Date', 'Remarks'])
    
    for report in reports:
        for item in report.items:
            writer.writerow([
                report.id, report.facility.name, report.report_date, report.report_period,
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

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename.endswith('.csv'):
            flash('Please upload a valid CSV file.', 'danger')
            return redirect(url_for('import_reports'))

        try:
            df = pd.read_csv(file)
            for _, row in df.iterrows():
                facility = Facility.query.filter_by(name=row['Facility']).first()
                commodity = Commodity.query.filter_by(name=row['Commodity']).first()
                if not facility or not commodity:
                    flash(f"Invalid facility or commodity: {row['Facility']} or {row['Commodity']}", 'danger')
                    continue

                report = Report(
                    facility_id=facility.id,
                    user_id=user.id,
                    report_date=datetime.strptime(row['Report Date'], '%Y-%m-%d').date(),
                    report_period=row['Period']
                )
                db.session.add(report)
                db.session.flush()

                item = ReportItem(
                    report_id=report.id,
                    commodity_id=commodity.id,
                    opening_balance=int(row['Opening Balance']),
                    received=int(row['Received']),
                    used=int(row['Used']),
                    closing_balance=int(row['Closing Balance']),
                    exp_date=row['Expiration Date'] if pd.notna(row['Expiration Date']) else None,
                    remarks=row['Remarks'] if pd.notna(row['Remarks']) else None
                )
                db.session.add(item)

            db.session.add(AuditLog(user_id=user.id, action='import_reports', details='Imported reports from CSV'))
            db.session.commit()
            cache.delete_memoized(get_previous_report)
            flash('Reports imported successfully!', 'success')
        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            logger.error(f"Import error: {str(e)}")
            flash(f'Failed to import reports: {str(e)}', 'danger')

    return render_template('import_reports.html', user=user)

with app.app_context():
    initialize_database()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV', 'development') == 'development')
```
