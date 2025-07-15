import os
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from sqlalchemy import extract
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///luapula_supply_chain.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    role = db.Column(db.String(20), default='user')
    approved = db.Column(db.Boolean, default=False)

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    district = db.Column(db.String(50), nullable=False)
    reports = db.relationship('Report', backref='facility', lazy=True)
    users = db.relationship('User', backref='facility', lazy=True)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(200))
    active = db.Column(db.Boolean, default=True)
    items = db.relationship('ReportItem', backref='commodity', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_date = db.Column(db.Date, nullable=False)
    report_period = db.Column(db.String(20), nullable=False)  # weekly, monthly, quarterly
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('ReportItem', backref='report', lazy=True, cascade='all, delete-orphan')
    user = db.relationship('User', backref='reports')

class ReportItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False)
    opening_balance = db.Column(db.Integer, nullable=False)
    received = db.Column(db.Integer, nullable=False)
    used = db.Column(db.Integer, nullable=False)
    closing_balance = db.Column(db.Integer, nullable=False)
    exp_date = db.Column(db.String(20))
    remarks = db.Column(db.Text)

# Initialize database
def initialize_database():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin_facility = Facility(name='Provincial Health Office', district='Luapula')
            db.session.add(admin_facility)
            db.session.commit()
            
            admin = User(
                username='admin',
                password=generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123')),
                facility_id=admin_facility.id,
                role='admin',
                approved=True
            )
            db.session.add(admin)
        
        # Create Luapula Province facilities if not exists
        if not Facility.query.first():
            districts = {
                'Mansa': ['Mansa General Hospital', 'St. Theresa Mission Hospital', 
                         'Mansa Urban Health Centre', 'Kashikishi Rural Health Centre'],
                'Samfya': ['Samfya District Hospital', 'Mambilima Mission Hospital',
                           'Samfya Urban Health Centre'],
                'Kawambwa': ['Kawambwa District Hospital', 'St. Paul\'s Mission Hospital',
                             'Kawambwa Urban Health Centre'],
                'Nchelenge': ['Nchelenge District Hospital', 'Chiengi Rural Hospital',
                              'Nchelenge Urban Health Centre'],
                'Mwense': ['Mwense District Hospital', 'Luwingu Rural Health Centre'],
                'Chembe': ['Chembe District Hospital', 'Mbereshi Mission Hospital'],
                'Chienge': ['Chienge District Hospital', 'Kaputa District Hospital']
            }
            
            for district, facilities in districts.items():
                for facility_name in facilities:
                    db.session.add(Facility(name=facility_name, district=district))
        
        # Create default commodities if not exists
        if not Commodity.query.first():
            commodities = [
                "TLD 30", "TLD90", "TLD 180s", "PALD", "TAFED(KOCITAF)", 
                "ABC/3TC Pdtg10mg", "DTG50mg", "Pdtg10mg", "INH 300mg", 
                "NVP", "BENZATHINE", "LIGNOCAIN", "ORAL QUICKS", "DETERMINE", 
                "SD BIOLINE", "HIV/SYPHILIS DUO", "TDF/FTC (PrEP)", 
                "DBS CARDS", "EDTA BOTTLES", "AZT/3TC peads"
            ]
            for item in commodities:
                db.session.add(Commodity(name=item, description=item))
        
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Database initialization failed: {str(e)}")

# Initialize the database when app starts
with app.app_context():
    initialize_database()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# Helper functions
def get_previous_report(facility_id, commodity_id):
    prev_report = ReportItem.query.join(Report).filter(
        Report.facility_id == facility_id,
        ReportItem.commodity_id == commodity_id
    ).order_by(Report.report_date.desc()).first()
    return prev_report

def validate_report_items(items, facility_id):
    errors = []
    for item in items:
        try:
            commodity_id = int(item['commodity_id'])
            opening_balance = int(item['opening_balance'])
            received = int(item['received'])
            used = int(item['used'])
            closing_balance = int(item['closing_balance'])
            
            calculated_closing = opening_balance + received - used
            if closing_balance != calculated_closing:
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Closing balance for {commodity.name} doesn't match calculation (should be {calculated_closing})")
            
            prev_report = get_previous_report(facility_id, commodity_id)
            if prev_report and opening_balance != prev_report.closing_balance:
                commodity = Commodity.query.get(commodity_id)
                errors.append(f"Opening balance for {commodity.name} doesn't match previous closing balance ({prev_report.closing_balance})")
        except (ValueError, KeyError):
            errors.append("Invalid input values in report items")
    
    return errors

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if not user.approved:
                flash('Your account is pending approval', 'warning')
                return render_template('login.html')
            
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    reports = Report.query.filter_by(facility_id=user.facility_id).order_by(Report.report_date.desc()).limit(5).all()
    
    return render_template('dashboard.html', user=user, reports=reports)

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    commodities = Commodity.query.filter_by(active=True).order_by(Commodity.name).all()
    
    if request.method == 'POST':
        try:
            report_date_str = request.form.get('report_date', '')
            if not report_date_str:
                flash('Report date is required', 'danger')
                return render_template('submit_report.html', commodities=commodities, user=user)
            
            try:
                report_date = datetime.strptime(report_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date format. Use YYYY-MM-DD', 'danger')
                return render_template('submit_report.html', commodities=commodities, user=user)
            
            report_period = request.form.get('report_period', 'weekly')
            if report_period not in ['weekly', 'monthly', 'quarterly']:
                flash('Invalid report period', 'danger')
                return render_template('submit_report.html', commodities=commodities, user=user)
            
            items = []
            for commodity in commodities:
                commodity_id = str(commodity.id)
                try:
                    items.append({
                        'commodity_id': commodity_id,
                        'opening_balance': request.form.get(f'opening_balance_{commodity_id}', '0'),
                        'received': request.form.get(f'received_{commodity_id}', '0'),
                        'used': request.form.get(f'used_{commodity_id}', '0'),
                        'closing_balance': request.form.get(f'closing_balance_{commodity_id}', '0'),
                        'exp_date': request.form.get(f'exp_date_{commodity_id}', ''),
                        'remarks': request.form.get(f'remarks_{commodity_id}', '')
                    })
                except ValueError:
                    flash(f'Invalid values for commodity {commodity.name}', 'danger')
                    return render_template('submit_report.html', commodities=commodities, user=user)
            
            validation_errors = validate_report_items(items, user.facility_id)
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'danger')
                return render_template('submit_report.html', commodities=commodities, user=user, form_data=request.form)
            
            report = Report(
                facility_id=user.facility_id,
                user_id=user.id,
                report_date=report_date,
                report_period=report_period
            )
            db.session.add(report)
            db.session.flush()
            
            for item in items:
                report_item = ReportItem(
                    report_id=report.id,
                    commodity_id=int(item['commodity_id']),
                    opening_balance=int(item['opening_balance']),
                    received=int(item['received']),
                    used=int(item['used']),
                    closing_balance=int(item['closing_balance']),
                    exp_date=item['exp_date'],
                    remarks=item['remarks']
                )
                db.session.add(report_item)
            
            db.session.commit()
            flash('Report submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Database error: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Error submitting report: {str(e)}', 'danger')
    
    form_data = {}
    for commodity in commodities:
        prev_report = get_previous_report(user.facility_id, commodity.id)
        if prev_report:
            form_data[f'opening_balance_{commodity.id}'] = prev_report.closing_balance
    
    return render_template('submit_report.html', commodities=commodities, user=user, form_data=form_data)

# ... [Rest of the routes remain similar but with the same error handling improvements] ...

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
