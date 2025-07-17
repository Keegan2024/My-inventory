import os
import io
import csv
import json
import uuid
import logging
import pandas as pd
import openpyxl
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
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

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

# Models (unchanged from your original)
# ... [All your model definitions remain exactly the same] ...

# Forms (unchanged from your original)
# ... [All your form definitions remain exactly the same] ...

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
            
            try:
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
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to initialize provinces: {str(e)}")
                raise

        # Initialize Facilities
        if not Facility.query.first():
            facilities_data = {
                'Mansa': ['Mansa General Hospital', 'Kabuta RHC', 'Chembe RHC'],
                'Samfya': ['Samfya District Hospital', 'Mambilima Mission Hospital'],
                'Kawambwa': ['Kawambwa District Hospital', 'St. Paul\'s Mission Hospital'],
                'Lusaka': ['University Teaching Hospital', 'Levy Mwanawasa Hospital'],
                'Ndola': ['Ndola Teaching Hospital', 'Arthur Davison Hospital'],
            }
            
            try:
                for district_name, facilities in facilities_data.items():
                    district = District.query.filter_by(name=district_name).first()
                    if district:
                        for facility_name in facilities:
                            db.session.add(Facility(name=facility_name, district_id=district.id))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to initialize facilities: {str(e)}")
                raise

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
                db.session.add(AuditLog(user_id=admin.id, action='create_admin', details='Admin user created'))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Admin creation failed: {str(e)}")
                raise

        # Initialize Commodities
        if not Commodity.query.first():
            try:
                commodities = [
                    {"name": "TLD 30", "description": "Tenofovir/Lamivudine/Dolutegravir 30 tablets"},
                    # ... [rest of your commodities list] ...
                ]
                for item in commodities:
                    db.session.add(Commodity(name=item['name'], description=item['description']))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Commodity creation failed: {str(e)}")
                raise

# Helpers
@cache.memoize(timeout=300)
def get_previous_report(facility_id, commodity_id):
    try:
        return ReportItem.query.join(Report).filter(
            Report.facility_id == facility_id,
            ReportItem.commodity_id == commodity_id
        ).order_by(Report.report_date.desc()).first()
    except Exception as e:
        logger.error(f"Error getting previous report: {str(e)}")
        return None

def validate_report_items(items, facility_id):
    errors = []
    for item in items:
        try:
            commodity_id = item.get('commodity_id')
            if not commodity_id:
                errors.append("Missing commodity ID")
                continue

            commodity = Commodity.query.get(commodity_id)
            if not commodity:
                errors.append(f"Invalid commodity ID: {commodity_id}")
                continue

            for field in ['opening_balance', 'received', 'used', 'closing_balance']:
                if not isinstance(item.get(field), int) or item[field] < 0:
                    errors.append(f"Invalid {field.replace('_', ' ')} for {commodity.name}: Must be non-negative integer")

            if item.get('closing_balance') != (item.get('opening_balance', 0) + item.get('received', 0) - item.get('used', 0)):
                errors.append(f"Closing balance for {commodity.name} doesn't match calculation")

            prev = get_previous_report(facility_id, commodity_id)
            if prev and item.get('opening_balance') != prev.closing_balance:
                errors.append(f"Opening balance for {commodity.name} doesn't match previous closing balance of {prev.closing_balance}")

            if item.get('exp_date') and not isinstance(item['exp_date'], str):
                errors.append(f"Expiration date for {commodity.name} must be a string")

        except Exception as e:
            errors.append(f"Validation error for commodity ID {commodity_id}: {str(e)}")
    return errors

def check_permission(user, required_role):
    if not user or user.role not in [required_role, 'admin']:
        flash('Insufficient permissions.', 'danger')
        return False
    return True

def generate_reset_token():
    return str(uuid.uuid4())

def parse_excel(file):
    try:
        wb = openpyxl.load_workbook(io.BytesIO(file.read()))
        if 'WEEK 1' not in wb.sheetnames:
            raise ValueError("Excel file must contain 'WEEK 1' sheet")
            
        sheet = wb['WEEK 1']
        data = []
        commodities = Commodity.query.all()
        commodity_map = {c.name: c.id for c in commodities}
        
        for row in sheet.iter_rows(min_row=9, max_row=28, min_col=1, max_col=7, values_only=True):
            item_desc = str(row[0]) if row[0] is not None else ''
            if item_desc in commodity_map:
                exp_date = str(row[5]) if row[5] is not None else ''
                data.append({
                    'commodity_id': commodity_map[item_desc],
                    'opening_balance': int(row[1]) if row[1] is not None else 0,
                    'received': int(row[2]) if row[2] is not None else 0,
                    'used': int(row[3]) if row[3] is not None else 0,
                    'closing_balance': int(row[4]) if row[4] is not None else 0,
                    'exp_date': exp_date,
                    'remarks': str(row[6]) if row[6] is not None else ''
                })
        return data
    except Exception as e:
        logger.error(f"Excel parsing error: {str(e)}")
        raise ValueError(f"Error processing Excel file: {str(e)}")

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            username = form.username.data.strip()
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            
            if not user or not check_password_hash(user.password, password):
                flash('Invalid credentials.', 'danger')
                return render_template('login.html', form=form)
            
            if not user.approved:
                flash('Your account is pending approval.', 'warning')
                return render_template('login.html', form=form)
            
            session['user_id'] = user.id
            db.session.add(AuditLog(user_id=user.id, action='login', details=f'User {username} logged in'))
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'danger')
    return render_template('login.html', form=form)

# ... [Other routes remain similar but with added error handling] ...

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User not found. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    if not check_permission(user, 'user'):
        return redirect(url_for('dashboard'))

    form = ReportForm()
    form.province_id.choices = [(p.id, p.name) for p in Province.query.order_by(Province.name).all()]
    form.hub_id.choices = [(h.id, h.name) for h in Hub.query.filter_by(
        province_id=form.province_id.data or Province.query.first().id
    ).order_by(Hub.name).all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.filter_by(
        hub_id=form.hub_id.data or Hub.query.first().id
    ).order_by(District.name).all()]
    form.facility_id.choices = [(f.id, f.name) for f in Facility.query.filter_by(
        district_id=form.district_id.data or District.query.first().id
    ).order_by(Facility.name).all()]
    
    commodities = Commodity.query.filter_by(active=True).order_by(Commodity.name).all()
    item_forms = {c.id: ReportItemForm(prefix=str(c.id)) for c in commodities}

    if request.method == 'POST' and form.validate():
        try:
            facility_id = form.facility_id.data
            if user.role != 'admin' and user.facility_id != facility_id:
                flash('You can only submit reports for your assigned facility.', 'danger')
                return render_template('submit_report.html', form=form, item_forms=item_forms, commodities=commodities, user=user)

            report_date = form.report_date.data
            report = Report(
                facility_id=facility_id,
                user_id=user.id,
                report_date=report_date,
                report_period='weekly'
            )
            db.session.add(report)
            db.session.flush()

            items = []
            for c in commodities:
                form_data = item_forms[c.id]
                items.append({
                    'commodity_id': c.id,
                    'opening_balance': form_data.opening_balance.data,
                    'received': form_data.received.data,
                    'used': form_data.used.data,
                    'closing_balance': form_data.closing_balance.data,
                    'exp_date': form_data.exp_date.data,
                    'remarks': form_data.remarks.data
                })

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

            db.session.add(AuditLog(
                user_id=user.id,
                action='submit_report',
                details=f'Report ID {report.id} submitted for facility {facility_id}'
            ))
            db.session.commit()
            cache.delete_memoized(get_previous_report)
            flash('Report submitted successfully!', 'success')
            return redirect(url_for('dashboard'))

        except (ValueError, SQLAlchemyError) as e:
            db.session.rollback()
            logger.error(f"Report submission error: {str(e)}")
            flash(f'Failed to submit report: {str(e)}', 'danger')

    # Pre-fill forms with previous data
    form_data = {}
    facility_id = user.facility_id if user.role != 'admin' else (form.facility_id.data or Facility.query.first().id)
    
    for commodity in commodities:
        cid = commodity.id
        prev = get_previous_report(facility_id, cid)
        default_value = prev.closing_balance if prev else 0
        
        item_forms[cid].opening_balance.data = default_value
        item_forms[cid].received.data = 0
        item_forms[cid].used.data = 0
        item_forms[cid].closing_balance.data = default_value
        item_forms[cid].exp_date.data = ''
        item_forms[cid].remarks.data = ''
        
        form_data[f'opening_balance_{cid}'] = default_value

    return render_template(
        'submit_report.html',
        form=form,
        item_forms=item_forms,
        commodities=commodities,
        user=user,
        form_data=form_data
    )

# ... [Other routes with similar error handling improvements] ...

@app.route('/view-reports', methods=['GET'])
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

        # Get filter parameters
        facility_id = request.args.get('facility_id', type=int, default=user.facility_id)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        period = request.args.get('period', 'weekly')
        page = request.args.get('page', 1, type=int)

        # Restrict to user's facility unless admin
        if user.role != 'admin' and facility_id != user.facility_id:
            flash('You can only view reports for your assigned facility.', 'danger')
            facility_id = user.facility_id

        # Build query
        query = Report.query.filter_by(facility_id=facility_id)
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                query = query.filter(Report.report_date >= start_date)
            except ValueError:
                flash('Invalid start date format. Use YYYY-MM-DD.', 'danger')
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                query = query.filter(Report.report_date <= end_date)
            except ValueError:
                flash('Invalid end date format. Use YYYY-MM-DD.', 'danger')
        
        if period:
            query = query.filter_by(report_period=period)

        reports = query.order_by(Report.report_date.desc()).paginate(
            page=page,
            per_page=10,
            error_out=False
        )
        
        facilities = Facility.query.all() if user.role == 'admin' else [user.facility]
        
        return render_template(
            'view_reports.html',
            user=user,
            reports=reports,
            facilities=facilities,
            selected_facility_id=facility_id,
            start_date=start_date,
            end_date=end_date,
            period=period
        )
    except Exception as e:
        logger.error(f"Error in view_reports: {str(e)}", exc_info=True)
        flash('An error occurred while loading reports.', 'danger')
        return redirect(url_for('dashboard'))

# ... [Continue with other routes] ...

if __name__ == '__main__':
    with app.app_context():
        initialize_database()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV', 'development') == 'development')
