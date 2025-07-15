import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///supply_chain.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facility = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    approved = db.Column(db.Boolean, default=False)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))

class WeeklyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    facility = db.Column(db.String(100), nullable=False)
    week_number = db.Column(db.Integer, nullable=False)
    report_date = db.Column(db.Date, nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False)
    opening_balance = db.Column(db.Integer, default=0)
    total_received = db.Column(db.Integer, default=0)
    total_dispensed = db.Column(db.Integer, default=0)
    stock_on_hand = db.Column(db.Integer, default=0)
    exp_date = db.Column(db.String(20))
    remarks = db.Column(db.Text)
    clients_seen = db.Column(db.Integer, default=0)
    screened = db.Column(db.Integer, default=0)
    eligible_for_heps = db.Column(db.Integer, default=0)
    heps_given = db.Column(db.Integer, default=0)
    total_refill = db.Column(db.Integer, default=0)
    heps_stock = db.Column(db.Integer, default=0)
    tpt_initiations = db.Column(db.Integer, default=0)
    vl_collected = db.Column(db.Integer, default=0)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123')),
            facility='Admin',
            role='admin',
            approved=True
        )
        db.session.add(admin)
    
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
        
        db.session.commit()

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) and user.approved:
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or account not approved', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    reports = WeeklyReport.query.filter_by(facility=user.facility).order_by(WeeklyReport.week_number.desc()).limit(5).all()
    return render_template('dashboard.html', user=user, reports=reports)

@app.route('/submit-report', methods=['GET', 'POST'])
def submit_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    commodities = Commodity.query.all()
    
    if request.method == 'POST':
        try:
            week_number = int(request.form['week_number'])
            report_date = datetime.strptime(request.form['report_date'], '%Y-%m-%d').date()
            
            # Save each commodity entry
            for commodity in commodities:
                commodity_id = commodity.id
                report = WeeklyReport(
                    user_id=user.id,
                    facility=user.facility,
                    week_number=week_number,
                    report_date=report_date,
                    commodity_id=commodity_id,
                    opening_balance=int(request.form.get(f'opening_balance_{commodity_id}', 0)),
                    total_received=int(request.form.get(f'total_received_{commodity_id}', 0)),
                    total_dispensed=int(request.form.get(f'total_dispensed_{commodity_id}', 0)),
                    stock_on_hand=int(request.form.get(f'stock_on_hand_{commodity_id}', 0)),
                    exp_date=request.form.get(f'exp_date_{commodity_id}', ''),
                    remarks=request.form.get(f'remarks_{commodity_id}', ''),
                    clients_seen=int(request.form.get('clients_seen', 0)),
                    screened=int(request.form.get('screened', 0)),
                    eligible_for_heps=int(request.form.get('eligible_for_heps', 0)),
                    heps_given=int(request.form.get('heps_given', 0)),
                    total_refill=int(request.form.get('total_refill', 0)),
                    heps_stock=int(request.form.get('heps_stock', 0)),
                    tpt_initiations=int(request.form.get('tpt_initiations', 0)),
                    vl_collected=int(request.form.get('vl_collected', 0))
                )
                db.session.add(report)
            
            db.session.commit()
            flash('Weekly report submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting report: {str(e)}', 'danger')
    
    return render_template('submit_report.html', commodities=commodities)

@app.route('/view-reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    reports = WeeklyReport.query.filter_by(facility=user.facility).order_by(WeeklyReport.week_number.desc()).all()
    
    # Group reports by week
    weeks = {}
    for report in reports:
        if report.week_number not in weeks:
            weeks[report.week_number] = {
                'date': report.report_date,
                'reports': [],
                'summary': {
                    'clients_seen': report.clients_seen,
                    'screened': report.screened,
                    'eligible_for_heps': report.eligible_for_heps,
                    'heps_given': report.heps_given,
                    'total_refill': report.total_refill,
                    'heps_stock': report.heps_stock,
                    'tpt_initiations': report.tpt_initiations,
                    'vl_collected': report.vl_collected
                }
            }
        weeks[report.week_number]['reports'].append(report)
    
    return render_template('view_reports.html', weeks=weeks)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
