from flask import Flask, render_template, redirect, url_for, request, flash, session, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import io
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///inventory.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False, default="Zambia")
    province = db.Column(db.String(100), nullable=False)
    district = db.Column(db.String(100), nullable=False)
    hub = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='facility', lazy=True)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(100), nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    approved = db.Column(db.Boolean, default=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False)
    quantity_used = db.Column(db.Integer, nullable=False)
    quantity_received = db.Column(db.Integer, nullable=False)
    balance = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.String(20), nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    facility = db.relationship('Facility')
    commodity = db.relationship('Commodity')

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, approved=False)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful. Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.approved:
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Account not yet approved by admin.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    facilities = Facility.query.all()
    return render_template('dashboard.html', user=user, facilities=facilities)

@app.route('/reports')
def reports():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    user_reports = Report.query
    facility_name = request.args.get('facility')
    commodity_name = request.args.get('commodity')
    date_str = request.args.get('date')
    if facility_name:
        user_reports = user_reports.join(Facility).filter(Facility.name.ilike(f"%{facility_name}%"))
    if commodity_name:
        user_reports = user_reports.join(Commodity).filter(Commodity.name.ilike(f"%{commodity_name}%"))
    if date_str:
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            user_reports = user_reports.filter(db.func.date(Report.date_submitted) == date_obj.date())
        except:
            flash('Invalid date format', 'danger')
    user_reports = user_reports.all()
    return render_template('reports.html', user=user, reports=user_reports)

@app.route('/submit_report', methods=['GET', 'POST'])
def submit_report():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    facility = Facility.query.first()
    commodities = Commodity.query.all()
    for commodity in commodities:
        last_report = Report.query.filter_by(facility_id=facility.id, commodity_id=commodity.id).order_by(Report.date_submitted.desc()).first()
        commodity.opening_balance = last_report.balance if last_report else 0
    if request.method == 'POST':
        for commodity in commodities:
            opening_balance = int(request.form.get(f'opening_balance_{commodity.id}', 0))
            quantity_received = int(request.form.get(f'quantity_received_{commodity.id}', 0))
            quantity_used = int(request.form.get(f'quantity_used_{commodity.id}', 0))
            balance = opening_balance + quantity_received - quantity_used
            expiry_date = request.form.get(f'expiry_date_{commodity.id}', '')
            report = Report(
                user_id=user.id,
                facility_id=facility.id,
                commodity_id=commodity.id,
                quantity_received=quantity_received,
                quantity_used=quantity_used,
                balance=balance,
                expiry_date=expiry_date
            )
            db.session.add(report)
        db.session.commit()
        flash('Report submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('submit_report.html', user=user, facility=facility, commodities=commodities)

@app.route('/download_reports')
def download_reports():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    reports = Report.query.all()
    if not reports:
        flash('No reports to download.', 'warning')
        return redirect(url_for('reports'))
    data = []
    for r in reports:
        data.append({
            'Facility': r.facility.name if r.facility else '',
            'Commodity': r.commodity.name if r.commodity else '',
            'Quantity Used': r.quantity_used,
            'Quantity Received': r.quantity_received,
            'Balance': r.balance,
            'Expiry Date': r.expiry_date,
            'Submitted On': r.date_submitted.strftime('%Y-%m-%d'),
        })
    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Reports')
    output.seek(0)
    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=reports.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return response

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()
    if Facility.query.count() == 0:
        df = pd.read_csv('zambia_facilities.csv')
        for _, row in df.iterrows():
            f = Facility(
                country=row['Country'],
                province=row['Province'],
                hub=row['Hub'] if not pd.isna(row['Hub']) else None,
                district=row['District'],
                name=row['FacilityName']
            )
            db.session.add(f)
        db.session.commit()
    if Commodity.query.count() == 0:
        df_c = pd.read_csv('commodities.csv')
        for _, row in df_c.iterrows():
            c = Commodity(
                name=row['Name'],
                description=row['Description'],
                category=row['Category']
            )
            db.session.add(c)
        db.session.commit()
    admin_user = User.query.filter_by(username='Keegan').first()
    if admin_user:
        admin_user.password = generate_password_hash('44665085')
        admin_user.role = 'master_admin'
        admin_user.approved = True
        db.session.commit()
    else:
        new_admin = User(username='Keegan', password=generate_password_hash('44665085'), role='master_admin', approved=True)
        db.session.add(new_admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
