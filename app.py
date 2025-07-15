from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import io
import csv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)

# ---------------------------
# Database models
# ---------------------------

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    unit = db.Column(db.String(50))
    balance_opening = db.Column(db.Integer, default=0)
    received = db.Column(db.Integer, default=0)
    given_to_others = db.Column(db.Integer, default=0)
    balance = db.Column(db.Integer, default=0)
    expiry_date = db.Column(db.String(20))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # master_admin, admin, user
    approved = db.Column(db.Boolean, default=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    commodity_id = db.Column(db.Integer, db.ForeignKey('commodity.id'), nullable=False)
    period = db.Column(db.String(20), nullable=False)  # daily, weekly, etc.
    quantity_used = db.Column(db.Integer, nullable=False)
    quantity_received = db.Column(db.Integer, nullable=False)
    balance = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='submitted')  # submitted, acknowledged, flagged
    feedback = db.Column(db.String(300), default='')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------------
# Helper functions
# ---------------------------

def current_user():
    username = session.get('username')
    if username:
        return User.query.filter_by(username=username).first()
    return None

def is_master_admin():
    user = current_user()
    return user and user.role == 'master_admin'

def is_admin():
    user = current_user()
    return user and (user.role == 'admin' or user.role == 'master_admin')

# ---------------------------
# Auth routes
# ---------------------------

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, approved=False)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful. Please wait for approval.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/', methods=['GET', 'POST'])
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
                flash('Account not yet approved.', 'warning')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'success')
    return redirect(url_for('login'))
@app.route('/dashboard')
def dashboard():
    username = session.get('username', 'Guest')
    user = User.query.filter_by(username=username).first()
    return render_template('dashboard.html', user=user)

# ---------------------------
# Dashboard
# ---------------------------

@app.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user)

# ---------------------------
# Commodities
# ---------------------------

@app.route('/commodities', methods=['GET', 'POST'])
def commodities():
    if not is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.form
        new_commodity = Commodity(
            name=data['name'],
            description=data['description'],
            unit=data['unit'],
            balance_opening=int(data['balance_opening']),
            received=int(data['received']),
            given_to_others=int(data['given_to_others']),
            balance=int(data['balance']),
            expiry_date=data['expiry_date']
        )
        db.session.add(new_commodity)
        db.session.commit()
        flash('Commodity added.', 'success')
        return redirect(url_for('commodities'))
    commodities = Commodity.query.all()
    return render_template('commodities.html', commodities=commodities)

# ---------------------------
# Reports
# ---------------------------

@app.route('/submit_report', methods=['GET', 'POST'])
def submit_report():
    user = current_user()
    if not user:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))

    facilities = Facility.query.all()
    commodities = Commodity.query.all()

    if request.method == 'POST':
        data = request.form
        new_report = Report(
            user_id=user.id,
            facility_id=data['facility_id'],
            commodity_id=data['commodity_id'],
            period=data['period'],
            quantity_used=int(data['quantity_used']),
            quantity_received=int(data['quantity_received']),
            balance=int(data['balance']),
            expiry_date=data['expiry_date'],
            status='submitted'
        )
        db.session.add(new_report)
        db.session.commit()
        flash('Report submitted.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('submit_report.html', facilities=facilities, commodities=commodities)

@app.route('/reports')
def reports():
    user = current_user()
    if not user:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    if is_admin():
        reports = Report.query.all()
    else:
        reports = Report.query.filter_by(facility_id=user.facility_id).all()
    return render_template('reports.html', reports=reports)

@app.route('/export_reports')
def export_reports():
    reports = Report.query.all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'User', 'Facility', 'Commodity', 'Period', 'Used', 'Received', 'Balance', 'Expiry', 'Status', 'Feedback', 'Date'])
    for r in reports:
        cw.writerow([r.id, r.user_id, r.facility_id, r.commodity_id, r.period, r.quantity_used, r.quantity_received, r.balance, r.expiry_date, r.status, r.feedback, r.date_submitted])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', download_name='reports.csv', as_attachment=True)

# ---------------------------
# Users
# ---------------------------

@app.route('/users')
def users():
    if not is_master_admin():
        flash('Access denied. Master admin only.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('users.html', users=users)

# ---------------------------
# Help page
# ---------------------------

@app.route('/help')
def help_page():
    return render_template('help.html')

# ---------------------------
# DB Init
# ---------------------------

with app.app_context():
    db.create_all()
    user = User.query.filter_by(username='Keegan').first()
    if not user:
        new_user = User(username='Keegan', password=generate_password_hash('44665085'), role='master_admin', approved=True)
        db.session.add(new_user)
        db.session.commit()
        print("✅ User 'Keegan' created as master admin!")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
