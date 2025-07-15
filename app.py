from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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
    users = db.relationship('User', backref='facility', lazy=True)

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    unit = db.Column(db.String(50))
    expiry_date = db.Column(db.String(20))

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

# ---------------------------
# Routes
# ---------------------------

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

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    return render_template('dashboard.html', user=user)

@app.route('/commodities')
def commodities():
    username = session.get('username')
    if not username:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    commodities = Commodity.query.all()
    user = User.query.filter_by(username=username).first()
    return render_template('commodities.html', commodities=commodities, user=user)

@app.route('/submit_report', methods=['GET', 'POST'])
def submit_report():
    username = session.get('username')
    if not username:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    commodities = Commodity.query.all()
    if request.method == 'POST':
        commodity_id = request.form['commodity_id']
        quantity_used = int(request.form['quantity_used'])
        quantity_received = int(request.form['quantity_received'])
        balance = int(request.form['balance'])
        expiry_date = request.form['expiry_date']

        report = Report(
            user_id=user.id,
            facility_id=user.facility_id,
            commodity_id=commodity_id,
            quantity_used=quantity_used,
            quantity_received=quantity_received,
            balance=balance,
            expiry_date=expiry_date
        )
        db.session.add(report)
        db.session.commit()
        flash('Report submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('submit_report.html', commodities=commodities, user=user)

@app.route('/reports')
def reports():
    username = session.get('username')
    if not username:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role == 'master_admin':
        all_reports = Report.query.all()
    else:
        all_reports = Report.query.filter_by(facility_id=user.facility_id).all()
    return render_template('reports.html', reports=all_reports, user=user)

@app.route('/users')
def users():
    username = session.get('username')
    if not username:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role != 'master_admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    all_users = User.query.all()
    return render_template('users.html', users=all_users, user=user)

@app.route('/help')
def help_page():
    return render_template('help.html')

# ---------------------------
# Database initialization
# ---------------------------

with app.app_context():
    db.create_all()

    # Create or update master admin user
    master_admin = User.query.filter_by(username='Keegan').first()
    if master_admin:
        master_admin.password = generate_password_hash('44665085')
        master_admin.role = 'master_admin'
        master_admin.approved = True
        db.session.commit()
        print("✅ Master admin 'Keegan' updated!")
    else:
        new_admin = User(username='Keegan', password=generate_password_hash('44665085'), role='master_admin', approved=True)
        db.session.add(new_admin)
        db.session.commit()
        print("✅ Master admin 'Keegan' created!")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
