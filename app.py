from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

def preload_zambian_facilities():
    # Example data (expand this as needed!)
    facilities_data = [
        {
            "country": "Zambia",
            "province": "Luapula",
            "district": "Nchelenge",
            "hub": "Nchelenge Hub",
            "name": "St. Paul’s Mission Hospital"
        },
        {
            "country": "Zambia",
            "province": "Luapula",
            "district": "Kawambwa",
            "hub": "Kawambwa Hub",
            "name": "Kawambwa District Hospital"
        },
        {
            "country": "Zambia",
            "province": "Lusaka",
            "district": "Lusaka",
            "hub": "Lusaka Urban Hub",
            "name": "University Teaching Hospital"
        },
        {
            "country": "Zambia",
            "province": "Copperbelt",
            "district": "Ndola",
            "hub": "Ndola Hub",
            "name": "Ndola Central Hospital"
        },
        {
            "country": "Zambia",
            "province": "Southern",
            "district": "Choma",
            "hub": "Choma Hub",
            "name": "Choma General Hospital"
        },
        # ➕ You can add many more here
    ]

    for f in facilities_data:
        existing = Facility.query.filter_by(name=f["name"]).first()
        if not existing:
            new_facility = Facility(
                name=f["name"]
                # You can extend your Facility model to include country, province, district, hub columns if you want
            )
            db.session.add(new_facility)
    db.session.commit()
    print("✅ Preloaded sample Zambian facilities!")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)

# ---------------------------
# Database models
# ---------------------------

class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False, default="Zambia")
    province = db.Column(db.String(100), nullable=False)
    district = db.Column(db.String(100), nullable=False)
    hub = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='facility', lazy=True)
    with app.app_context():
    db.create_all()
    preload_zambian_facilities()

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)

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

@app.route('/submit_report')
def submit_report():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    return render_template('submit_report.html', user=user)

@app.route('/reports')
def reports():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    return render_template('reports.html', user=user)

@app.route('/help')
def help_page():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    return render_template('help.html', user=user)


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

@app.route('/users')
def users():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role not in ['admin', 'master_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/approve_user/<int:user_id>')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    flash(f'User {user.username} approved!', 'success')
    return redirect(url_for('users'))

@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} rejected and deleted!', 'danger')
    return redirect(url_for('users'))

@app.route('/commodities')
def commodities():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    all_commodities = Commodity.query.all()
    return render_template('commodities.html', user=user, commodities=all_commodities)

@app.route('/facilities', methods=['GET', 'POST'])
def facilities():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role not in ['admin', 'master_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    
    all_facilities = Facility.query.all()

    if request.method == 'POST':
        name = request.form['name']
        if name:
            new_facility = Facility(name=name)
            db.session.add(new_facility)
            db.session.commit()
            flash('Facility added successfully.', 'success')
            return redirect(url_for('facilities'))

    return render_template('facilities.html', user=user, facilities=all_facilities)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# ---------------------------
# Database initialization
# ---------------------------

with app.app_context():
    db.create_all()
import pandas as pd

# Check if facilities already exist (to avoid duplicates)
if Facility.query.count() == 0:
    # Load CSV
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
    print("✅ Facilities loaded successfully!")
else:
    print("✅ Facilities already exist, skipping import.")

    # Create or update master admin user
    admin_user = User.query.filter_by(username='Keegan').first()
    if admin_user:
        admin_user.password = generate_password_hash('44665085')
        admin_user.role = 'master_admin'
        admin_user.approved = True
        db.session.commit()
        print("✅ User 'Keegan' updated as master admin!")
    else:
        new_admin = User(username='Keegan', password=generate_password_hash('44665085'), role='master_admin', approved=True)
        db.session.add(new_admin)
        db.session.commit()
        print("✅ User 'Keegan' created as master admin!")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
