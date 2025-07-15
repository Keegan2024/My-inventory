from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)

from flask import make_response
import pandas as pd
import io

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

    # Build data list
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
    
    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Create a BytesIO object
    output = io.BytesIO()

    # Write Excel using xlsxwriter
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Reports')

    # Go back to start of the stream
    output.seek(0)

    # Prepare response
    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=reports.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response
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

class Commodity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(100), nullable=True)  # Added category column for grouping

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

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    facilities = Facility.query.all()
    return render_template('dashboard.html', user=user, facilities=facilities)
# ---------------------------
# Reports page (view submitted reports)
# ---------------------------

@app.route('/reports')
def reports():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()

    # Base query
    user_reports = Report.query

    # Filters
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

# ---------------------------
# Submit report page (form and save logic)
# ---------------------------

@app.route('/submit_report', methods=['GET', 'POST'])
def submit_report():
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()

    # Get all facilities and commodities to fill dropdowns
    facilities = Facility.query.all()
    commodities = Commodity.query.all()

    if request.method == 'POST':
        facility_id = request.form.get('facility_id')
        commodity_id = request.form.get('commodity_id')
        quantity_used = int(request.form.get('quantity_used', 0))
        quantity_received = int(request.form.get('quantity_received', 0))
        balance = int(request.form.get('balance', 0))
        expiry_date = request.form.get('expiry_date')

        # Create and save the report
        report = Report(
            user_id=user.id,
            facility_id=facility_id,
            commodity_id=commodity_id,
            quantity_used=quantity_used,
            quantity_received=quantity_received,
            balance=balance,
            expiry_date=expiry_date
        )
        db.session.add(report)
        db.session.commit()
        flash('Report submitted successfully.', 'success')
        return redirect(url_for('reports'))

    return render_template('submit_report.html', user=user, facilities=facilities, commodities=commodities)

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
        province = request.form.get('province')
        district = request.form.get('district')
        hub = request.form.get('hub')
        if name and province and district:
            new_facility = Facility(
                name=name,
                province=province,
                district=district,
                hub=hub,
                country="Zambia"
            )
            db.session.add(new_facility)
            db.session.commit()
            flash('Facility added successfully.', 'success')
            return redirect(url_for('facilities'))

    return render_template('facilities.html', user=user, facilities=all_facilities)

@app.route('/facilities/edit/<int:facility_id>', methods=['GET', 'POST'])
def edit_facility(facility_id):
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role not in ['admin', 'master_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    facility = Facility.query.get_or_404(facility_id)

    if request.method == 'POST':
        facility.name = request.form['name']
        facility.province = request.form['province']
        facility.district = request.form['district']
        facility.hub = request.form.get('hub') or None
        db.session.commit()
        flash('Facility updated successfully.', 'success')
        return redirect(url_for('facilities'))

    return render_template('edit_facility.html', user=user, facility=facility)

@app.route('/facilities/delete/<int:facility_id>', methods=['POST'])
def delete_facility(facility_id):
    username = session.get('username')
    if not username:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if user.role not in ['admin', 'master_admin']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    facility = Facility.query.get_or_404(facility_id)
    db.session.delete(facility)
    db.session.commit()
    flash('Facility deleted successfully.', 'success')
    return redirect(url_for('facilities'))

@app.route('/help', endpoint='help_page')
def help_page():
    return render_template('help.html')

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

    # Load facilities
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
        print("✅ Facilities loaded successfully!")
    else:
        print("✅ Facilities already exist, skipping import.")

    # Load commodities
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
        print("✅ Commodities loaded successfully!")
    else:
        print("✅ Commodities already exist, skipping import.")

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
        print("Registered routes:")
for rule in app.url_map.iter_rules():
    print(rule)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
