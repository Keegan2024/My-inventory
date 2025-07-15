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

# Initialize database with Luapula Province facilities
def initialize_database():
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            # First create a dummy facility for admin
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
                'Mansa': [
                    'Mansa General Hospital', 'St. Theresa Mission Hospital', 
                    'Mansa Urban Health Centre', 'Kashikishi Rural Health Centre'
                ],
                'Samfya': [
                    'Samfya District Hospital', 'Mambilima Mission Hospital',
                    'Samfya Urban Health Centre'
                ],
                'Kawambwa': [
                    'Kawambwa District Hospital', 'St. Paul\'s Mission Hospital',
                    'Kawambwa Urban Health Centre'
                ],
                'Nchelenge': [
                    'Nchelenge District Hospital', 'Chiengi Rural Hospital',
                    'Nchelenge Urban Health Centre'
                ],
                'Mwense': [
                    'Mwense District Hospital', 'Luwingu Rural Health Centre'
                ],
                'Chembe': [
                    'Chembe District Hospital', 'Mbereshi Mission Hospital'
                ],
                'Chienge': [
                    'Chienge District Hospital', 'Kaputa District Hospital'
                ]
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
        
        db.session.commit()

# Helper functions
def get_previous_report(facility_id, commodity_id):
    # Get the most recent report for this facility and commodity
    prev_report = ReportItem.query.join(Report).filter(
        Report.facility_id == facility_id,
        ReportItem.commodity_id == commodity_id
    ).order_by(Report.report_date.desc()).first()
    
    return prev_report

def validate_report_items(items, facility_id):
    errors = []
    for item in items:
        commodity_id = int(item['commodity_id'])
        opening_balance = int(item['opening_balance'])
        received = int(item['received'])
        used = int(item['used'])
        closing_balance = int(item['closing_balance'])
        
        # Check if closing balance matches calculation
        calculated_closing = opening_balance + received - used
        if closing_balance != calculated_closing:
            commodity = Commodity.query.get(commodity_id)
            errors.append(f"Closing balance for {commodity.name} doesn't match calculation (should be {calculated_closing})")
        
        # Check if opening balance matches previous closing balance
        prev_report = get_previous_report(facility_id, commodity_id)
        if prev_report and opening_balance != prev_report.closing_balance:
            commodity = Commodity.query.get(commodity_id)
            errors.append(f"Opening balance for {commodity.name} doesn't match previous closing balance ({prev_report.closing_balance})")
    
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
            report_date = datetime.strptime(request.form['report_date'], '%Y-%m-%d').date()
            report_period = request.form['report_period']
            
            # Prepare report items
            items = []
            for commodity in commodities:
                commodity_id = str(commodity.id)
                items.append({
                    'commodity_id': commodity_id,
                    'opening_balance': request.form.get(f'opening_balance_{commodity_id}', '0'),
                    'received': request.form.get(f'received_{commodity_id}', '0'),
                    'used': request.form.get(f'used_{commodity_id}', '0'),
                    'closing_balance': request.form.get(f'closing_balance_{commodity_id}', '0'),
                    'exp_date': request.form.get(f'exp_date_{commodity_id}', ''),
                    'remarks': request.form.get(f'remarks_{commodity_id}', '')
                })
            
            # Validate report items
            validation_errors = validate_report_items(items, user.facility_id)
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'danger')
                return render_template('submit_report.html', commodities=commodities, user=user, form_data=request.form)
            
            # Create report
            report = Report(
                facility_id=user.facility_id,
                user_id=user.id,
                report_date=report_date,
                report_period=report_period
            )
            db.session.add(report)
            db.session.flush()  # To get the report ID
            
            # Add report items
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
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting report: {str(e)}', 'danger')
    
    # For GET request, pre-fill opening balances from previous report
    form_data = {}
    for commodity in commodities:
        prev_report = get_previous_report(user.facility_id, commodity.id)
        if prev_report:
            form_data[f'opening_balance_{commodity.id}'] = prev_report.closing_balance
            # Auto-calculate closing balance in JavaScript
    
    return render_template('submit_report.html', commodities=commodities, user=user, form_data=form_data)

@app.route('/view-reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get filter parameters
    period = request.args.get('period', 'weekly')
    facility_id = request.args.get('facility_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Base query
    if user.role == 'admin':
        query = Report.query
        if facility_id:
            query = query.filter_by(facility_id=facility_id)
    else:
        query = Report.query.filter_by(facility_id=user.facility_id)
    
    # Apply date filters
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        query = query.filter(Report.report_date >= start_date)
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        query = query.filter(Report.report_date <= end_date)
    
    # Apply period filter
    if period in ['weekly', 'monthly', 'quarterly']:
        query = query.filter_by(report_period=period)
    
    reports = query.order_by(Report.report_date.desc()).all()
    
    # Group reports by period for display
    grouped_reports = {}
    for report in reports:
        if report.report_period == 'weekly':
            key = f"Week {report.report_date.strftime('%U, %Y')}"
        elif report.report_period == 'monthly':
            key = report.report_date.strftime('%B %Y')
        else:  # quarterly
            quarter = (report.report_date.month - 1) // 3 + 1
            key = f"Q{quarter} {report.report_date.year}"
        
        if key not in grouped_reports:
            grouped_reports[key] = []
        grouped_reports[key].append(report)
    
    facilities = Facility.query.order_by(Facility.name).all() if user.role == 'admin' else None
    
    return render_template('view_reports.html', 
                         grouped_reports=grouped_reports,
                         user=user,
                         facilities=facilities,
                         period=period,
                         start_date=start_date.strftime('%Y-%m-%d') if start_date else '',
                         end_date=end_date.strftime('%Y-%m-%d') if end_date else '',
                         selected_facility=int(facility_id) if facility_id else None)

@app.route('/export-report/<int:report_id>/<format>')
def export_report(report_id, format):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    report = Report.query.get_or_404(report_id)
    
    # Check permissions
    if user.role != 'admin' and report.facility_id != user.facility_id:
        flash('You do not have permission to view this report', 'danger')
        return redirect(url_for('view_reports'))
    
    # Get report items with commodity names
    items = db.session.query(
        ReportItem, Commodity.name
    ).join(
        Commodity, ReportItem.commodity_id == Commodity.id
    ).filter(
        ReportItem.report_id == report_id
    ).order_by(
        Commodity.name
    ).all()
    
    if format == 'excel':
        # Create Excel export
        output = io.BytesIO()
        
        # Create a Pandas DataFrame
        data = []
        for item, commodity_name in items:
            data.append([
                commodity_name,
                item.opening_balance,
                item.received,
                item.used,
                item.closing_balance,
                item.exp_date if item.exp_date else '',
                item.remarks if item.remarks else ''
            ])
        
        df = pd.DataFrame(data, columns=[
            'Commodity', 'Opening Balance', 'Received', 'Used', 
            'Closing Balance', 'Expiry Date', 'Remarks'
        ])
        
        # Create Excel writer
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Report', index=False)
            
            # Get workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Report']
            
            # Add header
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'fg_color': '#D7E4BC',
                'border': 1
            })
            
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Add report info
            info = [
                ['Facility:', report.facility.name],
                ['Report Date:', report.report_date.strftime('%Y-%m-%d')],
                ['Report Period:', report.report_period.capitalize()],
                ['Submitted At:', report.submitted_at.strftime('%Y-%m-%d %H:%M')],
                ['Submitted By:', report.user.username]
            ]
            
            info_df = pd.DataFrame(info)
            info_df.to_excel(writer, sheet_name='Report', 
                           startrow=len(df)+3, index=False, header=False)
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        filename = f"{report.facility.name.replace(' ', '_')}_{report.report_date}_{report.report_period}.xlsx"
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
    
    elif format == 'pdf':
        # Create PDF export
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        styles = getSampleStyleSheet()
        
        # Add title
        title = Paragraph(f"Supply Chain Report - {report.report_period.capitalize()}", styles['Title'])
        elements.append(title)
        
        # Add report info
        info = [
            f"Facility: {report.facility.name}",
            f"Report Date: {report.report_date.strftime('%Y-%m-%d')}",
            f"Report Period: {report.report_period.capitalize()}",
            f"Submitted At: {report.submitted_at.strftime('%Y-%m-%d %H:%M')}",
            f"Submitted By: {report.user.username}"
        ]
        
        for line in info:
            elements.append(Paragraph(line, styles['Normal']))
        
        elements.append(Spacer(1, 12))
        
        # Add commodity table
        table_data = [['Commodity', 'Opening', 'Received', 'Used', 'Closing', 'Expiry', 'Remarks']]
        
        for item, commodity_name in items:
            table_data.append([
                commodity_name,
                str(item.opening_balance),
                str(item.received),
                str(item.used),
                str(item.closing_balance),
                item.exp_date if item.exp_date else '',
                item.remarks if item.remarks else ''
            ])
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D7E4BC')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        filename = f"{report.facility.name.replace(' ', '_')}_{report.report_date}_{report.report_period}.pdf"
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
    
    flash('Invalid export format', 'danger')
    return redirect(url_for('view_reports'))

@app.route('/manage-commodities', methods=['GET', 'POST'])
def manage_commodities():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Add new commodity
        if 'add_commodity' in request.form:
            name = request.form['name'].strip()
            description = request.form.get('description', '').strip()
            
            if not name:
                flash('Commodity name is required', 'danger')
            elif Commodity.query.filter_by(name=name).first():
                flash('Commodity with this name already exists', 'danger')
            else:
                commodity = Commodity(name=name, description=description)
                db.session.add(commodity)
                db.session.commit()
                flash('Commodity added successfully', 'success')
        
        # Toggle commodity status
        elif 'toggle_commodity' in request.form:
            commodity_id = int(request.form['commodity_id'])
            commodity = Commodity.query.get(commodity_id)
            if commodity:
                commodity.active = not commodity.active
                db.session.commit()
                flash('Commodity status updated', 'success')
            else:
                flash('Commodity not found', 'danger')
        
        return redirect(url_for('manage_commodities'))
    
    commodities = Commodity.query.order_by(Commodity.name).all()
    return render_template('manage_commodities.html', commodities=commodities)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    initialize_database()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
