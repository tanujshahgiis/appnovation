# File Begins
# Load the necessary libraries
from flask import Blueprint, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import BannedIP, db, User, Report
from datetime import datetime
from flask import flash

# Setup the blueprints
auth_bp = Blueprint('auth', __name__)
teacher_dashboard_bp = Blueprint('teacher_dashboard', __name__)
volunteer_dashboard_bp = Blueprint('volunteer_dashboard', __name__)
report_bp = Blueprint('report', __name__)
home_bp = Blueprint('home', __name__)
admin_dashboard_bp = Blueprint('admin_dashboard', __name__) 
guide_bp = Blueprint('guide', __name__) 

# Routes and backend code

# @home_bp
# Default web page that will be loaded
@home_bp.route('/')
def home():
    return render_template('home.html') # Loads the home.html page from the /templates folder




# @auth_bp 
# Route and backend code for signup page
@auth_bp.route('/signup', methods=['GET', 'POST']) # Request methods allowed by the route. POST request will be used to create a new account
def signup():
    message = None
    if request.method == 'POST': # A POST request is made once the submit button is clicked. 
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user: # Checks if account already exists in the database
            message = "This username already exists. Please choose a different one."
        else: # Uses the data recieved from the POST request and stores it in the database
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                username=username,
                password=hashed_password,
                account_type='Volunteer',
                name=request.form['name'],
                class_=request.form['class'],  
                section=request.form['section'],
                age=int(request.form['age']),
                roll_no=request.form['roll_no']
            )
            db.session.add(new_user)
            db.session.commit() 
            flash("You have successfully signed up! Login to access your account!") # Shows a success message
            return redirect(url_for('auth.login')) # Redirects to the login page for the user to input the details of their newly created account to log in
    return render_template('signup.html', message=message)

# Route and backend code for login page
@auth_bp.route('/login', methods=['GET', 'POST']) 
def login(): 
    message = None
    if request.method == 'POST': # IF a POST request is done by the client m
        username = request.form['username'] # Gets and stores the credentials on the server
        password = request.form['password']
        user = User.query.filter_by(username=username).first() # Finds the first occurence of the username in the database
        if user and check_password_hash(user.password, password): # If they match
            user.last_login_ip = request.remote_addr # Get the IP address to the client 
            db.session.commit() # Store it in the database
            session['username'] = username # Store it in a session
            session['account_type'] = user.account_type 
            if user.account_type == 'Teacher': # Redirect to the respective dashboard
                return redirect(url_for('teacher_dashboard.dashboard'))
            elif user.account_type == 'Admin':
                return redirect(url_for('admin_dashboard.admin_dashboard'))
            else:
                return redirect(url_for('volunteer_dashboard.dashboard'))
        else:
            message = "Invalid Credentials. Please try again." # Set a  message if wrong username or password
    return render_template('login.html', message=message) # Pass the message back to the client along with the login page. This would also clear the inputted fields.

# Route and backend code for logout page
@auth_bp.route('/logout') # Upon a logout request done by accessing the /logout page
def logout():
    session.pop('username', None) # Delete the username and account_type from the session data
    session.pop('account_type', None)
    return redirect(url_for('home.home'))




# @guide_bp
# Route and backend code for the guide page
@guide_bp.route('/guide') 
def guide():
    return render_template('guide.html') # Load guide.html




# @volunteer_dashboard_bp
# Route and backend code for volunteer dashboard page
@volunteer_dashboard_bp.route('/volunteer_dashboard')
def dashboard():
    if 'username' not in session: # If someone tries to access without having logged in
        return redirect(url_for('auth.login')) # Redirect to login page
    user = User.query.filter_by(username=session['username']).first() # Check with the database 
    if not user or user.account_type != 'Volunteer': # If the account accessing is not a Volunteer
        return redirect(url_for('auth.login')) # Redirect back to the login page
    reports = Report.query.filter_by(assigned_volunteer=user.id).all() # Get the reports assigned to the user 
    return render_template('volunteer_dashboard.html', username=session['username'], account_type=user.account_type, reports=reports) # Send the relevant data back to the client to display on the HTML page





# @teacher_dashboard_bp
# Route and backend code for teacher dashboard page
@teacher_dashboard_bp.route('/teacher_dashboard')
def dashboard():
    if 'username' not in session:  # If someone tries to access without having logged in
        return redirect(url_for('auth.login')) # Redirect to login page
    user = User.query.filter_by(username=session['username']).first() # Check with the database
    if not user or user.account_type != 'Teacher': # If the account accessing is not a Teacher
        return redirect(url_for('auth.login')) # Redirect to login page
    unassigned_reports = Report.query.filter_by(assigned_volunteer=None, escalated_by=None).all() # Get the relevant data
    assigned_reports = Report.query.filter(Report.assigned_volunteer != None, Report.escalated_by == None).all()
    escalated_reports = Report.query.filter(Report.escalated_by != None).all()
    return render_template('teacher_dashboard.html', username=session['username'], account_type=user.account_type, unassigned_reports=unassigned_reports, assigned_reports=assigned_reports, escalated_reports=escalated_reports) # Send the relevant data to the client





# @report_bp
# Route and backend code for report page
@report_bp.route('/report', methods=['GET', 'POST']) #
def report():
    if request.method == 'POST': # Upon a POST request done by the HTML form, store the data in the server 
        offender_name = request.form['offender_name']
        offender_class = request.form['offender_class']
        section = request.form['section']
        details = request.form['details']
        report_type = request.form['report_type']
        reporter_ip = request.remote_addr
        reporter_name = request.form['reporter_name']
        incident_date = datetime.strptime(request.form['incident_date'], "%Y-%m-%d")
        people_involved = request.form['people_involved']
        location = request.form.getlist('location')
        report = Report(
            offender_name=offender_name, offender_class=offender_class, section=section, 
            details=details, report_type=report_type, reporter_ip=reporter_ip, 
            reporter_name=reporter_name, incident_date=incident_date, people_involved=people_involved, 
            location=','.join(location)
        )
        db.session.add(report) # Add the report to the database
        db.session.commit() # Save changes
        flash("Report successfully submitted!") # Send a success message
        return redirect(url_for('home.home')) # Redirect back to the home page
    return render_template('report.html') 

# Route and backend code for assigning a report to a volunteer
@report_bp.route('/assign/<int:report_id>', methods=['GET', 'POST']) 
def assign(report_id):
    if 'username' in session and session['account_type'] == 'Teacher': # Only teachers can assign
        report = Report.query.get(report_id) # Get relevant data
        volunteers = User.query.filter_by(account_type='Volunteer').all() 
        if request.method == 'POST': # Check for request made by the HTML form using POST
            volunteer_id = request.form['volunteer_id']
            report.assigned_volunteer = volunteer_id
            db.session.commit() # Save the assigned volunteer
            return redirect(url_for('teacher_dashboard.dashboard')) # Redirect back to the dashboard
        return render_template('assign.html', report=report, volunteers=volunteers) # Send relevant data
    return redirect(url_for('auth.login'))

# Route and backend code for escalating a report from the dashboard
@report_bp.route('/escalate_report/<int:report_id>')
def escalate_report(report_id):
    if 'username' in session:
        report = Report.query.get(report_id)
        report.escalated_by = User.query.filter_by(username=session['username']).first().id
        report.assigned_volunteer = None
        db.session.commit()
        return redirect(url_for('volunteer_dashboard.dashboard'))
    return redirect(url_for('auth.login'))

# Route and backend code for resolving a report from the dashboard
@report_bp.route('/resolve_report/<int:report_id>')
def resolve_report(report_id):
    if 'username' in session:
        report = Report.query.get(report_id)
        if report:
            print(f"Resolving Report ID: {report_id}")
            db.session.delete(report) # Delete the resolved report from the session
            db.session.commit()
            user = User.query.filter_by(username=session['username']).first()
            if user.account_type == 'Admin': # Redirect to the respective dashboard
                return redirect(url_for('admin_dashboard.admin_dashboard'))
            elif user.account_type == 'Teacher':
                return redirect(url_for('teacher_dashboard.dashboard'))
            else:
                return redirect(url_for('volunteer_dashboard.dashboard'))
    return redirect(url_for('auth.login'))




# @admin_dashboard_bp
# Route and backend code for admin dashboard page
@admin_dashboard_bp.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.account_type != 'Admin':
        return redirect(url_for('auth.login'))
    active_reports = Report.query.filter(Report.assigned_volunteer != None, Report.escalated_by == None).all()
    past_reports = Report.query.filter(Report.assigned_volunteer == None, Report.escalated_by == None).all()
    escalated_reports = Report.query.filter(Report.escalated_by != None).all()
    users = User.query.all()
    banned_ips = BannedIP.query.all() 
    return render_template('admin_dashboard.html', username=session['username'], account_type=user.account_type, active_reports=active_reports, past_reports=past_reports, escalated_reports=escalated_reports, users=users, banned_ips=banned_ips)

# Route and backend code for banning an ip address from the admin dashboard
@admin_dashboard_bp.route('/ban_ip', methods=['POST'])
def ban_ip():
    if 'username' not in session or session['account_type'] != 'Admin':
        return redirect(url_for('auth.login'))
    ip_address = request.form['ip_address']
    reason = request.form['reason']
    duration = request.form['duration']
    banned_ip = BannedIP(ip_address=ip_address, reason=reason, duration=duration)
    banned_ip.set_unban_date()
    db.session.add(banned_ip)
    db.session.commit()
    return redirect(url_for('admin_dashboard.admin_dashboard'))

# Route and backend code for unbanning an ip address from the admin dashboard
@admin_dashboard_bp.route('/unban_ip', methods=['POST'])
def unban_ip():
    if 'username' not in session or session['account_type'] != 'Admin':
        return redirect(url_for('auth.login'))
    ip_address = request.form['unban_ip_address']
    banned_ip = BannedIP.query.filter_by(ip_address=ip_address).first()
    if banned_ip:
        db.session.delete(banned_ip)
        db.session.commit()
    return redirect(url_for('admin_dashboard.admin_dashboard'))

# Route and backend code for creating an account from the admin dashboard
@admin_dashboard_bp.route('/create_account', methods=['POST'])
def create_account():
    if 'username' not in session or session['account_type'] != 'Admin':
        return redirect(url_for('auth.login'))

    username = request.form['username']
    password = request.form['password']
    name = request.form['name']
    class_ = request.form['class']
    section = request.form['section']
    age = int(request.form['age'])
    roll_no = request.form['roll_no']
    account_type = request.form['account_type']

    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        message = "This username already exists. Please choose a different one."
        return render_template('admin_dashboard.html', message=message)

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(
        username=username,
        password=hashed_password,
        account_type=account_type,
        name=name,
        class_=class_,
        section=section,
        age=age,
        roll_no=roll_no
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('admin_dashboard.admin_dashboard'))


# Route and backend code for deleting an account from the admin dashboard
@admin_dashboard_bp.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session or session['account_type'] != 'Admin':
        return redirect(url_for('auth.login'))
    username = request.form['delete_username']
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_dashboard.admin_dashboard'))

# File ends