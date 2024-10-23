# Created by Ragunandan, Tanuj and Neel of 11 A CBSE for RWCC

# The Flask Application is composed of HTML files in the /templates folder, a CSS file in the /static/css folder and 3 python files

# Import necessary libraries
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, request, url_for, session
from models import BannedIP, db, User
from werkzeug.security import generate_password_hash
from flask_migrate import Migrate

# Setup the flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'THIS_IS_A_S3CR3T_3NCRYPTION_K3Y_with_a_few_random_numbers_at_the_end_3939493939293949293942424442345543'

# Set up the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)
# Migrate avoids circular imports as we will also access a file called "routes.py" which has the routes and will also access this file
migrate = Migrate(app, db)

# Import routes
from routes import auth_bp, teacher_dashboard_bp, volunteer_dashboard_bp, report_bp, home_bp, admin_dashboard_bp, guide_bp

# Register blueprint for the routes imported
app.register_blueprint(auth_bp)
app.register_blueprint(teacher_dashboard_bp)
app.register_blueprint(volunteer_dashboard_bp)
app.register_blueprint(report_bp)
app.register_blueprint(home_bp)
app.register_blueprint(admin_dashboard_bp)
app.register_blueprint(guide_bp)

# Creates a default admin account with username 'admin' and password 'admin123'
# This admin account will have priveleges to manage other accounts and create volunteer and teacher accounts
def create_default_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256', salt_length=8)
        admin = User(
            username='admin',
            password=hashed_password,
            account_type='Admin',
            name='Administrator',         
            class_='N/A',               
            section='N/A',              
            age=0,                      
            roll_no='N/A'               
        )
        db.session.add(admin)
        db.session.commit()

# Redirects to the "not_approved.html" page if the user who opens the webapp has been ip banned by the admin
@app.route('/not_approved')
def not_approved():
    ip_address = request.remote_addr
    banned_ip = BannedIP.query.filter_by(ip_address=ip_address).first()
    if banned_ip:
        ban_duration = banned_ip.duration
        ban_reason = banned_ip.reason
        ban_date = banned_ip.ban_date.strftime("%Y-%m-%d %H:%M:%S") if banned_ip.ban_date else "N/A"
        unban_date = "Permanent" if ban_duration == "Permanent" else (banned_ip.unban_date.strftime("%Y-%m-%d %H:%M:%S") if banned_ip.unban_date else "N/A")
        return render_template('not_approved.html', ban_date=ban_date, ban_duration=ban_duration, ban_reason=ban_reason, unban_date=unban_date)
    return redirect(url_for('home.home'))

# Shall check if the ban has expried and will automatically unban the ip address allowing that ip address to access the webapp
@app.before_request
def block_banned_ips():
    ip_address = request.remote_addr
    banned_ip = BannedIP.query.filter_by(ip_address=ip_address).first()
    if banned_ip:
        if banned_ip.unban_date and banned_ip.unban_date < datetime.utcnow():
            db.session.delete(banned_ip)
            db.session.commit()
        else:
            return render_template('not_approved.html', banned_ip=banned_ip)

# Creates the database if not already created and runs the app.
# host="0.0.0.0" makes the web app accessible to all connected to the local network
# port=8080 sets the port which can be used to access the web app as 8080
# So, the web app will be accessible from http://your_ip_address:8080
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True, host="0.0.0.0", port=8080) 
