# Import necessary libraries for SQL and date and time
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy

# Creates the classes through which data can be referenced to and accessed
# There are 3 classes used: User, Report and BannedIP
# Through these classes, relevant data can be access from the database
db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    account_type = db.Column(db.String(50), nullable=False, default='Volunteer')
    name = db.Column(db.String(150), nullable=False)
    class_ = db.Column(db.String(50), nullable=False)
    section = db.Column(db.String(50), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    roll_no = db.Column(db.String(50), nullable=False)
    last_login_ip = db.Column(db.String(50), nullable=True)
    reports = db.relationship('Report', backref='volunteer', foreign_keys='Report.assigned_volunteer')
    escalations = db.relationship('Report', backref='escalator', foreign_keys='Report.escalated_by')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_name = db.Column(db.String(150), nullable=False)
    incident_date = db.Column(db.DateTime, nullable=False)
    people_involved = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    offender_name = db.Column(db.String(150), nullable=False)
    offender_class = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(10), nullable=False)
    details = db.Column(db.String(500), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    reporter_ip = db.Column(db.String(50), nullable=False)
    assigned_volunteer = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    escalated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    ban_date = db.Column(db.DateTime, default=datetime.utcnow)
    unban_date = db.Column(db.DateTime, nullable=True)

    def set_unban_date(self):
        if self.ban_date is None:
            self.ban_date = datetime.utcnow()

        if self.duration == "1 Day":
            self.unban_date = self.ban_date + timedelta(days=1)
        elif self.duration == "3 Days":
            self.unban_date = self.ban_date + timedelta(days=3)
        elif self.duration == "1 Week":
            self.unban_date = self.ban_date + timedelta(weeks=1)
        elif self.duration == "2 Weeks":
            self.unban_date = self.ban_date + timedelta(weeks=2)
        elif self.duration == "Permanent":
            self.unban_date = None
