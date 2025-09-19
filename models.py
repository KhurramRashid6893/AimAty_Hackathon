from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), unique=True, nullable=False)
    aadhaar = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    face_image = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f"<Voter {self.voter_id} - {self.name}>"

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    party = db.Column(db.String(64), nullable=False)
    constituency = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"<Candidate {self.candidate_id} - {self.name}>"

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), nullable=False)
    candidate_id = db.Column(db.String(64), nullable=False)
    booth_number = db.Column(db.String(32), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    receipt = db.Column(db.String(256))

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class BoothOfficer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    booth_number = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class BallotStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(64), nullable=False)
    booth_number = db.Column(db.String(32), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class MismatchLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aadhaar = db.Column(db.String(20), nullable=False)
    voter_id = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    note = db.Column(db.String(256))
