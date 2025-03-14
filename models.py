from extensions import db
from flask_login import UserMixin
from datetime import datetime

class Student(db.Model, UserMixin): 
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    claims = db.relationship('ClaimRequest', backref='claimer', lazy=True)
    notifications = db.relationship('Notification', backref='recipient', lazy=True)

class LostItem(db.Model):
    __tablename__ = 'lost_item'
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)  
    item_name = db.Column(db.String(100), nullable=False)
    last_seen_location = db.Column(db.String(255), nullable=False)
    date_lost = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), nullable=False)
    matches = db.relationship('Match', backref='lost_item', lazy=True)

class FoundItem(db.Model):
    __tablename__ = 'found_item'
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    location_found = db.Column(db.String(255), nullable=False)
    date_found = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), nullable=False)
    matches = db.relationship('Match', backref='found_item', lazy=True)
    claims = db.relationship('ClaimRequest', backref='found_item_claimed', lazy=True)

class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    lost_items = db.relationship('LostItem', backref='category', lazy=True)
    found_items = db.relationship('FoundItem', backref='category', lazy=True)

    def __repr__(self):
        return f'<Category {self.name}>'

class Match(db.Model):
    __tablename__ = 'match'
    id = db.Column(db.Integer, primary_key=True)
    lost_item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id'), nullable=False)
    found_item_id = db.Column(db.Integer, db.ForeignKey('found_item.id'), nullable=False)
    match_score = db.Column(db.Float, nullable=False)
    match_status = db.Column(db.String(50), nullable=False)

class ClaimRequest(db.Model):
    __tablename__ = 'claim_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    found_item_id = db.Column(db.Integer, db.ForeignKey('found_item.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)  # Fixed table reference
    status = db.Column(db.String(50), nullable=False)
    claim_date = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)

class Admin(db.Model, UserMixin):  
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)  
    password = db.Column(db.String(255), nullable=False) 
    permissions = db.Column(db.String(255), nullable=False)
