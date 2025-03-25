from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  
    theme = db.Column(db.String(10), default='Light')  
    notifications = db.Column(db.Boolean, default=True)  
    is_confirmed = db.Column(db.Boolean, default=False) 
    profile_image = db.Column(db.String(120), nullable=False, default='default.jpg') 

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class LostItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    date_lost = db.Column(db.Date, nullable=False)
    image = db.Column(db.String(200))
    status = db.Column(db.String(50), default='Lost')

    category = db.relationship('Category', backref='lost_item', lazy=True)
    location = db.relationship('Location', backref='lost_item', lazy=True)

class FoundItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    date_found = db.Column(db.Date, nullable=False)
    image = db.Column(db.String(200))
    status = db.Column(db.String(50), default='Unclaimed')

    category = db.relationship('Category', backref='found_item', lazy=True)
    location = db.relationship('Location', backref='found_item', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False) 
    comment = db.Column(db.Text, nullable=False)  
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) 

    user = db.relationship('User', backref=db.backref('reviews', lazy=True))

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, nullable=False)
    item_type = db.Column(db.String(50), nullable=False)
    claimed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    proof_of_ownership = db.Column(db.String(200), nullable=True) 
    date_claimed = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending')  
    user = db.relationship('User', backref='claim', lazy=True)

    def __repr__(self):
        return f"<Claim {self.id}, Item ID {self.item_id}, Claimed by {self.claimed_by}, Status {self.status}>"

class MatchedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lost_item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id'), nullable=False)
    found_item_id = db.Column(db.Integer, db.ForeignKey('found_item.id'), nullable=False)
    date_matched = db.Column(db.DateTime, default=datetime.utcnow)

    lost_item = db.relationship('LostItem', backref='matched_items', lazy=True)
    found_item = db.relationship('FoundItem', backref='matched_items', lazy=True)


