from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    lost_items = db.relationship("Item", backref="student", lazy=True)

class Admin(db.Model, UserMixin):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    lost_items_processed = db.relationship("Item", backref="admin", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    lost_items = db.relationship("Item", backref="category", lazy=True)

class Item(db.Model):
    __tablename__ = 'item'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_lost = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="Lost")
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=False)
    processed_by_admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"), nullable=True)

class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    review_text = db.Column(db.Text, nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  
