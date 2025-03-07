from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
db = SQLAlchemy() 

User(db.Model, UserMixin):
id = db.Column(db.Integer, primary_key=True)
username = db.Column(db.String(80), unique=True, nullable=False) 
email = db.Column(db.String(120), unique=True, nullable=False) 
password = db.Column(db.String(200), nullable=False)
is_admin = db.Column(db.Boolean, default=False)

def __repr__(self): return f'<User {self.username}>'

Item(db.Model):
id = db.Column(db.Integer, primary_key=True) 
name = db.Column(db.String(100), nullable=False) 
description = db.Column(db.Text, nullable=False) 
location = db.Column(db.String(200), nullable=False) 
date_reported = db.Column(db.DateTime, default=db.func.current_timestamp()) 
status = db.Column(db.String(20), default='Lost') 
reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

def __repr__(self): return f'<Item {self.name} ({self.item_type})>'
