import os
from flask_mail import Mail

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'Platformers') 
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:JXDL86@localhost/platformersdatabase')
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/images')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = bool(os.getenv('MAIL_USE_TLS', True))
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'dutlostandfoundportal@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'shas xavx iptu bpmy')  
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'lostandfoundportal@dut4life.ac.za')

mail = Mail()
