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
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'dutlostandfound@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'jyhw jjpm gcjr tvmz')  
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'lostandfound@dut4life.ac.za')

mail = Mail()
