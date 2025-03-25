import os
from flask_mail import Mail

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'Platformers') 
<<<<<<< HEAD
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:JXDL86@localhost/platformersdatabase')
=======
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:Nkambule%40123@localhost/platformersdatabase')
>>>>>>> d320566b2868d1a457ffbca956a76ec4ccd04999
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/images')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = bool(os.getenv('MAIL_USE_TLS', True))
<<<<<<< HEAD
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'dutlostandfoundportal@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'shas xavx iptu bpmy')  
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'lostandfoundportal@dut4life.ac.za')
=======
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'dutlostandfound@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'jyhw jjpm gcjr tvmz')  
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'lostandfound@dut4life.ac.za')
>>>>>>> d320566b2868d1a457ffbca956a76ec4ccd04999

mail = Mail()
