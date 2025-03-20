import os
from flask_mail import Mail

class Config:
    SECRET_KEY = 'Platformers'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:Nkambule%40123@localhost/lost_and_found'
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/images')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'dutlostandfound@gmail.com'  
    MAIL_PASSWORD = 'jyhw jjpm gcjr tvmz'        
    MAIL_DEFAULT_SENDER = 'dutlostandfound.ac.za'

mail = Mail()
