from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
import os
from forms import LoginForm, RegistrationForm, ReportItemForm, MatchItemForm
from flask import flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lost_and_found.db'
#app.config['SECRET_KEY'] = AnySecretCode
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}

db = SQLAlchemy(app)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    student = Student.query.get(int(user_id))
    if student:
        return student
    return Admin.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Assume we have a user lookup function
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed. Please check your credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    items = Item.query.all()
    return render_template('dashboard.html', items=items)

@app.route('/report_item', methods=['GET', 'POST'])

def report_item():
            form = ReportItemForm()
            if form.validate_on_submit():
                     if 'image' in request.files:
                              image_file = request.files['image']
                             if image_file and allowed_file(image_file.filename):
                                       filename = secure_filename(image_file.filename)
                             image_path = os.path.join(app.config['UPLOAD_FOLDER'],   filename)
                image_file.save(image_path)
                image_url = os.path.join('static/uploads', filename
            else:
                image_url = None  
        else:
            image_url = None  
        
        item = Item(name=form.name.data,   description=form.description.data, location=form.location.data,   item_type=form.item_type.data, image_url=image_url)
        db.session.add(item)
        db.session.commit()
        flash(f'Item "{form.name.data}" has been reported successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('report_item.html', form=form)

@app.route('/match_item/<item_id>', methods=['GET', 'POST'])
def match_item(item_id):
    form = MatchItemForm()
    if form.validate_on_submit():
        found_item = Item.query.get_or_404(form.found_item_id.data)
        lost_item = Item.query.get_or_404(item_id)
        if lost_item.item_type == 'lost' and found_item.item_type == 'found':
            flash(f'Match found between {lost_item.name} and {found_item.name}!', 'success')
        else:
            flash('Invalid match attempt. Ensure the items are of correct type (lost/found).', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('match_item.html', form=form)
@app.route('/logout')
def logout():
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
