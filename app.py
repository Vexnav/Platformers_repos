import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

from config import Config
from extensions import db
from models import Student, LostItem, FoundItem, Category, Match, Notification, ClaimRequest, Admin

# login manager
login_manager = LoginManager()
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/images')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    @login_manager.user_loader
    def load_user(user_id):
        return Student.query.get(int(user_id)) or Admin.query.get(int(user_id))

    @app.route('/', methods=['GET', 'POST'])
    def home():
        return render_template('home.html')

@app.route('/index', methods=['GET'])
def index():
    query = request.args.get('q', '')  

    if query:
        items = LostItem.query.filter(
            (LostItem.item_name.ilike(f"%{query}%")) |
            (LostItem.description.ilike(f"%{query}%")) |
            (LostItem.last_seen_location.ilike(f"%{query}%"))
        ).all()
    else:
        items = LostItem.query.all()  

    return render_template('index.html')

    @app.route('/report', methods=['GET', 'POST'])
    def report():
        categories = Category.query.all()  
        if request.method == 'POST':
            item_name = request.form.get('item_name')

            category_id = int(request.form.get('category_id'))  
            category_id = request.form.get('category')
            if category_id is not None and category_id.isdigit():  
                category_id = int(category_id)
            else:
                flash("Invalid category selected. Please try again.", "danger")
                return redirect(request.url)
            
            last_seen_location = request.form.get('last_seen_location')
            description = request.form.get('description')
            date_lost = datetime.strptime(request.form.get('date_lost'), "%Y-%m-%d")
            file = request.files.get('image') 
            image_filename = None

            if file and allowed_file(file.filename): 
                filename = secure_filename(file.filename)
                image_filename = filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  

            lost_item = LostItem(
                item_name=item_name,
                category_id=category_id,
                last_seen_location=last_seen_location,
                date_lost=date_lost,
                description=description,
                image=image_filename,
                status='Pending'
            )
            db.session.add(lost_item)
            db.session.commit()
            flash("Lost item reported successfully!", "success")
            return redirect(url_for('home'))

        return render_template('report.html', categories=categories)

    @app.route('/report_found', methods=['GET', 'POST'])
    def report_found():
        categories = Category.query.all()  
        if request.method == 'POST':
            item_name = request.form.get('item_name')
            category_id = int(request.form.get('category'))  
            location_found = request.form.get('location_found')
            description = request.form.get('description')
            date_found = datetime.strptime(request.form.get('date_found'), "%Y-%m-%d")
            file = request.files.get('image')
            image_filename = None

            if file and allowed_file(file.filename): 
                filename = secure_filename(file.filename)
                image_filename = filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  

            found_item = FoundItem(
                item_name=item_name,
                category_id=category_id,
                location_found=location_found,
                description=description,
                date_found=date_found,
                image=image_filename,
                status='Unclaimed'
            )
            db.session.add(found_item)
            db.session.commit()
            flash("Found item reported successfully!", "success")
            return redirect(url_for('home'))

        return render_template('report_found.html', categories=categories)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = Student.query.filter_by(email=email).first() or Admin.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password.', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))

    @app.route('/admin/dashboard', methods=['GET'])
    @login_required
    def admin_dashboard():
        items = LostItem.query.all()
        return render_template('admin_dashboard.html', items=items)

    @app.route('/admin/update/<int:item_id>', methods=['POST'])
    @login_required
    def update_lost_item(item_id):
        item = LostItem.query.get_or_404(item_id)
        new_status = request.form.get('status')
        item.status = new_status
        db.session.commit()
        flash("Lost item status updated.", "success")
        return redirect(url_for('admin_dashboard'))

    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
