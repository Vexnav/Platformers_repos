import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from models import Item, Student, Category, Review
from forms import LoginForm, ReportLostItemForm, ReviewForm
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from models import Admin, Student

app = Flask(__name__)
app.config.from_object('config.Config') 

db = SQLAlchemy(app)

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/images')
if not os.path.isdir(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Return True if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

@login_manager.user_loader
def load_user(admin_id):
    return Admin.query.get(int(admin_id))

    
@app.route('/', methods=['GET', 'POST'])
def home():
    form = ReviewForm()
    if request.method == 'POST':
        name = request.form.get('name')
        review_text = request.form.get('review_text')
        if name and review_text:
            new_review = Review(name=name, review_text=review_text)
            db.session.add(new_review)
            db.session.commit()
            flash("Thank you for your review!", "success")
        else:
            flash("All fields are required.", "danger")
        return redirect(url_for('home'))
    
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    return render_template('home.html', reviews=reviews, form=form)

@app.route('/index', methods=['GET', 'POST'])
def index():
    query = request.args.get('q', '')
    if query:
        items = Item.query.filter(
            (Item.title.ilike(f"%{query}%")) | 
            (Item.description.ilike(f"%{query}%"))
        ).all()
    else:
        items = Item.query.all()
    return render_template('index.html', items=items, query=query)

@app.route('/report', methods=['GET', 'POST'])
def report():
    form = ReportLostItemForm()
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category_id = request.form.get('category_id')
        date_lost = request.form.get('date_lost')
        file = request.files.get('image')
        image_filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_filename = filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_item = Item(
            title=title,
            description=description,
            category_id=category_id,
            date_lost=date_lost,
            image_filename=image_filename
        )
        db.session.add(new_item)
        db.session.commit()
        flash("Lost item reported successfully!", "success")
        return redirect(url_for('index'))
    categories = Category.query.all()
    return render_template('report.html', categories=categories, form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            flash("Logged in successfully!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if 'admin_id' not in session:
        flash("You must be logged in as an admin to access the dashboard.", "danger")
        return redirect(url_for('login'))
    items = Item.query.all()
    reviews = Review.query.all()
    return render_template('admin_dashboard.html', items=items)


@app.route('/admin/update/<int:item_id>', methods=['POST'])
@login_required
def update_lost_item(item_id):
    if 'admin_id' not in session:
        flash("You must be logged in as an admin to perform this action.", "danger")
        return redirect(url_for('login'))
    items = Item.query.get_or_404(item_id)
    new_status = request.form.get('status')
    update_lost_item.status = new_status
    db.session.commit()
    flash("Lost item status updated.", "success")
    return redirect(url_for('admin_dashboard'))
    
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)