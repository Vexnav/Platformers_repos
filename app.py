import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_mail import Message, Mail
from flask import jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from models import db, Admin, LostItem, FoundItem, Category, Location, Review, User
from forms import LoginForm, ReportLostItemForm, ReportFoundItemForm, RegistrationForm

app = Flask(__name__)

app.config.from_object('config.Config')

db.init_app(app)
mail= Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.isdir(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user is not None:
        return user
    return Admin.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms_and_conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: 
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():  
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  
        if isinstance(current_user, Admin):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            login_user(admin)
            flash('Logged in as Admin successfully!', 'success')
            return redirect(url_for('admin_dashboard'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))

        flash('Invalid username or password. Please try again.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    reviews = Review.query.order_by(Review.date_posted.desc()).all()
    if request.method == 'POST':
        username = request.form.get('username')
        comment = request.form.get('comment')

        new_review = Review(username=username, comment=comment)

        try:
            db.session.add(new_review)
            db.session.commit()
            flash("Your review has been submitted!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")

        return redirect(url_for('home'))

    if request.method == 'POST':
        query = request.form.get('query')
        return redirect(url_for('search_results', query=query))

    lost_items = LostItem.query.all()
    found_items = FoundItem.query.all()
    return render_template('index.html', lost_items=lost_items, found_items=found_items, reviews=reviews)

@app.route('/search_results', methods=['GET'])
@login_required
def search_results():
    query = request.args.get('query', '')
    lost_items = LostItem.query.filter(
        (LostItem.item_name.ilike(f"%{query}%")) | 
        (LostItem.description.ilike(f"%{query}%"))
    ).all()
    found_items = FoundItem.query.filter(
        (FoundItem.item_name.ilike(f"%{query}%")) | 
        (FoundItem.description.ilike(f"%{query}%"))
    ).all()
    return render_template('search_results.html', query=query, lost_items=lost_items, found_items=found_items)
    
@app.route('/portal', methods=['GET', 'POST'])
@login_required
def user_portal():
    if request.method == 'POST':
        
        bio = request.form.get('bio')
        if bio:
            current_user.bio = bio

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.profile_picture = f'static/images/{filename}'

        theme = request.form.get('theme')
        notifications = request.form.get('notifications') == 'on'  
        current_user.theme = theme
        current_user.notifications = notifications

        db.session.commit()
        flash('Profile and settings updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('user_portal.html', user=current_user)

@app.route('/delete_profile', methods=['POST'])
@login_required
def delete_profile():
    user_id = current_user.id
    logout_user()
    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Your profile has been deleted successfully.', 'info')
    
    return redirect(url_for('register'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    categories = Category.query.all()
    locations = Location.query.all()
    form = ReportLostItemForm()
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        category_id = request.form.get('category')
        location_id = request.form.get('location')
        new_category = request.form.get('new_category')
        new_location = request.form.get('new_location')
        if new_category and new_category.strip():  
            categories.append(new_category.strip())
        if new_location and new_location.strip():
            locations.append(new_location.strip())
        description = request.form.get('description')
        date_lost = datetime.strptime(request.form.get('date_lost'), "%Y-%m-%d")
        file = request.files.get('image')
        image = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_filename = filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        lost_item = LostItem(
            item_name=item_name,
            category_id=category_id,
            location_id=location_id,
            date_lost=date_lost,
            description=description,
            image=image_filename,
            status='Pending'
        )
        db.session.add(lost_item)
        db.session.commit()
        flash("Lost item reported successfully!", "success")
        return redirect(url_for('home'))

    return render_template('report.html', categories=categories, locations=locations, form=form)

@app.route('/report_found', methods=['GET', 'POST'])
@login_required
def report_found():
    form = ReportFoundItemForm()
    categories = Category.query.all()
    locations = Location.query.all()
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        category_id = request.form.get('category')
        location_id = request.form.get('location')
        new_category = request.form.get('new_category')
        new_location = request.form.get('new_location')

        if new_category and new_category.strip():  
            categories.append(new_category.strip())
        if new_location and new_location.strip():
            locations.append(new_location.strip())

        description = request.form.get('description')
        date_found = datetime.strptime(request.form.get('date_found'), "%Y-%m-%d")
        file = request.files.get('image')
        image = None
        if form.image.data:
            try:
                image_filename = image.save(form.image.data)
            except Exception as e:
                flash('Image upload failed. Please try again.', 'danger')
                image_filename = None 
                
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_filename = filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        found_item = FoundItem(
            item_name=item_name,
            category_id=category_id,
            location_id=location_id,
            date_found=date_found,
            description=description,
            image=image_filename,
            status='Pending'
        )
        db.session.add(found_item)
        db.session.commit()
        flash("Found item reported successfully!", "success")
        return redirect(url_for('home'))

    return render_template('report_found.html', categories=categories, locations=locations, form=form)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    # Ensure the user is an admin
    if not isinstance(current_user, Admin):
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('home'))

    # Fetch data for the dashboard
    locations = Location.query.all()
    categories = Category.query.all()
    admins = Admin.query.all()
    lost_items = LostItem.query.all()
    found_items = FoundItem.query.all()
    reviews = Review.query.all()

    if request.method == 'POST':
        item_type = request.form.get('item_type') 
        item_id = request.form.get('item_id')
        new_status = request.form.get('status')

        if item_type == 'lost':
            item = LostItem.query.get(item_id)
        elif item_type == 'found':
            item = FoundItem.query.get(item_id)
        else:
            flash("Invalid item type.", "danger")
            return redirect(url_for('admin_dashboard'))

        if item:
            item.status = new_status
            db.session.commit()
            flash(f"Status updated to '{new_status}' for {item.item_name}!", "success")
        else:
            flash("Item not found.", "danger")

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', 
                           lost_items=lost_items, 
                           locations=locations, 
                           admins=admins, 
                           categories=categories, 
                           found_items=found_items, 
                           reviews=reviews)



@app.route('/edit_admin/<int:admin_id>', methods=['GET', 'POST'])
@login_required
def edit_admin(admin_id):
    admin = Admin.query.get(admin_id)
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        admin.username = request.form.get('username')
        admin.set_password(request.form.get('password'))  
        db.session.commit()
        flash("Admin details updated successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_admin.html', admin=admin)

@app.route('/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
def delete_admin(admin_id):
    admin = Admin.query.get(admin_id)
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(admin)
    db.session.commit()
    flash("Admin deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    categories = Category.query.all()
    if request.method == 'POST':
        name = request.form.get('name') 
        category = Category(
            name=name
        ) 
        db.session.add(category)
        db.session.commit()
        flash("Category added successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_category.html', categories=categories)

@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    category= Category.query.get(category_id)
    if not category:
        flash("Category not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(category)
    db.session.commit()
    flash("Category deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/add_location', methods=['GET', 'POST'])
@login_required
def add_location():
    locations = Location.query.all()
    if request.method == 'POST':
        name = request.form.get('name') 
        location = Location(
            name=name
        ) 
        db.session.add(location)
        db.session.commit()
        flash("Location added successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_location.html', locations=locations)

@app.route('/delete_location/<int:location_id>', methods=['POST'])
@login_required
def delete_location(location_id):
    location = Location.query.get(location_id)
    if not location:
        flash("Location not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(location)
    db.session.commit()
    flash("Location deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update/<int:item_id>', methods=['POST'])
@login_required
def update_status(item_id):

    item = LostItem.query.get(item_id) or FoundItem.query.get(item_id)

    if not item:
        flash("Item not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    new_status = request.form.get('status')
    if new_status not in ['Lost', 'Found', 'Claimed']:
        flash("Invalid status.", "danger")
        return redirect(url_for('admin_dashboard'))

    item.status = new_status
    db.session.commit()
    flash(f"Status for {item.item_name} updated to '{new_status}'!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_item/<item_type>/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_type, item_id):
    if item_type == 'lost':
        items = LostItem.query.get(item_id)
    elif item_type == 'found':
        items = FoundItem.query.get(item_id)
    else:
        flash("Invalid item type.", "danger")
        return redirect(url_for('admin_dashboard'))

    if items:
        db.session.delete(items)
        db.session.commit()
        flash(f"{items.item_name} has been deleted successfully.", "success")
    else:
        flash("Item not found.", "danger")

    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    logout_user()  
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all() 

    if not Admin.query.filter_by(username='AdminDUT').first():
        default_admin = Admin(
            username='AdminDUT'
        )
        default_admin.set_password('$$Dut12345') 
        db.session.add(default_admin)
        db.session.commit()
        print("Default admin created with username: 'AdmnDUT' and password: '$$Dut12345'")




@app.route('/api/dashboard-data')
@login_required
def dashboard_data():
    # Ensure the user is an admin
    if not isinstance(current_user, Admin):
        return jsonify({"error": "Unauthorized access"}), 403

    # Fetch statistics for the dashboard
    lost_items_count = LostItem.query.count()
    found_items_count = FoundItem.query.count()

    # Logic to calculate matched items
    matched_items_count = db.session.query(LostItem).join(FoundItem, LostItem.item_name == FoundItem.item_name).count()

    # Logic to calculate returned items
    returned_items_count = LostItem.query.filter(LostItem.status == 'Returned').count()

    # Logic to calculate disposed items
    disposed_items_count = LostItem.query.filter(LostItem.status == 'Disposed').count() + \
                          FoundItem.query.filter(FoundItem.status == 'Disposed').count()

    # Example of recent items (Customize if necessary later on)
    recent_lost_items = LostItem.query.order_by(LostItem.date_lost.desc()).limit(5).all()
    recent_found_items = FoundItem.query.order_by(FoundItem.date_found.desc()).limit(5).all()

    return jsonify({
        "stats": {
            "lostItemsCount": lost_items_count,
            "foundItemsCount": found_items_count,
            "matchedItemsCount": matched_items_count,
            "returnedItemsCount": returned_items_count,
            "disposedItemsCount": disposed_items_count
        },
        "recentLostItems": [{"itemName": item.item_name, "description": item.description} for item in recent_lost_items],
        "recentFoundItems": [{"itemName": item.item_name, "description": item.description} for item in recent_found_items],
    })

if __name__ == '__main__':
    app.run(debug=True)

