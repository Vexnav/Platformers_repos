import os
import random
from flask import jsonify
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt, generate_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_mail import Mail, Message
from flask_migrate import Migrate
from datetime import timedelta, datetime
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, Admin, LostItem, FoundItem, Category, Location, Review, User, MatchedItem, Claim
from forms import LoginForm, ReportLostItemForm, ReportFoundItemForm, RegistrationForm, ResetPasswordForm, ResetPasswordRequestForm, ReviewForm, UserPortalForm, VerifyCodeForm, ProofOfOwnershipForm

app = Flask(__name__)

app.config.from_object('config.Config')

db.init_app(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

if not os.path.isdir(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/stats')
def stats():
    total_items_reported = LostItem.query.count() + FoundItem.query.count()

    items_found = LostItem.query.filter_by(status='Matched').count() + FoundItem.query.filter_by(status='Matched').count()

    match_rate = (items_found / total_items_reported) * 100 if total_items_reported > 0 else 0

    return render_template('stats.html', total_items_reported=total_items_reported, items_found=items_found, match_rate=match_rate)

@app.route('/api/stats', methods=['GET'])
def api_stats():
    total_items_reported = LostItem.query.count() + FoundItem.query.count()
    items_found = LostItem.query.filter_by(status='Matched').count() + FoundItem.query.filter_by(status='Matched').count()
    match_rate = (items_found / total_items_reported) * 100 if total_items_reported > 0 else 0
    
    return jsonify({
        'total_items_reported': total_items_reported,
        'items_found': items_found,
        'match_rate': round(match_rate, 2)
    })

def match_lost_and_found(item_name, category_id, location_id, description, match_type):
    if match_type == 'lost':
        return FoundItem.query.filter(
            FoundItem.category_id == category_id,
            FoundItem.location_id == location_id,
            FoundItem.item_name.ilike(f"%{item_name}%") if item_name else True,
            FoundItem.description.ilike(f"%{description}%") if description else True,
            FoundItem.status == 'Pending'
        ).all()

    elif match_type == 'found':
        return LostItem.query.filter(
            LostItem.category_id == category_id,
            LostItem.location_id == location_id,
            LostItem.item_name.ilike(f"%{item_name}%") if item_name else True,
            LostItem.description.ilike(f"%{description}%") if description else True,
            LostItem.status == 'Pending'
        ).all()


def find_matches():
    matches = []
    lost_items = LostItem.query.filter_by(status='Lost').all()
    found_items = FoundItem.query.filter_by(status='Unclaimed').all()

    for lost_item in lost_items:
        for found_item in found_items:
            if (
                lost_item.category_id == found_item.category_id and
                lost_item.location_id == found_item.location_id and
                isinstance(found_item.date_found, datetime) and
                isinstance(lost_item.date_lost, datetime) and
                abs((found_item.date_found - lost_item.date_lost).days) <= 7 and  
                lost_item.item_name.lower() in found_item.item_name.lower()
            ):
                matches.append({'lost_item': lost_item, 'found_item': found_item})

                lost_item.status = 'Matched'
                found_item.status = 'Matched'
                db.session.commit()

    return matches


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return Admin.query.get(int(user_id))

@app.route('/')
def home():
    users = User.query.all()
    reviews = Review.query.all()
    total_items_reported = LostItem.query.count() + FoundItem.query.count()

    items_found = LostItem.query.filter_by(status='Matched').count() + FoundItem.query.filter_by(status='Matched').count()

    match_rate = (items_found / total_items_reported) * 100 if total_items_reported > 0 else 0

    return render_template('home.html',users=users, reviews=reviews, total_items_reported=total_items_reported, items_found=items_found, match_rate=match_rate)


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
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            is_confirmed=False
        )
        db.session.add(new_user)
        db.session.commit()

        send_email_confirmation(new_user)

        flash('Registration successful! Please confirm your email before logging in.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

def send_email_confirmation(user):
    token = serializer.dumps(user.email, salt='email-confirm-salt')
    confirm_url = url_for('confirm_email', token=token, _external=True)

    msg = Message(
        subject='Welcome to DUT Lost & Found Portal',
        recipients=[user.email],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = f"""
    Hello {user.username},

    Welcome to the DUT LOST AND FOUND PORTAL!
    Please confirm your email by clicking the link below:
    {confirm_url}

    Warm regards,
    The DUT Lost & Found Portal Team
    """
    try:
        mail.send(msg)
    except Exception as e:
        flash(f'Failed to send confirmation email: {e}', 'danger')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600) 
        user = User.query.filter_by(email=email).first()

        if user.is_confirmed:
            flash('Your email is already confirmed.', 'info')
            return redirect(url_for('login'))

        user.is_confirmed = True
        db.session.commit()
        flash('Your email has been confirmed successfully. You can now log in!', 'success')
        return redirect(url_for('login'))

    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email.', 'danger')
            return redirect(url_for('reset_password'))

        verification_code = random.randint(100000, 999999)
        user.reset_code = verification_code 
        db.session.commit() 

        msg = Message(
            'Password Reset Verification Code',
            recipients=[user.email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.body = f"""Hi {user.username},

        You have requested a password reset. Your verification code is:

        {verification_code}

        If you did not request this, please ignore this email.

        Best regards,
        DUT LOST & FOUND PORTAL
        """
        mail.send(msg)
        flash('A verification code has been sent to your email. Enter it below to continue.', 'info')

        return redirect(url_for('verify_code', email=email))

    return render_template('reset_password.html', form=form)

@app.route('/verify_code/<email>', methods=['GET', 'POST'])
def verify_code(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid email address.', 'danger')
        return redirect(url_for('reset_password'))

    form = VerifyCodeForm()
    if form.validate_on_submit():
        entered_code = form.code.data
        if str(user.reset_code) == str(entered_code):  
            flash('Verification successful! Please reset your password.', 'success')
            return redirect(url_for('reset_password_form', email=email))  
        else:
            flash('Incorrect verification code. Please try again.', 'danger')

    return render_template('verify_code.html', form=form)

@app.route('/reset_password_form/<email>', methods=['GET', 'POST'])
def reset_password_form(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid email address.', 'danger')
        return redirect(url_for('reset_password'))

    form = ResetPasswordForm()  
    if form.validate_on_submit():
        new_password = form.password.data
        confirm_password = form.confirm_password.data

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('reset_password_form', email=email))

        user.password = generate_password_hash(new_password) 
        user.reset_code = None  
        db.session.commit() 

        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('login')) 

    return render_template('reset_password_form.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        admin = Admin.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('User login successful!', category='success')
            return redirect(url_for('dashboard'))  
        elif admin and admin.check_password(password):
            login_user(admin)
            flash('Admin login successful!', category='success')
            return redirect(url_for('admin_dashboard'))  
        else:
            flash('Invalid credentials. Please try again.', category='error')

    return render_template('login.html')  

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if request.method == 'POST':
        query = request.form.get('query')
        return redirect(url_for('search_results', query=query))

    stats = {
        'lost_count': LostItem.query.count(),
        'found_count': FoundItem.query.count(),
        'matched_count': MatchedItem.query.count()
    }

    lost_items = LostItem.query.order_by(LostItem.date_lost.desc()).limit(5).all()
    found_items = FoundItem.query.order_by(FoundItem.date_found.desc()).limit(5).all()

    current_month = datetime.now().month
    current_year = datetime.now().year

    lost_items_last_month = []
    for i in range(12):
        month = (current_month - i) % 12
        year = current_year if current_month - i > 0 else current_year - 1
        result = db.session.query(db.func.count(LostItem.id)).filter(
            db.extract('month', LostItem.date_lost) == month,
            db.extract('year', LostItem.date_lost) == year
        ).scalar()
        lost_items_last_month.append({'month': f"{year}-{month:02d}", 'count': result or 0})

    found_items_last_month = []
    for i in range(12):
        month = (current_month - i) % 12
        year = current_year if current_month - i > 0 else current_year - 1
        result = db.session.query(db.func.count(FoundItem.id)).filter(
            db.extract('month', FoundItem.date_found) == month,
            db.extract('year', FoundItem.date_found) == year
        ).scalar()
        found_items_last_month.append({'month': f"{year}-{month:02d}", 'count': result or 0})

    lost_items_data = {
        'labels': [item['month'] for item in lost_items_last_month],
        'data': [item['count'] for item in lost_items_last_month]
    }
    found_items_data = {
        'labels': [item['month'] for item in found_items_last_month],
        'data': [item['count'] for item in found_items_last_month]
    }

    return render_template(
        'admin_dashboard.html',
        stats=stats,
        lost_items=lost_items,
        found_items=found_items,
        lost_items_data=lost_items_data,
        found_items_data=found_items_data
    )

@app.route('/Manage_categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if request.method == 'POST':
        category_name = request.form['name']
        new_category = Category(name=category_name)
        try:
            db.session.add(new_category)
            db.session.commit()
            flash('Category added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding category: {e}', 'danger')
    categories = Category.query.all()
    return render_template('manage_categories.html', categories=categories)

@app.route('/admin/categories/delete/<int:id>')
@login_required
def delete_category(id):
    category = Category.query.get_or_404(id)
    try:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting category: {e}', 'danger')
    return redirect(url_for('manage_categories'))

@app.route('/manage_locations', methods=['GET', 'POST'])
@login_required
def manage_locations():
    if request.method == 'POST':
        location_name = request.form['name']
        new_location = Location(name=location_name)
        try:
            db.session.add(new_location)
            db.session.commit()
            flash('Location added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding location: {e}', 'danger')
    locations = Location.query.all()
    return render_template('manage_locations.html', locations=locations)

@app.route('/admin/locations/delete/<int:id>')
@login_required
def delete_location(id):
    location = Location.query.get_or_404(id)
    try:
        db.session.delete(location)
        db.session.commit()
        flash('Location deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting location: {e}', 'danger')
    return redirect(url_for('manage_locations'))

@app.route('/recent_items')
@login_required
def recent_items():
    recent_lost = LostItem.query.order_by(LostItem.date_lost.desc()).limit(5).all()
    recent_found = FoundItem.query.order_by(FoundItem.date_found.desc()).limit(5).all()
    return render_template('recent_items.html', recent_lost=recent_lost, recent_found=recent_found)

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.all()
    lost_items_count = LostItem.query.count()
    found_items_count = FoundItem.query.count()
    matched_items_count = MatchedItem.query.count()

    return render_template('dashboard.html', users=users, lost_items_count=lost_items_count, found_items_count=found_items_count, matched_items_count=matched_items_count)

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    query = ''
    if request.method == 'POST':
        query = request.form.get('query')
        return redirect(url_for('index', query=query))

    query = request.args.get('query', '')

    lost_items = LostItem.query.filter(
        (LostItem.item_name.ilike(f"%{query}%")) | 
        (LostItem.description.ilike(f"%{query}%"))
    ).all()

    found_items = FoundItem.query.filter(
        (FoundItem.item_name.ilike(f"%{query}%")) | 
        (FoundItem.description.ilike(f"%{query}%"))
    ).all()
    reviews = Review.query.all()

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

        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)  
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.profile_image = filename  

        theme = request.form.get('theme')
        notifications = request.form.get('notifications') == 'on'  
        current_user.theme = theme
        current_user.notifications = notifications

        db.session.commit()
        flash('Profile and settings updated successfully!', 'success')
        return redirect(url_for('user_portal'))  

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

@app.route('/report_lost', methods=['GET', 'POST'])
@login_required
def report_lost():
    categories = Category.query.all()
    locations = Location.query.all()
    form = ReportLostItemForm()
    matches = []

    new_category = request.form.get('new_category')
    new_location = request.form.get('new_location')

    if new_category:
        if new_category.strip():
            category = Category(name=new_category.strip())
            db.session.add(category)
            db.session.commit()
            flash(f"New category '{new_category}' added.", "success")
        else:
            flash("Category name cannot be empty.", "danger")
    
    if new_location:
        if new_location.strip():
            location = Location(name=new_location.strip())
            db.session.add(location)
            db.session.commit()
            flash(f"New location '{new_location}' added.", "success")
        else:
            flash("Location name cannot be empty.", "danger")

    if request.method == 'POST':
        item_name = request.form.get('item_name')
        category_id = request.form.get('category_id')
        location_id = request.form.get('location_id')
        description = request.form.get('description')
        date_lost = request.form.get('date_lost')

        try:
            category_id = int(category_id)
            location_id = int(location_id)
        except ValueError:
            flash("Invalid category or location selection.", "danger")
            return render_template('report_lost.html', categories=categories, locations=locations, form=form, matches=matches)

        if date_lost:
            date_lost = datetime.strptime(date_lost, "%Y-%m-%d")
        else:
            flash("Please provide a valid date.", "danger")
            return render_template('report_lost.html', categories=categories, locations=locations, form=form, matches=matches)

        file = request.files.get('image')
        image_filename = None

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

        matches = find_matches()

        if matches:
            flash("Potential matches found! Claim the item below.", "info")
        else:
            flash("Lost item reported successfully!", "success")
            return redirect(url_for('dashboard'))

    return render_template('report_lost.html', categories=categories, locations=locations, form=form, matches=matches)

@app.route('/item', methods=['GET', 'POST'])
@login_required
def item():
    categories = Category.query.all()
    locations = Location.query.all()
    form = ReportFoundItemForm()
    matches = []

    new_category = request.form.get('new_category')
    new_location = request.form.get('new_location')

    if new_category:
        if new_category.strip():
            category = Category(name=new_category.strip())
            db.session.add(category)
            db.session.commit()
            flash(f"New category '{new_category}' added.", "success")
        else:
            flash("Category name cannot be empty.", "danger")
    
    if new_location:
        if new_location.strip():
            location = Location(name=new_location.strip())
            db.session.add(location)
            db.session.commit()
            flash(f"New location '{new_location}' added.", "success")
        else:
            flash("Location name cannot be empty.", "danger")

    if request.method == 'POST':
        item_name = request.form.get('item_name')
        category_id = request.form.get('category_id')
        location_id = request.form.get('location_id')
        description = request.form.get('description')

        try:
            category_id = int(category_id)
            location_id = int(location_id)
        except (ValueError, TypeError):
            flash("Invalid category or location selection.", "danger")
            return render_template('item.html', categories=categories, locations=locations, form=form, matches=matches)

        date_found = request.form.get('date_found')
        if date_found:
            try:
                date_found = datetime.strptime(date_found, "%Y-%m-%d")
            except ValueError:
                flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
                return render_template('item.html', categories=categories, locations=locations, form=form, matches=matches)
        else:
            flash("Please provide a valid date.", "danger")
            return render_template('item.html', categories=categories, locations=locations, form=form, matches=matches)

        file = request.files.get('image')
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
        matches = find_matches()

        if matches:
            flash("Potential matches found! Claim the item below.", "info")
            return render_template('claim_item.html', categories=categories, locations=locations, form=form, matches=matches)
        else:
            flash("Lost item reported successfully!", "success")
            return redirect(url_for('dashboard'))

    return render_template('item.html', categories=categories, locations=locations, form=form, matches=matches)

@app.route('/claim_item/<int:item_id>/<string:item_type>', methods=['GET', 'POST'])
@login_required
def claim_item(item_id, item_type):
    if item_type == 'lost':
        item = LostItem.query.get_or_404(item_id)
    elif item_type == 'found':
        item = FoundItem.query.get_or_404(item_id)
    else:
        flash("Invalid claim type.", "danger")
        return redirect(url_for('home'))

    form = ProofOfOwnershipForm()

    if form.validate_on_submit():
        proof_details = form.proof.data
        file = form.file.data

        uploaded_file_path = None
        if file:
            filename = secure_filename(file.filename)
            upload_folder = app.config['UPLOAD_FOLDER']
            uploaded_file_path = os.path.join(upload_folder, filename)
            file.save(uploaded_file_path)

        claim = Claim(
            item_id=item.id,
            item_type=item_type,
            claimed_by=current_user.id,
            proof_of_ownership=uploaded_file_path,
            status='Pending'  
        )
        db.session.add(claim)
        try:
            db.session.commit()  
            flash("Claim has been submitted successfully. Awaiting approval.", "success")
            return redirect(url_for('dashboard'))  
        except Exception as e:
            db.session.rollback()  
            flash("There was an issue submitting your claim. Please try again.", "danger")
            print(f"Error: {e}")  
            return redirect(url_for('claim_item'))

    return render_template('claim_item.html', form=form, item=item)

@app.route('/admin_claims', methods=['GET'])
@login_required
def admin_claims():
    claims = Claim.query.filter_by(status='Pending').all()
    return render_template('admin_claims.html', claims=claims)


@app.route('/approve_claim/<int:claim_id>', methods=['POST'])
@login_required
def approve_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    if claim.status != 'Pending':
        flash("This claim has already been processed.", "warning")
        return redirect(url_for('admin_claims'))

    claim.status = 'Approved'
    db.session.commit()

    send_claim_approved_notification(claim.claimed_by)

    flash(f"Claim for item {claim.item_id} has been approved.", "success")
    return redirect(url_for('admin_claims'))


@app.route('/decline_claim/<int:claim_id>', methods=['POST'])
@login_required
def decline_claim(claim_id):

    claim = Claim.query.get_or_404(claim_id)

    if claim.status != 'Pending':
        flash("This claim has already been processed.", "warning")
        return redirect(url_for('admin_claims'))

    claim.status = 'Declined'
    db.session.commit()

    send_claim_declined_notification(claim.claimed_by)

    flash(f"Claim for item {claim.item_id} has been declined.", "danger")
    return redirect(url_for('admin_claims'))


def send_claim_approved_notification(user_id):
    user = User.query.get(user_id)
    if user:
        msg = Message(
            'Your Claim Has Been Approved',
            recipients=[user.email],
            body=f'Hello {user.username},\n\nYour claim for the item has been approved. You can now proceed with further actions.\n\nRegards,\nLost & Found Team'
        )
        mail.send(msg)


def send_claim_declined_notification(user_id):
    user = User.query.get(user_id)
    if user:
        msg = Message(
            'Your Claim Has Been Declined',
            recipients=[user.email],
            body=f'Hello {user.username},\n\nUnfortunately, your claim for the item has been declined. Please check the claim details and try again.\n\nRegards,\nLost & Found Team'
        )
        mail.send(msg)


def send_claim_notification(user_email, item):
    msg = Message(
        'Claim Submitted',
        recipients=[user_email],
        body=f'Hello, your claim for the item {item.title} has been successfully submitted. We will notify you once it has been processed.'
    )
    mail.send(msg)

@app.route('/lost_item', methods=['GET'])
@login_required
def lost_item():
    lost_item = LostItem.query.all()
    return render_template('lost_item.html', lost_item=lost_item)

@app.route('/found_item', methods=['GET'])
@login_required
def found_item():
    found_items = FoundItem.query.all()
    return render_template('found_item.html', found_items=found_items)


@app.route('/lost_items', methods=['GET'])
@login_required
def lost_items():
    lost_items = LostItem.query.all()
    return render_template('lost_items.html', lost_items=lost_items)

@app.route('/found_items', methods=['GET'])
@login_required
def found_items():
    found_items = FoundItem.query.all()
    return render_template('found_items.html', found_items=found_items)

@app.route('/matched_items', methods=['GET'])
@login_required
def matched_items():
    matches = MatchedItem.query.all()
    return render_template('matched_items.html', matches=matches)

@app.route('/reports')
@login_required
def reports():
    lost_items = LostItem.query.all()
    users = User.query.all()
    claims = Claim.query.all()
    return render_template('reports.html', users=users, lost_items=lost_items, claims=claims)

@app.route('/reports/items')
def items_report():
    lost_items = LostItem.query.all()

    categories = db.session.query(LostItem.category_id, db.func.count(LostItem.id)) \
        .group_by(LostItem.category_id).all()
    status_count = db.session.query(LostItem.status, db.func.count(LostItem.id)) \
        .group_by(LostItem.status).all()

    category_labels = [f"Category {category[0]}" for category in categories]
    category_data = [category[1] for category in categories]

    status_labels = [status[0] for status in status_count]
    status_data = [status[1] for status in status_count]

    return render_template('items_report.html', lost_items=lost_items, lost_items_categories={'labels': category_labels, 'data': category_data},lost_items_status={'labels': status_labels, 'data': status_data},report_type="Lost Items")

@app.route('/manage_admin')
def manage_admin():
    admins = Admin.query.all()
    return render_template('manage_admin.html', admins=admins)

@app.route('/delete_lost_item/<int:item_id>', methods=['POST'])
@login_required
def delete_lost_item(item_id):
    item = LostItem.query.get(item_id)  
    if item:
        db.session.delete(item)  
        db.session.commit()  
        flash("Item deleted successfully.", "success")
    else:
        flash("Item not found.", "danger")
    
    return redirect(url_for('lost_items'))  

@app.route('/delete_found_item/<int:item_id>', methods=['POST'])
@login_required
def delete_found_item(item_id):
    item = FoundItem.query.get(item_id)  
    if item:
        db.session.delete(item) 
        db.session.commit()
        flash("Found item deleted successfully.", "success")
    else:
        flash("Found item not found.", "danger")
    
    return redirect(url_for('found_items'))  

@app.route('/edit_admin/<int:admin_id>', methods=['GET', 'POST'])
@login_required
def edit_admin(admin_id):
    admin = Admin.query.get(admin_id)
    if not admin:
        flash("Admin not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        admin.username = request.form.get('username')

        password = request.form.get('password')
        if password:
            admin.set_password(password)  

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

@app.route('/reviews', methods=['GET', 'POST'])
@login_required
def reviews():
    form = ReviewForm()
    if request.method == 'POST':
        rating = request.form.get('rating')
        comment = request.form.get('comment', '').strip()

        if not rating or not comment:
            flash("Both rating and comment are required.", "danger")
            return redirect(url_for('reviews'))

        new_review = Review(user_id=current_user.id, rating=int(rating), comment=comment)
        db.session.add(new_review)
        db.session.commit()

        flash("Review submitted successfully!", "success")
        return redirect(url_for('reviews'))

    all_reviews = Review.query.order_by(Review.timestamp.desc()).all()
    return render_template('reviews.html', reviews=all_reviews, form=form)

@app.route('/admin/reviews')
@login_required
def admin_reviews():
    if not current_user.is_admin: 
        flash("Access denied! Admins only.", "danger")
        return redirect(url_for('home'))

    all_reviews = Review.query.order_by(Review.timestamp.desc()).all()
    return render_template('admin_reviews.html', reviews=all_reviews)

@app.route('/admin/review/delete/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    if not current_user.is_admin:
        flash("Unauthorized action!", "danger")
        return redirect(url_for('admin_reviews'))

    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    flash("Review deleted successfully.", "success")
    return redirect(url_for('admin_reviews'))

@app.route('/logout')
def logout():
    logout_user()  
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()
    if not Admin.query.filter_by(username='DUTAdmin').first():
        default_admin = Admin(username='DUTAdmin')
        default_admin.password = generate_password_hash('$$Dut050504') 
        db.session.add(default_admin)
        db.session.commit()
        print("Default admin created with username: 'DUTAdmin' and password: '$$Dut050504'")
    
if __name__ == '__main__':
    app.run(debug=True)
