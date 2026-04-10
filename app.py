from functools import wraps
from pathlib import Path
import os

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / 'static' / 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
FREE_POST_LIMIT = 5
PAID_POST_FEE = 15

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

raw_database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if raw_database_url.startswith('postgres://'):
    raw_database_url = raw_database_url.replace('postgres://', 'postgresql://', 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = raw_database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = str(UPLOAD_DIR)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
app.config['EMAIL_VERIFICATION_REQUIRED'] = os.environ.get('EMAIL_VERIFICATION_REQUIRED', 'false').lower() == 'true'

mail = Mail(app)
db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=True)
    bio = db.Column(db.String(300), nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(300), nullable=True)
    image = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer)
    following_id = db.Column(db.Integer)


class ProductImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer)
    buyer_id = db.Column(db.Integer)
    seller_id = db.Column(db.Integer)
    status = db.Column(db.String(20), default='New')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    message = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)


UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
with app.app_context():
    db.create_all()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def mail_is_configured():
    return bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])


def send_verification_email(user):
    if not mail_is_configured():
        return False, 'Email is not configured yet.'

    token = serializer.dumps(user.email, salt='email-verify')
    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify your Lil Cart account', recipients=[user.email])
    msg.html = (
        f'<h2>Welcome to Lil Cart</h2>'
        f'<p>Click the button below to verify your email address.</p>'
        f'<p><a href="{verify_url}">Verify my email</a></p>'
    )

    try:
        mail.send(msg)
        return True, None
    except Exception as exc:
        app.logger.warning('Email send failed: %s', exc)
        return False, str(exc)



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def save_image(uploaded_file):
    if not uploaded_file or not uploaded_file.filename:
        return None

    if not allowed_file(uploaded_file.filename):
        return None

    filename = secure_filename(uploaded_file.filename)
    target = UPLOAD_DIR / filename
    stem = target.stem
    suffix = target.suffix
    counter = 1

    while target.exists():
        target = UPLOAD_DIR / f'{stem}-{counter}{suffix}'
        counter += 1

    uploaded_file.save(target)
    return target.name


@app.context_processor
def inject_globals():
    return {
        'current_user': current_user(),
        'free_post_limit': FREE_POST_LIMIT,
        'paid_post_fee': PAID_POST_FEE,
    }


@app.route('/')
def home():
    latest_products = Product.query.order_by(Product.id.desc()).limit(6).all()
    return render_template('index.html', latest_products=latest_products)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']
        role = request.form.get('role') or None

        if role not in {None, '', 'buyer', 'seller'}:
            flash('Please choose a valid role.')
            return render_template('signup.html', selected_role=None)

        if User.query.filter_by(email=email).first():
            flash('This email already exists. Please log in instead.')
            return render_template('signup.html', selected_role=role)

        user = User(
            name=name,
            email=email,
            phone=phone,
            password=generate_password_hash(password),
            role=role,
            is_verified=not app.config['EMAIL_VERIFICATION_REQUIRED'],
        )
        db.session.add(user)
        db.session.commit()

        if app.config['EMAIL_VERIFICATION_REQUIRED']:
            sent, error_message = send_verification_email(user)
            if sent:
                flash('Account created. Check your email to verify your account.')
                return render_template('signup.html', pending=True, email=user.email, selected_role=role)

            user.is_verified = True
            db.session.commit()
            flash('Account created. Email verification is unavailable right now, so your account has been activated automatically.')
            if error_message:
                app.logger.warning('Verification fallback activated for %s: %s', user.email, error_message)
        else:
            flash('Account created successfully.')

        session['user_id'] = user.id
        if user.role:
            return redirect(url_for('account'))
        return redirect(url_for('choose_role'))

    return render_template('signup.html', selected_role=None)


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except SignatureExpired:
        flash('This verification link expired. Please request a new one.')
        return redirect(url_for('login'))
    except BadSignature:
        flash('That verification link is invalid.')
        return redirect(url_for('signup'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('We could not find that account.')
        return redirect(url_for('signup'))

    user.is_verified = True
    db.session.commit()
    flash('Email verified. You can log in now.')
    return redirect(url_for('login'))


@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    email = request.form.get('email', '').strip().lower()
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('No account was found with that email address.')
        return redirect(url_for('login'))

    if user.is_verified:
        flash('This account is already verified. Please log in.')
        return redirect(url_for('login'))

    sent, _ = send_verification_email(user)
    if sent:
        flash('A new verification email has been sent.')
    else:
        flash('Email sending is unavailable right now. Please activate the account manually from your admin workflow or keep email verification disabled for now.')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password.')
            return render_template('login.html', show_resend=False, email=email)

        if app.config['EMAIL_VERIFICATION_REQUIRED'] and not user.is_verified:
            flash('Please verify your email before logging in.')
            return render_template('login.html', show_resend=True, email=email)

        session['user_id'] = user.id
        if user.role:
            return redirect(url_for('account'))
        return redirect(url_for('choose_role'))

    return render_template('login.html', show_resend=False, email='')


@app.route('/choose-role')
@login_required
def choose_role():
    return render_template('choose_role.html')


@app.route('/set-role/<role>')
@login_required
def set_role(role):
    if role not in {'buyer', 'seller'}:
        flash('Please choose a valid role.')
        return redirect(url_for('choose_role'))

    user = current_user()
    user.role = role
    db.session.commit()
    flash(f'Your account is now set as a {role}.')

    if role == 'buyer':
        return redirect(url_for('marketplace'))
    return redirect(url_for('account'))


@app.route('/marketplace')
def marketplace():
    products = Product.query.order_by(Product.id.desc()).all()
    return render_template('marketplace.html', products=products)


@app.route('/account')
@login_required
def account():
    user = current_user()
    products = Product.query.filter_by(user_id=user.id).order_by(Product.id.desc()).all()
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.id.desc()).all()
    product_count = len(products)
    extra_posts = max(0, product_count - FREE_POST_LIMIT)
    posting_due = extra_posts * PAID_POST_FEE

    return render_template(
        'account.html',
        user=user,
        products=products,
        notifications=notifications,
        product_count=product_count,
        posting_due=posting_due,
        extra_posts=extra_posts,
    )


@app.route('/products/add', methods=['POST'])
@login_required
def add_product():
    user = current_user()
    if user.role != 'seller':
        flash('Only sellers can add products.')
        return redirect(url_for('choose_role'))

    name = request.form['name'].strip()
    description = request.form.get('description', '').strip()

    try:
        price = int(request.form['price'])
    except ValueError:
        flash('Please enter a valid numeric price.')
        return redirect(url_for('account'))

    image_name = save_image(request.files.get('image'))
    if request.files.get('image') and not image_name:
        flash('Please upload a valid image file: png, jpg, jpeg, gif, or webp.')
        return redirect(url_for('account'))

    product = Product(
        name=name,
        price=price,
        description=description,
        image=image_name,
        user_id=user.id,
    )
    db.session.add(product)
    db.session.commit()

    seller_product_total = Product.query.filter_by(user_id=user.id).count()
    if seller_product_total > FREE_POST_LIMIT:
        flash(f'Product added. This listing falls in your paid tier: Rs.{PAID_POST_FEE} per post after the first {FREE_POST_LIMIT}.')
    else:
        flash('Product added successfully.')

    return redirect(url_for('account'))


@app.route('/delete-product/<int:product_id>')
@login_required
def delete_product(product_id):
    user = current_user()
    product = db.session.get(Product, product_id)

    if not product or product.user_id != user.id:
        flash('Product not found.')
        return redirect(url_for('account'))

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted.')
    return redirect(url_for('account'))


@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user()
    new_email = request.form['email'].strip().lower()
    existing_user = User.query.filter(User.email == new_email, User.id != user.id).first()
    if existing_user:
        flash('That email is already being used by another account.')
        return redirect(url_for('account'))

    user.name = request.form['name'].strip()
    user.bio = request.form.get('bio', '').strip() or None
    user.phone = request.form['phone'].strip()
    user.email = new_email
    db.session.commit()

    flash('Profile updated successfully.')
    return redirect(url_for('account'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
