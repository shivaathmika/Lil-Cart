from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)

# ── CONFIG ─────────────────────────────────────
app.config['SECRET_KEY'] = 'random-super-secret-key-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lilcartweb@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'lilcartweb@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)

# ── MODELS ─────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(15))
    password = db.Column(db.String(200))
    role = db.Column(db.String(10), nullable=True)
    bio = db.Column(db.String(300), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Integer)
    description = db.Column(db.String(300), nullable=True)
    image = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

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
    status = db.Column(db.String(20), default="New")

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    message = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)

# 🔥 CREATE TABLES ON START
with app.app_context():
    db.create_all()

# ── ROUTES ─────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash("Email already exists.")
            return render_template('signup.html')

        token = serializer.dumps({
            'name': name,
            'email': email,
            'phone': phone,
            'password': generate_password_hash(password)
        }, salt='email-verify')

        verify_url = url_for('verify_email', token=token, _external=True)

        msg = Message("Verify your Lil Cart account 💜", recipients=[email])
        msg.html = f"""
        <h2>Welcome 💜</h2>
        <p>Click below:</p>
        <a href="{verify_url}">Verify Email</a>
        """

        # 🔥 NON-BLOCKING EMAIL
        try:
            mail.send(msg)
        except Exception as e:
            print("Email error:", e)

        return render_template('signup.html', pending=True, email=email)

    return render_template('signup.html')


@app.route('/verify/<token>')
def verify_email(token):
    try:
        data = serializer.loads(token, salt='email-verify', max_age=3600)
    except:
        flash("Invalid or expired link.")
        return redirect('/signup')

    if User.query.filter_by(email=data['email']).first():
        return redirect('/login')

    user = User(
        name=data['name'],
        email=data['email'],
        phone=data['phone'],
        password=data['password'],
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()

    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()

        if not user or not check_password_hash(user.password, request.form['password']):
            flash("Invalid credentials")
            return render_template('login.html')

        if not user.is_verified:
            flash("Verify email first")
            return render_template('login.html')

        session['user_id'] = user.id
        return redirect('/account')

    return render_template('login.html')


@app.route('/account')
def account():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    user = User.query.get(user_id)
    products = Product.query.filter_by(user_id=user_id).all()

    return render_template('account.html', user=user, products=products)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)