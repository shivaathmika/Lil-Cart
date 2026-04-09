from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'random-super-secret-key-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lilcartweb@gmail.com'
import os
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'lilcartweb@gmail.com'
 
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
 
 
# ── MODELS ──────────────────────────────────────────────────────────────────
 
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
 
 
# ── ROUTES ───────────────────────────────────────────────────────────────────
 
@app.route('/')
def home():
    return render_template('index.html')
 
 
# ── SIGNUP: collect details & send verification email (don't create user yet)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name     = request.form['name'].strip()
        email    = request.form['email'].strip().lower()
        phone    = request.form['phone'].strip()
        password = request.form['password']
 
        # Check if email already registered
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.")
            return render_template('signup.html')
 
        # Sign a token that encodes the pending user data (expires in 1 hour)
        token = serializer.dumps(
            {
                'name':     name,
                'email':    email,
                'phone':    phone,
                'password': generate_password_hash(password),
            },
            salt='email-verify'
        )
 
        verify_url = url_for('verify_email', token=token, _external=True)
 
        # Send verification email
        try:
            msg = Message(
                subject="Verify your Lil Cart account 💜",
                recipients=[email]
            )
            msg.html = f"""
            <div style="font-family:sans-serif;max-width:480px;margin:auto;">
              <h2 style="color:#4b3f72;">Welcome to Lil Cart 💜</h2>
              <p>Hi {name}! Please verify your email to activate your account.</p>
              <a href="{verify_url}"
                 style="display:inline-block;margin:20px 0;padding:14px 28px;
                        background:#a393eb;color:white;border-radius:12px;
                        text-decoration:none;font-weight:600;">
                Verify my email ✨
              </a>
              <p style="color:#9b8fc7;font-size:13px;">
                This link expires in 1 hour. If you didn't sign up, ignore this email.
              </p>
            </div>
            """
            mail.send(msg)
        except Exception as e:
            flash(f"Could not send verification email: {e}")
            return render_template('signup.html')
 
        return render_template('signup.html', pending=True, email=email)
 
    return render_template('signup.html')
 
 
# ── VERIFY EMAIL: token check → create account → choose role
@app.route('/verify/<token>')
def verify_email(token):
    try:
        data = serializer.loads(token, salt='email-verify', max_age=3600)
    except SignatureExpired:
        flash("That verification link has expired. Please sign up again.")
        return redirect(url_for('signup'))
    except BadSignature:
        flash("Invalid verification link.")
        return redirect(url_for('signup'))
 
    email = data['email']
 
    # Guard: if somehow they click the link twice
    if User.query.filter_by(email=email).first():
        flash("Account already verified. Please log in.")
        return redirect(url_for('login'))
 
    # Now create the account
    user = User(
        name=data['name'],
        email=email,
        phone=data['phone'],
        password=data['password'],
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()
 
    return redirect(url_for('choose_role', user_id=user.id))
 
 
# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email'].strip().lower()
        password = request.form['password']
 
        user = User.query.filter_by(email=email).first()
 
        if not user:
            flash("No account found with that email.")
            return render_template('login.html')
 
        if not user.is_verified:
            flash("Please verify your email before logging in.")
            return render_template('login.html')
 
        if not check_password_hash(user.password, password):
            flash("Incorrect password.")
            return render_template('login.html')
 
        return redirect(url_for('choose_role', user_id=user.id))
 
    return render_template('login.html')
 
 
# ── CHOOSE ROLE ───────────────────────────────────────────────────────────────
@app.route('/choose-role/<int:user_id>')
def choose_role(user_id):
    return render_template('choose_role.html', user_id=user_id)
 
 
@app.route('/set-role/<role>/<int:user_id>')
def set_role(role, user_id):
    session['role']    = role
    session['user_id'] = user_id
 
    if role == "seller":
        return redirect('/account')
    else:
        return redirect('/shop')
 
 
# ── SELLER DASHBOARD ──────────────────────────────────────────────────────────
@app.route('/seller-dashboard', methods=['GET', 'POST'])
def seller_dashboard():
    user_id = session.get('user_id')
 
    if request.method == 'POST':
        name        = request.form['name']
        price       = int(request.form['price'])
        description = request.form.get('description', '')
        images      = request.files.getlist('images')
 
        if len(images) > 5:
            flash("Max 5 images allowed!")
            return redirect('/account')
 
        product = Product(
            name=name,
            price=price,
            description=description,
            user_id=user_id
        )
        db.session.add(product)
        db.session.commit()
 
        for img in images:
            if img and img.filename:
                filename = secure_filename(img.filename)
                img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                db.session.add(ProductImage(filename=filename, product_id=product.id))
 
        db.session.commit()
        return redirect('/account')
 
    return redirect('/account')
 
 
# ── ACCOUNT ───────────────────────────────────────────────────────────────────
@app.route('/account')
def account():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')
 
    user          = User.query.get(user_id)
    products      = Product.query.filter_by(user_id=user_id).all()
    count         = len(products)
    notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()
    is_own_profile = True
 
    return render_template(
        'account.html',
        user=user,
        products=products,
        count=count,
        notifications=notifications,
        is_own_profile=is_own_profile
    )
 
 
# ── DELETE PRODUCT ────────────────────────────────────────────────────────────
@app.route('/delete-product/<int:product_id>')
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != session.get('user_id'):
        return "Unauthorized", 403
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('account'))
 
 
# ── BUY ───────────────────────────────────────────────────────────────────────
@app.route('/buy/<int:product_id>')
def buy(product_id):
    buyer_id = session.get('user_id')
    product  = Product.query.get(product_id)
 
    order = Order(
        product_id=product.id,
        buyer_id=buyer_id,
        seller_id=product.user_id
    )
    db.session.add(order)
    db.session.add(Notification(
        user_id=product.user_id,
        message=f"New order for {product.name} 🛍️"
    ))
    db.session.commit()
    return "Order placed!"
 
 
# ── UPDATE PROFILE ────────────────────────────────────────────────────────────
@app.route('/update-profile', methods=['POST'])
def update_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
 
    user       = User.query.get(user_id)
    user.name  = request.form.get('name', user.name).strip()
    user.bio   = request.form.get('bio', '').strip() or None
    user.phone = request.form.get('phone', '').strip() or None
 
    new_email = request.form.get('email', '').strip()
    if new_email and new_email != user.email:
        if User.query.filter_by(email=new_email).first():
            flash("That email is already in use.")
            return redirect(url_for('account'))
        user.email = new_email
 
    db.session.commit()
    flash("Profile updated! ✨")
    return redirect(url_for('account'))
 
 
# ── FOLLOW ────────────────────────────────────────────────────────────────────
@app.route('/follow/<int:user_id>')
def follow(user_id):
    current_user = session.get('user_id')
 
    existing = Follow.query.filter_by(
        follower_id=current_user,
        following_id=user_id
    ).first()
 
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Follow(follower_id=current_user, following_id=user_id))
 
    db.session.commit()
    return redirect('/account')
 
 
# ── LOGOUT ────────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))
 
 
@app.route('/shop')
def shop():
    return "Welcome to Shopping 🛍️"
 
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
 