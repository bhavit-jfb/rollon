from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_socketio import SocketIO, emit

import os

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
socketio = SocketIO(app)

# Configure the SQLite databases
basedir = os.path.abspath(os.path.dirname(__file__))
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'contact.db')
# app.config['SQLALCHEMY_BINDS'] = {
#     'users': 'sqlite:///' + os.path.join(basedir, 'users.db')
# }
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SERVER_NAME'] = '5000-cs-699825599319-default.cs-asia-southeast1-seal.cloudshell.dev'
# app.config['PREFERRED_URL_SCHEME'] = 'https'

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define the User model for the login credentials
class User(UserMixin, db.Model):
    __bind_key__ = 'users'  # Bind this model to the 'users.db' database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Define the Contact model for the contact form submissions
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Contact {self.email}>'

@login_manager.user_loader

def load_user(user_id):
    return User.query.get(int(user_id))

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
@login_required
def home():
    if current_user.username == 'admin':
        # Admin: Show all contacts and users
        all_contacts = Contact.query.all()
        all_users = User.query.filter(User.username != "admin").all()
        return render_template('index.html', contacts=all_contacts, users=all_users, admin=True)
    else:
        # Non-admin: Show only the contact form
        return render_template('index.html', admin=False)

@app.route('/contact', methods=['POST'])
def contact():
    email = request.form.get('email')
    message = request.form.get('message')

    # Save to database
    new_contact = Contact(email=email, message=message)
    db.session.add(new_contact)
    db.session.commit()

    # Retrieve all contact submissions after saving
    all_contacts = Contact.query.all()

    contact_message = f"Thank you, {email}. Your message has been received."
    # return render_template('index.html', contact_message=contact_message, contacts=all_contacts)
    return redirect(url_for('home'))

@app.route('/edit_contact/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_contact(id):
    contact = Contact.query.get_or_404(id)
    if request.method == 'POST':
        contact.email = request.form['email']
        contact.message = request.form['message']
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('edit.html', contact=contact)

@app.route('/delete_contact/<int:id>', methods=['POST'])
@login_required
def delete_contact(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if id == 4:
        abort(403)
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if id == 4:
        abort(403)
    user = User.query.get_or_404(id)
    if user.username == "admin":
        flash("Admin cannot be deleted!", "danger")
        return redirect(url_for('home'))

    if current_user.username != "admin":
        flash("Unauthorized!", "danger")
        return redirect(url_for('home'))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted!", "success")
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Reset email sent successfully!")

        if User.query.filter_by(email=email).first():
            return "Email already registered"

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        socketio.emit("new_user", {
            "username": username,
            "email": email
        })

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check for admin credentials
        if username == 'admin' and password == 'password':
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(username='admin')
                admin.set_password('password')
                db.session.add(admin)
                db.session.commit()

            login_user(admin)
            return redirect(url_for('home'))

        # Check for regular user credentials
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))

        return render_template('invalid.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_user.check_password(old_password):
        flash("Old password wrong")
        return redirect(url_for('home'))

    if new_password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for('home'))

    current_user.set_password(new_password)
    db.session.commit()

    flash("Password changed successfully")
    return redirect(url_for('login'))


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'jfbrecov@gmail.com'
# app.config['MAIL_PASSWORD'] = 'xnrvemhkolarjhye'
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = 'jfbrecov@gmail.com'

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return "User not found"

        token = s.dumps(email, salt='password-reset')
        reset_url = url_for('reset_password_email', token=token, _external=True)

        msg = Message("Reset Your Password", recipients=[email])
        msg.body = f"Click this link to reset password:\n{reset_url}"
        mail.send(msg)

        flash("Reset email sent successfully!")

    return render_template('login.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_email(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=600)
    except:
        return "Link expired or invalid"

    print("EMAIL FROM TOKEN:", email)

    user = User.query.filter_by(email=email).first()

    print("USER FOUND:", user)
    if not user:
        return "User not found in database"

    if request.method == 'POST':
        new_password = request.form.get('password')
        user.set_password(new_password)
        db.session.commit()
        return "Password reset successful"

    return render_template("reset_password_email.html")

@app.template_filter('mask_email')
def mask_email(email):
    if not email or '@' not in email:
        return email
    
    name, domain = email.split('@')
    return name[:5] + "**@" + domain

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

if __name__ == '__main__':
    app.run()



#app.run(debug=True)