from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Configure the SQLite databases
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'contact.db')
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///' + os.path.join(basedir, 'users.db')
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    password = db.Column(db.String(100), unique=True, nullable=False)

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
        all_users = User.query.all()
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
    return render_template('index.html', contact_message=contact_message, contacts=all_contacts)
    # return redirect(url_for('home'))

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
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists'

        # Create a new user
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

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

        return 'Invalid credentials'
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')

#app.run(debug=True)