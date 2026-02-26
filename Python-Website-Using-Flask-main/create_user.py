from main import db, User
from werkzeug.security import generate_password_hash

def create_user():
    try:
        hashed_password = generate_password_hash('password', method='pbkdf2:sha256', salt_length=16)
        admin = User(username='admin', password=hashed_password)
        db.create_all()  # Ensure tables are created
        db.session.add(admin)
        db.session.commit()
        print("User created successfully!")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    create_user()
