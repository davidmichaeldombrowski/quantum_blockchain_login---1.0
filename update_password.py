from app import db, User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# Find the user
user = User.query.filter_by(username='Ttmart').first()

if user:
    new_password = 'Ttmart'
    new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = new_password_hash
    db.session.commit()
    print("Password updated successfully.")
else:
    print("User not found.")
