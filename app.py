from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyodbc

app = Flask(__name__)
app.config['SECRET_KEY'] = 'd786526b1b786949598fa89eae3e551dc1fc481ba192fb60'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://Ttmart:Ttmart@10.0.0.125/Adventureworks2022?driver=ODBC+Driver 17 for SQL Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'Users'  # Make sure this matches your actual table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Debug prints
        print(f"Attempting login with username: {username}")
        if user:
            print(f"User found: {user.username}")
            print(f"Stored password hash: {user.password}")
            try:
                if bcrypt.check_password_hash(user.password, password):
                    print("Password matched")
                    login_user(user)
                    return redirect(url_for('dashboard'))
                else:
                    print("Password did not match")
            except ValueError as ve:
                print(f"Error checking password: {ve}")
                flash('Login Unsuccessful. Please check username and password.', 'danger')
        else:
            print("User not found in database")
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
