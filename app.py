from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Connect to SQLite Database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Allowed file extensions for uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Create User Table and Requests Table
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            location TEXT NOT NULL,
            location_number INTEGER NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            image TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Routes for Signup, Login, and Logout
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)', 
                         (full_name, email, password))
            conn.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'error')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            return redirect(url_for('home'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Home page showing list of user’s requests
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    requests = conn.execute('SELECT * FROM requests WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('home.html', requests=requests)

# Page to add a new request
@app.route('/add_request', methods=['GET', 'POST'])
def add_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        location = request.form['location']
        location_number = request.form['location_number']
        problem_type = request.form['type']
        description = request.form['description']
        image = None

        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image = filename

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO requests (user_id, location, location_number, type, description, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], location, location_number, problem_type, description, image))
        conn.commit()
        conn.close()
        return redirect(url_for('home'))
    return render_template('add_request.html')

if __name__ == '__main__':
    app.run(debug=True)
