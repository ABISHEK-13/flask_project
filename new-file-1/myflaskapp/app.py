from flask import Flask, render_template, flash, redirect, url_for, session, request
import sqlite3
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, PasswordField, validators
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key'

DATABASE = 'database/myflask_health_records.db'


def create_table():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return sha256_crypt.encrypt(password)

def verify_password(password, password_hash):
    return sha256_crypt.verify(password, password_hash)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = hash_password(form.password.data)

        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, username, password_hash) VALUES (?, ?, ?, ?)", (name, email, username, password))
        conn.commit()
        conn.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user:
            password_hash = user[4]
            if verify_password(password_candidate, password_hash):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/dashboard')
@is_logged_in
def dashboard():
    username = session['username']
    
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT name, username, email FROM users WHERE username = ?", (username,))
    user_info = cur.fetchone()
    conn.close()
    
    return render_template('dashboard.html', user_info=user_info)

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_table()
    app.run(debug=True)
