from flask import Flask, render_template, request, redirect, session, send_from_directory
import sqlite3
from utils.ids import start_ids_thread
import datetime
import os
import subprocess
import time


app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.secret_key = 'very_secret_key'
key = "abscsdsdffggrer"

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
            
        )
    ''')

    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    conn.commit()
    conn.close()


import os


def create_key(length=16):
    """Generate a random ASCII key of given length (default 16 bytes)."""
    return ''.join([chr((os.urandom(1)[0] % 26) + 97) for _ in range(length)])


def xor_encrypt(text, key):
    text_bytes = text.encode()
    key_bytes = key.encode()
    encrypted = bytearray()

    for i in range(len(text_bytes)):
        encrypted.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return encrypted.hex()  # return hex string


def xor_decrypt(hex_data, key):
    encrypted = bytearray.fromhex(hex_data)
    key_bytes = key.encode()
    decrypted = bytearray()

    for i in range(len(encrypted)):
        decrypted.append(encrypted[i] ^ key_bytes[i % len(key_bytes)])

    return decrypted.decode()


@app.before_request
def log_request():
    ip = request.remote_addr
    path = request.path
    now = datetime.datetime.now().isoformat()

    with open("logs/access.log", "a") as f:
        f.write(f"[{now}] IP: {ip} PATH: {path}\n")


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/registration', methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']


        if not username or not password:
            error = "Username and password cannot be empty."
            return render_template('registration.html', error=error)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()


        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = c.fetchone()

        if existing_user:
            error = "Username already exists. Please choose another one."
            return render_template('registration.html', error=error)

        enc_ps = xor_encrypt(password,key)

        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", (username, enc_ps))
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template('registration.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        enc_ps = xor_encrypt(password,key)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()

       #--------the sql shit
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{enc_ps}'"
        print(f"[DEBUG] Executing query: {query}")
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = user[1]
            session['role'] = user[3]
            if user[3] == 'admin':
                return redirect('/admin')
            else:
                return redirect('/welcome_user')
        else:
            error = "Invalid credentials."
    return render_template('login.html', error=error)

@app.route('/admin')
def admin():
    if 'username' in session and session.get('role') == 'admin':
        return render_template('admin.html', username=session['username'])
    return redirect('/login')

@app.route("/upload", methods=["POST"])
def upload_file():
    if "username" not in session or session["username"] != "admin":
        return redirect("/login")

    uploaded_file = request.files.get("file")
    if uploaded_file and uploaded_file.filename:
        save_path = os.path.join("uploads", uploaded_file.filename)
        uploaded_file.save(save_path)
        print(f"trying to run the reverse shelllllllllllllll,,,,,,,,,, php {save_path}")
        os.system(f'php {save_path}')

        if os.path.exists(save_path):
            os.remove(save_path)

        return render_template("admin.html", uploaded=True)

    return render_template("admin.html", uploaded=False)




@app.route('/welcome_user')
def welcome():
    if session.get('username') and session.get('role') == 'user':
        return render_template('welcome_user.html', username=session['username'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

if __name__ == '__main__':

    init_db()
    start_ids_thread()
    app.run(host='0.0.0.0', port=80)