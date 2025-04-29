
import atexit
import threading

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file
import os
from werkzeug.utils import secure_filename

import sqlite3
import os
import threading


db_lock = threading.RLock()
app = Flask(__name__)
app.secret_key = 'uda de freak'

DATABASE = 'database.db'
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ---------- enc functions ----------

def create_key(length=16):
    #ascii key make
    return ''.join([chr((os.urandom(1)[0] % 26) + 97) for _ in range(length)])

def xor_encrypt(text, key):
    text_bytes = text.encode()
    key_bytes = key.encode()
    encrypted = bytearray()

    for i in range(len(text_bytes)):
        encrypted.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])

    return encrypted.hex()

def xor_decrypt(hex_data, key):
    encrypted = bytearray.fromhex(hex_data)
    key_bytes = key.encode()
    decrypted = bytearray()

    for i in range(len(encrypted)):
        decrypted.append(encrypted[i] ^ key_bytes[i % len(key_bytes)])

    return decrypted.decode()

# ---------- Classes

class DatabaseManager:
    @staticmethod
    def connect():
        return sqlite3.connect(DATABASE)

    @staticmethod
    def setup():
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    enc_key TEXT,
                    sql_injection INTEGER DEFAULT 0,
                    reverse_shell INTEGER DEFAULT 0,
                    privilege_escalation INTEGER DEFAULT 0,
                    box INTEGER DEFAULT 0,
                    active_status INTEGER DEFAULT 0
                )
            ''')
            conn.commit()
            conn.close()

class User:
    def __init__(self, username, password=None):
        self.username = username
        self.password = password
        self.key = 0

    def register(self):
        self.key = create_key()
        hashed_password = xor_encrypt(self.password, self.key)
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (self.username,))
            row = cursor.fetchone()
            if (row and row[0]):
                flash("username already in use")
                conn.close()
                return False
            try:
                cursor.execute('INSERT INTO users (username, password, enc_key) VALUES (?, ?, ?)', (self.username, hashed_password, self.key,))
                conn.commit()
                conn.close()
                return True
            except sqlite3.IntegrityError:
                conn.close()
                return False
            finally:
                conn.close()

    def login(self):
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('SELECT password, enc_key, active_status FROM users WHERE username = ?', (self.username,))
            row = cursor.fetchone()
            if not row:
                flash('invalid credentials')
                conn.close()
                return False
            passw, key, act_s = row
            if passw and xor_decrypt(passw, key) == self.password:
                if(act_s==0):
                    cursor.execute('UPDATE users SET active_status = ? WHERE username = ?', (1, self.username))
                    conn.commit()
                    conn.close()
                    return True
                else:
                    flash("the user is already using the site")
                    conn.close()
                    return False

            conn.close()
            return False


    def logout(self):
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET active_status = ? WHERE username = ?', (0, self.username))
            conn.commit()

    def has_completed_challenge(self,challenge):
        print("bedote db lock")
        with db_lock:
            print("after db lick")
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            print(challenge)
            print(self.username)
            cursor.execute(f'SELECT {challenge} FROM users WHERE username = ?', (self.username,))
            row = cursor.fetchone()
            print(row)
            conn.close()
            if(row[0] == 0):

                return False
            return True
    def challenges_complete(self):
        num = 0
        if self.has_completed_challenge('sql_injection'):
            num+=1
        if self.has_completed_challenge('reverse_shell'):
            num+=1
        if self.has_completed_challenge('privilege_escalation'):
            num+=1
        if self.has_completed_challenge('box'):
            num+=1
        return num
    @staticmethod
    def get_progress(username):
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('SELECT progress FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return row[0]
            return 0

    @staticmethod
    def update_progress(username, value):
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET progress = ? WHERE username = ?', (value, username))
            conn.commit()
            conn.close()


class Challenge:
    challenges = {
        'sql_injection': 1,
        'reverse_shell': 2,
        'privilege_escalation': 3,
        'box': 4
    }

    @staticmethod
    def complete_challenge(username, challenge_name):
        with db_lock:
            conn = DatabaseManager.connect()
            cursor = conn.cursor()
            cursor.execute(f'SELECT {challenge_name} FROM users WHERE username = ?', (username,))

            chal_already_completed = cursor.fetchone()

            if(chal_already_completed and chal_already_completed[0] ==0):
                cursor.execute(f'UPDATE users SET {challenge_name} = ? WHERE username = ?', (1, username))
                conn.commit()
                use1 = User(session['username'])
                current_progress = use1.get_progress(username)
                new_progress = current_progress + Challenge.challenges.get(challenge_name)
                use1.update_progress(username, new_progress)


            conn.close()

class AppManager:
    @staticmethod
    def is_logged_in():
        return 'username' in session


def logout_all_users():
    with db_lock:
        conn = DatabaseManager.connect()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET active_status = 0")
        conn.commit()
        conn.close()

# ---- routse

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))
    use1 = User(session['username'])
    progress = User.get_progress(session['username'])
    completed = {
        'sql_injection': use1.has_completed_challenge('sql_injection'),
        'reverse_shell': use1.has_completed_challenge('reverse_shell'),
        'privilege_escalation': use1.has_completed_challenge('privilege_escalation'),
        'box': use1.has_completed_challenge('box')
    }

    chal_done = use1.challenges_complete()
    return render_template('dashboard.html', username=session['username'], progress=progress, challenges = chal_done, completed=completed)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username, password)
        if user.register():
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
        else:
            flash('try again.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username, password)
        if user.login():
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('try again.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    user1 = User(session['username'])
    user1.logout()
    session.clear()
    return redirect(url_for('login'))

@app.route('/complete/<challenge_name>')
def complete(challenge_name):
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))
    use1 = User(session['username'])
    if use1.has_completed_challenge(challenge_name):


        return redirect(url_for('dashboard'))

    Challenge.complete_challenge(session['username'], challenge_name)
    return redirect(url_for('dashboard'))

@app.route('/sql_injection', methods=['GET', 'POST'])
def sql_injection():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))
    success = False
    finished = False
    submitted = False
    if request.method == 'POST':
        submitted = True
        fake_user = request.form['username']
        fake_pass = request.form['password']

        use1 = User(session['username'])
        if (use1.has_completed_challenge('sql_injection')):
            finished = True
        else:
            finished = False
        if ('admin' in fake_user) or ("'1'='1" in fake_pass):
            if( not finished):
                print("esdfef")
                complete('sql_injection')
                success = True
        else:
            success = False



    print(success, finished, submitted)

    return render_template('sql_injection.html', success = success, finished = finished, submitted=submitted)

@app.route('/reverse_shell')
def reverse_shell():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))

    submitted = session.pop('shell_submitted', False)
    success = session.pop('shell_success', False)
    finished = session.pop('shell_finished', False)

    print(finished,success,submitted)
    return render_template('reverse_shell.html', finished = finished, success=success, submitted=submitted)

@app.route('/upload-shell', methods=['POST'])
def upload_shell():
    success = False
    use1 = User(session['username'])
    if (use1.has_completed_challenge('reverse_shell')):
        finished = True
    else:
        finished = False
    submitted = True
    session['shell_submitted'] = True
    session['shell_success'] = success
    session['shell_finished'] = finished
    if 'file' not in request.files:
        if(not finished):
            flash("❌ No file uploaded.")
        return redirect(url_for('reverse_shell'))

    file = request.files['file']
    filename = secure_filename(file.filename)


    if not filename.lower().endswith('.php'):
        if (not finished):
            flash("❌ File must be a .php reverse shell.")
        return redirect(url_for('reverse_shell'))


    temp_path = os.path.join(UPLOAD_FOLDER, filename + '.txt')
    file.save(temp_path)

    with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
        contents = f.read()

    os.remove(temp_path)


    if any(keyword in contents for keyword in ['bash -i', 'nc -e', 'system($_GET']):

        success = True
        complete("reverse_shell")
        if (not finished):
            flash("✅ Reverse shell accepted!")

    else:
        success = False
        if (not finished):
            flash("❌ This is not a valid reverse shell.")

    session['shell_submitted'] = True
    session['shell_success'] = success
    session['shell_finished'] = finished

    return redirect(url_for('reverse_shell'))




@app.route('/privilege_escalation', methods=['GET', 'POST'])
def privilege_escalation():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))

    user = User(session['username'])

    submitted = False
    success = False
    finished = user.has_completed_challenge('privilege_escalation')
    pop_up_show = False
    extra_line = False
    if request.method == 'POST':
        submitted = True
        command = request.form.get('command', '').strip().lower()
        print(command)


        session.setdefault('escalation_step', 0)
        session.setdefault('terminal_log', [])
        response = ''
        step = session['escalation_step']
        print("initially: step ->", step)
        if step == 0 and command == 'find / -type f -writable -path "*cron*" 2>/dev/null':
            session['escalation_step'] = 1
            extra_line = True
            response = "✅ Good job! Now try editing backup.sh to insert your payload."



        elif step == 1 and 'echo' in command and '/opt/cronjobs/backups.sh' in command:

            if '#!/bin/bash' in command and 'bash -i >& /dev/tcp/' in command and '0>&1' in command:
                print("el haber")
                session['escalation_step'] = 2
                response = "✅ Edited /opt/cronjobs/backup.sh with reverse shell payload."
                pop_up_show = True

        elif step == 2 and 'nc -lvnp' in command:
            session['escalation_step'] = 3
            success = True
            port = command.split(" ")[2]
            response = f"listening on [any] 0.0.0.0 {port}..."
            pop_up_show = False
            if not finished:
                Challenge.complete_challenge(user.username, 'privilege_escalation')

        else:


            if (step == 0):
                response = "❓ Command not recognized. Think: what would you enumerate next?"

            elif (step == 1):
                response = "❓ Command not recognized. Think: how would you change the cron?"

            elif (step == 2):
                response = "❓ Command not recognized. Think: how to open a listener?"

        session['terminal_log'].append(f"<span style='color:#00ff88'>lowpriv@vulnbox:~$</span> {command}")
        if(extra_line):
            session['terminal_log'].append(f"<span style='color:#ffffff'>{">>> /opt/cronjobs/backup.sh"}</span>")
        session['terminal_log'].append(f"<span style='color:#ffffff'>{response}</span>")

    step = session.get('escalation_step', 0)
    logs = session.get('terminal_log', [])
    print(success,finished,submitted)
    return render_template('privilege_escalation.html', success=success, finished=finished, submitted=submitted, step = step, logs=logs, pop_show=pop_up_show)

@app.route('/boxes', methods=['GET', 'POST'])
def boxes():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))
    password = "ulel1337"
    submitted = False
    success = False
    user = User(session['username'])
    finished = user.has_completed_challenge('box')

    if request.method == "POST":
        passw = request.form.get('passwordInput', '').strip().lower()
        submitted = True
        if(passw == password):
            success= True
            if(not finished):
                complete('box')

    return render_template('boxes.html', success=success, finished=finished, submitted=submitted)

@app.route('/download_box')
def download_box():

    if not AppManager.is_logged_in():
        return redirect(url_for('login'))

    try:
        #return send_from_directory('/static/boxes', 'ulelbox.ova', as_attachment=True)
        full_path = os.path.join(app.root_path, 'static', 'boxes', 'ulelbox.ova')
        return send_file(full_path, as_attachment=True)
    except Exception as e:
        return f"Error: {str(e)}", 404





@app.route('/installations')
def installations():
    if not AppManager.is_logged_in():
        return redirect(url_for('login'))
    return render_template('installations.html')

# ---------- Init ----------
atexit.register(logout_all_users)
if __name__ == '__main__':
    DatabaseManager.setup()

    app.run(debug=True, threaded=True ,host='0.0.0.0', port=5000)

