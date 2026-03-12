import os
import sqlite3
import hashlib
import hmac
import base64
import subprocess
import random
import string
import pickle
import yaml
import bcrypt
from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

API_KEY = "sk_live_1234567890abcdef"          
DB_PASSWORD = "admin123"                     

def store_user_md5(username, password):
   
    hashed = hashlib.md5(password.encode()).hexdigest()   # ❌ слабый хеш (MD5)
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')"
    
    print(f"[MD5] Сохранено {username}:{hashed}")


def store_user_bcrypt(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    query = "INSERT INTO users (username, password) VALUES (?, ?)"
    
    print(f"[bcrypt] Сохранено {username}:{hashed.decode()}")


def get_user(request):
    username = request.args.get('username')

    query = f"SELECT * FROM users WHERE username = '{username}'"
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)        
    return cursor.fetchall()


def get_user_safe(username):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()


def ping_host():
    host = request.args.get('host')

    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


def ping_host_safe(host):
    subprocess.run(["ping", "-c", "1", host], check=True)


def load_user_session(data):
    user = pickle.loads(base64.b64decode(data))
    return user

def save_user_session(user):
    return base64.b64encode(pickle.dumps(user)).decode()


def read_user_file():
    filename = request.args.get('file')
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()


@app.route('/login', methods=['POST'])
def login():
    resp = make_response("Вошел в систему")
    
    resp.set_cookie('session_id', 'abc123')
    return resp


@app.route('/login_good', methods=['POST'])
def login_good():
    resp = make_response("Вошел в систему")
    resp.set_cookie('session_id', 'abc123', secure=True, httponly=True, samesite='Lax')
    return resp


def generate_reset_token():
    
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    return token


def generate_reset_token_secure():
    return secrets.token_urlsafe(20)


def calculate(expr):
    result = eval(expr)
    return result

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '2+2')
    return str(calculate(expr))


@app.route('/crash')
def crash():

    try:
        x = 1 / 0
    except Exception as e:
    
        import traceback
        return traceback.format_exc(), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f"/uploads/{file.filename}")
    return "Загружено"


def load_config(config_str):
    
    data = yaml.load(config_str)   
    return data


def load_config_safe(config_str):
    return yaml.safe_load(config_str)



config = {
    "auth_method": "basic",
    "password": "hardcoded_password",          
    "api_key": "AIzaSyD-..."                   
}


def verify_password(stored, provided):

    return stored == provided


def verify_password_secure(stored, provided):
    return hmac.compare_digest(stored.encode(), provided.encode())


def sign_message(message, key):

    return hmac.new(key.encode(), message.encode(), hashlib.md5).hexdigest()


def sign_message_secure(message, key):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def find_users(city):

    query = "SELECT * FROM users WHERE city = '{}'".format(city)
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()

def run_user_code(code):
    exec(code)


@app.route('/greet')
def greet():
    name = request.args.get('name', 'Гость')
    return render_template_string(f"<h1>Привет {name}</h1>")


import os
DB_USER = os.getenv('DB_USER', 'admin')          
DB_PASS = os.getenv('DB_PASS', 'password123')     


def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))


if __name__ == '__main__':

    store_user_md5("alice", "password123")
    store_user_bcrypt("bob", "securePass!")

    token = generate_reset_token()
    print("Токен сброса (слабый):", token)

    app.run(debug=True)   