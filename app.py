import os
import sqlite3
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def init_db():
    """初始化 SQLite 数据库"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


def get_safe_user_info(username):
    if username not in USERS:
        return None
    user = USERS[username].copy()
    user.pop("password", None)
    return user


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session or session["username"] not in USERS:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    keyword = request.args.get("keyword", "")
    results = []
    if keyword and username:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            for row in c.fetchall():
                results.append(dict(row))
        except Exception as e:
            print(f"[SQL Error] {e}")
        conn.close()
    return render_template("index.html", user=user_info, results=results, keyword=keyword)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error_msg = "用户名或密码错误"

        if username in USERS:
            if check_password_hash(USERS[username]["password"], password):
                session["username"] = username
                session.permanent = False
                return redirect("/")
            return render_template("login.html", error=error_msg)

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and row[2] == password:
            USERS[username] = {
                "username": row[1],
                "password": generate_password_hash(row[2]),
                "email": row[3],
                "phone": row[4],
                "role": "user",
                "balance": 0
            }
            session["username"] = username
            return redirect("/")
        return render_template("login.html", error=error_msg)
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
            conn.close()
            return render_template("login.html", msg="注册成功，请登录")
        except Exception as e:
            print(f"[SQL Error] {e}")
            conn.close()
            return render_template("register.html", error=f"注册失败：{e}")
    return render_template("register.html")


@app.route("/search")
def search():
    username = session.get("username")
    if not username or username not in USERS:
        return redirect("/login")
    keyword = request.args.get("keyword", "")
    results = []
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    print(f"[SQL] {sql}")
    try:
        c.execute(sql)
        for row in c.fetchall():
            results.append(dict(row))
    except Exception as e:
        print(f"[SQL Error] {e}")
    conn.close()
    return render_template("search_results.html", results=results, keyword=keyword)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
