import os
import re
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Session 安全配置
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # 生产环境应改为 True（需 HTTPS）
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # Session 30分钟超时
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ─── 安全 HTTP 头中间件 ───
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response

# ─── 用户数据库 ───
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

# 允许上传的图片扩展名
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'}


def init_db():
    """初始化 SQLite 数据库（密码使用哈希存储）"""
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
    # 使用哈希密码存储
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


def get_safe_user_info(username):
    """返回不包含密码的用户信息"""
    if username not in USERS:
        return None
    user = USERS[username].copy()
    user.pop("password", None)
    return user


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session or session["username"] not in USERS:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def safe_filename(filename):
    """安全化文件名：移除路径遍历和危险字符，限制为图片扩展名"""
    # 只保留文件名部分，移除路径
    filename = os.path.basename(filename)
    # 移除空字节
    filename = filename.replace('\x00', '')
    # 检查扩展名是否在白名单内
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None
    # 只保留安全字符
    safe_name = re.sub(r'[^\w\.\-]', '_', filename)
    # 防止空文件名
    if not safe_name or safe_name.startswith('.'):
        return None
    return safe_name


# ═══════════════════════════════════
# 路由
# ═══════════════════════════════════

@app.route("/")
def index():
    """首页"""
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    keyword = request.args.get("keyword", "")
    results = []
    if keyword and username:
        try:
            conn = sqlite3.connect("data/users.db")
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # 使用参数化查询，修复 SQL 注入
            like_pattern = f"%{keyword}%"
            c.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern)
            )
            for row in c.fetchall():
                row_dict = dict(row)
                # 手机号脱敏
                if row_dict.get('phone') and len(row_dict['phone']) >= 7:
                    row_dict['phone'] = row_dict['phone'][:3] + '****' + row_dict['phone'][-4:]
                results.append(row_dict)
            conn.close()
        except Exception as e:
            print(f"[DB Error] {e}")

    return render_template("index.html", user=user_info, results=results, keyword=keyword)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error_msg = "用户名或密码错误"

        # 统一验证流程，防止用户名枚举
        user_found = False
        if username in USERS:
            user_found = True
            if check_password_hash(USERS[username]["password"], password):
                session["username"] = username
                session.permanent = True
                return redirect(url_for("index"))

        if not user_found:
            # SQLite 验证
            try:
                conn = sqlite3.connect("data/users.db")
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = c.fetchone()
                conn.close()
                if row:
                    user_found = True
                    if check_password_hash(row[2], password):
                        USERS[username] = {
                            "username": row[1],
                            "password": row[2],
                            "email": row[3],
                            "phone": row[4],
                            "role": "user",
                            "balance": 0
                        }
                        session["username"] = username
                        session.permanent = True
                        return redirect(url_for("index"))
            except Exception:
                pass

        return render_template("login.html", error=error_msg)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面（使用参数化查询）"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 输入验证
        if not username or len(username) < 2:
            return render_template("register.html", error="用户名至少2个字符")
        if len(password) < 6:
            return render_template("register.html", error="密码至少6个字符")
        if not re.match(r'^[\w\@\.\-]+$', email):
            return render_template("register.html", error="邮箱格式不正确")

        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            # 使用参数化查询，修复 SQL 注入
            hashed_pw = generate_password_hash(password)
            c.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, phone)
            )
            conn.commit()
            conn.close()
            return render_template("login.html", msg="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在")
        except Exception as e:
            print(f"[Register Error] {e}")
            return render_template("register.html", error="注册失败，请稍后重试")

    return render_template("register.html")


@app.route("/search")
def search():
    """搜索用户（使用参数化查询）"""
    username = session.get("username")
    if not username or username not in USERS:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "")
    results = []

    try:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        like_pattern = f"%{keyword}%"
        c.execute(
            "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (like_pattern, like_pattern)
        )
        for row in c.fetchall():
            row_dict = dict(row)
            # 手机号脱敏
            if row_dict.get('phone') and len(row_dict['phone']) >= 7:
                row_dict['phone'] = row_dict['phone'][:3] + '****' + row_dict['phone'][-4:]
            results.append(row_dict)
        conn.close()
    except Exception as e:
        print(f"[Search Error] {e}")

    return render_template("search_results.html", results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """头像上传（带安全校验）"""
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择要上传的文件")

        filename = safe_filename(file.filename)
        if not filename:
            return render_template("upload.html", error="不支持的文件类型，请上传图片文件（jpg/png/gif/bmp/webp）")

        try:
            upload_dir = os.path.join("static", "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)
            file.save(upload_path)
            file_url = url_for('static', filename=f'uploads/{filename}')
            return render_template("upload.html", file_url=file_url, filename=filename)
        except Exception as e:
            print(f"[Upload Error] {e}")
            return render_template("upload.html", error="文件上传失败")

    return render_template("upload.html")


@app.route("/logout")
def logout():
    """登出"""
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    os.makedirs("static/uploads", exist_ok=True)
    app.run(debug=False, host="0.0.0.0", port=5000)
