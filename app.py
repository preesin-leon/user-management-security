import os
import re
import time
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

# ─── 登录失败计数器（内存存储，生产环境应使用 Redis）───
LOGIN_ATTEMPTS = {}  # {ip: [timestamp1, timestamp2, ...]}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 300  # 5分钟

# ─── CSRF Token 存储 ───
CSRF_TOKENS = {}  # {session_id: token}

# 允许上传的图片扩展名
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'}


# ─── 安全 HTTP 头中间件 ───
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'same-origin'
    # 严格 CSP 策略
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "font-src 'self'; "
        "form-action 'self'"
    )
    # 禁用自动嗅探 MIME 类型
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


# ─── 速率限制装饰器 ───
def rate_limit(max_attempts, window_seconds):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            now = time.time()
            if ip in LOGIN_ATTEMPTS:
                # 清理过期记录
                LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < window_seconds]
                if len(LOGIN_ATTEMPTS[ip]) >= max_attempts:
                    retry_after = int(window_seconds - (now - LOGIN_ATTEMPTS[ip][0]))
                    return render_template("login.html", error=f"登录尝试过于频繁，请 {retry_after} 秒后再试")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ─── CSRF 生成与验证 ───
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']


def validate_csrf_token(token):
    stored = session.get('_csrf_token')
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)


app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ─── 用户数据库 ───
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
        "failed_attempts": 0
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
        "failed_attempts": 0
    }
}


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
        phone TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
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
    user.pop("failed_attempts", None)
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
    filename = os.path.basename(filename)
    filename = filename.replace('\x00', '')
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None
    safe_name = re.sub(r'[^\w\.\-]', '_', filename)
    if not safe_name or safe_name.startswith('.'):
        return None
    # 限制文件名长度
    if len(safe_name) > 200:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:196] + ext
    return safe_name


def validate_email(email):
    """邮箱格式严格验证"""
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """手机号格式验证（中国大陆）"""
    pattern = r'^1[3-9]\d{9}$'
    return re.match(pattern, phone) is not None


def validate_password_strength(password):
    """密码强度验证"""
    if len(password) < 8:
        return False, "密码长度至少8位"
    if not re.search(r'[A-Z]', password):
        return False, "密码需包含至少1个大写字母"
    if not re.search(r'[a-z]', password):
        return False, "密码需包含至少1个小写字母"
    if not re.search(r'\d', password):
        return False, "密码需包含至少1个数字"
    return True, ""


# ═══════════════════════════════════
# 路由
# ═══════════════════════════════════

@app.route("/")
def index():
    """首页"""
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    keyword = request.args.get("keyword", "")
    # 限制搜索关键词长度防 DOS
    if len(keyword) > 100:
        keyword = keyword[:100]
    results = []

    if keyword and username:
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
                if row_dict.get('phone') and len(row_dict['phone']) >= 7:
                    row_dict['phone'] = row_dict['phone'][:3] + '****' + row_dict['phone'][-4:]
                results.append(row_dict)
            conn.close()
        except Exception as e:
            print(f"[DB Error] {e}")

    return render_template("index.html", user=user_info, results=results, keyword=keyword)


@app.route("/login", methods=["GET", "POST"])
@rate_limit(MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_TIME)
def login():
    """登录页面"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        csrf_input = request.form.get("csrf_token", "")

        # CSRF 验证
        if not validate_csrf_token(csrf_input):
            return render_template("login.html", error="会话已过期，请重新登录")

        error_msg = "用户名或密码错误"

        # 检查账户是否被临时锁定（针对 USERS 字典）
        if username in USERS:
            if USERS[username].get('failed_attempts', 0) >= 5:
                error_msg = "账户已被临时锁定，请 5 分钟后再试"

        # 统一验证流程
        user_authenticated = False
        user_found = False

        if username in USERS:
            user_found = True
            if check_password_hash(USERS[username]["password"], password):
                user_authenticated = True
                USERS[username]['failed_attempts'] = 0

        if not user_found:
            try:
                conn = sqlite3.connect("data/users.db")
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = c.fetchone()
                conn.close()
                if row:
                    user_found = True
                    if check_password_hash(row[2], password):
                        user_authenticated = True
            except Exception:
                pass

        if user_authenticated:
            # Session 安全：登录后重新生成 session
            session.clear()
            session.permanent = True
            session['username'] = username
            session['_csrf_token'] = secrets.token_hex(16)
            # 记录登录 IP
            session['login_ip'] = request.remote_addr
            # 重置 IP 级别的登录计数
            ip = request.remote_addr or 'unknown'
            if ip in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip]
            # 同步 SQLite 用户到 USERS
            if not user_found or username not in USERS:
                if row:
                    USERS[username] = {
                        "username": row[1],
                        "password": row[2],
                        "email": row[3],
                        "phone": row[4],
                        "role": "user",
                        "balance": 0,
                        "failed_attempts": 0
                    }
            return redirect(url_for("index"))

        # 登录失败：记录失败次数
        if username in USERS:
            USERS[username]['failed_attempts'] = USERS[username].get('failed_attempts', 0) + 1
        # 记录 IP 级别失败
        ip = request.remote_addr or 'unknown'
        if ip not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[ip] = []
        LOGIN_ATTEMPTS[ip].append(time.time())

        return render_template("login.html", error=error_msg)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面（使用参数化查询）"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        csrf_input = request.form.get("csrf_token", "")

        # CSRF 验证
        if not validate_csrf_token(csrf_input):
            return render_template("register.html", error="会话已过期，请刷新页面重试")

        # ── 输入验证 ──
        if not username or len(username) < 3:
            return render_template("register.html", error="用户名至少3个字符")
        if len(username) > 30:
            return render_template("register.html", error="用户名不能超过30个字符")
        if not re.match(r'^[a-zA-Z0-9_一-鿿]+$', username):
            return render_template("register.html", error="用户名只能包含字母、数字、下划线和中文")

        if password != confirm_password:
            return render_template("register.html", error="两次输入的密码不一致")
        valid, msg = validate_password_strength(password)
        if not valid:
            return render_template("register.html", error=msg)

        if not validate_email(email):
            return render_template("register.html", error="邮箱格式不正确")
        if len(email) > 100:
            return render_template("register.html", error="邮箱地址不能超过100个字符")

        if phone and not validate_phone(phone):
            return render_template("register.html", error="手机号格式不正确（请输入11位中国大陆手机号）")

        # ── 写入数据库 ──
        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            hashed_pw = generate_password_hash(password)
            c.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, phone)
            )
            conn.commit()
            conn.close()

            # 重置该 IP 的登录计数
            ip = request.remote_addr or 'unknown'
            if ip in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip]

            return render_template("login.html", msg="注册成功，请登录")

        except sqlite3.IntegrityError:
            return render_template("register.html", error="该用户名已被注册")
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
    # 限制搜索关键词长度
    if len(keyword) > 100:
        keyword = keyword[:100]
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
            if row_dict.get('phone') and len(row_dict['phone']) >= 7:
                row_dict['phone'] = row_dict['phone'][:3] + '****' + row_dict['phone'][-4:]
            results.append(row_dict)
        conn.close()
    except Exception as e:
        print(f"[Search Error] {e}")

    return render_template("search_results.html", results=results, keyword=keyword)


@app.route("/profile")
def profile():
    '''个人中心 - 根据 URL 参数 user_id 查询用户资料'''
    user_id = request.args.get("user_id", "")
    user_info = None

    # 从 USERS 字典中查找（按顺序匹配索引）
    usernames = list(USERS.keys())
    for idx, uname in enumerate(usernames, start=1):
        if str(idx) == user_id:
            user_info = get_safe_user_info(uname)
            user_info["id"] = idx
            break

    # 如果 USERS 中没找到，从 SQLite 查询
    if not user_info:
        try:
            conn = sqlite3.connect("data/users.db")
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, username, email, phone FROM users WHERE id = ?", (user_id,))
            row = c.fetchone()
            conn.close()
            if row:
                user_info = dict(row)
                # 从 USERS 中获取 balance
                if user_info["username"] in USERS:
                    user_info["balance"] = USERS[user_info["username"]].get("balance", 0)
                    user_info["role"] = USERS[user_info["username"]].get("role", "user")
                else:
                    user_info["balance"] = 0
                    user_info["role"] = "user"
                if user_info.get("phone") and len(user_info["phone"]) >= 7:
                    user_info["phone"] = user_info["phone"][:3] + "****" + user_info["phone"][-4:]
        except Exception as e:
            print(f"[Profile Error] {e}")

    return render_template("profile.html", user=user_info, user_id=user_id)


@app.route("/recharge", methods=["POST"])
def recharge():
    '''充值 - 直接修改用户余额，不校验正负'''
    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")

    try:
        amount = float(amount)
    except ValueError:
        amount = 0.0

    # 从 USERS 字典中查找并修改余额
    usernames = list(USERS.keys())
    for idx, uname in enumerate(usernames, start=1):
        if str(idx) == user_id:
            USERS[uname]["balance"] = USERS[uname].get("balance", 0) + amount
            break
    else:
        # USERS 中没有，从 SQLite 查并同步到 USERS
        try:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            row = c.fetchone()
            conn.close()
            if row:
                uname = row[0]
                if uname not in USERS:
                    USERS[uname] = {
                        "username": uname,
                        "password": "",
                        "email": "",
                        "phone": "",
                        "role": "user",
                        "balance": 0,
                        "failed_attempts": 0
                    }
                USERS[uname]["balance"] = USERS[uname].get("balance", 0) + amount
        except Exception as e:
            print(f"[Recharge Error] {e}")

    return redirect(f"/profile?user_id={user_id}")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """头像上传（带安全校验）"""
    if request.method == "POST":
        file = request.files.get("file")
        csrf_input = request.form.get("csrf_token", "")

        # CSRF 验证
        if not validate_csrf_token(csrf_input):
            return render_template("upload.html", error="会话已过期，请刷新页面重试")

        if not file or not file.filename:
            return render_template("upload.html", error="请选择要上传的文件")

        if file.content_length and file.content_length > 10 * 1024 * 1024:
            return render_template("upload.html", error="文件大小不能超过 10MB")

        filename = safe_filename(file.filename)
        if not filename:
            return render_template("upload.html", error="不支持的文件类型，请上传图片文件（jpg/png/gif/bmp/webp）")

        try:
            upload_dir = os.path.join("static", "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            upload_path = os.path.join(upload_dir, filename)

            # 防重名覆盖：如果文件已存在，添加序号
            base, ext = os.path.splitext(upload_path)
            counter = 1
            while os.path.exists(upload_path):
                upload_path = f"{base}_{counter}{ext}"
                filename = f"{os.path.splitext(filename)[0]}_{counter}{ext}"
                counter += 1

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
