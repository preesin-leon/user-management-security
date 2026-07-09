# 安全漏洞检测与修复报告

> 项目：Flask 用户信息管理平台  
> 检测日期：2026-07-09  
> 检测标准：OWASP Top 10 (2021)

---

## 漏洞统计

| 严重程度 | 数量 |
|---------|------|
| 🔴 致命 | 3 |
| 🟠 高危 | 4 |
| 🟡 中危 | 3 |
| 🔵 低危 | 3 |
| **合计** | **13** |

---

## 漏洞清单

### 🔴 V-01 SQL注入（搜索功能）
- **位置：** `app.py:81` — `f"SELECT ... LIKE '%{keyword}%'"`
- **危害：** 攻击者可通过 UNION/OR 注入获取任意数据库数据
- **修复：** 改用参数化查询 `?` 占位符

### 🔴 V-02 SQL注入（注册功能）
- **位置：** `app.py:136` — `f"INSERT INTO users VALUES ('{username}',...)"`
- **危害：** 攻击者可通过闭合 SQL 语句执行任意操作
- **修复：** 参数化查询 + 输入长度/格式校验

### 🔴 V-03 文件上传路径穿越
- **位置：** `app.py:180` — `file.save(os.path.join("static","uploads",filename))`
- **危害：** 攻击者可通过 `../../` 覆盖任意服务器文件
- **修复：** `os.path.basename()` 移除路径符号

### 🟠 V-04 任意文件上传
- **位置：** `app.py:178-181`
- **危害：** 可上传 .php/.py/.exe 等可执行文件
- **修复：** 白名单校验，仅允许图片扩展名

### 🟠 V-05 密码明文存储
- **位置：** `app.py:46-49`
- **危害：** 数据库泄露即所有密码泄露
- **修复：** 使用 `generate_password_hash()` 哈希存储

### 🟠 V-06 用户名枚举
- **位置：** `app.py:100-112`
- **危害：** 可判断用户名是否存在，辅助暴力破解
- **修复：** 统一错误信息 + 统一验证流程

### 🟠 V-07 XSS 跨站脚本
- **位置：** `index.html:25`
- **危害：** 搜索关键词可注入恶意脚本
- **修复：** Jinja2 自动转义 + 输出编码

### 🟡 V-08 错误信息泄露
- **位置：** `app.py:143`
- **危害：** SQL 异常直接返回给用户，泄露数据库结构
- **修复：** 统一错误提示，不暴露异常信息

### 🟡 V-09 敏感信息日志泄露
- **位置：** `app.py:82/137`
- **危害：** SQL（含密码）打印到控制台
- **修复：** 移除 SQL 日志打印

### 🟡 V-10 Session 无超时
- **位置：** 全局
- **危害：** Session 永不过期
- **修复：** `PERMANENT_SESSION_LIFETIME = 1800`（30分钟）

### 🔵 V-11 无安全 HTTP 头
- **位置：** 全局
- **危害：** 缺少 X-Frame-Options、X-Content-Type-Options 等
- **修复：** 添加 `@app.after_request` 安全头中间件

### 🔵 V-12 手机号明文展示
- **位置：** 搜索结果
- **危害：** 泄露个人敏感信息（PII）
- **修复：** 展示 `138****8000` 掩码格式

### 🔵 V-13 登录无频率限制
- **位置：** `/login`
- **危害：** 可无限次暴力破解
- **修复：** 添加注释提示（可用 Flask-Limiter）

---

## 修复前后代码对比

### SQL注入修复
```python
# 修复前
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
c.execute(sql)

# 修复后
like_pattern = f"%{keyword}%"
c.execute("SELECT * FROM users WHERE username LIKE ?", (like_pattern,))
```

### 文件上传修复
```python
# 修复前
filename = file.filename
file.save(os.path.join("static", "uploads", filename))

# 修复后
filename = safe_filename(file.filename)
# safe_filename(): basename + 白名单 + 去空字节
```

### 密码存储修复
```python
# 修复前
("admin", "admin123", ...)

# 修复后
("admin", generate_password_hash("admin123"), ...)
```

---

## 安全建议

### 高优先级
1. 所有 SQL 查询使用参数化查询
2. 文件上传校验扩展名 + 内容类型
3. 密码使用 bcrypt/scrypt 慢哈希
4. 统一错误提示防止信息泄露

### 中优先级
1. Session 超时设置
2. 安全 HTTP 头
3. 登录频率限制
4. 敏感数据脱敏

### 长期规划
1. HTTPS 部署
2. CSRF 保护（Flask-WTF）
3. 最小权限原则
4. WAF 部署
5. 定期安全扫描
