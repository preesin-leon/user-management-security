# 业务逻辑越权漏洞检测报告

> 项目：Flask 用户管理系统  
> 检测重点：越权漏洞 / IDOR / 业务逻辑缺陷

---

## 什么是越权漏洞

越权漏洞（Privilege Escalation / IDOR）属于 OWASP Top 10 "Broken Access Control"。

- **水平越权**：用户A访问用户B的同级别资源
- **垂直越权**：低权限用户访问高权限资源

**根因**：系统仅通过客户端传入的参数（user_id）定位资源，未验证当前用户是否有权访问。

---

## 漏洞汇总（8项）

| 编号 | 漏洞名称 | 严重程度 | 威胁 |
|------|---------|---------|------|
| AUTH-01 | 水平越权 - 个人中心 | 🔴 致命 | 任意用户查看任意用户资料 |
| AUTH-02 | 水平越权 - 充值接口 | 🔴 致命 | 任意用户为任意账户充值/扣款 |
| AUTH-03 | 垂直越权 | 🟠 高危 | 普通用户查看管理员信息 |
| AUTH-04 | 未授权访问 | 🟠 高危 | 未登录可访问资料和充值 |
| AUTH-05 | 金额篡改（负数充值） | 🟠 高危 | 可篡改余额盗取资金 |
| AUTH-06 | CSRF 伪造充值 | 🟠 高危 | 跨站伪造充值操作 |
| AUTH-07 | 导航栏硬编码泄露 | 🟡 中危 | 导航栏暴露admin的user_id |
| AUTH-08 | 参数篡改（无上限充值） | 🟡 中危 | 可充值任意大额金额 |

---

## 漏洞详细分析

### AUTH-01 水平越权 — 个人中心 🔴

**描述**：`/profile?user_id={id}` 完全依赖客户端传入的 user_id，无权限校验。

**代码定位**：
```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "")  # 来自客户端！
    # 直接查询，无任何权限校验
```

**攻击演示**：
```bash
# alice登录后，直接查看admin的资料
curl /profile?user_id=1  # → 看到admin的邮箱、手机、余额
```

### AUTH-02 水平越权 — 充值接口 🔴

**描述**：通过隐藏字段 user_id 指定目标，amount 无正负校验。

**代码定位**：
```python
USERS[uname]["balance"] += amount  # 直接使用客户端数据！
```

**攻击演示**：
```bash
# 拦截充值请求，修改参数
POST /recharge
user_id=1&amount=-99000  # 从admin扣款
```

### AUTH-03 垂直越权 🟠

**描述**：普通用户可查看管理员完整资料。

```bash
# 普通用户执行
curl /profile?user_id=1
# → admin余额: 99999, 邮箱: admin@example.com
```

### AUTH-04 未授权访问 🟠

**描述**：/profile 和 /recharge 没有 @login_required。

```bash
# 无需任何Cookie
curl /profile?user_id=1  # → 返回用户资料
```

### AUTH-05 金额篡改 🟠

**描述**：amount 无正负校验，可负数扣款。

```bash
POST /recharge
user_id=2&amount=-99999  # 从alice账户扣款
```

### AUTH-06 CSRF 伪造充值 🟠

**描述**：充值表单无 CSRF Token，可跨站伪造。

```html
<!-- 攻击者构造的恶意页面 -->
<form action="http://target/recharge" method="POST">
  <input name="user_id" value="999">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

### AUTH-07 导航栏硬编码泄露 🟡

**描述**：导航栏写死 `/profile?user_id=1`。

```html
<!-- base.html -->
<a href="/profile?user_id=1">个人中心</a>
<!-- 所有用户点击都跳转到admin页面 -->
```

### AUTH-08 参数篡改（无上限充值） 🟡

**描述**：amount 无最大值限制。

```bash
POST /recharge
amount=999999999999  # 充值到天文数字
```

---

## 攻击链演示

```
步骤1: 注册普通账户 attacker
步骤2: 登录获取 Session
步骤3: GET /profile?user_id=1       → 获取admin信息
步骤4: GET /profile?user_id=2,3,...  → 遍历所有用户
步骤5: POST /recharge user_id=1&amount=-99000  → 从admin扣款
步骤6: POST /recharge user_id=3(自己)&amount=99000  → 给自己充值
        ✅ 从信息窃取到资金盗取，完整攻击链！
```

---

## 修复方案

### profile 修复
```python
@app.route("/profile")
@login_required
def profile():
    username = session.get("username")  # 从Session获取
    user_info = get_safe_user_info(username)
    return render_template("profile.html", user=user_info)
```

### recharge 修复
```python
@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    username = session.get("username")  # 从Session获取
    amount = float(request.form.get("amount", "0"))
    if amount <= 0: return "金额必须为正数"
    if amount > 10000: return "单次充值上限10000"
    USERS[username]["balance"] += amount
```

### CSRF 修复
```html
<form method="POST" action="/recharge">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

---

## 修复优先级

| 优先级 | 漏洞 | 影响 | 难度 |
|-------|------|------|------|
| P0 立即 | AUTH-01 水平越权-个人中心 | 信息泄露 | 低 |
| P0 立即 | AUTH-02 水平越权-充值 | 资金被盗 | 低 |
| P1 紧急 | AUTH-05 金额篡改 | 资金被盗 | 低 |
| P1 紧急 | AUTH-06 CSRF | 资金被盗 | 中 |
| P2 高 | AUTH-04 未授权访问 | 信息泄露 | 低 |
| P2 高 | AUTH-03 垂直越权 | 信息泄露 | 低 |
| P3 中 | AUTH-08 参数篡改 | 数据异常 | 低 |
| P4 低 | AUTH-07 导航栏泄露 | 信息泄露 | 低 |
