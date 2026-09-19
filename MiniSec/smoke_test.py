# -*- coding: utf-8 -*-
"""MiniSec 回归冒烟测试。

它模拟浏览器把每个页面都点一遍、把每类攻击都试一遍，
用来确认改动之后平台仍然是好的。

运行（在 MiniSec 目录下，用 venv 里的 Python）：

    python smoke_test.py

退出码 0 = 全部通过；1 = 有检查失败。

覆盖范围：9 个关卡 + 平台安全基线 + 通关进度 + 分库隔离。
其中 SSRF 那一组会临时启动一个本地 HTTP 服务器当"内部靶子"，
这样测试不依赖任何外部网络，也不要求你先把网站跑起来。
"""

import http.server
import io
import os
import re
import socket
import sqlite3
import sys
import threading

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config
import curriculum
import init_db
import progress
import ratelimit
from app import app
from config import PLATFORM_DB, lab_db_path

# 保证数据库 / 靶子目录存在：全新克隆下来也能直接跑测试
init_db.ensure_databases()

app.config["TESTING"] = True

client = app.test_client()

FAILED = []

TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')

# ---------------------------------------------------------------- 限速放宽
# 这个测试会往各关卡发几十次请求，会撞上"实验查询 40 次/分钟"的正常限速。
# 所以在测试期间临时把额度调大，测完再还原 ——
# 限速本身仍然在下面单独验证（那一组会临时把额度调小）。
_ORIGINAL_RULES = dict(ratelimit.RULES)
ratelimit.RULES["lab_query"] = (60, 10000)
ratelimit.RULES["lab_reset"] = (60, 10000)
ratelimit.reset_all()


def check(name, condition, detail=""):
    """记录一条检查结果。"""

    if condition:
        print("  PASS  " + name)
    else:
        FAILED.append(name)
        print("  FAIL  " + name + "  " + detail)


def csrf_token(path="/login"):
    """从页面里取出 CSRF 令牌（模拟浏览器读取表单里的隐藏字段）。"""

    body = client.get(path).get_data(as_text=True)

    found = TOKEN_RE.search(body)

    return found.group(1) if found else ""


def as_text(response):
    return response.get_data(as_text=True)


# ---------------------------------------------------------------- 各关卡提交

def post_level1(payload, token=None):
    return client.post(
        "/labs/sql/level1",
        data={
            "username": payload,
            "csrf_token": token if token is not None else TOKEN,
        },
    )


def level1_text(payload):
    return as_text(post_level1(payload))


def level2_text(username, password):
    return as_text(
        client.post(
            "/labs/sql/level2",
            data={
                "username": username,
                "password": password,
                "csrf_token": TOKEN,
            },
        )
    )


def level3_text(payload):
    return as_text(
        client.post(
            "/labs/sql/level3",
            data={"username": payload, "csrf_token": TOKEN},
        )
    )


def xss1_text(payload):
    return as_text(client.get("/labs/xss/level1?q=" + payload))


def xss2_text(content, author="tester"):
    return as_text(
        client.post(
            "/labs/xss/level2",
            data={"author": author, "content": content, "csrf_token": TOKEN},
        )
    )


def upload_text(filename, content):
    return as_text(
        client.post(
            "/labs/upload/level1",
            data={
                "file": (io.BytesIO(content), filename),
                "csrf_token": TOKEN,
            },
            content_type="multipart/form-data",
        )
    )


def ssrf_text(url):
    return as_text(
        client.post(
            "/labs/ssrf/level1",
            data={"url": url, "csrf_token": TOKEN},
        )
    )


def cmdi_text(host):
    return as_text(
        client.post(
            "/labs/cmdi/level1",
            data={"host": host, "csrf_token": TOKEN},
        )
    )


def reset_lab_endpoint(path):
    return client.post(path, data={"csrf_token": TOKEN}, follow_redirects=True)


# ---------------------------------------------------------------- 数据库工具

def tables_in(path):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    names = {row[0] for row in cursor.fetchall()}
    conn.close()
    return names


def scalar(path, sql, args=()):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute(sql, args)
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def lab_usernames():
    conn = sqlite3.connect(lab_db_path("sql"))
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sql_users ORDER BY id")
    names = [row[0] for row in cursor.fetchall()]
    conn.close()
    return names


def login_usernames():
    conn = sqlite3.connect(lab_db_path("sql_login"))
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM login_users ORDER BY id")
    names = [row[0] for row in cursor.fetchall()]
    conn.close()
    return names


# ---------------------------------------------------------------- 内部靶子（SSRF 用）
# 这一组的检查需要一个"内网服务"当目标。
# 自己在本地起一个临时 HTTP 服务器，比依赖"网站已经跑起来"可靠得多，
# 而且能证明"服务端真的发出了这个请求"。

class _InternalHandler(http.server.BaseHTTPRequestHandler):
    """模拟内部接口：只在 /internal 路径上带内部标记。

    故意让别的路径返回普通内容 —— 这样测试才能验证
    "打到内网但没有内部标记"这种情况不会被误判为通关。
    """

    def do_GET(self):

        if self.path.startswith("/internal"):

            body = (
                "INTERNAL-ONLY\n"
                "service = test-internal\n"
                "flag{ssrf_internal_access}\n"
            ).encode("utf-8")

        else:

            body = "只是一个普通页面，没有内部标记。\n".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        """别把访问日志打到测试输出里。"""
        return


def start_internal_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _InternalHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# ================================================================
# 开始测试
# ================================================================

TOKEN = csrf_token()

print("== 数据库结构：平台库与六个靶子库必须分开 ==")

platform_tables = tables_in(PLATFORM_DB)
sql_tables = tables_in(lab_db_path("sql"))
login_tables = tables_in(lab_db_path("sql_login"))
union_tables = tables_in(lab_db_path("sql_union"))
xss_tables = tables_in(lab_db_path("xss"))
upload_tables = tables_in(lab_db_path("upload"))
cmdi_tables = tables_in(lab_db_path("cmdi"))
idor_tables = tables_in(lab_db_path("idor"))
csrf_tables = tables_in(lab_db_path("csrf"))

check(
    "平台库包含 users / labs / progress",
    {"users", "labs", "progress"} <= platform_tables,
)
check("Level 1 靶子库只有 sql_users", sql_tables - {"sqlite_sequence"} == {"sql_users"})
check(
    "Level 2 靶子库只有 login_users",
    login_tables - {"sqlite_sequence"} == {"login_users"},
)
check(
    "Level 3 靶子库有 union_users 与 secret_notes",
    {"union_users", "secret_notes"} <= union_tables,
)
check("XSS 靶子库只有 xss_guestbook", xss_tables - {"sqlite_sequence"} == {"xss_guestbook"})
check(
    "文件上传靶子库只有 uploaded_files",
    upload_tables - {"sqlite_sequence"} == {"uploaded_files"},
)
check(
    "命令注入靶子库只有 command_runs",
    cmdi_tables - {"sqlite_sequence"} == {"command_runs"},
)
check(
    "越权靶子库有 idor_users 与 idor_notes",
    {"idor_users", "idor_notes"} <= idor_tables,
)
check(
    "CSRF 靶子库只有 csrf_users",
    csrf_tables - {"sqlite_sequence"} == {"csrf_users"},
)

all_lab_tables = set()
for name in config.LAB_DB_FILES:
    all_lab_tables |= tables_in(lab_db_path(name))

check(
    "任何一个靶子库里都没有平台账号表",
    not ({"users", "labs", "progress"} & all_lab_tables),
    "实际: " + str({"users", "labs", "progress"} & all_lab_tables),
)
check(
    "靶子库之间互不包含对方的表（一关一库）",
    "sql_users" not in login_tables
    and "login_users" not in union_tables
    and "xss_guestbook" not in upload_tables,
)
check(
    "靶子目录存在（上传目录 / 命令注入沙箱）",
    config.UPLOAD_DIR.exists() and config.SANDBOX_DIR.exists(),
)
check(
    "沙箱里有本关的目标文件 secret.txt",
    (config.SANDBOX_DIR / config.SANDBOX_SECRET_FILE).exists(),
)

print()
print("== 登录与权限 ==")

response = client.get("/labs", follow_redirects=False)
check(
    "未登录访问 /labs 会跳转到 /login",
    response.status_code == 302 and "/login" in response.headers.get("Location", ""),
)

for path in (
    "/labs/sql/level3",
    "/labs/xss/level1",
    "/labs/upload/level1",
    "/labs/ssrf/level1",
    "/labs/cmdi/level1",
):
    response = client.get(path, follow_redirects=False)
    check(
        "未登录访问 " + path + " 会跳转到 /login",
        response.status_code == 302
        and "/login" in response.headers.get("Location", ""),
    )

body = client.post(
    "/login",
    data={"username": "admin", "password": "wrong", "csrf_token": TOKEN},
    follow_redirects=True,
).get_data(as_text=True)
check("错误密码给出提示", "用户名或密码错误" in body)

body = client.post(
    "/login",
    data={"username": "admin", "password": "123456", "csrf_token": TOKEN},
    follow_redirects=True,
).get_data(as_text=True)
check("admin/123456 登录成功", "当前用户" in body and "admin" in body)

body = client.post(
    "/login",
    data={"username": "admin' OR '1'='1' --", "password": "x", "csrf_token": TOKEN},
    follow_redirects=True,
).get_data(as_text=True)
check("平台登录对注入免疫（参数化查询）", "用户名或密码错误" in body)

print()
print("== 实验列表与关卡导航 ==")

body = as_text(client.get("/labs"))
check(
    "/labs 列出全部 7 个实验",
    all(
        s in body
        for s in [
            "SQL注入实验",
            "XSS跨站脚本实验",
            "文件上传实验",
            "SSRF实验",
            "命令注入实验",
            "越权访问实验",
            "CSRF跨站请求伪造实验",
        ]
    ),
)
check("所有实验都可以进入（一个「开发中」都没有）", "开发中" not in body)
check("列表页显示总进度", "总进度" in body)
check("首页也显示总进度", "总进度" in as_text(client.get("/")) or "progress" in as_text(client.get("/")))

for lab_name, level_texts in (
    ("sql", ["Level 1 基础查询注入", "Level 2 登录绕过", "Level 3 UNION查询"]),
    ("xss", ["Level 1 反射型XSS", "Level 2 存储型XSS"]),
    ("upload", ["Level 1 文件上传"]),
    ("ssrf", ["Level 1 服务端请求伪造"]),
    ("cmdi", ["Level 1 命令注入"]),
    ("idor", ["Level 1 水平越权"]),
    ("csrf", ["Level 1 跨站请求伪造"]),
):
    body = as_text(client.get("/labs/" + lab_name))
    check(
        "/labs/" + lab_name + " 列出关卡且都是可进入状态",
        all(t in body for t in level_texts) and "开发中" not in body,
    )

body = as_text(client.get("/labs/sql"))
check(
    "关卡列表有关卡链接",
    all(
        ('href="/labs/sql/level%d"' % i) in body
        for i in (1, 2, 3)
    ),
)

response = client.get("/labs/not_exist")
check("未知 lab 返回 404", response.status_code == 404)
check("404 使用双语错误页", "页面不存在" in as_text(response))

body = as_text(client.get("/labs/csrf"))
check("/labs/csrf 渲染关卡列表而不是占位页", "Level 1 跨站请求伪造" in body)

print()
print("== 关卡页公共结构（五段式）==")

for path, marker in (
    ("/labs/sql/level3", "UNION Based Injection"),
    ("/labs/xss/level1", "Reflected XSS"),
    ("/labs/xss/level2", "Stored XSS"),
    ("/labs/upload/level1", "Unrestricted File Upload"),
    ("/labs/ssrf/level1", "Server-Side Request Forgery"),
    ("/labs/cmdi/level1", "OS Command Injection"),
):
    body = as_text(client.get(path))
    check(
        path + " 含核心区块（后端代码 / 攻击分析 / 分层提示）",
        all(
            s in body
            for s in ["Backend Code", "Attack Analysis", "Hint 1", "实验说明"]
        ),
    )

print()
print("== SQL Level 1 基础查询注入 ==")

body = level1_text("admin")
check("正常查询 admin：返回 1 行且不判完成", "admin123" in body and "LEVEL 1 COMPLETED" not in body)

body = level1_text("nobody")
check("查无此人时给出提示", "No user found" in body)

body = level1_text("admin' OR '1'='1' --")
check(
    "Payload 注入成功并判完成",
    all(
        s in body
        for s in ["LEVEL 1 COMPLETED", "SQL Injection Successful", "administrator", "guest"]
    ),
)
check(
    "完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "参数化查询"]),
)
check("结果表格高亮了多出来的用户", 'class="leaked"' in body)

body = level1_text("admin'")
check("单引号触发 SQL 错误分析", "SQL 执行出错" in body)

body = level1_text("bob' --")
check(
    "单行注入：命中检测但不判完成",
    "检测到可疑输入" in body and "LEVEL 1 COMPLETED" not in body,
)

body = level1_text("<script>alert(1)</script>")
check(
    "L1 输入回显被 HTML 转义（无反射型 XSS）",
    "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body,
)

print()
print("== SQL Level 2 登录绕过 ==")

body = level2_text("admin", "admin123")
check("正常登录：返回 admin 记录但不判完成", "administrator" in body and "LOGIN BYPASSED" not in body)
check("正常登录给出「这是正常登录」的说明", "这是一次正常登录" in body)

body = level2_text("admin", "wrong-password")
check("密码错误时不返回任何记录", "用户名或密码错误" in body)

body = level2_text("admin' --", "anything")
check("Payload admin' -- 绕过成功并判完成", all(s in body for s in ["LOGIN BYPASSED", "administrator"]))
check(
    "L2 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "参数化查询"]),
)
check("L2 结果表格高亮了管理员那一行", 'class="leaked"' in body)
check("L2 页面说明不会改变平台登录状态", "不会" in body and "platform.db" in body)

body = level2_text("' OR '1'='1' --", "anything")
check("恒真条件同样可以绕过登录", "LOGIN BYPASSED" in body)

body = level2_text("admin'", "anything")
check("L2 单引号触发 SQL 错误分析", "SQL 执行出错" in body)

body = level2_text("alice' --", "anything")
check("绕过了密码但登入的是 alice：不判完成", "LOGIN BYPASSED" not in body and "alice" in body)

body = level2_text("<script>alert(1)</script>", "x")
check(
    "L2 输入回显被 HTML 转义",
    "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body,
)

print()
print("== SQL Level 3 UNION 查询 ==")

body = level3_text("carol")
check(
    "正常查询：返回 4 列且不判完成",
    "carol123" in body and "本次查询 <b>4</b> 列" in body and "LEVEL 3 COMPLETED" not in body,
)

body = level3_text("' UNION SELECT id, title, content, 'x' FROM secret_notes --")
check(
    "UNION payload 读到内部表并判完成",
    all(s in body for s in ["LEVEL 3 COMPLETED", "flag{union_injection_works}", "secret_notes"]),
)
check("L3 结果表格高亮了泄露的那一行", 'class="leaked"' in body)
check(
    "L3 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "最小权限"]),
)

body = level3_text("' UNION SELECT 1,2,3 --")
check("列数不一致时给出专门提示", "列数不一致" in body and "ORDER BY" in body)

body = level3_text("carol' ORDER BY 5 --")
check("ORDER BY 越界触发 SQL 错误分析", "SQL 执行出错" in body)

body = level3_text("nobody")
check("查无此人时给出提示", "没有这个用户" in body)

print()
print("== XSS Level 1 反射型 ==")

# 先重置一次：保证下面的通关进度是从干净状态开始记的
# （重置 xss 会把两关的进度都清掉，所以必须放在 L1 测试之前）
reset_lab_endpoint("/labs/xss/level2/reset")

body = xss1_text("hello")
check("普通搜索：正常回显且不判完成", "hello" in body and "XSS SUCCESSFUL" not in body)
check("页面展示「渲染进页面的 HTML」", "Rendered HTML" in as_text(client.get("/labs/xss/level1?q=hello")))

body = xss1_text("%3Cscript%3Ealert(1)%3C/script%3E")
check(
    "L1 不过滤：最经典的 script 标签直接生效",
    all(s in body for s in ["XSS SUCCESSFUL", "script 标签"]),
)

body = xss1_text("%3Cimg+src%3Dx+onerror%3Dalert(1)%3E")
check(
    "L1 换一种可执行结构同样生效（事件属性）",
    all(s in body for s in ["XSS SUCCESSFUL", "事件属性"]),
)
check(
    "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "输出编码"]),
)
check("L1 页面说明这一关不做过滤", "不做任何过滤" in body)

body = xss1_text("%3Cspan%3Ehello%3C/span%3E")
check(
    "L1 普通标签（无可执行结构）不判通关",
    "XSS SUCCESSFUL" not in body and "可执行结构" in body,
)

check(
    "两关都提供「可执行结构速查表」",
    "可执行结构速查表" in as_text(client.get("/labs/xss/level1"))
    and "可执行结构速查表" in as_text(client.get("/labs/xss/level2")),
)

print()
print("== XSS Level 2 存储型 ==")

body = xss2_text("<b>hello</b>")
check("普通留言（含标记）：保存成功且不判完成", "hello" in body and "STORED XSS SUCCESSFUL" not in body)

body = xss2_text("<script>alert(1)</script>")
check("script 标签被过滤掉，打不通", "STORED XSS SUCCESSFUL" not in body)

body = xss2_text("<img src=x onerror=alert(1)>")
check("事件属性留言触发判完成", all(s in body for s in ["STORED XSS SUCCESSFUL", "可执行"]))
check(
    "L2 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "白名单"]),
)
check(
    "留言真的落到了数据库里",
    scalar(
        lab_db_path("xss"),
        "SELECT COUNT(*) FROM xss_guestbook WHERE content LIKE '%onerror%'",
    )
    >= 1,
)
check("L2 页面列出了「库里的原始内容」对比", "库里的原始内容" in body)

print()
print("== 文件上传 ==")

body = upload_text("avatar.png", b"\x89PNG\r\n\x1a\n" + b"0" * 200)
check("上传真图片：保存成功但不判完成", "是图片（PNG）" in body and "BYPASSED" not in body)

body = upload_text("shell.php", b"<?php echo 1; ?>")
check("黑名单里的后缀被拒绝", "黑名单" in body and "BYPASSED" not in body)

body = upload_text("note.html", b"<html><script>alert('uploaded')</script></html>")
check(
    "非图片文件绕过校验并判完成",
    all(s in body for s in ["UPLOAD VALIDATION BYPASSED", "不是图片 NOT an image"]),
)
check("页面给出了可直接访问的地址", "/static/uploads/note.html" in body)
check(
    "文件真的写到了 web 可访问的目录里",
    (config.UPLOAD_DIR / "note.html").exists(),
)
check(
    "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "白名单"]),
)
check(
    "上传账本记录了这次上传",
    scalar(lab_db_path("upload"), "SELECT COUNT(*) FROM uploaded_files") >= 2,
)
check("页面区分了客户端声明类型与文件头", "文件头" in body and "Content-Type" in body)

print()
print("== SSRF（用本机临时服务器当内部靶子）==")

server, port = start_internal_server()
internal_url = "http://127.0.0.1:%d/internal/admin-config" % port

try:

    body = ssrf_text("http://127.0.0.1:%d/not-exist-marker" % port)
    check(
        "请求内网地址但没有内部标记：不判完成",
        "SSRF SUCCESSFUL" not in body and "没有内部标记" in body,
    )

    body = ssrf_text(internal_url)
    check(
        "请求内网靶子并拿到内部标记：判完成",
        all(s in body for s in ["SSRF SUCCESSFUL", "INTERNAL-ONLY"]),
    )
    check("页面标出了目标是否内网地址", "是否内网地址" in body and "是 YES" in body)
    check(
        "服务端真的发出了这个请求（拿到了响应体）",
        "flag{ssrf_internal_access}" in body,
    )
    check(
        "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
        all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "白名单"]),
    )

    body = ssrf_text("file:///etc/passwd")
    check("非 http(s) 协议被拒绝", "只支持 http" in body and "SSRF SUCCESSFUL" not in body)

    body = ssrf_text("http://127.0.0.1:1/")
    check("连不上的地址给出失败提示", "请求失败" in body)

finally:

    server.shutdown()
    server.server_close()

print()
print("== 命令注入 ==")

body = cmdi_text("127.0.0.1")
check("正常诊断：执行成功且不判完成", "退出码" in body and "COMMAND INJECTION SUCCESSFUL" not in body)

if os.name == "nt":
    payload = "127.0.0.1 & type secret.txt"
else:
    payload = "127.0.0.1; cat secret.txt"

body = cmdi_text(payload)
check(
    "追加命令读到沙箱里的 flag：判完成",
    all(s in body for s in ["COMMAND INJECTION SUCCESSFUL", "flag{command_injection_works}"]),
)
check("页面展示了实际执行的完整命令", payload in body or "&amp;" in body)
check(
    "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "shell=False"]),
)
check(
    "执行历史被记录进靶子库",
    scalar(lab_db_path("cmdi"), "SELECT COUNT(*) FROM command_runs") >= 2,
)
check("页面列出了沙箱目录里的文件", "secret.txt" in body)
check(
    "页面明确提示这一关会真的执行系统命令",
    "真的会执行系统命令" in as_text(client.get("/labs/cmdi/level1")),
)

print()
print("== 越权访问 IDOR ==")

reset_lab_endpoint("/labs/idor/level1/reset")

body = as_text(client.get("/labs/idor/level1?as=1"))
check(
    "以 alice 身份：列表只有自己的 2 条笔记",
    body.count('href="/labs/idor/level1?as=1&note_id=') == 2,
)
check(
    "列表不出现别人的笔记标题（bob 的笔记看不到）",
    "读书笔记" not in body and "购物清单" in body,
)
check("页面讲清了认证与授权的区别", "认证" in body and "授权" in body)

body = as_text(client.get("/labs/idor/level1?as=1&note_id=1"))
check("读自己的笔记：不判通关", "IDOR SUCCESSFUL" not in body and "正常访问" in body)

body = as_text(client.get("/labs/idor/level1?as=1&note_id=3"))
check(
    "身份不变、改 id 读到 bob 的笔记：判通关",
    all(s in body for s in ["IDOR SUCCESSFUL", "bob"]),
)
check(
    "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "owner_id"]),
)

body = as_text(client.get("/labs/idor/level1?as=1&note_id=6"))
check(
    "读到管理员的私密笔记并拿到 flag",
    "flag{idor_horizontal_access}" in body and "私密" in body,
)
check("页面标出「归属不是你的」", "不是你的" in body)

body = as_text(client.get("/labs/idor/level1?as=1&note_id=999"))
check("不存在的 id 给出提示而不是报错", "没有 id = 999" in body)

body = as_text(client.get("/labs/idor/level1?as=99&note_id=1"))
check("非法身份参数被兜底成默认身份", "IDOR SUCCESSFUL" not in body)

print()
print("== CSRF 跨站请求伪造 ==")

reset_lab_endpoint("/labs/csrf/level1/reset")

ATTACKER_EMAIL = "attacker@evil.example"


def csrf_profile(email, with_token=True):
    data = {"email": email}
    if with_token:
        data["csrf_token"] = TOKEN
    return as_text(
        client.post("/labs/csrf/level1/profile", data=data, follow_redirects=True)
    )


body = as_text(client.get("/labs/csrf/level1"))
check("以 victim 身份进入，邮箱是原值", "victim" in body and "victim@example.com" in body)
check(
    "页面讲清关键事实：Cookie 是浏览器自动带的",
    "自动带上 Cookie" in body and "不校验" in body,
)

body = csrf_profile("me@example.com")
check(
    "正常改邮箱：能改成，但不判通关",
    "me@example.com" in body and "CSRF SUCCESSFUL" not in body,
)
check("页面提示「表单带了令牌但没校验」", "没校验" in body or "没有校验" in body)

attacker = as_text(client.get("/labs/csrf/attacker"))
check(
    "攻击者页面：自动提交表单 + 指向靶子接口 + 不带令牌",
    all(s in attacker for s in ["csrf-form", "attacker@evil.example", "/labs/csrf/level1/profile"])
    and "csrf_token" not in attacker,
)
check("攻击者页面有明显提示说明这是演示", "演示说明" in attacker)

reset_lab_endpoint("/labs/csrf/level1/reset")

body = csrf_profile(ATTACKER_EMAIL, with_token=False)
check(
    "不带令牌的请求照样改成功：判通关",
    all(s in body for s in ["CSRF SUCCESSFUL", ATTACKER_EMAIL]),
)
check(
    "页面展示了这次请求的四要素（Cookie / 令牌 / Referer / 请求体）",
    all(s in body for s in ["Cookie", "CSRF 令牌", "Referer", "请求体"]),
)
check(
    "L1 完成后展示漏洞代码 / 修复代码 / 实验总结",
    all(s in body for s in ["Vulnerable Code", "Secure Code", "实验总结", "SameSite"]),
)
check(
    "靶子库里 victim 的邮箱真的被改了",
    scalar(lab_db_path("csrf"), "SELECT email FROM csrf_users WHERE username = 'victim'")
    == ATTACKER_EMAIL,
)

response = client.post("/labs/csrf/level1/reset", data={})
check(
    "豁免是定向的：平台接口（恢复出厂）仍然要求令牌（400）",
    response.status_code == 400,
)

# 注意：这里故意**不**重置靶子。
# 重置会连带清掉这一关的通关进度，而下面「通关进度记录」那一组正要检查它；
# 恢复出厂的验证统一放在后面那一组做。

print()
print("== 通关进度记录 ==")

check("SQL 实验记录了 3 关通关", progress.cleared_levels("sql") == {1, 2, 3}, str(progress.cleared_levels("sql")))
check("XSS 实验记录了 2 关通关", progress.cleared_levels("xss") == {1, 2}, str(progress.cleared_levels("xss")))
check("文件上传记录了 1 关通关", progress.cleared_levels("upload") == {1})
check("SSRF 记录了 1 关通关", progress.cleared_levels("ssrf") == {1})
check("命令注入记录了 1 关通关", progress.cleared_levels("cmdi") == {1})
check("越权访问记录了 1 关通关", progress.cleared_levels("idor") == {1})
check("CSRF 记录了 1 关通关", progress.cleared_levels("csrf") == {1})
check("总关卡数是 10", progress.total_levels() == 10, str(progress.total_levels()))
check("总通关数与各实验之和一致", progress.total_cleared() == 10, str(progress.total_cleared()))

body = as_text(client.get("/labs"))
check("列表页显示「全部通关」徽标", "全部通关" in body)

body = as_text(client.get("/labs/sql"))
check("关卡页显示「已通关」徽标", "已通关 Cleared" in body)

body = as_text(client.get("/labs/sql/level3"))
check("再次进入已通关的关卡会提示「之前已经通关过」", "已经通关过" in body)

print()
print("== 数据 ==")

check("Level 1 靶子库含 4 个假用户", len(lab_usernames()) == 4)
check("Level 2 靶子库含 4 个假账号", len(login_usernames()) == 4)
check(
    "Level 3 内部表里有 flag",
    scalar(lab_db_path("sql_union"), "SELECT COUNT(*) FROM secret_notes WHERE content LIKE 'flag{%'") == 1,
)

conn = sqlite3.connect(PLATFORM_DB)
cursor = conn.cursor()
cursor.execute("SELECT password FROM users WHERE username = 'admin'")
row = cursor.fetchone()
conn.close()

check("平台密码以哈希值存储（不是明文）", row is not None and row[0] != "123456" and len(row[0]) > 20)

print()
print("== 上线安全防护 ==")

response = client.get("/robots.txt")
check("robots.txt 禁止收录", response.status_code == 200 and "Disallow: /" in as_text(response))

response = client.post("/login", data={"username": "admin", "password": "123456"})
check("没有 CSRF 令牌的表单被拒绝（400）", response.status_code == 400)

response = client.post(
    "/login",
    data={"username": "admin", "password": "123456", "csrf_token": "伪造的令牌"},
)
check("伪造的 CSRF 令牌被拒绝（400）", response.status_code == 400)
check("CSRF 拒绝页有双语提示", "表单校验失败" in as_text(response))

# 限速：临时把"实验查询"上限调成 2 次/分钟
saved_rule = ratelimit.RULES["lab_query"]

try:

    ratelimit.RULES["lab_query"] = (60, 2)
    ratelimit.reset_all()

    first = post_level1("admin").status_code
    second = post_level1("admin").status_code
    third = post_level1("admin")

    check(
        "限速：额度内正常（前 2 次 200）",
        first == 200 and second == 200,
        "实际 " + str(first) + " / " + str(second),
    )
    check("限速：超出后返回 429", third.status_code == 429, "实际 " + str(third.status_code))
    check(
        "限速页有双语提示与 Retry-After",
        "请求过于频繁" in as_text(third) and third.headers.get("Retry-After") == "60",
    )

finally:

    ratelimit.RULES["lab_query"] = saved_rule
    ratelimit.reset_all()

print()
print("== 恢复出厂（每一关各管各的）==")

conn = sqlite3.connect(lab_db_path("sql"))
conn.execute("UPDATE sql_users SET username = 'hacked' WHERE id = 1")
conn.commit()
conn.close()
check("L1 数据被改坏（准备工作）", lab_usernames()[0] == "hacked")

reset_lab_endpoint("/labs/sql/reset")
check(
    "L1 恢复出厂：回到原始 4 个用户",
    lab_usernames() == ["admin", "alice", "bob", "guest"],
    "实际 " + str(lab_usernames()),
)
check(
    "重置 L1 只清掉 L1 的进度，L3 的通关记录还在（一关一库）",
    1 not in progress.cleared_levels("sql") and 3 in progress.cleared_levels("sql"),
    str(progress.cleared_levels("sql")),
)

conn = sqlite3.connect(lab_db_path("sql_login"))
conn.execute("UPDATE login_users SET username = 'hacked' WHERE id = 1")
conn.commit()
conn.close()
reset_lab_endpoint("/labs/sql/level2/reset")
check(
    "L2 恢复出厂：登录靶子回到原始 4 个账号",
    login_usernames() == ["admin", "alice", "bob", "support"],
    "实际 " + str(login_usernames()),
)
check("L2 恢复出厂不影响 Level 1 数据", lab_usernames() == ["admin", "alice", "bob", "guest"])

reset_lab_endpoint("/labs/sql/level3/reset")
check(
    "L3 恢复出厂：内部表 flag 还在且只有一行",
    scalar(lab_db_path("sql_union"), "SELECT COUNT(*) FROM secret_notes") == 3,
)

reset_lab_endpoint("/labs/xss/level2/reset")
check(
    "XSS 恢复出厂：留言板回到最初的 2 条正常留言",
    scalar(lab_db_path("xss"), "SELECT COUNT(*) FROM xss_guestbook") == 2,
)

reset_lab_endpoint("/labs/upload/level1/reset")
check("上传恢复出厂：上传目录被清空", len(os.listdir(config.UPLOAD_DIR)) == 0)
check(
    "上传恢复出厂：账本被清空",
    scalar(lab_db_path("upload"), "SELECT COUNT(*) FROM uploaded_files") == 0,
)

reset_lab_endpoint("/labs/csrf/level1/reset")
check(
    "CSRF 恢复出厂：靶子账号回到 2 个、邮箱复原",
    scalar(lab_db_path("csrf"), "SELECT COUNT(*) FROM csrf_users") == 2
    and scalar(lab_db_path("csrf"), "SELECT email FROM csrf_users WHERE username = 'victim'")
    == "victim@example.com",
)

reset_lab_endpoint("/labs/idor/level1/reset")
check(
    "越权恢复出厂：用户与笔记回到原始 4 用户 / 7 条笔记",
    scalar(lab_db_path("idor"), "SELECT COUNT(*) FROM idor_users") == 4
    and scalar(lab_db_path("idor"), "SELECT COUNT(*) FROM idor_notes") == 7,
)

reset_lab_endpoint("/labs/cmdi/level1/reset")
check(
    "命令注入恢复出厂：沙箱重建且 secret.txt 回来了",
    (config.SANDBOX_DIR / config.SANDBOX_SECRET_FILE).exists(),
)
check(
    "命令注入恢复出厂：执行历史被清空",
    scalar(lab_db_path("cmdi"), "SELECT COUNT(*) FROM command_runs") == 0,
)

check(
    "恢复出厂会清掉该实验的通关进度",
    progress.cleared_levels("cmdi") == set()
    and progress.cleared_levels("upload") == set()
    and progress.cleared_levels("idor") == set(),
    "cmdi=" + str(progress.cleared_levels("cmdi")) + " upload=" + str(progress.cleared_levels("upload")),
)

conn = sqlite3.connect(PLATFORM_DB)
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
platform_admin = cursor.fetchone()[0]
conn.close()
check("所有恢复出厂都不影响平台账号（分库隔离生效）", platform_admin == 1)

print()
print("== 靶场自身不泄漏平台数据 ==")

# 平台库文件路径不应该出现在任何关卡页面上（否则等于给了攻击者地图）
body = as_text(client.get("/labs/sql/level1"))
check("关卡页面不暴露平台库路径", str(PLATFORM_DB) not in body)
check("页面有免责声明", "仅用于网络安全教学实验" in body)

# 收尾：还原限速规则
ratelimit.RULES.clear()
ratelimit.RULES.update(_ORIGINAL_RULES)

print()

if FAILED:
    print(str(len(FAILED)) + " check(s) FAILED")
    for name in FAILED:
        print("   - " + name)
    sys.exit(1)

print("All smoke checks passed.")
sys.exit(0)
