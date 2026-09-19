# -*- coding: utf-8 -*-
"""逐关验收脚本。

和 smoke_test.py 的分工：
    smoke_test.py    回归测试：135 项自动化检查，改代码后跑它，确认没改坏东西
    verify_levels.py 逐关验收：一关一条命令，把「输入 / 实际结果 / 判定」打给你看

用法（在 MiniSec 目录下）：

    python verify_levels.py            逐关跑一遍，最后给出汇总
    python verify_levels.py sql1       只验收 SQL Level 1
    python verify_levels.py list       列出所有关卡编号

每一关都会跑**一个正例 + 一个反例**：
正例必须通关，反例必须不通关 —— 两边都对，才说明判定既不过松也不过严。

脚本用的是 Flask 的测试客户端（不是网络请求），所以不需要先把网站跑起来；
但它渲染的是真实的模板、执行的是真实的路由逻辑。
想亲眼看到弹窗，请按每关打印的「浏览器复核」地址自己打一遍。
"""

import http.server
import io
import os
import re
import sys
import threading

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config
import init_db
import progress
from app import app

init_db.ensure_databases()

app.config["TESTING"] = True
client = app.test_client()

TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')

LINE = "─" * 66


def _token():
    body = client.get("/login").get_data(as_text=True)
    found = TOKEN_RE.search(body)
    return found.group(1) if found else ""


def _login():
    token = _token()
    client.post(
        "/login",
        data={"username": "admin", "password": "123456", "csrf_token": token},
    )
    return token


TOKEN = _login()


# ---------------------------------------------------------------- 提交工具

def post(path, data):
    payload = dict(data)
    payload["csrf_token"] = TOKEN
    return client.post(path, data=payload).get_data(as_text=True)


def get(path):
    return client.get(path).get_data(as_text=True)


def post_file(filename, content):
    return client.post(
        "/labs/upload/level1",
        data={
            "file": (io.BytesIO(content), filename),
            "csrf_token": TOKEN,
        },
        content_type="multipart/form-data",
    ).get_data(as_text=True)


# ---------------------------------------------------------------- 内部靶子（SSRF 用）

class _Internal(http.server.BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path.startswith("/internal"):
            body = (
                "INTERNAL-ONLY\nservice = local-target\n"
                "flag{ssrf_internal_access}\n"
            ).encode("utf-8")
        else:
            body = "普通页面，没有内部标记。\n".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


# ---------------------------------------------------------------- 各关验收

def check_sql1():
    """SQL Level 1：基础查询注入。"""

    init_db.reset_lab("sql")

    body = post("/labs/sql/level1", {"username": "admin' OR '1'='1' --"})

    positive = "LEVEL 1 COMPLETED" in body and 'class="leaked"' in body

    body2 = post("/labs/sql/level1", {"username": "bob' --"})

    negative = "LEVEL 1 COMPLETED" not in body2 and "检测到可疑输入" in body2

    return [
        ("正例　用户名 = admin' OR '1'='1' --", positive, "出现 LEVEL 1 COMPLETED，结果表 4 行、多出来的高亮"),
        ("反例　用户名 = bob' --", negative, "命中注入特征，但不判通关（只返回 1 行）"),
    ]


def check_sql2():
    """SQL Level 2：登录绕过。"""

    init_db.reset_lab("sql_login")

    body = post("/labs/sql/level2", {"username": "admin' --", "password": "whatever"})

    positive = "LOGIN BYPASSED" in body and "administrator" in body

    body2 = post("/labs/sql/level2", {"username": "admin", "password": "admin123"})

    negative = "LOGIN BYPASSED" not in body2 and "这是一次正常登录" in body2

    return [
        ("正例　用户名 = admin' --　密码 = whatever", positive, "出现 LOGIN BYPASSED，身份 administrator"),
        ("反例　用户名 = admin　密码 = admin123", negative, "正常登录，明确提示「不算通关」"),
    ]


def check_sql3():
    """SQL Level 3：UNION 跨表读取。"""

    init_db.reset_lab("sql_union")

    payload = "' UNION SELECT id, title, content, 'x' FROM secret_notes --"

    body = post("/labs/sql/level3", {"username": payload})

    positive = (
        "LEVEL 3 COMPLETED" in body
        and "flag{union_injection_works}" in body
        and 'class="leaked"' in body
    )

    body2 = post("/labs/sql/level3", {"username": "carol"})

    negative = "LEVEL 3 COMPLETED" not in body2 and "carol123" in body2

    return [
        ("正例　用户名 = " + payload, positive, "出现 LEVEL 3 COMPLETED，表格里读到 flag"),
        ("反例　用户名 = carol", negative, "正常查询（页面会显示返回 4 列），但不判通关"),
    ]


def check_xss1():
    """XSS Level 1：反射型（这一关不做任何过滤）。"""

    body = get("/labs/xss/level1?q=%3Cscript%3Ealert(1)%3C/script%3E")
    positive = "XSS SUCCESSFUL" in body and "script 标签" in body

    body2 = get("/labs/xss/level1?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
    positive2 = "XSS SUCCESSFUL" in body2 and "事件属性" in body2

    body3 = get("/labs/xss/level1?q=%3Cspan%3Ehello%3C/span%3E")
    negative = "XSS SUCCESSFUL" not in body3 and "可执行结构" in body3

    return [
        ("正例　?q=<script>alert(1)</script>", positive, "出现 XSS SUCCESSFUL，浏览器会真的弹窗"),
        ("正例　?q=<img src=x onerror=alert(1)>", positive2, "换一种可执行结构同样成立"),
        ("反例　?q=<span>hello</span>", negative, "普通标签不执行代码，不判通关"),
        ("浏览器复核　", None, BASE_URL + "/labs/xss/level1 里展开「可执行结构速查表」对照着打"),
    ]


def check_xss2():
    """XSS Level 2：存储型。"""

    init_db.reset_lab("xss")

    body = post("/labs/xss/level2", {"author": "tester", "content": "<img src=x onerror=alert(1)>"})

    positive = "STORED XSS SUCCESSFUL" in body and "可执行" in body

    # 反例之前必须清空留言板：
    # 存储型的特点就是"注入一次、一直留在库里"，
    # 不清掉的话第二条正常留言的页面上仍然能看到那条可执行留言，
    # 于是"反例"也会被判通关 —— 这一点本身就是这一关要教的东西。
    init_db.reset_lab("xss")

    body2 = post("/labs/xss/level2", {"author": "tester", "content": "<b>普通留言</b>"})

    negative = "STORED XSS SUCCESSFUL" not in body2

    return [
        ("正例　留言内容 = <img src=x onerror=alert(1)>", positive, "出现 STORED XSS SUCCESSFUL，留言被标「可执行」"),
        ("反例　留言内容 = <b>普通留言</b>（已先清空留言板）", negative, "能存能显示，但没有可执行结构，不判通关"),
    ]


def check_upload():
    """文件上传。"""

    init_db.reset_lab("upload")

    html = b"<html><body><script>alert('uploaded')</script></body></html>"

    body = post_file("note.html", html)

    positive = (
        "UPLOAD VALIDATION BYPASSED" in body
        and "不是图片 NOT an image" in body
        and "/static/uploads/note.html" in body
    )

    body2 = post_file("avatar.png", b"\x89PNG\r\n\x1a\n" + b"0" * 200)

    negative = "UPLOAD VALIDATION BYPASSED" not in body2 and "是图片（PNG）" in body2

    body3 = post_file("shell.php", b"<?php echo 1; ?>")

    negative2 = "UPLOAD VALIDATION BYPASSED" not in body3 and "黑名单" in body3

    return [
        ("正例　上传 note.html（内容是 HTML）", positive, "出现 BYPASSED，给出可访问地址 /static/uploads/note.html"),
        ("反例　上传真图片 avatar.png", negative, "识别为图片，不判通关"),
        ("反例　上传 shell.php", negative2, "命中黑名单被拒绝"),
    ]


def check_ssrf():
    """SSRF：服务端请求伪造。"""

    server = http.server.HTTPServer(("127.0.0.1", 0), _Internal)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    try:

        body = post("/labs/ssrf/level1", {"url": "http://127.0.0.1:%d/internal/admin-config" % port})

        positive = (
            "SSRF SUCCESSFUL" in body
            and "INTERNAL-ONLY" in body
            and "flag{ssrf_internal_access}" in body
        )

        body2 = post("/labs/ssrf/level1", {"url": "http://127.0.0.1:%d/plain-page" % port})

        negative = "SSRF SUCCESSFUL" not in body2 and "没有内部标记" in body2

        body3 = post("/labs/ssrf/level1", {"url": "file:///etc/passwd"})

        negative2 = "SSRF SUCCESSFUL" not in body3 and "只支持 http" in body3

    finally:

        server.shutdown()
        server.server_close()

    browser_url = "http://127.0.0.1:5001/internal/admin-config"

    return [
        ("正例　URL = http://127.0.0.1:<临时端口>/internal/admin-config", positive, "内网地址 + 内部标记 → 判通关"),
        ("反例　URL = 同主机但没有标记的路径", negative, "打到内网但没有标记，不判通关"),
        ("反例　URL = file:///etc/passwd", negative2, "非 http(s) 协议被拒绝"),
        ("浏览器复核　URL = " + browser_url, None, "（这一条只给你手工用：填进 SSRF 关也能通关）"),
    ]


def check_cmdi():
    """命令注入。"""

    init_db.reset_lab("cmdi")

    if os.name == "nt":
        payload = "127.0.0.1 & type secret.txt"
    else:
        payload = "127.0.0.1; cat secret.txt"

    body = post("/labs/cmdi/level1", {"host": payload})

    positive = "COMMAND INJECTION SUCCESSFUL" in body and "flag{command_injection_works}" in body

    body2 = post("/labs/cmdi/level1", {"host": "127.0.0.1"})

    negative = "COMMAND INJECTION SUCCESSFUL" not in body2 and "退出码" in body2

    return [
        ("正例　主机 = " + payload, positive, "输出里出现沙箱 secret.txt 的 flag → 判通关"),
        ("反例　主机 = 127.0.0.1", negative, "正常执行 ping，不判通关"),
    ]


def check_idor():
    """越权访问：水平越权。"""

    init_db.reset_lab("idor")

    body = get("/labs/idor/level1?as=1&note_id=3")

    positive = "IDOR SUCCESSFUL" in body and "bob" in body

    body2 = get("/labs/idor/level1?as=1&note_id=1")

    negative = "IDOR SUCCESSFUL" not in body2 and "购物清单" in body2

    body3 = get("/labs/idor/level1?as=1")

    # 注意：不能直接数 "note_id="，因为页面上的"后端代码示例"里也有一行 note_id=3，
    # 只数列表里真正的链接
    negative2 = body3.count('href="/labs/idor/level1?as=1&note_id=') == 2

    return [
        ("正例　身份 as=1（alice）+ note_id=3", positive, "读到 bob 的笔记 → 出现 IDOR SUCCESSFUL"),
        ("反例　身份 as=1 + note_id=1", negative, "自己的笔记，不判通关"),
        ("反例　只看列表（不给 note_id）", negative2, "列表只有自己的 2 条，看不到别人的标题"),
        ("浏览器复核　", None, BASE_URL + "/labs/idor/level1?as=1&note_id=6 能看到管理员私密笔记里的 flag"),
    ]


def check_csrf():
    """CSRF：跨站请求伪造。"""

    import init_db as _init_db

    _init_db.reset_lab("csrf")

    attacker = "attacker@evil.example"

    page = get("/labs/csrf/attacker")
    positive = (
        "csrf-form" in page
        and attacker in page
        and "csrf_token" not in page
    )

    # 不带令牌提交（就是攻击者页面做的事）
    body = post("/labs/csrf/level1/profile", {"email": attacker})
    body = get("/labs/csrf/level1")
    positive2 = "CSRF SUCCESSFUL" in body and attacker in body

    _init_db.reset_lab("csrf")

    # 反例：正常改自己的邮箱（带令牌），不判通关
    post("/labs/csrf/level1/profile", {"email": "me@example.com"})
    body2 = get("/labs/csrf/level1")
    negative = "CSRF SUCCESSFUL" not in body2 and "me@example.com" in body2

    return [
        ("正例　攻击者页面：自动提交表单且不带令牌", positive, "页面里有表单、有攻击者邮箱、没有任何 csrf_token"),
        ("正例　不带令牌提交改邮箱请求", positive2, "出现 CSRF SUCCESSFUL —— 豁免生效，靶子确实没校验"),
        ("反例　正常改自己的邮箱", negative, "能改成功，但不是攻击者指定的地址，不判通关"),
        ("浏览器复核　", None, BASE_URL + "/labs/csrf/level1 → 点「打开攻击者页面」，回来邮箱就变了"),
    ]


# ---------------------------------------------------------------- 关卡登记表

LEVELS = [
    ("sql1", "SQL Level 1　基础查询注入", "/labs/sql/level1", check_sql1),
    ("sql2", "SQL Level 2　登录绕过", "/labs/sql/level2", check_sql2),
    ("sql3", "SQL Level 3　UNION 跨表读取", "/labs/sql/level3", check_sql3),
    ("xss1", "XSS Level 1　反射型", "/labs/xss/level1", check_xss1),
    ("xss2", "XSS Level 2　存储型", "/labs/xss/level2", check_xss2),
    ("upload", "文件上传", "/labs/upload/level1", check_upload),
    ("ssrf", "SSRF　服务端请求伪造", "/labs/ssrf/level1", check_ssrf),
    ("cmdi", "命令注入", "/labs/cmdi/level1", check_cmdi),
    ("idor", "越权访问　水平越权", "/labs/idor/level1", check_idor),
    ("csrf", "CSRF　跨站请求伪造", "/labs/csrf/level1", check_csrf),
]

BASE_URL = "http://127.0.0.1:%d" % config.PORT


def run_one(key, title, path, func):

    print(LINE)
    print("【" + title + "】")
    print("  浏览器复核： " + BASE_URL + path)
    print("")

    try:
        results = func()
    except Exception as error:
        print("  ❌ 验收时出错：" + repr(error))
        return False

    all_ok = True

    for label, ok, expect in results:

        if ok is None:
            print("  ○ " + label)
            print("      " + expect)
            continue

        print("  " + ("✅" if ok else "❌") + " " + label)
        print("      预期：" + expect)

        if not ok:
            all_ok = False

    print("")
    print("  结论：" + ("✅ 通过" if all_ok else "❌ 未通过"))

    return all_ok


def main():

    args = sys.argv[1:]

    if args and args[0] == "list":

        print("可用关卡编号：")
        for key, title, path, _ in LEVELS:
            print("  %-8s %s" % (key, title))
        return 0

    if args:

        chosen = [item for item in LEVELS if item[0] == args[0]]

        if not chosen:
            print("没有这个关卡编号：" + args[0])
            print("用 python verify_levels.py list 看全部编号")
            return 2

        ok = run_one(*chosen[0])
        print(LINE)
        return 0 if ok else 1

    # 不带参数：逐关全跑一遍
    init_db.reset_databases()
    progress.clear_lab("sql")
    progress.clear_lab("xss")
    progress.clear_lab("upload")
    progress.clear_lab("ssrf")
    progress.clear_lab("cmdi")
    progress.clear_lab("idor")
    progress.clear_lab("csrf")

    print("")
    print("MiniSec 逐关验收 —— 每关跑「一个正例 + 一个反例」")
    print("正例必须通关、反例必须不通关，两边都对才算通过")
    print("")

    passed = []

    for key, title, path, func in LEVELS:
        passed.append((title, run_one(key, title, path, func)))

    print(LINE)
    print("汇总")
    print("")

    for title, ok in passed:
        print("  " + ("✅" if ok else "❌") + "  " + title)

    total = len(passed)
    good = len([1 for _, ok in passed if ok])

    print("")
    print("  通过 %d / %d 关" % (good, total))

    if good == total:
        print("")
        print("  全部通过。最后一步：浏览器打开 " + BASE_URL + "/labs")
        print("  用每关上面写的 payload 亲手打一遍，确认 XSS 那两关真的会弹窗。")

    print("")

    return 0 if good == total else 1


if __name__ == "__main__":
    sys.exit(main())
