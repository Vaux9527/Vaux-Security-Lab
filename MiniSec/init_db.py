# -*- coding: utf-8 -*-
"""MiniSec 数据库 / 靶子目录初始化与重建工具。

用法（在 MiniSec 目录下运行）：

    python init_db.py            建库；已存在的数据保持不变（可重复运行）
    python init_db.py --reset    删掉重建（靶子数据恢复出厂状态）
    python init_db.py --show     打印所有数据库里现在有什么

这个脚本取代了原来的 create_db.py / add_user.py / add_data.py /
add_sql_users.py / check_db.py（那些脚本每个只干一小块，而且重复运行会插重复数据）。

设计原则：

1. 幂等：跑一次和跑一百次结果一样，不会重复插入
2. 分离：平台数据（platform.db）和实验靶子数据（lab_*.db）放在不同文件
3. 可重建：靶子随时可以删掉重建，碰不到平台账号和实验目录
4. 一关一库：每个关卡有自己的靶子（数据库或目录），互不干扰
5. 靶子是"代码派生"的：数据库文件不进版本库，靠这个脚本从零生成
"""

import argparse
import shutil
import sqlite3

from werkzeug.security import generate_password_hash

from config import (
    LAB_DB_FILES,
    PLATFORM_DB,
    SANDBOX_DIR,
    SANDBOX_SECRET_CONTENT,
    SANDBOX_SECRET_FILE,
    UPLOAD_DIR,
    lab_db_path,
)


# ---------------------------------------------------------------- 表结构

PLATFORM_SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS labs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    title_en TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    description_en TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'wip',
    entry_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS progress(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lab TEXT NOT NULL,
    level INTEGER NOT NULL,
    cleared_at TEXT NOT NULL,
    UNIQUE(lab, level)
);
"""

# Level 1：一张普通的"用户表"，练最基础的查询注入
LAB_SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS sql_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);
"""

# Level 2：一张"登录账号表"，练登录绕过
LAB_LOGIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);
"""

# Level 3：会员表 + 一张"前台查询本不该读到"的内部表
LAB_UNION_SCHEMA = """
CREATE TABLE IF NOT EXISTS union_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_notes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL
);
"""

# XSS Level 2：留言板（存储型 XSS 的载体）
LAB_XSS_SCHEMA = """
CREATE TABLE IF NOT EXISTS xss_guestbook(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# 文件上传：已上传文件的账本
LAB_UPLOAD_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploaded_files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT NOT NULL,
    saved_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);
"""

# 命令注入：命令执行历史
LAB_CMD_SCHEMA = """
CREATE TABLE IF NOT EXISTS command_runs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_input TEXT NOT NULL,
    executed_command TEXT NOT NULL,
    exit_code INTEGER,
    output TEXT NOT NULL,
    ran_at TEXT NOT NULL
);
"""

# 越权访问：用户表 + 笔记表
# 笔记表里有 owner_id，这正是本关的关键 ——
# 详情接口的 SQL 故意不带这个条件，所以谁都能读别人的笔记。
LAB_IDOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS idor_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idor_notes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_private INTEGER NOT NULL DEFAULT 0
);
"""

# CSRF：靶子账号。
# 只有一个字段是"要害"：email —— 攻下它就能走"忘记密码"接管账号。
LAB_CSRF_SCHEMA = """
CREATE TABLE IF NOT EXISTS csrf_users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL
);
"""


# ---------------------------------------------------------------- 种子数据

# 平台登录账号。password 存进数据库时会自动转成哈希值，不保存明文。
PLATFORM_USERS = [
    ("admin", "123456", "admin"),
]

# 实验目录。
# status: ready = 可以进入；wip = 还在开发（页面上显示"开发中"，不给死链）
LABS = [
    {
        "name": "sql",
        "title": "SQL注入实验",
        "title_en": "SQL Injection Lab",
        "description": "学习用户输入如何改变数据库查询逻辑，以及如何修复。",
        "description_en": "Learn how user input changes the database query, and how to fix it.",
        "status": "ready",
        "entry_url": "/labs/sql",
    },
    {
        "name": "xss",
        "title": "XSS跨站脚本实验",
        "title_en": "Cross-Site Scripting Lab",
        "description": "学习用户输入被当作代码执行时的危害与防御。",
        "description_en": "Learn the impact and defense when user input is executed as code.",
        "status": "ready",
        "entry_url": "/labs/xss",
    },
    {
        "name": "upload",
        "title": "文件上传实验",
        "title_en": "Unrestricted File Upload Lab",
        "description": "学习上传功能为什么不能只靠后缀名做校验。",
        "description_en": "Learn why an upload feature must not trust the file extension.",
        "status": "ready",
        "entry_url": "/labs/upload",
    },
    {
        "name": "ssrf",
        "title": "SSRF实验",
        "title_en": "Server-Side Request Forgery Lab",
        "description": "学习服务端请求伪造：借服务器之手访问内部资源。",
        "description_en": "Learn SSRF: making the server reach internal resources for you.",
        "status": "ready",
        "entry_url": "/labs/ssrf",
    },
    {
        "name": "cmdi",
        "title": "命令注入实验",
        "title_en": "OS Command Injection Lab",
        "description": "学习用户输入进入系统命令时会造成的后果。",
        "description_en": "Learn the consequences of letting input flow into an OS command.",
        "status": "ready",
        "entry_url": "/labs/cmdi",
    },
    {
        "name": "idor",
        "title": "越权访问实验",
        "title_en": "Broken Access Control Lab",
        "description": "学习水平越权：改一个编号就能看到别人的数据。",
        "description_en": "Learn horizontal privilege escalation: change an id, read someone else's data.",
        "status": "ready",
        "entry_url": "/labs/idor",
    },
    {
        "name": "csrf",
        "title": "CSRF跨站请求伪造实验",
        "title_en": "Cross-Site Request Forgery Lab",
        "description": "学习攻击者如何借你已登录的身份，在你不知情时发出请求。",
        "description_en": "Learn how an attacker borrows your logged-in identity to send requests you never made.",
        "status": "ready",
        "entry_url": "/labs/csrf",
    },
]

# SQL Level 1 的"靶子用户"：故意使用弱口令，password 明文存储（教学需要）。
SQL_USERS = [
    ("admin", "admin123", "administrator"),
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("guest", "guest123", "guest"),
]

# Level 2 的"靶子账号"。
#
# 教学性故意为之的两点：
#   1. 弱口令 + 明文存储 —— 让学习者直观看到"数据库泄露等于密码泄露"
#   2. 真实系统里这里存的应该是哈希值，比对用 check_password_hash
#
# admin 是本关的"目标账号"：能在不知道它密码的情况下进去，才算通关。
LOGIN_USERS = [
    ("admin", "admin123", "administrator"),
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("support", "support123", "support"),
]

# Level 3 的会员表：换一套名字，让学习者意识到这是"另一个应用"。
UNION_USERS = [
    ("admin", "admin123", "administrator"),
    ("carol", "carol123", "user"),
    ("dave", "dave123", "user"),
    ("erin", "erin123", "vip"),
]

# Level 3 的"内部表"：前台查询本不该读到它。
# 第一条的内容就是本关的 flag —— 通关判定看的是"结果里有没有出现它"。
UNION_SECRETS = [
    ("内部备忘", "flag{union_injection_works}"),
    ("服务器清单", "web-01 = 10.0.0.11 / db-01 = 10.0.0.12 （示例数据，非真实内网）"),
    ("交接说明", "这张表只给运维看，前台页面不提供任何入口。"),
]

# XSS Level 2 的留言板初始内容（两条正常留言，页面不至于空白）
XSS_GUESTBOOK_SEED = [
    ("alice", "这个留言板做得挺好看的～"),
    ("bob", "楼上说得对，我也来留一条。"),
]

# 越权访问：4 个用户，其中 admin 不在页面的"可切换身份"里（他的数据才是目标）
IDOR_USERS = [
    ("alice", "艾丽丝", "user"),
    ("bob", "鲍勃", "user"),
    ("carol", "卡罗", "user"),
    ("admin", "系统管理员", "administrator"),
]

# 每个用户各有几条笔记；id = 6 那条属于 admin 且是私密的，里面放着本关的 flag。
# 注意：这些 id 是自增的、连续的 —— 这正是真实世界里越权遍历能成功的原因。
IDOR_NOTES = [
    (1, "购物清单", "牛奶、鸡蛋、面包、咖啡豆", 0),
    (1, "会议记录", "周五 10:00，与 bob 对需求", 0),
    (2, "读书笔记", "《Web 安全深度剖析》第 3 章：注入类漏洞", 0),
    (2, "旅行计划", "国庆去海边，记得订民宿", 0),
    (3, "健身计划", "每周三次，先练背", 0),
    (4, "私密备忘", "flag{idor_horizontal_access}", 1),
    (4, "口令轮换说明", "每 90 天轮换一次（假数据，不是真口令）", 1),
]

# CSRF：靶子账号。victim 是本关的目标，邮箱被改掉就算通关。
CSRF_USERS = [
    ("victim", "victim@example.com", "受害者（本关目标账号）"),
    ("admin", "admin@example.com", "管理员（对照用）"),
]


# ---------------------------------------------------------------- 建库

def _connect(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def create_platform_db(reset=False):
    """建立平台数据库：登录账号 + 实验目录 + 通关进度。"""

    if reset and PLATFORM_DB.exists():
        PLATFORM_DB.unlink()

    conn = _connect(PLATFORM_DB)
    cursor = conn.cursor()

    cursor.executescript(PLATFORM_SCHEMA)

    for username, password, role in PLATFORM_USERS:

        cursor.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        )

        if cursor.fetchone() is None:

            cursor.execute(
                """
                INSERT INTO users(username, password, role)
                VALUES (?, ?, ?)
                """,
                (username, generate_password_hash(password), role),
            )

    for lab in LABS:

        # 用 UPSERT 而不是"没有才插入"：
        # 这样改了实验的标题 / 状态 / 入口地址之后，
        # 老的数据库文件再跑一次 init_db.py 就能同步过来，不用手动删库。
        cursor.execute(
            """
            INSERT INTO labs(
                name, title, title_en,
                description, description_en,
                status, entry_url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                title = excluded.title,
                title_en = excluded.title_en,
                description = excluded.description,
                description_en = excluded.description_en,
                status = excluded.status,
                entry_url = excluded.entry_url
            """,
            (
                lab["name"],
                lab["title"],
                lab["title_en"],
                lab["description"],
                lab["description_en"],
                lab["status"],
                lab["entry_url"],
            ),
        )

    conn.commit()
    conn.close()


def _create_lab_db(lab_name, schema, seeds, reset=False):
    """通用的靶子库建库逻辑：建表 + 只在空表时插入种子数据。

    seeds 是 {表名: [行, ...]}；建表语句里的表顺序不限。
    """

    path = lab_db_path(lab_name)

    if reset and path.exists():
        path.unlink()

    conn = _connect(path)
    cursor = conn.cursor()

    cursor.executescript(schema)

    for table, rows in seeds.items():

        cursor.execute("SELECT COUNT(*) FROM %s" % table)

        if cursor.fetchone()[0] > 0 or not rows:
            continue

        placeholders = ", ".join(["?"] * len(rows[0]))

        cursor.executemany(
            "INSERT INTO %s VALUES (NULL, %s)" % (table, placeholders),
            rows,
        )

    conn.commit()
    conn.close()


def create_lab_sql_db(reset=False):
    """Level 1：一张普通用户表。"""

    _create_lab_db("sql", LAB_SQL_SCHEMA, {"sql_users": SQL_USERS}, reset=reset)


def create_lab_login_db(reset=False):
    """Level 2：一张登录账号表。"""

    _create_lab_db(
        "sql_login", LAB_LOGIN_SCHEMA, {"login_users": LOGIN_USERS}, reset=reset
    )


def create_lab_union_db(reset=False):
    """Level 3：会员表 + 内部表。"""

    _create_lab_db(
        "sql_union",
        LAB_UNION_SCHEMA,
        {"union_users": UNION_USERS, "secret_notes": UNION_SECRETS},
        reset=reset,
    )


def create_lab_xss_db(reset=False):
    """XSS Level 2：留言板。"""

    from datetime import datetime

    now = datetime.now().isoformat(timespec="seconds")

    seeds = {
        "xss_guestbook": [
            (author, content, now) for author, content in XSS_GUESTBOOK_SEED
        ]
    }

    _create_lab_db("xss", LAB_XSS_SCHEMA, seeds, reset=reset)


def create_lab_upload_db(reset=False):
    """文件上传：只建一张空的账本表，文件都在 uploads 目录里。"""

    _create_lab_db("upload", LAB_UPLOAD_SCHEMA, {"uploaded_files": []}, reset=reset)


def create_lab_cmd_db(reset=False):
    """命令注入：只建一张空的执行历史表。"""

    _create_lab_db("cmdi", LAB_CMD_SCHEMA, {"command_runs": []}, reset=reset)


def create_lab_idor_db(reset=False):
    """越权访问：用户表 + 笔记表。"""

    _create_lab_db(
        "idor",
        LAB_IDOR_SCHEMA,
        {"idor_users": IDOR_USERS, "idor_notes": IDOR_NOTES},
        reset=reset,
    )


def create_lab_csrf_db(reset=False):
    """CSRF：一张靶子账号表。"""

    _create_lab_db("csrf", LAB_CSRF_SCHEMA, {"csrf_users": CSRF_USERS}, reset=reset)


def create_uploads_dir(reset=False):
    """文件上传关的靶子目录。

    reset=True 时整个目录清空（恢复出厂 = 把上传过的东西都删掉）。
    """

    if reset and UPLOAD_DIR.exists():
        shutil.rmtree(UPLOAD_DIR)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def create_sandbox_dir(reset=False):
    """命令注入关的工作目录。

    reset=True 时整个目录重建（学习者在里面创建的文件会被清掉），
    然后重新放回本关的目标文件 secret.txt。
    """

    if reset and SANDBOX_DIR.exists():
        shutil.rmtree(SANDBOX_DIR)

    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    secret = SANDBOX_DIR / SANDBOX_SECRET_FILE

    if not secret.exists():
        secret.write_text(SANDBOX_SECRET_CONTENT, encoding="utf-8")


# 实验名 -> 建库函数（新增关卡时在这里登记一行）
LAB_CREATORS = {
    "sql": create_lab_sql_db,
    "sql_login": create_lab_login_db,
    "sql_union": create_lab_union_db,
    "xss": create_lab_xss_db,
    "upload": create_lab_upload_db,
    "cmdi": create_lab_cmd_db,
    "idor": create_lab_idor_db,
    "csrf": create_lab_csrf_db,
}

# 实验名 -> 靶子目录（不是数据库，但同样需要"能一键重建"）
#
# 注意：这里故意不把两个字典合并成一个 ——
# upload / cmdi 两个实验**同时**有一个靶子库和一个靶子目录，
# 如果合成一个字典，同名键会互相覆盖，结果就是数据库永远建不出来。
DIR_TARGETS = {
    "upload": create_uploads_dir,
    "cmdi": create_sandbox_dir,
}


def _all_creators():
    """所有靶子的创建函数：先数据库，再目录（一个个来，不合并字典）。"""

    for creator in LAB_CREATORS.values():
        yield creator

    for creator in DIR_TARGETS.values():
        yield creator


def reset_lab(lab_name):
    """只重建某一个实验的靶子，平台数据完全不受影响。

    网页上"恢复出厂状态"按钮用的就是它。
    如果这个靶子对应着通关进度，进度也一起清掉（重新开始练）。
    """

    # 局部 import：progress 会绕回 database -> init_db，
    # 放在函数里可以避免模块级循环依赖。
    import progress

    creators = []

    if lab_name in LAB_CREATORS:
        creators.append(LAB_CREATORS[lab_name])

    if lab_name in DIR_TARGETS:
        creators.append(DIR_TARGETS[lab_name])

    if not creators:
        raise KeyError("未登记的靶子: " + str(lab_name))

    for creator in creators:
        creator(reset=True)

    progress.clear_for_target_lab(lab_name)


def ensure_databases():
    """确保所有库和靶子目录都存在。

    数据库文件不存在时，database.py 会自动调用这里，
    所以全新克隆下来直接启动网站也不会因为缺数据库而报错。
    """

    create_platform_db()

    for creator in _all_creators():
        creator()


def reset_databases():
    """删掉重建：所有靶子数据（以及平台账号）恢复出厂状态。"""

    create_platform_db(reset=True)

    for creator in _all_creators():
        creator(reset=True)


# ---------------------------------------------------------------- 查看

def show_databases():
    """打印所有数据库里现在有什么。"""

    targets = [("平台库 platform.db", PLATFORM_DB)]

    for lab_name, filename in LAB_DB_FILES.items():
        targets.append(("靶子库 " + filename, lab_db_path(lab_name)))

    for label, path in targets:

        print("")
        print("====================")
        print(label, "->", path)
        print("====================")

        if not path.exists():
            print("(文件不存在，请先运行 python init_db.py)")
            continue

        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table'
            ORDER BY name
            """
        )

        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:

            cursor.execute("PRAGMA table_info(%s)" % table)
            columns = [row[1] for row in cursor.fetchall()]

            cursor.execute("SELECT * FROM %s" % table)
            rows = cursor.fetchall()

            print("")
            print("-- %s (%d 行) --" % (table, len(rows)))
            print("   列:", ", ".join(columns))

            for row in rows:
                print("   ", row)

        conn.close()


# ---------------------------------------------------------------- 命令行

def main():

    parser = argparse.ArgumentParser(
        description="MiniSec 数据库 / 靶子目录初始化工具"
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="删掉重建（所有靶子恢复出厂状态，平台账号也会重置）",
    )

    parser.add_argument(
        "--show",
        action="store_true",
        help="打印数据库里现在有什么",
    )

    args = parser.parse_args()

    if args.reset:

        print("提示：如果网站正在运行，请先停掉再重置。")

        reset_databases()

        print("已重建（数据恢复出厂状态）：")

    else:

        ensure_databases()

        print("已就绪（已存在的数据保持不变）：")

    print("  平台库 platform.db   ->  users（登录账号，密码为哈希值）")
    print("                          labs（实验目录）")
    print("                          progress（通关进度）")
    print("  靶子库 lab_sql.db    ->  sql_users（Level 1 假用户）")
    print("  靶子库 lab_login.db  ->  login_users（Level 2 假账号）")
    print("  靶子库 lab_union.db  ->  union_users + secret_notes（Level 3 会员表与内部表）")
    print("  靶子库 lab_xss.db    ->  xss_guestbook（XSS 留言板）")
    print("  靶子库 lab_upload.db ->  uploaded_files（上传账本）")
    print("  靶子库 lab_cmd.db    ->  command_runs（命令执行历史）")
    print("  靶子库 lab_idor.db   ->  idor_users + idor_notes（越权访问的用户与笔记）")
    print("  靶子库 lab_csrf.db   ->  csrf_users（CSRF 实验的靶子账号）")
    print("  靶子目录 static/uploads/  ->  文件上传关的上传位置")
    print("  靶子目录 lab_sandbox/     ->  命令注入关的工作目录（含 secret.txt）")

    if args.show:
        show_databases()


if __name__ == "__main__":
    main()
