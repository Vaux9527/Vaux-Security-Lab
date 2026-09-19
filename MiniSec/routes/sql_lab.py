# -*- coding: utf-8 -*-
"""SQL Injection Lab：Level 1 基础查询注入 + Level 2 登录绕过 + Level 3 UNION 查询。

⚠️ 三个 Level 里的漏洞都是故意保留的：用户输入被直接拼接进 SQL 语句。
   这是教学靶子的核心，不要"顺手修好"它。
   平台自身的代码（登录、实验列表）用的都是参数化查询，是安全的。

关卡与靶子库的对应关系（一关一库）：

    Level 1  基础查询注入   lab_sql.db     sql_users
    Level 2  登录绕过       lab_login.db   login_users
    Level 3  UNION 查询     lab_union.db   union_users + secret_notes

三关的通关判定都不是"看关键词"，而是看**查询实际返回了什么**：
    1. 返回行数 > 1
    2. 进到了 admin 但提交的不是合法凭据
    3. 结果里出现了内部表的内容（flag）
这样判定标准客观、可复现，也不依赖黑名单是否写得全。
"""

from flask import Blueprint, flash, redirect, render_template, request

import curriculum
import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

sql_bp = Blueprint(
    "sql",
    __name__
)

LAB_NAME = "sql"

# Level 1：正常查询只应该返回 1 行；超过这个数字说明注入成功
EXPECTED_ROWS = 1

# Level 3：内部表里的 flag 长这样，结果里出现它就算通关
SECRET_MARKER = "flag{"


# ================================================================
# 共用的注入特征检测
# ================================================================

# 粗略的注入特征检测。
# 只用于页面提示，不用于判定通关（判定以查询实际返回的结果为准）。
SUSPICIOUS_KEYWORDS = [
    "'",
    '"',
    "--",
    "#",
    "/*",
    "*/",
    " or ",
    " and ",
    " union ",
    "=",
]


def looks_like_attack(text):
    """判断输入里有没有 SQL 注入特征。"""

    padded = " " + text.lower() + " "

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in padded:
            return True

    return False


def _columns_of(cursor):
    """这次查询返回了几列（UNION 注入要先知道列数）。"""

    return len(cursor.description or [])


# ================================================================
# Level 1 基础查询注入
# ================================================================

# 有漏洞的写法：用户输入被直接拼进 SQL 字符串
LEVEL1_VULNERABLE_CODE = '''generated_sql = f"""
SELECT id, username, password, role
FROM sql_users
WHERE username = '{username}'
"""

cursor.execute(generated_sql)'''

# 安全写法：参数化查询，输入永远只被当作数据
LEVEL1_SECURE_CODE = '''cursor.execute(
    """
    SELECT id, username, password, role
    FROM sql_users
    WHERE username = ?
    """,
    (username,)
)'''

LEVEL1_HINTS = [
    {
        "zh": "先输入一个正常用户名（例如 admin），观察右侧 Generated SQL："
              "你的输入被夹在两个单引号中间。",
        "en": "Search for a normal name (e.g. admin) and look at Generated SQL: "
              "your input sits between two single quotes.",
    },
    {
        "zh": "在 SQL 里，单引号表示一段文字的「开始」和「结束」。"
              "如果输入里自己带一个单引号，它会提前把这段文字关掉。",
        "en": "In SQL a single quote starts and ends a string. "
              "If your input contains one, it ends the string early.",
    },
    {
        "zh": "想办法让 WHERE 条件永远成立（例如 1=1 这种恒真条件），"
              "再用 -- 把末尾多余的引号注释掉。",
        "en": "Make the WHERE condition always true (e.g. 1=1), "
              "then use -- to comment out the leftover quote.",
    },
]

LEVEL1_SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：用户输入被直接拼接进 SQL 语句，数据变成了代码。",
            "en": "Root cause: user input is concatenated into the SQL text, "
                  "so data becomes code.",
        },
        {
            "zh": "利用手法：单引号提前结束字符串，恒真条件让 WHERE 判断失效，"
                  "-- 注释掉语句末尾多余的部分。",
            "en": "Exploitation: a quote ends the string early, an always-true "
                  "condition defeats the WHERE clause, and -- comments out the rest.",
        },
        {
            "zh": "危害：本该只返回 1 行的查询返回了整张表，"
                  "用户名和密码被一次性拿走。",
            "en": "Impact: a query that should return one row returns the whole "
                  "table, leaking every username and password.",
        },
        {
            "zh": "修复：使用参数化查询（? 占位符），"
                  "让数据库永远把你的输入当作数据，而不是命令。",
            "en": "Fix: use parameterized queries (? placeholders) so your input "
                  "is always treated as data, never as a command.",
        },
    ],
    "takeaway_zh": "记住一句话：只要用户输入被拼进 SQL 语句，就一定存在注入风险。",
    "takeaway_en": "Rule of thumb: if user input is concatenated into SQL, "
                   "injection is possible.",
    "next_zh": "下一关 Level 2 会用同样的手法绕过登录验证。",
    "next_en": "Level 2 uses the same trick to bypass authentication.",
}


@sql_bp.route(
    "/labs/sql/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def sql_reset():
    """把 Level 1 的靶子数据恢复出厂状态。

    只重建 lab_sql.db，其他关卡和平台账号都不受影响。
    """

    init_db.reset_lab("sql")

    flash(
        "Level 1 实验数据已恢复出厂状态 Lab data restored",
        "success"
    )

    return redirect("/labs/sql/level1")


@sql_bp.route(
    "/labs/sql/level1",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def sql_level1():

    result = None
    username = None
    generated_sql = None
    analysis_zh = None
    analysis_en = None
    is_attack = False
    completed = False
    rows_returned = None
    column_count = None

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        # ⚠️ 故意漏洞：字符串拼接，用户输入直接进入 SQL 语句
        generated_sql = f"""
SELECT id, username, password, role
FROM sql_users
WHERE username = '{username}'
"""

        # 注意：这里连的是靶子数据库，里面只有假数据，
        # 即使被注入读走，也碰不到平台账号（platform.db）。
        conn = get_lab_db("sql")

        cursor = conn.cursor()

        try:

            cursor.execute(generated_sql)

            result = cursor.fetchall()

            column_count = _columns_of(cursor)

        except Exception as error:

            result = []

            is_attack = True

            analysis_zh = (
                "SQL 执行出错："
                + str(error)
                + "。这说明你的输入已经改变了 SQL 语句的语法结构，"
                "是注入生效的直接证据。"
            )

            analysis_en = (
                "SQL error: "
                + str(error)
                + ". Your input changed the syntax of the statement, "
                "which is direct evidence that injection worked."
            )

        conn.close()

        rows_returned = len(result)

        if looks_like_attack(username):
            is_attack = True

        if analysis_zh is None:

            if rows_returned > EXPECTED_ROWS:

                completed = True
                is_attack = True

                analysis_zh = (
                    "实验成功。你构造的条件让 WHERE 判断永远成立，"
                    "一次查询返回了 "
                    + str(rows_returned)
                    + " 个用户，而本关原本只应该返回 1 个。"
                    "这说明用户输入已经不再只是数据，"
                    "而是改变了 SQL 语句的执行逻辑。"
                )

                analysis_en = (
                    "Success. Your condition made the WHERE clause always true, "
                    "so the query returned "
                    + str(rows_returned)
                    + " users instead of 1. "
                    "The input is no longer plain data: it changed how the "
                    "SQL statement behaves."
                )

            elif is_attack:

                analysis_zh = (
                    "检测到特殊 SQL 输入。用户输入被直接拼接进 SQL 语句，"
                    "因此可能影响 WHERE 条件或语法，"
                    "但本次还没有让查询返回多行结果。"
                )

                analysis_en = (
                    "Suspicious SQL input detected. The input is concatenated "
                    "into the statement, but it did not make the query return "
                    "multiple rows yet."
                )

            elif result:

                analysis_zh = (
                    "正常查询成功，返回 1 个用户。本次输入没有改变查询逻辑，"
                    "但这种字符串拼接的写法本身仍然存在注入风险。"
                )

                analysis_en = (
                    "Normal query, one user returned. The input did not change "
                    "the logic this time, but the string concatenation itself "
                    "is still vulnerable."
                )

            else:

                analysis_zh = (
                    "没有匹配的用户。注意：即使这次查询为空，"
                    "这个功能也仍然是可注入的。"
                )

                analysis_en = (
                    "No matching user. Note: the endpoint is still injectable "
                    "even though this query returned nothing."
                )

        if completed:
            progress.mark_cleared(LAB_NAME, 1)

    return render_template(
        "sql_level1.html",
        result=result,
        username=username,
        generated_sql=generated_sql,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        is_attack=is_attack,
        completed=completed,
        cleared_before=cleared_before,
        rows_returned=rows_returned,
        column_count=column_count,
        expected_rows=EXPECTED_ROWS,
        hints=LEVEL1_HINTS,
        vulnerable_code=LEVEL1_VULNERABLE_CODE,
        secure_code=LEVEL1_SECURE_CODE,
        summary=LEVEL1_SUMMARY,
        # 以下四项由 lab_base.html 的公共骨架使用
        ok_label="SQL Injection Successful 注入成功",
        artifact_title="Generated SQL 实际执行的语句",
        artifact_body=generated_sql,
        artifact_note=(
            "对比一下：哪些字符来自原本的代码，哪些来自你的输入？"
            " / Compare: which characters came from the code, and which came "
            "from your input?"
        ),
        fix_vulnerable_zh=(
            "用户输入被直接拼接到 SQL 语句中，"
            "输入的内容因此可以改变整条语句的结构。"
        ),
        fix_vulnerable_en=(
            "User input is concatenated into the statement, so it can change "
            "the structure of the statement."
        ),
        fix_secure_zh=(
            "使用参数化查询后，用户输入会被当作数据 处理，"
            "而不会被当作 SQL 代码执行。"
        ),
        fix_secure_en=(
            "With parameterized queries the input is handled as data, "
            "never as executable SQL."
        )
    )


# ================================================================
# Level 2 登录绕过
# ================================================================

# 本关的目标账号：能在不知道它密码的情况下进去，才算通关
LEVEL2_TARGET_USER = "admin"

LEVEL2_VULNERABLE_CODE = '''generated_sql = f"""
SELECT id, username, role
FROM login_users
WHERE username = '{username}' AND password = '{password}'
"""

cursor.execute(generated_sql)
row = cursor.fetchone()

if row:
    # 查到记录就认为登录成功
    session["username"] = row[1]'''

LEVEL2_SECURE_CODE = '''# 1) 只按用户名取记录，密码不参与 SQL（参数化查询）
cursor.execute(
    """
    SELECT id, username, password, role
    FROM login_users
    WHERE username = ?
    """,
    (username,)
)
row = cursor.fetchone()

# 2) 密码单独校验：认证逻辑留在代码里，不写进 SQL
#    真实系统存的是哈希值，用 check_password_hash 比对
if row and check_password_hash(row[2], password):
    session["username"] = row[1]
else:
    flash("用户名或密码错误")'''

LEVEL2_HINTS = [
    {
        "zh": "先用 admin / admin123 正常登录一次，看右侧 Generated SQL："
              "用户名和密码都被夹在单引号里，中间用 AND 连在一起——"
              "两条都成立，数据库才会返回记录。",
        "en": "Log in normally with admin / admin123 first, then look at "
              "Generated SQL: both the username and the password sit inside "
              "quotes, joined by AND. The database only returns a row when "
              "both parts are true.",
    },
    {
        "zh": "登录判断写成了「用户名对 并且 密码对」。"
              "想一想：能不能让后半段（密码那部分）整段失效？",
        "en": "The check is written as 'username correct AND password correct'. "
              "Can you make the second half (the password part) disappear?",
    },
    {
        "zh": "在 SQL 里 -- 表示注释，它后面的内容会被数据库直接忽略。"
              "把 -- 放在用户名后面试试（注意 -- 后面要跟一个空格），"
              "这样 AND password='...' 这一整段就没了。",
        "en": "In SQL, -- starts a comment: everything after it is ignored. "
              "Try putting -- right after the username (with a space after it), "
              "so the whole AND password='...' part disappears.",
    },
]

LEVEL2_SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：登录查询同样是字符串拼接，而且把「认证判断」写进了 SQL 条件里——"
                  "能不能进系统，取决于 SQL 语句的语法结构，而不是密码对不对。",
            "en": "Root cause: the login query is also built by concatenation, and "
                  "the authentication decision is expressed as a SQL condition. "
                  "Whether you get in depends on the SQL syntax, not on the password.",
        },
        {
            "zh": "利用手法：用户名后面加一个单引号提前结束字符串，"
                  "再用 -- 把 AND password='...' 整段注释掉。"
                  "于是 WHERE 只剩 username='admin' 一个条件，密码检查被彻底跳过。",
            "en": "Exploitation: a quote ends the username string early, then -- "
                  "comments out the whole AND password='...' clause, leaving only "
                  "username='admin' in the WHERE clause. The password check is gone.",
        },
        {
            "zh": "危害：不需要密码就能以管理员身份登录，等于直接拿到后台；"
                  "真实系统里这一步之后就是数据泄露、篡改和横向移动。",
            "en": "Impact: you log in as the administrator without knowing the "
                  "password at all. In a real system this is the front door to "
                  "data theft and lateral movement.",
        },
        {
            "zh": "修复：两件事一起做——① 用参数化查询，让输入只能当数据；"
                  "② 把认证逻辑从 SQL 里拿出来，先按用户名取记录，"
                  "再用哈希函数单独比对密码。",
            "en": "Fix: do both. (1) Use parameterized queries so input can only "
                  "ever be data. (2) Move authentication out of SQL: fetch the row "
                  "by username, then compare the password hash separately in code.",
        },
    ],
    "takeaway_zh": "口诀：认证不是一个 SQL 条件，而是一次完整的校验流程。",
    "takeaway_en": "Rule of thumb: authentication is a verification flow, "
                   "not a SQL condition.",
    "next_zh": "下一关 Level 3 不再满足于「绕过」，而是用 UNION 主动把别的表读出来。",
    "next_en": "Level 3 goes further: instead of bypassing a check, "
               "UNION injection reads data from other tables.",
}


@sql_bp.route(
    "/labs/sql/level2/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def sql_level2_reset():
    """只把 Level 2 的登录靶子恢复出厂状态（lab_login.db）。"""

    init_db.reset_lab("sql_login")

    flash(
        "Level 2 登录靶子已恢复出厂状态 Login lab data restored",
        "success"
    )

    return redirect("/labs/sql/level2")


@sql_bp.route(
    "/labs/sql/level2",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def sql_level2():

    result = None
    username = None
    generated_sql = None
    analysis_zh = None
    analysis_en = None
    is_attack = False
    completed = False
    logged_in_as = None
    used_valid_credentials = None

    cleared_before = progress.is_cleared(LAB_NAME, 2)

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        # ⚠️ 故意漏洞：用户名和密码都被直接拼进 SQL 语句
        generated_sql = f"""
SELECT id, username, role
FROM login_users
WHERE username = '{username}' AND password = '{password}'
"""

        conn = get_lab_db("sql_login")

        cursor = conn.cursor()

        try:

            cursor.execute(generated_sql)

            result = cursor.fetchall()

        except Exception as error:

            result = []

            is_attack = True

            analysis_zh = (
                "SQL 执行出错："
                + str(error)
                + "。这说明你的输入已经改变了登录语句的语法结构——"
                "登录判断本来是一条 SQL 条件，所以语句一变形，"
                "认证逻辑就跟着变了。"
            )

            analysis_en = (
                "SQL error: "
                + str(error)
                + ". Your input changed the syntax of the login statement. "
                "Because the authentication check IS a SQL condition, "
                "changing the statement changes the authentication logic."
            )

        if looks_like_attack(username) or looks_like_attack(password):
            is_attack = True

        if result:
            # 登录语句返回的第一行，就是"系统认为你是谁"
            logged_in_as = result[0][1]

        if analysis_zh is None:

            # 通关判定要用到"这次提交的账号密码本身是不是一组合法凭据"，
            # 所以这里再查一次（这次是平台自己的代码，用参数化查询）。
            cursor.execute(
                """
                SELECT 1 FROM login_users
                WHERE username = ? AND password = ?
                """,
                (username, password),
            )

            used_valid_credentials = cursor.fetchone() is not None

            if logged_in_as is None:

                analysis_zh = (
                    "登录失败：用户名或密码错误。"
                    "注意：即使这次没进去，这个登录接口本身仍然是可注入的。"
                )

                analysis_en = (
                    "Login failed: wrong username or password. "
                    "Note: the endpoint is still injectable even though "
                    "this attempt did not get in."
                )

            elif not used_valid_credentials and logged_in_as == LEVEL2_TARGET_USER:

                completed = True
                is_attack = True

                analysis_zh = (
                    "实验成功。你以 "
                    + logged_in_as
                    + " 的身份进入了系统，但你提交的账号密码并不是一组合法凭据——"
                    "也就是说，你不是「知道密码」，而是「绕过了密码」。"
                    "原因是 AND password='...' 这一整段被注释掉了，"
                    "登录判断只剩下用户名一个条件。"
                )

                analysis_en = (
                    "Success. You got in as "
                    + logged_in_as
                    + ", but the credentials you submitted are not a valid pair "
                    "for this database: you bypassed the password rather than "
                    "knowing it. The AND password='...' clause was commented out, "
                    "so the login check kept only the username condition."
                )

            elif not used_valid_credentials:

                analysis_zh = (
                    "你确实绕过了密码，登录语句返回了账号 "
                    + str(logged_in_as)
                    + "。但本关的目标是管理员账号 "
                    + LEVEL2_TARGET_USER
                    + "——换成它再试一次。"
                )

                analysis_en = (
                    "You did bypass the password and the query returned "
                    + str(logged_in_as)
                    + ", but this level targets the administrator account "
                    + LEVEL2_TARGET_USER
                    + ". Try again aiming at that account."
                )

            elif logged_in_as != LEVEL2_TARGET_USER:

                analysis_zh = (
                    "正常登录成功，身份是 "
                    + str(logged_in_as)
                    + "。本关要的是管理员账号 "
                    + LEVEL2_TARGET_USER
                    + "，而且要求不使用它的真实密码。"
                )

                analysis_en = (
                    "Normal login as "
                    + str(logged_in_as)
                    + ". This level targets the administrator account "
                    + LEVEL2_TARGET_USER
                    + ", and requires getting in without its real password."
                )

            else:

                analysis_zh = (
                    "这是一次正常登录：你提交的账号密码本身就是合法凭据，"
                    "数据库如实返回了它。登录功能正常工作，"
                    "但请注意——它把认证判断写进了 SQL 条件里，"
                    "所以只要输入里带上特殊字符，判断逻辑就可能被改写。"
                )

                analysis_en = (
                    "This is a normal login: the credentials you submitted are "
                    "valid, and the database returned the matching row. The login "
                    "works as intended — but the authentication check lives inside "
                    "the SQL statement, so special characters in the input can "
                    "rewrite the check itself."
                )

        conn.close()

        if completed:
            progress.mark_cleared(LAB_NAME, 2)

    return render_template(
        "sql_level2.html",
        result=result,
        username=username,
        generated_sql=generated_sql,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        is_attack=is_attack,
        completed=completed,
        cleared_before=cleared_before,
        logged_in_as=logged_in_as,
        target_user=LEVEL2_TARGET_USER,
        hints=LEVEL2_HINTS,
        vulnerable_code=LEVEL2_VULNERABLE_CODE,
        secure_code=LEVEL2_SECURE_CODE,
        summary=LEVEL2_SUMMARY,
        # 以下四项由 lab_base.html 的公共骨架使用
        ok_label="Authentication Bypassed 认证被绕过",
        artifact_title="Generated SQL 实际执行的语句",
        artifact_body=generated_sql,
        artifact_note=(
            "对比一下：哪些字符来自原本的代码，哪些来自你的输入？"
            "如果你注释掉了某一段，它会从这条语句里消失。"
            " / Compare: which characters came from the code and which from your "
            "input? Anything you commented out is simply gone from this statement."
        ),
        fix_vulnerable_zh=(
            "两个问题叠在一起：用户输入被直接拼接进语句，"
            "而且「认证」被写成了 SQL 的一个条件。"
            "只要输入能改变语句结构，认证结果就跟着被改写。"
        ),
        fix_vulnerable_en=(
            "Two problems stack up: the input is concatenated into the "
            "statement, and authentication itself is expressed as a SQL "
            "condition. If input can change the statement, it can change the "
            "authentication result."
        ),
        fix_secure_zh=(
            "修好它需要两件事一起做：参数化查询让输入只能当数据；"
            "认证逻辑回到代码里——先按用户名取记录，再用哈希函数单独比对密码。"
            "任何一段密码判断都不应该出现在 SQL 里。"
        ),
        fix_secure_en=(
            "Two changes together: parameterized queries so input is only ever "
            "data, and authentication back in code — fetch the row by username, "
            "then compare the password hash separately. No part of the password "
            "check should appear in SQL."
        )
    )


# ================================================================
# Level 3 UNION 查询
# ================================================================

# 这条查询返回 4 列 —— 这是 UNION 注入必须先搞清楚的事
LEVEL3_QUERY_COLUMNS = 4

LEVEL3_VULNERABLE_CODE = '''generated_sql = f"""
SELECT id, username, password, role
FROM union_users
WHERE username = '{username}'
"""

cursor.execute(generated_sql)
rows = cursor.fetchall()'''

LEVEL3_SECURE_CODE = '''# 1) 参数化查询：输入永远只是数据，没法改变语句结构
cursor.execute(
    """
    SELECT id, username, password, role
    FROM union_users
    WHERE username = ?
    """,
    (username,)
)

# 2) 光参数化还不够 —— 数据库账号也要最小权限：
#    前台这个账号只该有 union_users 的 SELECT 权限，
#    不该有读 secret_notes 的权限。
#    这样即使查询被改写，能读到的也只有它本来就能读的表。'''

LEVEL3_HINTS = [
    {
        "zh": "先正常查一个用户名（例如 carol），页面上会告诉你这次查询返回了几列——"
              "记住这个数字，UNION 必须和它对齐。",
        "en": "Look up a normal user first (e.g. carol). The page shows how many "
              "columns the query returns — remember that number. A UNION must "
              "match it exactly.",
    },
    {
        "zh": "不确定有几列？用 ORDER BY 数字 去试："
              "`carol' ORDER BY 1 --`、`ORDER BY 2`…… 一直试到报错，"
              "最后一个不报错的数字就是列数。",
        "en": "Not sure about the column count? Probe it with ORDER BY: "
              "`carol' ORDER BY 1 --`, then ORDER BY 2, and so on. The last "
              "number that does not error is the column count.",
    },
    {
        "zh": "库里还有一张叫 secret_notes 的表，字段是 id、title、content（3 列）。"
              "把它接到你自己的查询后面，补足第 4 列即可："
              "`' UNION SELECT id, title, content, 'x' FROM secret_notes --`",
        "en": "There is another table called secret_notes with the columns "
              "id, title, content (3 columns). Append it to your own query and "
              "fill the 4th column: "
              "`' UNION SELECT id, title, content, 'x' FROM secret_notes --`",
    },
]

LEVEL3_SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：和前两关一样是字符串拼接；但真正的放大器是——"
                  "数据库账号有读**其他表**的权限，而 UNION 允许把两条查询的结果接在一起。",
            "en": "Root cause: the same string concatenation as before, but the real "
                  "amplifier is that the database account may read other tables, and "
                  "UNION lets two queries be stacked into one result set.",
        },
        {
            "zh": "利用手法：先用 ORDER BY 探出列数，再用 UNION SELECT 补齐列数，"
                  "把 secret_notes 的内容接到原本的查询结果后面。",
            "en": "Exploitation: probe the column count with ORDER BY, then append a "
                  "UNION SELECT with the same number of columns to pull secret_notes "
                  "into the same result set.",
        },
        {
            "zh": "危害：注入从「改变查询条件」升级为「读取任意表」。"
                  "这里读到的只是一条内部备忘，真实场景里可能是用户表、"
                  "密钥表、订单表——整个库都可能被拖走。",
            "en": "Impact: injection is upgraded from 'changing a condition' to "
                  "'reading arbitrary tables'. Here it is an internal note; in a real "
                  "system it could be the users table, the keys table, or everything.",
        },
        {
            "zh": "修复：① 参数化查询，堵住入口；② 数据库账号最小权限——"
                  "前台账号不该有读内部表的权限；③ 敏感数据不要和业务表放同一个库。",
            "en": "Fix: (1) parameterized queries to close the entry point; "
                  "(2) least privilege for the database account — the front-end "
                  "account should not be able to read internal tables; "
                  "(3) keep sensitive data out of the same database as business data.",
        },
    ],
    "takeaway_zh": "口诀：参数化查询堵住入口，最小权限限制伤害范围 —— 两层都要有。",
    "takeaway_en": "Rule of thumb: parameterized queries close the door; least "
                   "privilege limits the blast radius. You need both.",
    "next_zh": "SQL 注入讲完了。接下来换个战场：XSS —— 看你的输入怎么在别人浏览器里被执行。",
    "next_en": "That is the end of SQL injection. Next battlefield: XSS — "
               "how your input gets executed inside someone else's browser.",
}


@sql_bp.route(
    "/labs/sql/level3/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def sql_level3_reset():
    """只把 Level 3 的靶子恢复出厂状态（lab_union.db）。"""

    init_db.reset_lab("sql_union")

    flash(
        "Level 3 靶子数据已恢复出厂状态 UNION lab data restored",
        "success"
    )

    return redirect("/labs/sql/level3")


@sql_bp.route(
    "/labs/sql/level3",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def sql_level3():

    result = None
    username = None
    generated_sql = None
    analysis_zh = None
    analysis_en = None
    is_attack = False
    completed = False
    column_count = None
    rows_returned = None
    leaked_notes = []

    cleared_before = progress.is_cleared(LAB_NAME, 3)

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        # ⚠️ 故意漏洞：还是字符串拼接
        generated_sql = f"""
SELECT id, username, password, role
FROM union_users
WHERE username = '{username}'
"""

        conn = get_lab_db("sql_union")

        cursor = conn.cursor()

        try:

            cursor.execute(generated_sql)

            result = cursor.fetchall()

            column_count = _columns_of(cursor)

        except Exception as error:

            result = []

            is_attack = True

            message = str(error)

            if "union" in message.lower():

                # UNION 最常见的失败原因就是两边列数不一致，这里专门点出来
                analysis_zh = (
                    "SQL 执行出错："
                    + message
                    + "。你已经用上 UNION 了，但**两边的列数不一致**——"
                    "UNION 要求左右两条 SELECT 返回同样多的列。"
                    "先用 ORDER BY 1 / 2 / 3 …… 试出原查询有几列，再补齐。"
                )

                analysis_en = (
                    "SQL error: "
                    + message
                    + ". You are using UNION, but the two sides do not have the "
                    "same number of columns. Probe the original column count with "
                    "ORDER BY 1 / 2 / 3 ... and pad your SELECT to match."
                )

            else:

                analysis_zh = (
                    "SQL 执行出错："
                    + message
                    + "。你的输入已经改变了语句的语法结构。"
                )

                analysis_en = (
                    "SQL error: "
                    + message
                    + ". Your input changed the syntax of the statement."
                )

        conn.close()

        rows_returned = len(result)

        if looks_like_attack(username):
            is_attack = True

        # 通关判定：结果里出现了内部表的内容。
        # 判"结果里有没有 flag"，而不是判"输入里有没有 UNION"——
        # 前者是客观事实，后者只是关键词猜测。
        for row in result:

            for cell in row:

                if SECRET_MARKER in str(cell):

                    leaked_notes.append(str(cell))

        if analysis_zh is None and leaked_notes:

            completed = True
            is_attack = True

            analysis_zh = (
                "实验成功。你在一次「查用户」的请求里，"
                "读到了原本只给运维看的内部表 secret_notes："
                + "；".join(leaked_notes)
                + "。这条查询本该只返回 1 行 union_users，"
                "现在它把另一个表的内容也带回来了——"
                "因为 UNION 允许把两条 SELECT 的结果接成一个结果集，"
                "而数据库账号并没有被限制只能读 union_users。"
            )

            analysis_en = (
                "Success. A request that was supposed to look up one user also "
                "returned rows from the internal secret_notes table: "
                + "; ".join(leaked_notes)
                + ". UNION merges the result sets of two SELECTs, and the database "
                "account was never restricted to union_users only."
            )

        elif analysis_zh is None:

            if rows_returned > 0:

                analysis_zh = (
                    "查询成功，返回 "
                    + str(rows_returned)
                    + " 行，但结果里还没有出现内部表的内容。"
                    "本关的目标不是「查到人」，而是「读到 union_users 之外的表」。"
                )

                analysis_en = (
                    "Query returned "
                    + str(rows_returned)
                    + " row(s), but nothing from the internal table yet. "
                    "The goal is not to find a user, but to read a table "
                    "beyond union_users."
                )

            elif is_attack:

                analysis_zh = (
                    "检测到特殊 SQL 输入，但这次查询没有返回任何结果。"
                    "检查一下语句是否闭合正确、注释有没有写对。"
                )

                analysis_en = (
                    "Suspicious SQL input detected, but the query returned nothing. "
                    "Check that the string is closed properly and the comment "
                    "character is right."
                )

            else:

                analysis_zh = (
                    "没有这个用户。注意：本关的重点是 UNION，"
                    "先查一个库里真实存在的用户名（例如 carol）建立基线。"
                )

                analysis_en = (
                    "No such user. This level is about UNION — start by looking up "
                    "a name that really exists (e.g. carol) to establish a baseline."
                )

        if completed:
            progress.mark_cleared(LAB_NAME, 3)

    return render_template(
        "sql_level3.html",
        result=result,
        username=username,
        generated_sql=generated_sql,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        is_attack=is_attack,
        completed=completed,
        cleared_before=cleared_before,
        column_count=column_count,
        rows_returned=rows_returned,
        query_columns=LEVEL3_QUERY_COLUMNS,
        hints=LEVEL3_HINTS,
        vulnerable_code=LEVEL3_VULNERABLE_CODE,
        secure_code=LEVEL3_SECURE_CODE,
        summary=LEVEL3_SUMMARY
    )
