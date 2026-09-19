# -*- coding: utf-8 -*-
"""越权访问实验：Level 1 水平越权（IDOR）。

⚠️ 故意保留的漏洞：详情接口只用用户可控的 id 去取数据，
   **没有校验这条数据属不属于当前身份**。

这一关想讲清楚一个区分：
    认证（Authentication）= 你是谁        → 平台用 login_required 做了
    授权（Authorization）= 你能看什么    → 这一关故意没做

所以它和前面几关的"漏洞形态"不一样：
    SQL 注入、XSS、命令注入是"输入被当成了代码"，
    越权是"逻辑上少问了一句：这条数据是你的吗"。
这也是 OWASP Top 10 里排第一的「失效的访问控制」。

靶子库 lab_idor.db：
    idor_users  4 个用户（alice / bob / carol / admin）
    idor_notes  每个用户的笔记；admin 的私密笔记里放着本关的 flag

通关判定：读到了一条 **owner 不是当前身份** 的笔记。
判定看的是"这条数据的归属和你提交的身份是否一致"，客观且可复现。
"""

from flask import Blueprint, flash, redirect, render_template, request

import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

idor_bp = Blueprint(
    "idor",
    __name__
)

LAB_NAME = "idor"

FLAG_MARKER = "flag{"

# 可以在页面上切换的"动手身份"。
# 真实系统里这个身份来自登录状态，不会让你随便切——
# 这里做成可切换的，是为了让你能同时看到"我的视角"和"别人的数据"。
IDENTITIES = [
    (1, "alice"),
    (2, "bob"),
    (3, "carol"),
]

DEFAULT_IDENTITY = 1


def username_of(user_id):
    """把用户 id 换成用户名（页面上显示用）。"""

    conn = get_lab_db("idor")
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM idor_users WHERE id = ?", (user_id,))

    row = cursor.fetchone()

    conn.close()

    return row[0] if row else None


def all_users():
    """全部用户（用来展示"库里其实有别人"）。"""

    conn = get_lab_db("idor")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, display_name, role FROM idor_users ORDER BY id")

    rows = cursor.fetchall()

    conn.close()

    return rows


def notes_of(owner_id):
    """某个用户自己的笔记列表（正常功能只展示自己的）。"""

    conn = get_lab_db("idor")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, owner_id, title, content, is_private
        FROM idor_notes
        WHERE owner_id = ?
        ORDER BY id
        """,
        (owner_id,),
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def note_by_id(note_id):
    """按 id 取一条笔记。

    ⚠️ 故意漏洞就在这一行 SQL 里：条件只有 id，没有 owner_id。
       修复方案见页面上的 Secure Code 对照。
    """

    conn = get_lab_db("idor")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, owner_id, title, content, is_private
        FROM idor_notes
        WHERE id = ?
        """,
        (note_id,),
    )

    row = cursor.fetchone()

    conn.close()

    return row


def total_notes():
    """库里一共有多少条笔记（页面上用来说"不止你看到的那几条"）。"""

    conn = get_lab_db("idor")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM idor_notes")

    total = cursor.fetchone()[0]

    conn.close()

    return total


VULNERABLE_CODE = '''# 当前身份：真实系统里来自登录会话，用户改不了
current_user = session["user_id"]

# 地址栏里的 ?note_id=3 是用户完全可控的
note_id = request.args.get("note_id")

# ⚠️ 故意漏洞：只按 id 取记录 —— 没有问"这条记录是不是你的"
cursor.execute(
    "SELECT id, owner_id, title, content FROM idor_notes WHERE id = ?",
    (note_id,)
)
note = cursor.fetchone()

# 列表只显示自己的笔记，但详情接口谁都能取。
# 于是把 note_id 改一个数字，就看到了别人的数据。'''

SECURE_CODE = '''current_user = session["user_id"]
note_id = request.args.get("note_id")

# 1) 把"归属"写进查询条件里 —— 让数据库替你把关，
#    而不是取出来之后再用 if 判断（那样很容易漏掉某个分支）
cursor.execute(
    """
    SELECT id, owner_id, title, content
    FROM idor_notes
    WHERE id = ? AND owner_id = ?
    """,
    (note_id, current_user)
)
note = cursor.fetchone()

# 2) 取不到就统一返回 404：
#    不要用 403「存在但你没权限」—— 那等于告诉攻击者"这个 id 是有效的"，
#    他就能靠 403/404 的差别把全站数据的存在性一个个试出来
if note is None:
    abort(404)

# 3) 外部标识别用自增 id（可枚举）。换成 UUID 之后，
#    "改一个数字"这招就失效了 —— 但它只是提高门槛，不能替代授权校验。
# 4) 授权逻辑集中写一处（装饰器 / 中间件），别在每个接口里各写一遍。'''

HINTS = [
    {
        "zh": "先以 alice 的身份看一遍：左边是「我的笔记」，只有 2 条。"
              "点开其中一条，注意地址栏最后多出来的那个参数。",
        "en": "Start as alice: the left column shows her notes, and there are only "
              "two. Open one and look at the parameter that appears in the URL.",
    },
    {
        "zh": "列表只给你看自己的笔记，但**详情是另一条路径**："
              "它只拿 id 去数据库取记录，从没问过「这条是不是你的」。"
              "那么把那个 id 改成别的数字，会发生什么？",
        "en": "The list only shows your own notes, but the detail view is a "
              "different code path: it fetches by id and never asks whose record it "
              "is. So what happens if you change that number?",
    },
    {
        "zh": "试试 `note_id` 从 1 到 7 逐个走一遍（注意保持 `as=1` 不变）。"
              "你会看到别人、甚至管理员的私密笔记 —— 其中一条里就是本关的 flag。",
        "en": "Walk note_id from 1 to 7 while keeping as=1. You will see other "
              "users' notes and even the administrator's private note — one of them "
              "holds this level's flag.",
    },
]

SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：接口用用户可控的 id 直接取数据，"
                  "缺少「这条数据属不属于当前身份」的校验。"
                  "认证已经做了（你要登录才能进来），但授权没做。",
            "en": "Root cause: the endpoint fetches a record by a user-controlled id "
                  "without checking whether the record belongs to the caller. "
                  "Authentication was done; authorization was not.",
        },
        {
            "zh": "利用手法：把 id 换成别人的（水平越权，同级别用户之间）；"
                  "如果把普通用户的 id 换成管理员的（垂直越权），危害更大。",
            "en": "Exploitation: swap the id for someone else's (horizontal "
                  "privilege escalation, between peers). Swapping a normal user for "
                  "an admin is vertical escalation and is worse.",
        },
        {
            "zh": "危害：id 通常是自增的，写个循环就能把所有数据拖走 ——"
                  "这类攻击叫「越权遍历」。真实事故里泄露的往往是订单、"
                  "地址、身份证号、聊天记录。",
            "en": "Impact: ids are usually sequential, so a simple loop dumps the "
                  "whole table — that is enumeration. Real-world leaks are orders, "
                  "addresses, ID numbers and chat logs.",
        },
        {
            "zh": "修复：① 查询条件里带上 owner_id（让数据库把关）；"
                  "② 取不到统一返回 404，别用 403 暴露数据的存在性；"
                  "③ 外部标识改用 UUID，降低可枚举性；"
                  "④ 授权逻辑集中写一处，而不是每个接口各写一遍。",
            "en": "Fix: (1) put owner_id into the query so the database enforces it; "
                  "(2) return 404 rather than 403 so you do not reveal existence; "
                  "(3) use UUIDs for external identifiers; (4) centralise "
                  "authorization instead of re-implementing it per endpoint.",
        },
    ],
    "takeaway_zh": "口诀：认证回答「你是谁」，授权回答「你能看什么」—— 只做前者，等于没锁门。",
    "takeaway_en": "Rule of thumb: authentication answers who you are, "
                   "authorization answers what you may see. Do only the first and "
                   "the door is still open.",
    "next_zh": "到这里五类漏洞（SQL 注入 / XSS / 文件上传 / SSRF / 命令注入）"
               "加上越权就都打通了。回实验列表看看总进度，再逐个重做一遍——第二遍不看提示。",
    "next_en": "That covers five vulnerability classes plus access control. Go back "
               "to the lab list to see your progress, then redo them without hints.",
}


@idor_bp.route(
    "/labs/idor/level1/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def idor_level1_reset():
    """把笔记与用户恢复出厂。"""

    init_db.reset_lab("idor")

    flash(
        "越权实验靶子已恢复出厂状态 IDOR lab data restored",
        "success"
    )

    return redirect("/labs/idor/level1")


@idor_bp.route("/labs/idor/level1")
@login_required
@ratelimit.limit("lab_query")
def idor_level1():

    # 当前"动手身份"（见文件顶部说明：真实系统里这个来自登录会话）
    identity = request.args.get("as", type=int)

    if identity not in [uid for uid, _ in IDENTITIES]:
        identity = DEFAULT_IDENTITY

    identity_name = username_of(identity)

    note_id = request.args.get("note_id", type=int)

    note = None
    owner_name = None
    generated_sql = None
    completed = False
    is_attack = False
    analysis_zh = None
    analysis_en = None
    contains_flag = False

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if note_id is not None:

        # 页面上显示的"实际执行的语句"，方便对照
        generated_sql = (
            "SELECT id, owner_id, title, content, is_private\n"
            "FROM idor_notes\n"
            "WHERE id = " + str(note_id) + "          ← 只有 id，没有 owner_id"
        )

        note = note_by_id(note_id)

        if note is None:

            is_attack = True

            analysis_zh = (
                "没有 id = "
                + str(note_id)
                + " 这条笔记。注意：<b>代码里并没有因此报错或拦你</b>，"
                "它只是老老实实去数据库查了一次 —— "
                "这正说明它把「这个 id 能不能看」完全交给了调用者。"
            )

            analysis_en = (
                "There is no note with id = "
                + str(note_id)
                + ". Note that the code did not stop you: it simply queried the "
                "database. The question of whether you may see this id was never "
                "asked."
            )

        else:

            owner_name = username_of(note[1])

            contains_flag = FLAG_MARKER in str(note[3])

            if note[1] != identity:

                # 归属和当前身份不一致 —— 越权成立
                completed = True
                is_attack = True

                analysis_zh = (
                    "实验成功。你现在的身份是 <b>"
                    + str(identity_name)
                    + "</b>，却读到了 <b>"
                    + str(owner_name)
                    + "</b> 的笔记《"
                    + str(note[2])
                    + "》。"
                    "这不是「猜到了密码」，也不是「绕过了登录」——"
                    "你的登录完全正常，只是这个接口<b>少问了一句：这条数据是你的吗</b>。"
                )

                if contains_flag:

                    analysis_zh += (
                        "而且这条正是管理员的私密笔记，里面放着本关的 flag。"
                    )

                analysis_en = (
                    "Success. You are acting as "
                    + str(identity_name)
                    + " yet you read a note owned by "
                    + str(owner_name)
                    + " ('"
                    + str(note[2])
                    + "'). You did not guess a password and you did not bypass the "
                    "login — the endpoint simply never asked whether the record "
                    "belongs to you."
                )

                if contains_flag:

                    analysis_en += (
                        " This particular note belongs to the administrator and "
                        "holds the level flag."
                    )

            elif contains_flag:

                analysis_zh = (
                    "这是你自己的笔记。注意 <code>is_private = 1</code> 的笔记"
                    "在列表里也有标记 —— 但列表和详情是两条路径，"
                    "详情这一条谁都能取。换个别人的 id 试试。"
                )

                analysis_en = (
                    "This note is yours. Note that private notes are flagged in the "
                    "list, yet the list and the detail view are separate code paths "
                    "and the detail view checks nothing. Try someone else's id."
                )

            else:

                analysis_zh = (
                    "这是 <b>"
                    + str(identity_name)
                    + "</b> 自己的笔记《"
                    + str(note[2])
                    + "》，正常访问。"
                    "把 note_id 改一个数字，你就会看到别人的数据 —— "
                    "而这一关的判定标准正是「归属和身份是否一致」。"
                )

                analysis_en = (
                    "This is "
                    + str(identity_name)
                    + "'s own note ('"
                    + str(note[2])
                    + "'), a legitimate access. Change the note_id and you will read "
                    "someone else's data — which is exactly what this level checks "
                    "for."
                )

        if completed:
            progress.mark_cleared(LAB_NAME, 1)

    return render_template(
        "idor_level1.html",
        identities=IDENTITIES,
        identity=identity,
        identity_name=identity_name,
        note_id=note_id,
        note=note,
        owner_name=owner_name,
        contains_flag=contains_flag,
        my_notes=notes_of(identity),
        all_users=all_users(),
        total_notes=total_notes(),
        generated_sql=generated_sql,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        artifact_title="实际执行的语句与归属对比 Executed Query",
        artifact_body=(
            (
                "当前身份: " + str(identity_name) + " (id=" + str(identity) + ")\n"
                "请求的 id: " + str(note_id) + "\n"
                "------------------------------\n"
                + generated_sql
                + "\n------------------------------\n"
                + (
                    "这条笔记的归属: " + str(owner_name) + " (id=" + str(note[1]) + ")\n"
                    + "归属与身份是否一致: "
                    + ("是 YES（正常访问）" if note[1] == identity else "否 NO（越权！）")
                    if note
                    else "没有查到这条记录"
                )
            )
            if generated_sql
            else None
        ),
        artifact_note=(
            "对比第 1 行和第 6 行：身份是一个值，数据归属是另一个值。"
            "这一关的漏洞就是「没人比较这两个值」。"
            " / Compare line 1 and line 6: your identity is one value, the record's "
            "owner is another. The bug is that nothing compares them."
        ),
        ok_label="IDOR Successful 越权访问成功",
        hints=HINTS,
        vulnerable_code=VULNERABLE_CODE,
        secure_code=SECURE_CODE,
        fix_vulnerable_zh=(
            "查询条件里只有 id。列表接口做了过滤（只查自己的），"
            "但详情接口没有 —— 这类「一个地方做了、另一个地方忘了」正是越权最常见的成因。"
        ),
        fix_vulnerable_en=(
            "The query filters on id only. The list endpoint filters by owner, the "
            "detail endpoint does not — that 'done here, forgotten there' pattern is "
            "how most IDOR bugs are born."
        ),
        fix_secure_zh=(
            "把 owner_id 写进查询条件，让数据库把关；取不到统一 404；"
            "外部标识用 UUID；授权逻辑集中一处维护。"
        ),
        fix_secure_en=(
            "Put owner_id into the query so the database enforces ownership, return "
            "404 instead of 403, use UUIDs externally, and centralise authorization."
        ),
        summary=SUMMARY
    )
