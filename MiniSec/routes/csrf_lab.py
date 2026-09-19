# -*- coding: utf-8 -*-
"""CSRF 实验：Level 1 跨站请求伪造。

⚠️ 故意保留的漏洞：修改资料的接口只靠 Cookie 判断身份，
   **不校验请求是不是从本站页面发出来的**。

这一关和前六关的形态又不一样：
    SQL 注入 / XSS / 命令注入 —— 输入被当成了代码
    越权（IDOR）            —— 少问了「这条数据是你的吗"
    CSRF                    —— 少问了「这个请求是你想发的吗"

关键事实只有一条：**浏览器发请求时会自动带上 Cookie**。
所以只要能让已登录的浏览器向这个接口发一个请求，攻击就得手了 ——
而「让浏览器发请求」最简单的方式，就是让用户打开一个攻击者的页面。

本项目的对照设计：
    平台自身的接口（登录、恢复出厂…）由 security.py 全站校验 CSRF 令牌；
    这一关的靶子接口被**故意加进豁免名单**，用来演示「不校验会怎样"。
    豁免名单写在 security.py 里，并注明「只给靶子用，平台接口不准加进来"。

靶子库 lab_csrf.db：
    csrf_users  一个受害者账号（victim）+ 一个管理员账号

通关判定：受害者的邮箱被改成了攻击者指定的地址。
判定看的是数据库里真实的值，不是请求里带了什么。
"""

from flask import Blueprint, flash, redirect, render_template, request, session

import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

csrf_bp = Blueprint(
    "csrf",
    __name__
)

LAB_NAME = "csrf"

# 本关固定的「已登录身份"。
# 真实系统里这个来自登录会话；这里用 session 存一下，
# 是为了让「身份来自 Cookie"这件事在代码里看得见。
LAB_SESSION_KEY = "csrf_lab_user"
VICTIM = "victim"

# 攻击者想改成什么（也是通关判定依据）
ATTACKER_EMAIL = "attacker@evil.example"

# 受害者原本的邮箱（恢复出厂后应该回到这个值）
ORIGINAL_EMAIL = "victim@example.com"


def get_user(username):
    """读一个靶子账号。"""

    conn = get_lab_db("csrf")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, email, display_name FROM csrf_users WHERE username = ?",
        (username,),
    )

    row = cursor.fetchone()

    conn.close()

    return row


def set_email(username, email):
    """改邮箱 —— 这就是那个「没有校验来源」的接口在做的事。"""

    conn = get_lab_db("csrf")
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE csrf_users SET email = ? WHERE username = ?",
        (email, username),
    )

    conn.commit()
    conn.close()


def all_users():
    """靶子库里的所有账号（给页面做对照用）。"""

    conn = get_lab_db("csrf")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, username, email, display_name FROM csrf_users ORDER BY id"
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


VULNERABLE_CODE = '''# 修改资料：身份完全依赖 Cookie（浏览器会自动带上）
@app.route("/labs/csrf/level1/profile", methods=["POST"])
def update_profile():

    username = session.get("csrf_lab_user")     # ← 只信 Cookie

    email = request.form.get("email")

    # ⚠️ 故意漏洞：这里**没有**校验 CSRF 令牌。
    #   表单里其实带了 token，但后端从来没看过它 ——
    #   "加了但没校验「等于没加。
    conn.execute(
        "UPDATE csrf_users SET email = ? WHERE username = ?",
        (email, username)
    )
    return redirect("/labs/csrf/level1")'''

SECURE_CODE = '''# 修复方案一：同步器令牌（本项目平台自身用的就是这个）
#   security.py 里 before_request 统一校验：POST 必须带上会话里的令牌，
#   并且用 compare_digest 做固定时间比较。
@app.before_request
def protect():
    if request.method != "POST":
        return None
    sent = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token")
    if not expected or not secrets.compare_digest(
        sent.encode("utf-8", "replace"), expected.encode("utf-8")
    ):
        return reject_400()

# 修复方案二：Cookie 加 SameSite
#   session cookie 设 SameSite=Lax / Strict，
#   跨站发起的 POST 根本带不上 Cookie，攻击直接失效。

# 修复方案三：校验来源
#   检查 Origin / Referer 是不是本站（注意 Referer 可能缺失，只能当辅助）。

# 修复方案四：敏感操作二次确认（重新输入密码 / 邮箱验证链接）'''

HINTS = [
    {
        "zh": "先正常用一次这个功能：把自己的邮箱改成一个别的地址，"
              "然后看右侧「浏览器实际发出的请求」—— 注意里面带了什么、没带什么。",
        "en": "Use the feature normally first: change your email to something else, "
              "then look at the request on the right — note what it carries and what "
              "it does not.",
    },
    {
        "zh": "两个关键事实：① 这个接口靠 <b>Cookie</b> 认人；"
              "② 浏览器发请求时会<b>自动带上 Cookie</b>，不管这个请求是谁发起的。"
              "那么问题来了：如果请求是<b>别人的网页</b>发起的呢？",
        "en": "Two key facts: (1) this endpoint identifies you by your <b>Cookie</b>; "
              "(2) the browser attaches cookies <b>automatically</b>, no matter who "
              "initiated the request. So what if another site initiates it?",
    },
    {
        "zh": "点左侧那条「攻击者页面」的链接（模拟你被诱导打开了一个无关网站）。"
              "它里面有一个自动提交的表单，指向这个改邮箱接口，"
              "而且<b>没有令牌</b>—— 攻击者当然拿不到你的令牌。"
              "页面自己会提交，回来看看邮箱是不是被改了。",
        "en": "Open the attacker page linked on the left (imagine you were lured "
              "into opening an unrelated site). It contains a form that submits "
              "itself to the email endpoint and carries <b>no token</b> — an attacker "
              "cannot obtain yours. Watch your email change.",
    },
]

SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：接口只凭 Cookie 判断身份，而没有判断"
                  "「这个请求是不是从我的页面发出来的」。"
                  "Cookie 是浏览器<b>自动</b>携带的，它证明「你是谁」，"
                  "但不证明「这个请求是你想发的」。",
            "en": "Root cause: the endpoint identifies the caller by Cookie alone and "
                  "never checks whether the request came from its own page. Cookies "
                  "are attached automatically: they prove <b>who you are</b>, not "
                  "that you intended this request.",
        },
        {
            "zh": "利用手法：诱导已登录的用户打开攻击者的页面，"
                  "页面里放一个自动提交的表单指向目标接口。"
                  "浏览器带上 Cookie 提交，服务端看到的是「一次合法的请求」。",
            "en": "Exploitation: lure a logged-in user onto the attacker's page, which "
                  "contains a self-submitting form aimed at the target endpoint. The "
                  "browser submits it with cookies attached, and the server sees "
                  "'a perfectly valid request'.",
        },
        {
            "zh": "危害：能做的正是「登录用户能做的任何事」。"
                  "经典利用链：改邮箱 → 用邮箱找回密码 → 账号被接管；"
                  "同理还有转账、改权限、删数据。",
            "en": "Impact: anything the logged-in user could do. The classic chain is "
                  "change the email, trigger a password reset, and take over the "
                  "account — the same applies to transfers, privilege changes and "
                  "deletions.",
        },
        {
            "zh": "修复：① CSRF 令牌（本项目平台自身用的就是这个）；"
                  "② Cookie 加 SameSite=Lax/Strict；③ 校验 Origin / Referer；"
                  "④ 敏感操作二次确认。注意：<b>只在表单里加令牌、后端不校验，"
                  "等于没加</b> —— 这一关的靶子就是这样。",
            "en": "Fix: (1) CSRF tokens (what this project's own platform uses); "
                  "(2) SameSite=Lax/Strict cookies; (3) check Origin/Referer; "
                  "(4) re-authenticate for sensitive actions. Note that <b>putting a "
                  "token in the form without validating it server-side is the same as "
                  "having none</b> — which is exactly this lab's bug.",
        },
    ],
    "takeaway_zh": "口诀：Cookie 只回答「你是谁」，不回答「这个请求是不是你想发的」。",
    "takeaway_en": "Rule of thumb: a cookie answers who you are, never whether you "
                   "meant to send this request.",
    "next_zh": "到这里七个实验、十个关卡就全部打通了。"
               "回实验列表看看总进度，再逐个重做一遍 —— 第二遍不看提示和速查表。",
    "next_en": "That completes seven labs and ten levels. Go back to the lab list to "
               "see your progress, then redo them all without hints or cheatsheets.",
}


def _current_user():
    """本关的「已登录身份"。真实系统里来自会话。"""

    return session.get(LAB_SESSION_KEY, VICTIM)


@csrf_bp.route("/labs/csrf/level1/reset", methods=["POST"])
@login_required
@ratelimit.limit("lab_reset")
def csrf_level1_reset():
    """把靶子账号恢复出厂（邮箱改回原值）。

    注意：这个接口**不在豁免名单里**，它照常校验 CSRF 令牌 ——
    平台自己的操作永远是受保护的。
    """

    init_db.reset_lab("csrf")

    flash(
        "CSRF 靶子已恢复出厂状态 CSRF lab data restored",
        "success"
    )

    return redirect("/labs/csrf/level1")


@csrf_bp.route("/labs/csrf/level1/profile", methods=["POST"])
@login_required
@ratelimit.limit("lab_query")
def csrf_level1_profile():
    """修改邮箱 —— 本关的靶子接口。

    ⚠️ 这个接口被 security.py 的豁免名单放过了，所以它**不校验 CSRF 令牌**。
       它的存在就是为了演示「不校验会怎样"。

    注意它拿身份的方式：只读 session（也就是 Cookie）。
    """

    username = _current_user()

    email = request.form.get("email", "").strip()

    # 记录本次请求的样子，页面上要展示这四条 —— 这就是攻击的全部证据
    session["csrf_last_request"] = {
        "email": email,
        "had_token": bool(request.form.get("csrf_token")),
        "cookie_present": bool(request.cookies.get("session")),
        "referer": request.headers.get("Referer", "") or "（无）",
    }

    if email:
        set_email(username, email)

    return redirect("/labs/csrf/level1")


@csrf_bp.route("/labs/csrf/attacker")
@login_required
def csrf_attacker():
    """模拟的「攻击者页面"。

    真实世界里它在攻击者的服务器上，用户只是被诱导打开了它。
    这里放在靶场内部是为了方便演示 —— 但它**同样拿不到你的令牌**，
    因为页面里只有一段写死的 HTML 表单。

    顺便说明为什么这个页面不用带头登录：
    攻击者根本不需要登录你的站，他要的只是「你的浏览器发一个请求"。
    """

    return render_template(
        "csrf_attacker.html",
        target="/labs/csrf/level1/profile",
        attacker_email=ATTACKER_EMAIL,
    )


@csrf_bp.route("/labs/csrf/level1")
@login_required
@ratelimit.limit("lab_query")
def csrf_level1():

    # 首次进入时把身份写进会话（真实系统里这是登录动作做的事）
    if LAB_SESSION_KEY not in session:
        session[LAB_SESSION_KEY] = VICTIM

    username = _current_user()

    user = get_user(username)

    email = user[2] if user else None

    last = session.get("csrf_last_request")

    completed = email == ATTACKER_EMAIL

    analysis_zh = None
    analysis_en = None
    is_attack = False

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if completed:

        is_attack = True

        analysis_zh = (
            "实验成功。你（victim）并没有主动改邮箱，"
            "但数据库里的邮箱已经变成了攻击者指定的地址 "
            "<code>"
            + str(ATTACKER_EMAIL)
            + "</code>。"
            "整个过程里，服务端看到的是一次<b>完全正常的请求</b>："
            "Cookie 有效、身份明确、参数合法 —— "
            "它唯一没问的是：<b>这个请求到底是不是你发的？</b>"
            "如果这是真实站点，攻击者下一步就是点「忘记密码」，"
            "用这个邮箱把账号整个拿走。"
        )

        analysis_en = (
            "Success. You (victim) never changed your email, yet the database now "
            "holds the attacker's address "
            "<code>"
            + str(ATTACKER_EMAIL)
            + "</code>. To the server this looked like a perfectly normal request: "
            "valid cookie, known identity, well-formed parameters. The one question "
            "it never asked was <b>whether you actually sent it</b>. On a real site "
            "the attacker's next step is 'forgot password' — and the account is gone."
        )

        progress.mark_cleared(LAB_NAME, 1)

    elif last:

        if last["had_token"]:

            analysis_zh = (
                "邮箱已被改成 <code>"
                + str(email)
                + "</code>。"
                "注意这次请求<b>带了令牌</b>（是你从本站表单提交的），"
                "但服务端<b>根本没有校验它</b> —— "
                "这正是「加了但没校验等于没加」。"
                "再想想：如果请求不是从本站表单发出的，令牌从哪来？"
            )

            analysis_en = (
                "The email is now <code>"
                + str(email)
                + "</code>. Note this request <b>carried a token</b> (your own form "
                "sent it), but the server <b>never validated it</b> — a token that is "
                "not checked is the same as no token. Now ask: if the request came "
                "from somewhere else, where would the token come from?"
            )

        else:

            analysis_zh = (
                "邮箱已被改成 <code>"
                + str(email)
                + "</code>，而且这次请求<b>完全没有令牌</b>。"
                "服务端照样接受了 —— 说明它确实没有校验。"
                "翻回上面的「浏览器实际发出的请求」，对照一下。"
            )

            analysis_en = (
                "The email is now <code>"
                + str(email)
                + "</code> and this request carried <b>no token at all</b>. The "
                "server accepted it anyway, which proves it never validates one."
            )

    else:

        analysis_zh = (
            "先正常用一次这个功能（改自己的邮箱），"
            "观察右侧的「浏览器实际发出的请求」，"
            "然后去点那条「攻击者页面」的链接。"
        )

        analysis_en = (
            "Use the feature normally first (change your own email) and look at the "
            "request on the right. Then open the attacker page link."
        )

    artifact_body = None

    if last:

        artifact_body = (
            "POST /labs/csrf/level1/profile\n"
            "Cookie: session=…（浏览器<b>自动</b>携带，攻击者不需要知道内容）\n"
            "Referer: " + str(last["referer"]) + "\n"
            "Body: email=" + str(last["email"]) + "\n"
            "请求里的 csrf_token: "
            + ("有" if last["had_token"] else "（没有）")
            + "\n"
            "服务端校验了吗: 没有 —— 这就是漏洞"
        )

    return render_template(
        "csrf_level1.html",
        username=username,
        display_name=user[3] if user else "",
        email=email,
        original_email=ORIGINAL_EMAIL,
        attacker_email=ATTACKER_EMAIL,
        users=all_users(),
        last_request=last,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        artifact_title="浏览器实际发出的请求 The Actual Request",
        artifact_body=artifact_body,
        artifact_note=(
            "四条里最关键的是第一行：Cookie 是浏览器自己带上的，"
            "跟「这个请求是谁发起的」完全无关。"
            " / The important line is the first one: the cookie is attached by the "
            "browser, regardless of who initiated the request."
        ),
        ok_label="CSRF Successful 跨站请求伪造成功",
        hints=HINTS,
        vulnerable_code=VULNERABLE_CODE,
        secure_code=SECURE_CODE,
        fix_vulnerable_zh=(
            "身份来自 Cookie（这没问题），但请求来源没有被校验（这才是问题）。"
            "表单里那个令牌形同虚设 —— 后端从来没看过它。"
        ),
        fix_vulnerable_en=(
            "Identity coming from a cookie is fine; never validating where the "
            "request came from is not. The token in the form is decorative — the "
            "backend never looks at it."
        ),
        fix_secure_zh=(
            "令牌 + 后端校验（本项目的 security.py 就是这套）、"
            "SameSite Cookie、Origin/Referer 校验、敏感操作二次确认 —— "
            "四层里至少要做到前两层。"
        ),
        fix_secure_en=(
            "A token that the server validates (security.py does exactly this), "
            "SameSite cookies, Origin/Referer checks, and re-authentication for "
            "sensitive actions — do at least the first two."
        ),
        summary=SUMMARY
    )
