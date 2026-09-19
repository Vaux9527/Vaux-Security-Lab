# -*- coding: utf-8 -*-
"""XSS 实验：Level 1 反射型 + Level 2 存储型。

⚠️ 这两关的漏洞也是故意保留的：用户输入被直接插进 HTML（没有转义），
   浏览器会把数据当成代码执行。为了教学效果，模板里**故意**使用了 |safe。

和 SQL 关卡一致的两个设计原则：

1. **通关判定看事实，不看关键词**
   判定的是"过滤之后真正进入页面的 HTML 里，是否存在可执行结构"，
   而不是"输入里有没有 <script 这几个字"。
   学习者用黑名单外的手法绕过时，判定依然正确。

2. **过滤是黑名单，漏洞是黑名单之外的一切**
   靶场只删掉 `<script`，这正好演示"黑名单永远不够用"。

靶子：
    Level 1 反射型：无状态，输入立刻回显（不需要靶子库）
    Level 2 存储型：留言存在 lab_xss.db 的 xss_guestbook 表里，持久生效
"""

import re
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request

import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

xss_bp = Blueprint(
    "xss",
    __name__
)

LAB_NAME = "xss"

# ---------------------------------------------------------------- 靶场的"防护"
# 故意做得很弱的黑名单：只把 <script 这七个字符删掉。
# 教学点就在这里 —— 黑名单挡不住 <img src=x onerror=...> 这类写法。
SCRIPT_TAG_RE = re.compile(r"<script", re.IGNORECASE)


def weak_filter(text):
    """靶场自带的"防护"：删掉 <script。故意留一个明显的缺口。"""

    return SCRIPT_TAG_RE.sub("", text)


# ---------------------------------------------------------------- 速查表
# "能执行 JavaScript 的写法"不止一种，但初学者往往只知道 <script>。
# 过滤把 script 挡掉之后，提示里突然出现 <img ... onerror=...>
# 就变成了一串没见过的东西 —— 这张表就是补这一层前置知识。
#
# 给的是"招式表"，不是答案：哪一招在你面前这一关能生效，仍然要自己判断。
XSS_CHEATSHEET = [
    {
        "code": "<script>alert(1)</script>",
        "why": "最直接：浏览器解析到 script 标签就会执行里面的代码。",
        "when": "没有任何过滤的时候，一招就够。",
    },
    {
        "code": "<img src=x onerror=alert(1)>",
        "why": "图片加载失败会触发 onerror 事件 —— 事件属性的值就是一段代码。",
        "when": "script 标签被过滤掉时，换一个「会触发事件」的标签。",
    },
    {
        "code": "<svg onload=alert(1)>",
        "why": "svg 加载完成时触发 onload，同样把代码当属性值执行。",
        "when": "同上，只是换一个标签；有的过滤只盯着 img。",
    },
    {
        "code": "<body onpageshow=alert(1)>",
        "why": "页面显示时触发 onpageshow。HTML 里几乎所有 on* 属性都是这个套路。",
        "when": "过滤放行了 body 这类结构性标签时。",
    },
    {
        "code": '<a href="javascript:alert(1)">click</a>',
        "why": "javascript: 是伪协议，点击链接时浏览器会执行后面的代码。",
        "when": "标签能进，但可能只剩 href 这样的属性可用。",
    },
]


# ---------------------------------------------------------------- 通关判定
# 判定标准：过滤之后真正进入 HTML 的内容里，还有没有"能被浏览器执行"的结构。
# 每一项都写成 (正则, 人话说明)，命中时把说明回显给学习者。
EXECUTABLE_PATTERNS = [
    (r"<script", "script 标签"),
    (r"<[a-z][^>]*\son[a-z]+\s*=", "事件属性（如 onerror / onload / onfocus）"),
    (r"<(iframe|svg|object|embed|math)\b", "可执行或可嵌入的标签"),
    (r"(href|src|action)\s*=\s*[\"']?\s*javascript:", "javascript: 伪协议"),
]


def detect_executable(text):
    """检查一段 HTML 里有没有可执行结构；返回命中的说明，没有则返回 None。"""

    lowered = text.lower()

    for pattern, label in EXECUTABLE_PATTERNS:

        if re.search(pattern, lowered):
            return label

    return None


def render_into_page(payload):
    """模拟页面真正渲染出来的那一小段 HTML。

    这一段的用途是"把看不见的东西变成看得见的"：
    学习者能直接对比"我输入了什么"和"页面里变成了什么"。
    """

    return '<p>没有找到与 "' + payload + '" 相关的结果。</p>'


def count_messages():
    """留言板里现在有几条留言。"""

    conn = get_lab_db("xss")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM xss_guestbook")

    total = cursor.fetchone()[0]

    conn.close()

    return total


def all_messages():
    """读出全部留言（新→旧）。"""

    conn = get_lab_db("xss")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, author, content, created_at
        FROM xss_guestbook
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


# ================================================================
# Level 1 反射型 XSS
# ================================================================

LEVEL1_VULNERABLE_CODE = '''# ⚠️ 故意漏洞：用户输入被原样拼进 HTML —— 没有过滤，也没有输出编码
snippet = '<p>没有找到与 "' + keyword + '" 相关的结果。</p>'

return render_template(
    "search.html",
    snippet=Markup(snippet)     # 当成 HTML 输出，浏览器会把输入解析成标记
)'''

LEVEL1_SECURE_CODE = '''# 1) 输出编码：让模板引擎自动把 < > " & 转成实体，
#    浏览器只会把它们当文字显示，不会当标签解析
return render_template(
    "search.html",
    keyword=keyword          # 模板里用 {{ keyword }}，Jinja2 默认自动转义
)

# 2) 真的需要富文本时，不要自己写正则过滤 ——
#    用成熟的白名单库（bleach 之类）清洗，并配合 CSP 再兜一层
# 3) 会话 Cookie 加 HttpOnly，即使被注入也拿不到登录态'''

LEVEL1_HINTS = [
    {
        "zh": "先搜一个普通词（比如 hello），然后在浏览器里右键 →「查看页面源代码」，"
              "Ctrl+F 搜 hello：你会发现自己输入的内容原样躺在 HTML 里，"
              "没有被转成 &lt; 之类的实体。",
        "en": "Search for a normal word first (e.g. hello), then use "
              "View Source in the browser and search for it: your input sits in "
              "the HTML verbatim, not encoded as &lt; entities.",
    },
    {
        "zh": "第 1 步看到的事实很关键：<b>你的输入变成了 HTML 的一部分</b>。"
              "那么在 HTML 里，什么样的写法会让浏览器去执行 JavaScript？"
              "（想不起来的话，展开上面的「可执行结构速查表」，看第一行。）",
        "en": "What you saw in step 1 is the key fact: <b>your input became part of "
              "the HTML</b>. So what kind of HTML makes a browser run JavaScript? "
              "(Open the cheatsheet above if nothing comes to mind — start with the "
              "first row.)",
    },
    {
        "zh": "最直接的一招：写一个 script 标签，让它的内容是一句弹窗代码 —— "
              "`<script>alert(1)</script>`，贴进搜索框回车。"
              "这一关没有做任何过滤，所以它会原封不动地进入页面并被执行。",
        "en": "The most direct move: write a script tag whose content is a call to "
              "alert — `<script>alert(1)</script>` — and submit it. This level does "
              "no filtering at all, so it lands in the page unchanged and runs.",
    },
]

LEVEL1_SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：用户输入被直接插进 HTML，没有做输出编码。"
                  "浏览器分不清「这是开发者写的标签」和「这是用户输入的文字」，"
                  "于是把数据当成了代码。",
            "en": "Root cause: user input is inserted into the HTML without output "
                  "encoding. The browser cannot tell developer-written markup from "
                  "user-supplied text, so it treats data as code.",
        },
        {
            "zh": "利用手法：写一个 script 标签就够了 —— 这一关没有任何过滤，"
                  "输入原封不动地变成了页面的一部分。"
                  "真正要记住的不是这一条 payload，而是「能执行 JS 的写法不止一种」："
                  "事件属性（onerror / onload）、javascript: 伪协议都是同一个原理。",
            "en": "Exploitation: one script tag is enough — this level filters "
                  "nothing, so the input became part of the page unchanged. What "
                  "matters is not this single payload but the fact that script has "
                  "many entry points: event attributes and javascript: URLs all work "
                  "on the same principle.",
        },
        {
            "zh": "危害：攻击者可以偷走你的 Cookie（拿到就等于拿到登录态）、"
                  "冒充你发请求、篡改页面内容做钓鱼、记录你的键盘输入。",
            "en": "Impact: an attacker can steal cookies (which means your session), "
                  "send requests as you, rewrite the page for phishing, or log your "
                  "keystrokes.",
        },
        {
            "zh": "修复：① 输出编码——模板引擎默认就会转义，别用 |safe 关掉它；"
                  "② 真需要富文本就用白名单库清洗；③ 加 CSP；"
                  "④ 会话 Cookie 设 HttpOnly。",
            "en": "Fix: (1) output encoding — template engines escape by default, so "
                  "do not switch it off with |safe; (2) sanitize rich text with a "
                  "whitelist library; (3) add CSP; (4) set HttpOnly on session cookies.",
        },
    ],
    "takeaway_zh": "口诀：在 HTML 里没有「数据」，只有标记 —— 不转义，就会被当成代码。",
    "takeaway_en": "Rule of thumb: inside HTML there is no data, only markup. "
                   "If you do not encode it, it becomes code.",
    "next_zh": "下一关是存储型 XSS：同样的手法，但一次注入会永久生效，"
               "而且不再需要骗任何人点链接。",
    "next_en": "Next: stored XSS. Same trick, but the injection persists and you no "
               "longer need to trick anyone into clicking a link.",
}


@xss_bp.route("/labs/xss/level1")
@login_required
@ratelimit.limit("lab_query")
def xss_level1():

    keyword = request.args.get("q", "").strip()

    filtered = None
    rendered = None
    executed = None
    completed = False
    is_attack = False
    analysis_zh = None
    analysis_en = None

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if keyword:

        # ⚠️ 故意漏洞：原样当成 HTML 用 —— 没有过滤，也没有输出编码
        # （筛选与绕过的手法留给 Level 2；这一关先让你看清最基本的因果）
        filtered = None

        rendered = render_into_page(keyword)

        executed = detect_executable(keyword)

        if "<" in keyword:
            is_attack = True

        if executed:

            completed = True
            is_attack = True

            analysis_zh = (
                "实验成功。你的输入以可执行的形式进入了页面：命中的是「"
                + executed
                + "」。"
                "这一关没有做任何过滤 —— 目的就是让你先看清最基本的因果："
                "<b>你输入的文字变成了 HTML 的一部分，于是浏览器把它当代码执行了</b>。"
                "在真实浏览器里打开这一关，你会直接看到脚本执行的效果。"
                "（下一关会加上过滤，那时才需要换别的写法。）"
            )

            analysis_en = (
                "Success. Your input reached the page in an executable form: "
                + executed
                + ". This level filters nothing on purpose, so that the basic causal "
                "chain is unmistakable — <b>your text became part of the HTML, and "
                "the browser executed it</b>. Open this level in a real browser and "
                "you will see it run. (The next level adds filtering; that is when "
                "you need a different payload.)"
            )

        elif is_attack:

            analysis_zh = (
                "你的输入里带了 HTML 标记，但它不含任何<b>可执行结构</b> —— "
                "普通标签（比如 &lt;b&gt;、&lt;span&gt;）只会改变排版，不会执行代码。"
                "展开「可执行结构速查表」看第一列，挑一个真正会被执行的写法。"
            )

            analysis_en = (
                "Your input contains markup, but nothing <b>executable</b>: ordinary "
                "tags such as &lt;b&gt; or &lt;span&gt; only change the layout. Open "
                "the cheatsheet and pick a construct that actually runs."
            )

        else:

            analysis_zh = (
                "搜索正常完成。注意右侧「渲染进页面的 HTML」："
                "你输入的 <b>"
                + keyword.replace("<", "&lt;")
                + "</b> 被原样放进了 HTML，"
                "没有做任何转义 —— 这就是这个功能的风险所在。"
            )

            analysis_en = (
                "Search completed normally. Look at the rendered HTML on the right: "
                "your input was placed into the HTML verbatim, with no encoding at "
                "all. That is the risk in this feature."
            )

        if completed:
            progress.mark_cleared(LAB_NAME, 1)

    return render_template(
        "xss_level1.html",
        keyword=keyword,
        filtered=filtered,
        rendered=rendered,
        executed=executed,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        artifact_title="渲染进页面的 HTML Rendered HTML",
        artifact_body=rendered,
        artifact_note=(
            "这一小段就是页面里真正出现的 HTML。"
            "注意你的输入没有被转义，而是直接成为了标记的一部分。"
            " / This is the exact HTML that ends up in the page: your input became "
            "markup instead of text."
        ),
        ok_label="XSS Successful 脚本注入成功",
        cheatsheet=XSS_CHEATSHEET,
        hints=LEVEL1_HINTS,
        vulnerable_code=LEVEL1_VULNERABLE_CODE,
        secure_code=LEVEL1_SECURE_CODE,
        fix_vulnerable_zh=(
            "用户输入被拼进 HTML，浏览器把它当作标记解析。"
            "黑名单只删了 <script，等于只锁了一扇门。"
        ),
        fix_vulnerable_en=(
            "User input is concatenated into HTML and parsed as markup. The "
            "blacklist removed only <script — one door locked out of many."
        ),
        fix_secure_zh=(
            "输出编码是首选：模板引擎默认就会转义，不要用 |safe 关掉它。"
            "真需要富文本时用白名单库清洗，并加 CSP 与 HttpOnly 兜底。"
        ),
        fix_secure_en=(
            "Output encoding comes first: template engines escape by default, so do "
            "not disable it with |safe. For rich text, sanitize with a whitelist "
            "library and add CSP plus HttpOnly as a safety net."
        ),
        summary=LEVEL1_SUMMARY
    )


# ================================================================
# Level 2 存储型 XSS
# ================================================================

LEVEL2_VULNERABLE_CODE = '''# 1) 用户提交的留言被存进数据库（没有清洗）
cursor.execute(
    "INSERT INTO xss_guestbook(author, content, created_at) VALUES (?, ?, ?)",
    (author, content, now)
)

# 2) 展示时只做了一次很弱的黑名单过滤，然后当成 HTML 拼进页面
#    ⚠️ 故意漏洞：过滤后的内容用 Markup(...) 直接输出，没有转义
for row in messages:
    html += Markup('<div class="msg">' + weak_filter(row[2]) + '</div>')'''

LEVEL2_SECURE_CODE = '''# 1) 入库前清洗：用白名单库去掉所有脚本与事件属性
content = bleach.clean(content, tags=[], attributes={}, strip=True)

# 2) 出库时依然要输出编码 —— 入库清洗和输出编码是两道独立的防线，
#    只做一道都不够（历史数据、其他写入路径都可能绕过第一道）
cursor.execute(
    "INSERT INTO xss_guestbook(author, content, created_at) VALUES (?, ?, ?)",
    (author, content, now)
)

return render_template("guestbook.html", messages=messages)
# 模板里写 {{ message.content }}，Jinja2 默认自动转义'''

LEVEL2_HINTS = [
    {
        "zh": "先发一条普通留言（比如 hello），提交后看页面：留言被存下来并展示给所有人。"
              "再右键「查看页面源代码」，看你的留言在 HTML 里是什么样子。",
        "en": "Post a normal message first (e.g. hello) and watch it get stored and "
              "shown to everyone. Then use View Source to see how your message "
              "appears in the HTML.",
    },
    {
        "zh": "这一关在 Level 1 的基础上加了一个过滤器，它只删掉 `<script` 这七个字符。"
              "所以在 Level 1 里那一招在这里<b>打不通</b>了 —— "
              "展开「可执行结构速查表」，第一列里还有哪几行能用？"
              "（注意它们和 script 标签的<b>共同点</b>是什么。）",
        "en": "This level adds a filter on top of Level 1: it strips only the seven "
              "characters `<script`. So the payload that worked before is dead here. "
              "Open the cheatsheet — which other rows in the first column still "
              "apply? Look for what they have <b>in common</b> with a script tag.",
    },
    {
        "zh": "速查表的第二行：`<img src=x onerror=alert(1)>`。"
              "它和 script 标签的原理一样（都是让浏览器把某段文字当代码执行），"
              "只是换了触发时机 —— 图片加载失败时。"
              "而存储型的关键差别不在这条 payload，在<b>影响面</b>："
              "它躺在数据库里，每个打开页面的人都中招。",
        "en": "Row two of the cheatsheet: `<img src=x onerror=alert(1)>`. It works on "
              "exactly the same principle as a script tag — the browser runs some "
              "text as code — just with a different trigger. The real difference in "
              "stored XSS is not the payload but the <b>blast radius</b>: it sits in "
              "the database and hits every visitor.",
    },
]

LEVEL2_SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：和反射型一样是「输入没有输出编码」，"
                  "但多了一层 —— 恶意内容被**存进了数据库**，"
                  "于是它从「一次性的回显」变成了「常驻的页面内容」。",
            "en": "Root cause: the same missing output encoding, plus one more layer — "
                  "the payload is now stored in the database, turning a one-off echo "
                  "into permanent page content.",
        },
        {
            "zh": "利用手法：绕过手法与反射型相同（黑名单挡不住事件属性），"
                  "区别在于不需要诱导点击，只要有人访问页面就会执行。",
            "en": "Exploitation: the bypass is the same as reflected XSS (blacklists "
                  "miss event attributes). The difference is that no click is needed: "
                  "anyone who opens the page runs it.",
        },
        {
            "zh": "危害：影响面被放大到所有访客，包括管理员。"
                  "经典利用链是「注入留言 → 管理员查看后台时中招 → 权限被拿走」。",
            "en": "Impact: the blast radius covers every visitor, including admins. "
                  "The classic chain is: inject a message → an admin reviews it → the "
                  "session is stolen.",
        },
        {
            "zh": "修复：入库时用白名单清洗 + 出库时输出编码，两道防线都要有；"
                  "再加 CSP 与 HttpOnly。只做入库清洗不够——"
                  "历史数据和别的写入路径都可能绕过它。",
            "en": "Fix: sanitize on input with a whitelist AND encode on output — you "
                  "need both. Add CSP and HttpOnly on top. Input sanitizing alone is "
                  "not enough: legacy rows and other write paths can bypass it.",
        },
    ],
    "takeaway_zh": "口诀：反射型要骗人点链接，存储型只需要等人来访 —— 所以它更危险。",
    "takeaway_en": "Rule of thumb: reflected XSS needs a click, stored XSS only "
                   "needs a visitor. That is why stored XSS is worse.",
    "next_zh": "XSS 讲完了。下一站：文件上传 —— 看「校验只看后缀名」会带来什么。",
    "next_en": "That is XSS. Next stop: file upload — what happens when validation "
               "only looks at the file extension.",
}


def _guestbook_state():
    """算出留言板的当前状态：每条留言的过滤结果 + 是否存在可执行留言。"""

    entries = []
    executable_labels = []

    for row in all_messages():

        raw = row[2]
        filtered = weak_filter(raw)
        label = detect_executable(filtered)

        if label:
            executable_labels.append(label)

        entries.append(
            {
                "id": row[0],
                "author": row[1],
                "raw": raw,
                "filtered": filtered,
                "executable": label,
                "created_at": row[3],
            }
        )

    return entries, executable_labels


@xss_bp.route(
    "/labs/xss/level2/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def xss_level2_reset():
    """清空留言板，恢复成最初的两条正常留言。"""

    init_db.reset_lab("xss")

    flash(
        "留言板已清空并恢复出厂状态 Guestbook reset",
        "success"
    )

    return redirect("/labs/xss/level2")


@xss_bp.route(
    "/labs/xss/level2",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def xss_level2():

    author = None
    content = None
    submitted = False
    executed = None
    analysis_zh = None
    analysis_en = None
    is_attack = False

    cleared_before = progress.is_cleared(LAB_NAME, 2)

    if request.method == "POST":

        author = request.form.get("author", "").strip() or "匿名 anonymous"
        content = request.form.get("content", "").strip()

        if content:

            conn = get_lab_db("xss")
            cursor = conn.cursor()

            # ⚠️ 故意漏洞：留言原样入库，没有清洗
            cursor.execute(
                """
                INSERT INTO xss_guestbook(author, content, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    author,
                    content,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

            conn.commit()
            conn.close()

            submitted = True

            if "<" in content or "on" in content.lower():
                is_attack = True

    entries, executable_labels = _guestbook_state()

    completed = len(executable_labels) > 0

    if completed:
        progress.mark_cleared(LAB_NAME, 2)

        executed = executable_labels[0]

    if request.method == "POST" and submitted:

        if completed and executed:

            analysis_zh = (
                "实验成功。你的留言被存进了数据库，而且在展示时仍然以可执行的形式"
                "进入页面（命中「"
                + executed
                + "」）。"
                "这就是存储型和反射型的本质区别：这条留言不会随着这次请求结束而消失，"
                "**任何人**（包括管理员）之后打开这个页面，都会执行它一次。"
            )

            analysis_en = (
                "Success. Your message was stored in the database and still reached "
                "the page in executable form ("
                + executed
                + "). That is the essential difference from reflected XSS: the "
                "payload does not disappear when this request ends. Every future "
                "visitor — including an admin — executes it again."
            )

        elif is_attack:

            analysis_zh = (
                "留言已保存，但过滤之后没有剩下可执行的结构，所以还没有通关。"
                "回想一下：过滤只删了 <script。"
            )

            analysis_en = (
                "The message was saved, but nothing executable survived the filter, "
                "so this attempt did not succeed. Remember: the filter only strips "
                "<script."
            )

        else:

            analysis_zh = (
                "留言已保存并展示给所有访客。这是一条正常留言 —— "
                "但请注意：它同样是被原样拼进 HTML 的，"
                "所以只要内容里带上标记，就会变成代码。"
            )

            analysis_en = (
                "Your message is stored and shown to every visitor. It is a normal "
                "message — but note that it is concatenated into the HTML verbatim, "
                "so any markup inside it becomes code."
            )

    return render_template(
        "xss_level2.html",
        author=author,
        content=content,
        submitted=submitted,
        entries=entries,
        executed=executed,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        message_count=len(entries),
        artifact_title="渲染进页面的 HTML Rendered HTML",
        artifact_body=(
            "\n".join(
                '<div class="msg"><b>' + e["author"] + "</b>: " + e["filtered"] + "</div>"
                for e in entries
            )
            if entries
            else None
        ),
        artifact_note=(
            "这是留言板真正输出到页面上的 HTML（新留言在最上面）。"
            "每条留言都经过同一个弱过滤器，然后被当成标记拼进来。"
            " / This is the HTML the guestbook actually outputs; every message goes "
            "through the same weak filter and is then treated as markup."
        ),
        ok_label="Stored XSS Successful 存储型注入成功",
        cheatsheet=XSS_CHEATSHEET,
        hints=LEVEL2_HINTS,
        vulnerable_code=LEVEL2_VULNERABLE_CODE,
        secure_code=LEVEL2_SECURE_CODE,
        fix_vulnerable_zh=(
            "留言原样入库、原样拼进页面：恶意内容被持久化，"
            "并且对所有访客生效。"
        ),
        fix_vulnerable_en=(
            "The message is stored and rendered verbatim: the payload is persisted "
            "and hits every visitor."
        ),
        fix_secure_zh=(
            "入库用白名单清洗，出库照样输出编码 —— 两道防线都要有。"
            "再加上 CSP 和 HttpOnly，纵深防御。"
        ),
        fix_secure_en=(
            "Sanitize with a whitelist on the way in, and still encode on the way "
            "out. Add CSP and HttpOnly for defence in depth."
        ),
        summary=LEVEL2_SUMMARY
    )
