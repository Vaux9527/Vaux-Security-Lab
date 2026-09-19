# -*- coding: utf-8 -*-
"""文件上传实验：Level 1 只检查后缀名的上传校验。

⚠️ 故意保留的漏洞有两个，而且是叠加的：

    1. **校验只看后缀名，而且用的是黑名单**
       黑名单（.php/.jsp/.asp）永远列不全：.phtml、.php5、.PHP、以及各种
       服务器配置允许的后缀都能绕过去。正确做法是白名单 + 校验文件内容。

    2. **上传目录放在 web 可以直接访问的地方（static/uploads/）**
       文件存进去之后，浏览器可以用一个 URL 直接打开它。
       如果上传的是 .html，这就是"存储型 XSS 的上传版"。

靶场自己唯一做的一处防护：只取文件名的最后一段（basename），
不让 `../` 这种东西把文件写到项目外面去 —— 那不是本关要教的东西，
而且真写出去会把靶场本身搞坏。

通关判定：文件被成功保存，而且**它的内容不是图片**（文件头对不上）。
也就是说：这个上传功能接受了一个它不是用来接收的东西。
判定看的是磁盘上真实存在的文件，不是输入里有没有某个词。
"""

import os
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request

import config
import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

upload_bp = Blueprint(
    "upload",
    __name__
)

LAB_NAME = "upload"

# 靶场自带的"防护"：一个很短的黑名单
BLOCKED_EXTENSIONS = {".php", ".jsp", ".asp", ".aspx"}

# 真正应该用的白名单（修复方案里会用到）
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}

# 文件头特征：判断"这到底是不是一张图片"
IMAGE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
]


def sniff_image(head):
    """看文件头，判断它是不是图片；不是就返回 None。"""

    for signature, name in IMAGE_SIGNATURES:

        if head.startswith(signature):
            return name

    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WEBP"

    return None


def extension_of(filename):
    """取小写后缀。"""

    return os.path.splitext(filename)[1].lower()


def should_block_by_blacklist(filename):
    """靶场自带的"防护"：后缀在黑名单里就拒绝。"""

    return extension_of(filename) in BLOCKED_EXTENSIONS


def uploaded_files():
    """读出上传账本（新→旧）。"""

    conn = get_lab_db("upload")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, original_name, saved_name, size, content_type, uploaded_at
        FROM uploaded_files
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def upload_dir_listing():
    """磁盘上真实存在的文件（用来证明"文件真的落地了"）。"""

    if not config.UPLOAD_DIR.exists():
        return []

    listing = []

    for entry in sorted(config.UPLOAD_DIR.iterdir()):

        if entry.is_file():
            listing.append((entry.name, entry.stat().st_size))

    return listing


VULNERABLE_CODE = '''# 靶场自带的"防护"：后缀名黑名单
if os.path.splitext(filename)[1].lower() in {".php", ".jsp", ".asp", ".aspx"}:
    return "不允许的文件类型"

# ⚠️ 故意漏洞一：只看了后缀名，没有看文件内容
# ⚠️ 故意漏洞二：文件被存进 web 可以直接访问的目录，还保留了原始文件名
file.save(os.path.join("static/uploads", filename))'''

SECURE_CODE = '''import uuid, imghdr  # imghdr 已废弃，实际项目用 Pillow 或 python-magic

# 1) 白名单：只接受明确允许的类型（黑名单永远列不全）
ext = os.path.splitext(filename)[1].lower()
if ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
    return "只允许上传图片"

# 2) 校验真实内容：文件头对不对（后缀可以随便改，文件头改不了）
head = file.stream.read(32)
file.stream.seek(0)
if not looks_like_image(head):
    return "文件内容不是图片"

# 3) 重命名：丢掉用户给的文件名，用随机名 + 白名单后缀
safe_name = uuid.uuid4().hex + ext

# 4) 存到 web 根目录之外，并且用一个受控的接口来读取
file.save(os.path.join(UPLOAD_ROOT_OUTSIDE_WEBROOT, safe_name))'''

HINTS = [
    {
        "zh": "先上传一张真正的图片（随便截个图就行），观察结果区："
              "文件被保存到哪里了？页面给出的访问地址长什么样？",
        "en": "Upload a real image first (a screenshot works). Look at the result: "
              "where did the file go, and what does the access URL look like?",
    },
    {
        "zh": "校验只有一行：后缀在黑名单 {.php .jsp .asp .aspx} 里就拒绝。"
              "问题是 —— 黑名单能列全吗？想想大小写、双后缀、"
              "以及服务器还认识哪些后缀。",
        "en": "The check is one line: reject if the extension is in "
              "{.php .jsp .asp .aspx}. But can a blacklist ever be complete? "
              "Think about letter case, double extensions, and what other "
              "extensions a web server might execute.",
    },
    {
        "zh": "这一关不要求你真的丢一个 webshell 上去。"
              "目标是：让上传功能接受一个<b>不是图片</b>的文件。"
              "试试 `note.html` 或 `shell.phtml`，内容随便写点 HTML。",
        "en": "You do not need a real webshell here. The goal is to make the upload "
              "accept a file that is <b>not an image</b>. Try `note.html` or "
              "`shell.phtml` with some HTML inside.",
    },
]

SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：校验手段选错了。① 用黑名单而不是白名单；"
                  "② 只看文件名后缀，不看文件真实内容；"
                  "③ 保存时还用了用户给的文件名。",
            "en": "Root cause: the wrong kind of validation. (1) A blacklist instead "
                  "of a whitelist; (2) only the filename extension is checked, never "
                  "the actual bytes; (3) the user-supplied filename is kept.",
        },
        {
            "zh": "利用手法：换一个不在黑名单里的后缀（.phtml / .php5 / 大小写变形），"
                  "或者上传一个 .html —— 后者不需要服务器执行任何东西，"
                  "浏览器打开就会执行里面的脚本。",
            "en": "Exploitation: pick an extension the blacklist forgot "
                  "(.phtml / .php5 / different case), or upload an .html file. "
                  "The latter needs no server-side execution at all: the browser "
                  "runs the script when the URL is opened.",
        },
        {
            "zh": "危害：取决于服务器怎么配置。最轻的是存储型 XSS"
                  "（上传 .html，把访问链接发给别人）；"
                  "最重的是上传可执行脚本拿到服务器权限（RCE）。",
            "en": "Impact: it depends on server configuration. The mildest form is "
                  "stored XSS (upload .html and share the link). The worst is "
                  "uploading an executable script and taking over the server (RCE).",
        },
        {
            "zh": "修复：① 白名单后缀；② 校验文件头（内容）；③ 重命名成随机名；"
                  "④ 存到 web 根目录之外，用受控接口读取；⑤ 限制大小与数量。",
            "en": "Fix: (1) whitelist extensions; (2) validate the file header "
                  "(content); (3) rename to a random name; (4) store outside the web "
                  "root and serve through a controlled endpoint; (5) cap size and count.",
        },
    ],
    "takeaway_zh": "口诀：上传校验要问「我允许什么」，而不是「我禁止什么」——白名单永远比黑名单可靠。",
    "takeaway_en": "Rule of thumb: ask what you allow, not what you forbid. "
                   "A whitelist is always more reliable than a blacklist.",
    "next_zh": "下一站 SSRF：这次被利用的不是数据库、也不是浏览器，而是服务器自己的网络位置。",
    "next_en": "Next: SSRF — this time the thing being abused is neither the "
               "database nor the browser, but the server's own network position.",
}


@upload_bp.route(
    "/labs/upload/level1/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def upload_level1_reset():
    """清空上传目录与账本。"""

    init_db.reset_lab("upload")

    flash(
        "上传目录已清空 Uploads cleared",
        "success"
    )

    return redirect("/labs/upload/level1")


@upload_bp.route(
    "/labs/upload/level1",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def upload_level1():

    submitted_name = None
    result = None
    content_type = None
    size = None
    head_bytes = None
    saved_name = None
    save_path = None
    public_url = None
    sniffed = None
    blocked = False
    rejected_reason = None
    completed = False
    analysis_zh = None
    analysis_en = None
    is_attack = False

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if request.method == "POST":

        uploaded = request.files.get("file")

        if uploaded is None or not uploaded.filename:

            rejected_reason = "没有选择文件。 / No file was selected."

        else:

            submitted_name = uploaded.filename

            # 靶场自己的一处防护：只取文件名的最后一段，避免 ../ 写到项目外面。
            # （路径穿越不是本关的教学点，而且真写出去会把靶场搞坏。）
            filename = os.path.basename(submitted_name.replace("\\", "/"))

            data = uploaded.stream.read()

            size = len(data)
            content_type = uploaded.mimetype or "unknown"
            head_bytes = data[:16]

            if should_block_by_blacklist(filename):

                # 这就是靶场的"防护"：后缀在黑名单里 → 拒绝
                blocked = True
                is_attack = True

                rejected_reason = (
                    "被靶场的黑名单挡下了：后缀 "
                    + extension_of(filename)
                    + " 在禁止列表里。"
                    " / Blocked by the lab's blacklist."
                )

            elif size > config.UPLOAD_MAX_BYTES:

                rejected_reason = (
                    "文件超过 "
                    + str(config.UPLOAD_MAX_BYTES // 1024)
                    + " KB 上限。 / File too large."
                )

            else:

                # ⚠️ 故意漏洞：没有校验内容、没有重命名、存进 web 可访问目录
                config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

                target = config.UPLOAD_DIR / filename

                target.write_bytes(data)

                saved_name = filename
                save_path = str(target)
                public_url = "/static/uploads/" + filename

                # 看文件头：这东西到底是不是图片？
                sniffed = sniff_image(head_bytes)

                conn = get_lab_db("upload")
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO uploaded_files(
                        original_name, saved_name, size, content_type, uploaded_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        submitted_name,
                        saved_name,
                        size,
                        content_type,
                        datetime.now().isoformat(timespec="seconds"),
                    ),
                )

                conn.commit()
                conn.close()

                result = "saved"

                if sniffed is None:

                    # 内容是"非图片"，却照样被保存 —— 规则失效了
                    completed = True
                    is_attack = True

                if "<" in data[:2048].decode("utf-8", "ignore"):

                    is_attack = True

    if completed:
        progress.mark_cleared(LAB_NAME, 1)

    if completed:

        analysis_zh = (
            "实验成功。上传功能接受了一个<b>不是图片</b>的文件："
            "文件头是 <code>"
            + head_bytes.hex(" ")
            + "</code>，匹配不上任何图片格式，但它照样被存进了 "
            "<code>static/uploads/</code>，而且浏览器可以直接打开："
            "<code>"
            + str(public_url)
            + "</code>。"
            "原因很简单：校验只看了后缀名。"
            "后缀是给人看的，文件头才是给程序看的 —— "
            "攻击者想叫它什么名字都行。"
        )

        analysis_en = (
            "Success. The upload accepted a file that is not an image: its header "
            "("
            + head_bytes.hex(" ")
            + ") matches no image format, yet it was stored under "
            "<code>static/uploads/</code> and is directly reachable in a browser at "
            "<code>"
            + str(public_url)
            + "</code>. The reason is simple: validation only looked at the "
            "extension. An extension is a label the uploader chooses; the file "
            "header is what the bytes actually are."
        )

    elif blocked:

        analysis_zh = (
            "被挡下了，但请想清楚它挡住的到底是什么："
            "<b>只是这个后缀字符串</b>。"
            "换成 .phtml、.php5、.PHP，或者干脆上传 .html，"
            "同一份内容就能进来。黑名单的问题是「永远列不全」。"
        )

        analysis_en = (
            "Blocked — but think about what was actually blocked: just that "
            "extension string. Rename to .phtml, .php5 or .PHP, or simply upload "
            ".html, and the same bytes go through. A blacklist can never be complete."
        )

    elif result == "saved":

        analysis_zh = (
            "上传成功，而且文件内容确实是一张图片（"
            + str(sniffed)
            + "）—— 这一次是正常使用。"
            "但请注意它保存在哪里："
            "<code>static/uploads/</code> 是 web 可以直接访问的目录，"
            "文件名也是你说了算。"
        )

        analysis_en = (
            "Uploaded successfully, and the content really is an image ("
            + str(sniffed)
            + ") — a legitimate use. But notice where it was stored: "
            "<code>static/uploads/</code> is directly reachable over HTTP, and "
            "the filename is entirely up to the uploader."
        )

    elif rejected_reason:

        analysis_zh = "本次上传没有保存：" + rejected_reason

        analysis_en = "Nothing was saved this time: " + rejected_reason

    return render_template(
        "upload_level1.html",
        submitted_name=submitted_name,
        result=result,
        content_type=content_type,
        size=size,
        head_bytes=head_bytes,
        head_hex=(head_bytes.hex(" ") if head_bytes else None),
        saved_name=saved_name,
        save_path=save_path,
        public_url=public_url,
        sniffed=sniffed,
        blocked=blocked,
        rejected_reason=rejected_reason,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        files=uploaded_files(),
        disk_listing=upload_dir_listing(),
        blocked_extensions=sorted(BLOCKED_EXTENSIONS),
        allowed_extensions=sorted(ALLOWED_IMAGE_EXTENSIONS),
        max_kb=config.UPLOAD_MAX_BYTES // 1024,
        artifact_title="磁盘上的证据 On Disk",
        artifact_body=(
            (
                "保存路径: " + str(save_path) + "\n"
                "访问地址: " + str(public_url) + "\n"
                "原始文件名: " + str(submitted_name) + "\n"
                "后缀: " + extension_of(saved_name or "") + "\n"
                "大小: " + str(size) + " 字节\n"
                "Content-Type（客户端声明的）: " + str(content_type) + "\n"
                "文件头（真实内容）: " + (head_bytes.hex(" ") if head_bytes else "") + "\n"
                "文件头识别结果: " + (sniffed if sniffed else "不是图片 NOT an image")
            )
            if save_path
            else None
        ),
        artifact_note=(
            "注意最后两行：客户端说它是什么（Content-Type）不算数，"
            "文件头才是它真正是什么。"
            " / The last two lines matter: what the client claims (Content-Type) is "
            "irrelevant; the file header is what the bytes really are."
        ),
        ok_label="Upload Validation Bypassed 上传校验被绕过",
        hints=HINTS,
        vulnerable_code=VULNERABLE_CODE,
        secure_code=SECURE_CODE,
        fix_vulnerable_zh=(
            "黑名单 + 只看后缀 + 保留原名 + 存进 web 目录，"
            "四件事凑在一起，等于把服务器的一部分交给了上传者。"
        ),
        fix_vulnerable_en=(
            "A blacklist, extension-only checks, the original filename, and a "
            "web-reachable directory — together they hand part of the server to "
            "whoever uploads."
        ),
        fix_secure_zh=(
            "白名单定类型、文件头验内容、随机名去身份、web 根之外存文件。"
            "四步都做到，才能安心接收别人上传的东西。"
        ),
        fix_secure_en=(
            "Whitelist the type, validate the header, randomise the name, and store "
            "outside the web root. Only then is it safe to accept uploads."
        ),
        summary=SUMMARY
    )
