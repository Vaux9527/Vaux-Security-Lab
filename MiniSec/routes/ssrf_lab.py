# -*- coding: utf-8 -*-
"""SSRF 实验：Level 1 服务端请求伪造。

⚠️ 故意保留的漏洞：URL 完全由用户提供，服务端不做目标校验就发起请求。

为什么这一关"必须能打内网"：
    SSRF 的教学价值恰恰在于 —— 请求是**服务器**发出的。
    服务器通常处在一个"内网可信位置"：它能访问到你的浏览器访问不到的东西
    （只监听内网的接口、云环境的元数据服务、内网管理后台）。
    如果只允许请求 localhost，这一关就退化成了一个普通的网页抓取工具。

靶子：
    MiniSec 自己暴露了两个"内部接口"（见 app.py）：
        /internal/admin-config   模拟内部配置接口（含 flag）
        /internal/status         模拟内网探针页
    它们故意不做登录校验 —— 真实世界的内网服务经常就是这样。

通关判定（三个条件同时成立，全部是客观事实）：
    1. 请求成功（能拿到响应）
    2. 目标地址是内网/环回地址（不是"随便抓个外网网页"）
    3. 响应里出现了内部标记 INTERNAL-ONLY
"""

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request

import config
import progress
import ratelimit
from auth import login_required

ssrf_bp = Blueprint(
    "ssrf",
    __name__
)

LAB_NAME = "ssrf"

# 内部接口的标记：只有"够得着内部"的请求才会看到它
INTERNAL_MARKER = "INTERNAL-ONLY"

# 演示用的内部地址（本机上的这个应用自己）
DEMO_INTERNAL_URL = "http://127.0.0.1:5001/internal/admin-config"


def is_internal_host(host):
    """判断一个主机名是否指向内网/本机地址。

    注意这里解析的是**域名解析之后**的 IP：
    只比较字符串（比如"是不是 localhost"）挡不住 127.0.0.1、0.0.0.0、
    或者一个指向内网 IP 的自有域名。
    """

    if not host:
        return False

    lowered = host.lower().strip("[]")

    if lowered in ("localhost", "localhost.localdomain"):
        return True

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False

    for info in infos:

        address = info[4][0]

        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            continue

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True

    return False


def fetch(url):
    """服务端去请求这个 URL（这就是"服务端请求伪造"里的那个请求）。

    返回一个字典：ok / status / body / error / host / internal
    """

    result = {
        "url": url,
        "ok": False,
        "status": None,
        "body": "",
        "error": None,
        "host": None,
        "internal": False,
    }

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):

        result["error"] = (
            "只支持 http / https，其他协议（file、gopher、dict…）被拒绝。"
            " / Only http and https are supported."
        )

        return result

    host = parsed.hostname

    if not host:

        result["error"] = (
            "URL 里没有主机名。 / The URL has no hostname."
        )

        return result

    result["host"] = host
    result["internal"] = is_internal_host(host)

    # 可选的收紧开关：设 MINISEC_SSRF_ALLOW_EXTERNAL=0，
    # 只允许请求本机/内网地址，避免这台机器被当成访问外网的跳板。
    if not config.SSRF_ALLOW_EXTERNAL and not result["internal"]:

        result["error"] = (
            "当前配置（MINISEC_SSRF_ALLOW_EXTERNAL=0）不允许请求外网地址。"
            " / External addresses are disabled by configuration."
        )

        return result

    request_object = urllib.request.Request(
        url,
        headers={"User-Agent": "MiniSec-Lab/1.0 (SSRF teaching target)"},
    )

    try:

        with urllib.request.urlopen(
            request_object, timeout=config.SSRF_TIMEOUT
        ) as response:

            result["ok"] = True
            result["status"] = response.status
            result["body"] = response.read(config.SSRF_MAX_BYTES).decode(
                "utf-8", "replace"
            )

    except urllib.error.HTTPError as error:

        # 404 / 403 之类也算"请求成功到达了目标"，照样是 SSRF 的证据
        result["ok"] = True
        result["status"] = error.code
        result["body"] = error.read(config.SSRF_MAX_BYTES).decode("utf-8", "replace")

    except urllib.error.URLError as error:

        result["error"] = (
            "请求失败："
            + str(error.reason)
            + "。服务端连不上这个地址。 / The server could not reach it."
        )

    except Exception as error:

        result["error"] = "请求出错：" + str(error)

    return result


VULNERABLE_CODE = '''from urllib.parse import urlparse

url = request.form.get("url")          # ← 完全由用户提供
parsed = urlparse(url)

# ⚠️ 故意漏洞：只检查了协议，没有检查"这个地址是谁"
if parsed.scheme not in ("http", "https"):
    return "不支持的协议"

# 服务端拿着这个 URL 就去请求了。
# 而服务器所在的网络位置，往往比你的浏览器"更靠里"。
with urllib.request.urlopen(url, timeout=3) as response:
    return response.read()'''

SECURE_CODE = '''from urllib.parse import urlparse
import ipaddress, socket

parsed = urlparse(url)

# 1) 协议白名单
if parsed.scheme not in ("http", "https"):
    return "不支持的协议"

# 2) 解析成 IP 之后再判断，而不是比较字符串
#    （只挡 "localhost" 挡不住 127.0.0.1，也挡不住指向内网的自有域名）
ips = [info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)]
for address in ips:
    ip = ipaddress.ip_address(address)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "不允许访问内网地址"

# 3) 主机名白名单（只允许业务真正需要的目标）
if parsed.hostname not in ALLOWED_HOSTS:
    return "目标不在白名单里"

# 4) 禁止跟随重定向到内网（否则 302 一下就绕过了上面的检查）
# 5) 网络层兜底：让服务端出网走代理 / 独立网段，拿不到内网路由'''

HINTS = [
    {
        "zh": "先输入一个普通网址（比如 http://example.com），看看这个功能在做什么："
              "它把网页抓回来给你看。注意 —— 发起请求的是<b>服务器</b>，不是你。",
        "en": "Start with a normal URL (e.g. http://example.com) to see what the "
              "feature does: it fetches a page for you. Notice that the request is "
              "made by <b>the server</b>, not by your browser.",
    },
    {
        "zh": "既然请求是服务器发的，那么问题就变成了："
              "服务器能访问到、而你在浏览器里访问不到的东西，有哪些？"
              "（只监听内网的接口、内网管理后台、云环境的元数据服务……）",
        "en": "Since the server makes the request, the question becomes: what can "
              "the server reach that your browser cannot? (Internal-only endpoints, "
              "admin panels, cloud metadata services...)",
    },
    {
        "zh": "这台服务器自己就在 127.0.0.1 上跑着，而且暴露了两个内部接口。"
              "把地址填成 `http://127.0.0.1:5001/internal/admin-config` 试试 —— "
              "注意这个地址在浏览器里你也能打开，但真正的重点是"
              "<b>服务器替你打开它</b>时会发生什么。",
        "en": "This very server is listening on 127.0.0.1 and exposes two internal "
              "endpoints. Try `http://127.0.0.1:5001/internal/admin-config`. Yes, "
              "your browser can open it too — but the point is what happens when "
              "<b>the server opens it on your behalf</b>.",
    },
]

SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：服务端拿到用户提供的 URL 就直接发起请求，"
                  "没有校验目标是谁。而服务器通常处在「内网可信位置」，"
                  "它够得着的东西比外面的人多得多。",
            "en": "Root cause: the server takes a user-supplied URL and requests it "
                  "without validating the destination. Servers usually sit in a "
                  "trusted internal position and can reach far more than an outsider.",
        },
        {
            "zh": "利用手法：把 URL 指向本机或内网地址，让服务器替你去访问"
                  "那些「只有内网能访问」的资源。",
            "en": "Exploitation: point the URL at localhost or an internal address, "
                  "making the server fetch resources that are only reachable from "
                  "inside.",
        },
        {
            "zh": "危害：读取内网接口、探测内网拓扑（哪些主机活着、开了什么端口）、"
                  "在云环境里请求元数据服务拿到临时凭证 —— "
                  "后者经常直接导致整个云账号被接管。",
            "en": "Impact: read internal endpoints, map the internal network (which "
                  "hosts are alive, which ports are open), and in cloud environments "
                  "hit the metadata service for temporary credentials — which often "
                  "means losing the whole cloud account.",
        },
        {
            "zh": "修复：目标白名单；把域名解析成 IP 之后再判断是不是内网地址"
                  "（只比字符串挡不住自有域名）；禁止跟随重定向到内网；"
                  "网络层隔离，让服务端根本没有内网路由。",
            "en": "Fix: allow-list destinations; resolve the hostname and check the "
                  "resulting IP rather than comparing strings; block redirects into "
                  "internal ranges; and isolate the network so the server has no "
                  "internal route at all.",
        },
    ],
    "takeaway_zh": "口诀：服务器所在的网络位置，本身就是一种权限 —— 用户能影响它请求谁，就等于借用了这份权限。",
    "takeaway_en": "Rule of thumb: a server's network position is itself a "
                   "privilege. If a user can influence who it talks to, they borrow "
                   "that privilege.",
    "next_zh": "下一站命令注入：从「让服务器发一个请求」，升级成「让服务器执行一条命令」。",
    "next_en": "Next: command injection — from making the server send a request to "
               "making it run a command.",
}


@ssrf_bp.route(
    "/labs/ssrf/level1/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def ssrf_level1_reset():
    """SSRF 关没有靶子数据，重置只清掉提示。"""

    flash(
        "SSRF 关卡不保存任何数据，无需重置 Noting to reset here",
        "success"
    )

    return redirect("/labs/ssrf/level1")


@ssrf_bp.route(
    "/labs/ssrf/level1",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def ssrf_level1():

    url = None
    fetched = None
    completed = False
    is_attack = False
    analysis_zh = None
    analysis_en = None

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            fetched = fetch(url)

            if fetched["error"] is None and fetched["internal"]:

                is_attack = True

            if (
                fetched["ok"]
                and fetched["internal"]
                and INTERNAL_MARKER in fetched["body"]
            ):

                completed = True
                is_attack = True

                analysis_zh = (
                    "实验成功。你让<b>服务器</b>去请求 "
                    "<code>"
                    + str(fetched["host"])
                    + "</code>，"
                    "而这个地址是内网/环回地址；响应里的 "
                    "<code>"
                    + INTERNAL_MARKER
                    + "</code> 说明你真的够到了内部接口。"
                    "注意这件事的意义：你自己在浏览器里也能打开它，"
                    "但真实场景里那些内部服务通常<b>只对内网开放</b>——"
                    "那时你就只能借服务器的手去访问了。"
                )

                analysis_en = (
                    "Success. You made the <b>server</b> request "
                    "<code>"
                    + str(fetched["host"])
                    + "</code>, which is an internal or loopback address, and the "
                    "<code>"
                    + INTERNAL_MARKER
                    + "</code> marker proves it reached an internal endpoint. In "
                    "real environments those services are usually reachable only "
                    "from inside — which is exactly why you borrow the server."
                )

            elif fetched["error"] is not None:

                analysis_zh = fetched["error"]

                analysis_en = (
                    "The request did not go through: "
                    + str(fetched["error"])
                )

            elif fetched["internal"]:

                analysis_zh = (
                    "你打到了内网地址（"
                    + str(fetched["host"])
                    + "），"
                    "但响应里没有内部标记 "
                    "<code>"
                    + INTERNAL_MARKER
                    + "</code>。"
                    "换个内部路径试试 —— 这台服务器自己暴露了 "
                    "<code>/internal/admin-config</code> 与 "
                    "<code>/internal/status</code>。"
                )

                analysis_en = (
                    "You reached an internal address ("
                    + str(fetched["host"])
                    + "), but the response carries no internal marker. Try another "
                    "internal path — this server exposes "
                    "<code>/internal/admin-config</code> and "
                    "<code>/internal/status</code>."
                )

            else:

                analysis_zh = (
                    "请求成功，但目标 "
                    "<code>"
                    + str(fetched["host"])
                    + "</code> 是外网地址。"
                    "能抓到一个网页，并不等于 SSRF —— 服务器本来就能上外网。"
                    "SSRF 的关键是<b>让服务器去访问它内部才够得着的地方</b>。"
                )

                analysis_en = (
                    "The request worked, but "
                    "<code>"
                    + str(fetched["host"])
                    + "</code> is an external address. Fetching a public page is "
                    "not SSRF — the server can already reach the internet. The "
                    "point is making it reach something only it can see."
                )

            if completed:
                progress.mark_cleared(LAB_NAME, 1)

    return render_template(
        "ssrf_level1.html",
        url=url,
        fetched=fetched,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        internal_marker=INTERNAL_MARKER,
        demo_url=DEMO_INTERNAL_URL,
        allow_external=config.SSRF_ALLOW_EXTERNAL,
        timeout=config.SSRF_TIMEOUT,
        artifact_title="服务端实际发出的请求 Server-Side Request",
        artifact_body=(
            (
                "请求 URL: " + str(fetched["url"]) + "\n"
                "目标主机: " + str(fetched["host"]) + "\n"
                "是否内网地址: " + ("是 YES" if fetched["internal"] else "否 NO") + "\n"
                "响应状态: " + str(fetched["status"]) + "\n"
                "响应内容（前 "
                + str(config.SSRF_MAX_BYTES)
                + " 字节）:\n"
                + "------------------------------\n"
                + (fetched["body"] or "(空)")
            )
            if fetched
            else None
        ),
        artifact_note=(
            "这一段不是你自己浏览器看到的内容，"
            "而是<b>服务器</b>替你请求回来的内容。"
            " / This is not what your browser fetched — it is what the server "
            "fetched on your behalf."
        ),
        ok_label="SSRF Successful 服务端请求伪造成功",
        hints=HINTS,
        vulnerable_code=VULNERABLE_CODE,
        secure_code=SECURE_CODE,
        fix_vulnerable_zh=(
            "只校验了协议，没有校验目标。"
            "于是用户可以指定任意地址，服务器照办。"
        ),
        fix_vulnerable_en=(
            "The scheme is validated, the destination is not. So the user picks any "
            "address and the server obliges."
        ),
        fix_secure_zh=(
            "解析成 IP 后再判断内网、目标白名单、禁止重定向进内网、"
            "网络层隔离 —— 四层里至少要做到两层。"
        ),
        fix_secure_en=(
            "Resolve-then-check for internal ranges, allow-list destinations, block "
            "redirects into the internal network, and isolate at the network layer. "
            "Do at least two of the four."
        ),
        summary=SUMMARY
    )
