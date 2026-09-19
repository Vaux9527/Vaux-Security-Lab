# -*- coding: utf-8 -*-
"""命令注入实验：Level 1 网络诊断工具。

⚠️ 故意保留的漏洞：用户输入被直接拼进一条系统命令，并交给 shell 执行。

这一关是**真的执行系统命令**。原因：
    "模拟一个 shell"教不会任何东西 —— 学习者看不到真实的进程、真实的输出、
    真实的权限边界。既然这个靶场只在本地跑，就让它真实。

为此加了三道"不改变漏洞、只限制爆炸半径"的措施（写在文件末尾的说明里）：
    1. 工作目录固定在 lab_sandbox/（一个专门准备的目录，里面有本关的目标文件）
    2. 执行超时 3 秒
    3. 输出截断 4000 字符
注意：**没有**对输入做任何过滤 —— 过滤了就不是漏洞了。

通关判定：命令输出里出现了沙箱目录中 secret.txt 的内容（flag）。
也就是说：你成功让服务器执行了**一条不属于这个功能**的命令。
"""

import os
import subprocess

from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request

import config
import init_db
import progress
import ratelimit
from auth import login_required
from database import get_lab_db

cmdi_bp = Blueprint(
    "cmdi",
    __name__
)

LAB_NAME = "cmdi"

# 通关标记：沙箱目录里 secret.txt 的内容
FLAG_MARKER = "flag{"

# 输入里出现这些字符，说明学习者已经在尝试"追加命令"
SHELL_METACHARACTERS = ["&", "|", ";", "`", "$(", ">", "<", "\n"]


def is_windows():
    return os.name == "nt"


def build_command(host):
    """把用户输入拼进命令里 —— 这就是漏洞所在。"""

    if is_windows():
        # -n 1 只发一个包，-w 1000 超时 1 秒（不然 ping 不通的地址要等 4 秒）
        return "ping -n 1 -w 1000 " + host

    return "ping -c 1 -W 1 " + host


def decode_output(raw):
    """系统命令的输出编码取决于平台和语言设置，逐个试。"""

    if not raw:
        return ""

    for encoding in ("utf-8", "gbk", "big5", "latin-1"):

        try:
            return raw.decode(encoding)

        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", "replace")


def run_command(command):
    """在沙箱目录里执行命令。

    返回 (exit_code, output, timed_out)
    """

    config.SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    try:

        completed = subprocess.run(
            command,
            shell=True,                      # ← 漏洞的另一半：交给 shell 解释
            cwd=str(config.SANDBOX_DIR),     # 限制爆炸半径：工作目录固定在沙箱里
            capture_output=True,
            timeout=config.CMDI_TIMEOUT,
        )

        output = decode_output(completed.stdout) + decode_output(completed.stderr)

        return completed.returncode, output, False

    except subprocess.TimeoutExpired as error:

        partial = decode_output(error.stdout or b"") + decode_output(
            error.stderr or b""
        )

        return None, partial, True

    except Exception as error:

        return None, "执行出错：" + str(error), False


def looks_like_injection(text):
    """输入里有没有 shell 元字符（只用于页面提示，不用于判定通关）。"""

    return any(char in text for char in SHELL_METACHARACTERS)


def recent_runs(limit=5):
    """最近几次执行记录。"""

    conn = get_lab_db("cmdi")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, raw_input, executed_command, exit_code, output, ran_at
        FROM command_runs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


VULNERABLE_CODE = '''host = request.form.get("host")        # ← 用户输入

# ⚠️ 故意漏洞：字符串拼接 + 交给 shell 执行
command = "ping -n 1 " + host

result = subprocess.run(
    command,
    shell=True,          # shell 会把 & | ; ` $() 当成"命令分隔符"和"命令替换"
    capture_output=True
)'''

SECURE_CODE = '''import shlex, subprocess

host = request.form.get("host")

# 1) 先校验输入本身：网络诊断只该接受 IP 或域名
if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", host):
    return "非法的主机名"

# 2) 不要拼字符串 —— 用参数数组调用，让 shell 根本没有机会参与
result = subprocess.run(
    ["ping", "-c", "1", "-W", "1", host],   # 参数是列表，不是一整个字符串
    shell=False,                            # ← 关键：不经过 shell
    capture_output=True,
    timeout=3
)

# 3) 再加一层：用受限用户运行、容器/沙箱隔离、只给必要的文件权限'''

HINTS = [
    {
        "zh": "先输入 127.0.0.1 正常用一次，看看这个「网络诊断」在做什么："
              "它执行了一条 ping 命令，并把输出原样显示给你。",
        "en": "Start by entering 127.0.0.1 to see what the tool does: it runs a "
              "ping command and shows you the raw output.",
    },
    {
        "zh": "命令是用字符串拼出来的：`ping -n 1 <你的输入>`，"
              "然后交给 shell 执行。shell 会把 `&`、`|`、`;` 当成"
              "「再执行一条命令」的分隔符。",
        "en": "The command is built by concatenation: `ping -n 1 <your input>`, "
              "then handed to a shell. A shell treats `&`, `|` and `;` as "
              "'run another command' separators.",
    },
    {
        "zh": "这个功能的工作目录里放着一个 secret.txt（本关的 flag）。"
              "在输入里追加一条读文件的命令即可 —— "
              "Windows：`127.0.0.1 & type secret.txt`；"
              "Linux / macOS：`127.0.0.1; cat secret.txt`。",
        "en": "The working directory contains a secret.txt (this level's flag). "
              "Append a file-reading command — "
              "Windows: `127.0.0.1 & type secret.txt`; "
              "Linux / macOS: `127.0.0.1; cat secret.txt`.",
    },
]

SUMMARY = {
    "points": [
        {
            "zh": "漏洞成因：用户输入被拼进一条系统命令，而且这条命令是交给 "
                  "shell 执行的。shell 的职责就是解释 `&`、`|`、`;`、反引号、"
                  "`$()` 这些元字符 —— 于是数据又变成了代码。",
            "en": "Root cause: user input is concatenated into an OS command, and "
                  "that command is executed by a shell. A shell's whole job is to "
                  "interpret &, |, ;, backticks and $() — so data becomes code again.",
        },
        {
            "zh": "利用手法：用分隔符（`&` / `;` / `|`）追加一条自己的命令，"
                  "或者用反引号 / `$()` 做命令替换。"
                  "在这一关里，追加的命令是在服务器的工作目录里执行的。",
            "en": "Exploitation: append your own command with a separator "
                  "(& / ; / |), or use backticks / $() for command substitution. "
                  "Here the appended command runs in the server's working directory.",
        },
        {
            "zh": "危害：这是 Web 漏洞里后果最重的一类 —— 以服务器的身份执行任意命令，"
                  "等于拿到了一台机器的控制权（读文件、装后门、横向移动、"
                  "挖矿、当作跳板）。",
            "en": "Impact: this is the most severe class of web vulnerability — "
                  "arbitrary command execution as the server. That means control of "
                  "the machine: read files, install backdoors, move laterally, mine, "
                  "or use it as a pivot.",
        },
        {
            "zh": "修复：① 不要拼字符串，用参数数组调用（`shell=False`）；"
                  "② 输入按业务规则做白名单校验（网络诊断只该接受合法 IP/域名）；"
                  "③ 用最小权限账号运行；④ 容器/沙箱隔离，让命令出不去。",
            "en": "Fix: (1) never concatenate — pass an argument list with "
                  "shell=False; (2) validate input against the business rule (a "
                  "network tool should only accept IPs and hostnames); (3) run as a "
                  "least-privilege user; (4) sandbox it so commands cannot escape.",
        },
    ],
    "takeaway_zh": "口诀：只要输入能拼进命令、而且经过 shell，就等于把 shell 交给了用户。",
    "takeaway_en": "Rule of thumb: if input reaches a command line through a shell, "
                   "you have handed the shell to the user.",
    "next_zh": "五类漏洞到这里就全部打通了。回到实验列表看看自己的总进度，"
               "然后可以逐个重做一遍 —— 第二遍不看提示。",
    "next_en": "That is all five vulnerability classes. Go back to the lab list to "
               "see your progress, then redo them without the hints.",
}


@cmdi_bp.route(
    "/labs/cmdi/level1/reset",
    methods=["POST"]
)
@login_required
@ratelimit.limit("lab_reset")
def cmdi_level1_reset():
    """重建沙箱目录（清掉学习者在里面创建的文件）并清空执行历史。"""

    init_db.reset_lab("cmdi")

    flash(
        "沙箱目录已重建，执行历史已清空 Sandbox reset",
        "success"
    )

    return redirect("/labs/cmdi/level1")


@cmdi_bp.route(
    "/labs/cmdi/level1",
    methods=["GET", "POST"]
)
@login_required
@ratelimit.limit("lab_query")
def cmdi_level1():

    host = None
    command = None
    output = None
    exit_code = None
    timed_out = False
    completed = False
    is_attack = False
    analysis_zh = None
    analysis_en = None
    sandbox_listing = []

    cleared_before = progress.is_cleared(LAB_NAME, 1)

    if request.method == "POST":

        host = request.form.get("host", "").strip()

        if host:

            # ⚠️ 故意漏洞：直接拼接，没有任何过滤
            command = build_command(host)

            exit_code, output, timed_out = run_command(command)

            if looks_like_injection(host):
                is_attack = True

            if FLAG_MARKER in output:

                completed = True
                is_attack = True

                analysis_zh = (
                    "实验成功。你的输入里不只有主机名，还夹带了"
                    "<b>另一条命令</b>；shell 把分隔符后面的内容当成新命令执行了，"
                    "于是沙箱里的 secret.txt 被读了出来。"
                    "注意这意味什么：这一条命令是以<b>服务器进程的身份</b>执行的，"
                    "它能读到服务器能读到的任何东西 —— "
                    "这里只是被工作目录限制住了而已。"
                )

                analysis_en = (
                    "Success. Your input carried <b>a second command</b>; the shell "
                    "treated everything after the separator as a new command and read "
                    "secret.txt from the sandbox. Note what that means: the command ran "
                    "as <b>the server process</b>, so it could read anything the server "
                    "can read — only the working directory kept it contained here."
                )

            elif timed_out:

                analysis_zh = (
                    "命令执行超过 "
                    + str(config.CMDI_TIMEOUT)
                    + " 秒被强制结束。"
                    "（这正是一个典型的注入场景：`ping` 一个不存在的地址会挂很久，"
                    "真实攻击里也常用这种方式做延迟探测。）"
                )

                analysis_en = (
                    "The command exceeded "
                    + str(config.CMDI_TIMEOUT)
                    + " seconds and was killed. Note that a real attacker often uses "
                    "exactly this: a hanging ping as a timing probe."
                )

            elif output.strip():

                analysis_zh = (
                    "命令执行完成。请注意输出区显示的是<b>命令的真实输出</b> —— "
                    "后半段如果可以塞进别的东西，它就也会出现在这里。"
                    "本关的目标是读到沙箱目录里的 secret.txt。"
                )

                analysis_en = (
                    "The command finished. The output area shows the command's real "
                    "output — anything you can append will show up here too. The goal "
                    "is to read secret.txt from the sandbox directory."
                )

            else:

                analysis_zh = "命令执行了，但没有任何输出。"

                analysis_en = "The command ran but produced no output."

            if completed:
                progress.mark_cleared(LAB_NAME, 1)

            # 记录执行历史（教学用：能看到自己都执行过什么）
            conn = get_lab_db("cmdi")
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO command_runs(
                    raw_input, executed_command, exit_code, output, ran_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    host,
                    command,
                    exit_code,
                    (output or "")[: config.CMDI_MAX_OUTPUT],
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

            conn.commit()
            conn.close()

    if config.SANDBOX_DIR.exists():

        sandbox_listing = sorted(
            entry.name
            for entry in config.SANDBOX_DIR.iterdir()
            if entry.is_file()
        )

    return render_template(
        "cmdi_level1.html",
        host=host,
        command=command,
        output=output,
        exit_code=exit_code,
        timed_out=timed_out,
        completed=completed,
        cleared_before=cleared_before,
        is_attack=is_attack,
        analysis_zh=analysis_zh,
        analysis_en=analysis_en,
        runs=recent_runs(),
        sandbox_listing=sandbox_listing,
        sandbox_path=str(config.SANDBOX_DIR),
        timeout=config.CMDI_TIMEOUT,
        is_windows=is_windows(),
        artifact_title="实际执行的命令与输出 Executed Command",
        artifact_body=(
            (
                "工作目录: " + str(config.SANDBOX_DIR) + "\n"
                "执行的命令: " + str(command) + "\n"
                "退出码: " + str(exit_code) + ("（超时被结束）" if timed_out else "") + "\n"
                "------------------------------\n"
                + (output or "(无输出)")
            )
            if command
            else None
        ),
        artifact_note=(
            "第一行是拼接出来的完整命令 —— 你输入的每一个字符都在里面。"
            " / The first line is the concatenated command; every character you typed "
            "is in it."
        ),
        ok_label="Command Injection Successful 命令注入成功",
        hints=HINTS,
        vulnerable_code=VULNERABLE_CODE,
        secure_code=SECURE_CODE,
        fix_vulnerable_zh=(
            "字符串拼接把用户输入送进了命令行，"
            "shell=True 又让 shell 去解释它 —— 两步合起来就是 RCE。"
        ),
        fix_vulnerable_en=(
            "String concatenation puts user input on the command line, and "
            "shell=True lets a shell interpret it. Together that is remote code "
            "execution."
        ),
        fix_secure_zh=(
            "参数数组 + shell=False 是根治；输入白名单校验是必须的；"
            "最小权限和沙箱隔离限制最坏情况。"
        ),
        fix_secure_en=(
            "An argument list with shell=False fixes the root cause; input "
            "validation is mandatory; least privilege and sandboxing limit the "
            "worst case."
        ),
        summary=SUMMARY
    )
