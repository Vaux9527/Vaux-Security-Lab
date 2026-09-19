# -*- coding: utf-8 -*-
"""MiniSec 配置中心。

所有"会随环境变化"的东西集中放在这里：
本地开发用默认值，公网部署时用环境变量覆盖（不用改代码）。

可用的环境变量：

    MINISEC_SECRET_KEY        会话签名密钥（公网部署必须设置成随机值）
    MINISEC_DEBUG             1 = 开启调试模式（默认）；0 = 关闭（公网部署）
    MINISEC_PORT              本地开发端口，默认 5001
    MINISEC_PLATFORM_DB       平台数据库文件位置
    MINISEC_LAB_<实验名>_DB    某个靶子数据库文件位置（如 MINISEC_LAB_SQL_DB）
    MINISEC_UPLOAD_DIR        文件上传关的上传目录
    MINISEC_SANDBOX_DIR       命令注入关的工作目录
    MINISEC_SSRF_ALLOW_EXTERNAL
                              1（默认）= SSRF 关可以请求任意地址；
                              0 = 只允许请求本机（想更保险时用）
    MINISEC_RATE_LIMIT*       限速相关，见文件末尾
"""

import os
from pathlib import Path

# 项目根目录（MiniSec 文件夹）
BASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- 数据库
# 平台数据库：平台自己的数据（登录账号、实验目录、通关进度）。
# 里面的东西"不能被拿走"，因此绝不和实验靶子混在一起。
PLATFORM_DB = Path(
    os.environ.get("MINISEC_PLATFORM_DB") or (BASE_DIR / "platform.db")
)

# 靶子数据库：故意存在漏洞、注定会被"打穿"的数据。
#
# 一关一库的理由：
#   1. 各关的假数据互不干扰，练第 3 关不会把第 1 关的数据搞乱
#   2. 恢复出厂可以一关一关地做（重置 lab_login.db 不影响 lab_sql.db）
#   3. 每张表只服务一个教学点，读起来清楚："这张表就是给这一关准备的"
LAB_DB_FILES = {
    "sql": "lab_sql.db",            # Level 1 基础查询注入
    "sql_login": "lab_login.db",    # Level 2 登录绕过
    "sql_union": "lab_union.db",    # Level 3 UNION 查询
    "xss": "lab_xss.db",            # XSS Level 2 存储型留言板
    "upload": "lab_upload.db",      # 文件上传：已上传文件的账本
    "cmdi": "lab_cmd.db",           # 命令注入：命令执行历史
    "idor": "lab_idor.db",          # 越权访问：用户与私有笔记
    "csrf": "lab_csrf.db",          # CSRF：靶子账号（演示不校验令牌的后果）
}


def lab_db_path(lab_name):
    """返回某个实验的靶子数据库路径。"""

    filename = LAB_DB_FILES.get(lab_name)

    if filename is None:
        raise KeyError("未登记的靶子数据库: " + str(lab_name))

    override = os.environ.get("MINISEC_LAB_%s_DB" % lab_name.upper())

    if override:
        return Path(override)

    return BASE_DIR / filename


# ---------------------------------------------------------------- 靶子目录
# 不是所有靶子都是数据库：文件上传和命令注入各自需要一个目录。
#
# 上传目录**故意放在 static/ 下面** —— 也就是 web 能直接访问到的地方，
# 这本身就是本关要教的漏洞之一（上传的文件可以被浏览器直接打开）。
UPLOAD_DIR = Path(
    os.environ.get("MINISEC_UPLOAD_DIR") or (BASE_DIR / "static" / "uploads")
)

# 命令注入的工作目录：注入进来的命令在这里执行。
# 目录里放着 secret.txt 作为本关的目标（假数据，不是真密钥）。
SANDBOX_DIR = Path(
    os.environ.get("MINISEC_SANDBOX_DIR") or (BASE_DIR / "lab_sandbox")
)

SANDBOX_SECRET_FILE = "secret.txt"
SANDBOX_SECRET_CONTENT = "flag{command_injection_works}\n"


# ---------------------------------------------------------------- 关卡参数
# 文件上传：单个文件大小上限（超过就拒绝，避免本地磁盘被塞满）
UPLOAD_MAX_BYTES = 1024 * 1024

# SSRF：请求超时与响应体截断
SSRF_TIMEOUT = 3
SSRF_MAX_BYTES = 8192

# SSRF：是否允许请求任意地址。
# 默认允许 —— 服务端请求伪造这个漏洞的教学价值就在于"能打内网"，
# 只允许 localhost 会让这一关失去意义。因为靶场只在本地跑，风险可控；
# 如果你的机器确实连着不该被碰的网络，把它设成 0 即可收紧。
SSRF_ALLOW_EXTERNAL = os.environ.get("MINISEC_SSRF_ALLOW_EXTERNAL", "1") == "1"

# 命令注入：执行超时（秒）与输出截断长度
CMDI_TIMEOUT = 3
CMDI_MAX_OUTPUT = 4000


# ---------------------------------------------------------------- 运行时
# 会话签名密钥：本地开发有默认值；公网部署必须用环境变量覆盖，
# 否则任何人拿到源码就能伪造"已登录"的会话。
SECRET_KEY = os.environ.get("MINISEC_SECRET_KEY", "minisec-dev-only-key")

# 调试模式：默认开启。它只在 127.0.0.1（仅本机）下使用才安全。
# 公网部署时设置 MINISEC_DEBUG=0，并交给正式服务器运行。
DEBUG = os.environ.get("MINISEC_DEBUG", "1") == "1"

# 开发服务器地址：127.0.0.1 表示只接受本机访问，外人连不上。
HOST = "127.0.0.1"
PORT = int(os.environ.get("MINISEC_PORT", "5001"))


# ---------------------------------------------------------------- 限速防刷
# 公网免费实例每天只有 100 CPU 秒，被自动扫描器刷几分钟就烧光了。
RATE_LIMIT_ENABLED = os.environ.get("MINISEC_RATE_LIMIT", "1") != "0"

# 每个 IP 每分钟允许的请求数
RATE_LIMIT_GLOBAL = int(os.environ.get("MINISEC_RATE_LIMIT_GLOBAL", "150"))
RATE_LIMIT_LOGIN = int(os.environ.get("MINISEC_RATE_LIMIT_LOGIN", "10"))
RATE_LIMIT_LAB_QUERY = int(os.environ.get("MINISEC_RATE_LIMIT_LAB_QUERY", "40"))
RATE_LIMIT_LAB_RESET = int(os.environ.get("MINISEC_RATE_LIMIT_LAB_RESET", "5"))

# 服务是否跑在可信代理后面（决定要不要读 X-Forwarded-For 来取真实 IP）
# 默认关闭：这个请求头访客可以随便伪造，盲目相信它等于给限速开后门。
TRUST_PROXY = os.environ.get("MINISEC_TRUST_PROXY", "0") == "1"
