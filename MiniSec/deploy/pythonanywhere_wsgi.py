# -*- coding: utf-8 -*-
"""PythonAnywhere 的 WSGI 配置文件内容（模板）。

使用办法：把本文件的内容整个复制到 PythonAnywhere 的
"Web" 标签 -> "WSGI configuration file" 那个编辑框里，然后改三处：

    1. YOURNAME            -> 你的 PythonAnywhere 用户名
    2. Vaux-Security-Lab   -> 你克隆下来的仓库目录名
    3. MINISEC_SECRET_KEY  -> 本机生成的随机字符串

生成随机字符串的办法（在本机命令行运行）：

    python -c "import secrets; print(secrets.token_urlsafe(48))"

改完保存，回到 Web 页面点绿色的 Reload 按钮。
"""

import os
import sys

# ---- 1. 让 Python 找到我们的项目 ----
# 注意：仓库克隆下来后，Flask 代码在仓库里的 MiniSec 子目录
path = "/home/YOURNAME/Vaux-Security-Lab/MiniSec"

if path not in sys.path:
    sys.path.append(path)

# ---- 2. 生产环境必须设置的两项配置 ----
# 密钥：必须换成随机字符串。不换的话 wsgi.py 会拒绝启动（这是故意的保护）。
os.environ["MINISEC_SECRET_KEY"] = "在这里填入本机生成的随机字符串"

# 调试模式：公网必须关闭。
# 开着 debug 意味着出错时会暴露一个能在服务器上执行代码的调试页面。
os.environ["MINISEC_DEBUG"] = "0"

# ---- 3. 加载应用 ----
# wsgi.py 会再次检查密钥是否设置，并强制关闭调试模式。
from wsgi import application  # noqa: E402  (必须在上面设置环境变量之后导入)
