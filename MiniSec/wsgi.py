# -*- coding: utf-8 -*-
"""公网部署入口（本地开发不需要这个文件）。

托管平台的正式服务器通过这个文件加载应用，例如 PythonAnywhere 的 WSGI 配置：

    import sys
    path = "/home/你的用户名/minisec"
    if path not in sys.path:
        sys.path.append(path)

    os.environ["MINISEC_SECRET_KEY"] = "换成随机字符串"
    from wsgi import application

它做两件"生产环境必须"的事：

1. 强制关闭调试模式
   debug=True 时出错会打开一个能在服务器上执行代码的调试页面。
   本地只监听 127.0.0.1 时无所谓，暴露到公网就等于把服务器交出去。

2. 拒绝用默认开发密钥启动
   Flask 用密钥给"已登录"这个状态签名。如果沿用代码里的默认值，
   任何人（源码是公开的）都能自己伪造一个"已登录"的会话。
   所以这里直接报错停下，而不是带着隐患上线。
"""

import os

# 必须在导入应用之前设置：config.py 是在导入时读取这些变量的
os.environ.setdefault("MINISEC_DEBUG", "0")

if not os.environ.get("MINISEC_SECRET_KEY"):

    raise RuntimeError(
        "拒绝启动：公网部署必须先设置环境变量 MINISEC_SECRET_KEY。\n"
        "生成办法（在本机命令行运行）：python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
        "Refusing to start: set the MINISEC_SECRET_KEY environment variable first."
    )

from app import app as application  # noqa: E402  (必须在设置环境变量之后导入)
