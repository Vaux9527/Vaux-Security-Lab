# -*- coding: utf-8 -*-
"""访问限速（防刷），不依赖第三方库。

为什么需要：
公网免费实例（例如 PythonAnywhere 免费版）每天只有 100 CPU 秒。
一个自动扫描器几分钟就能把额度烧光，网站当天就打不开了。

实现方式：
在内存里记录每个 IP 在时间窗口内的请求次数。
单进程够用——免费托管通常只给一个 worker，正好匹配。

可调的环境变量：
    MINISEC_RATE_LIMIT=0        关闭限速（本地开发想随便刷新时用）
    MINISEC_RATE_LIMIT_GLOBAL   整站每分钟上限（默认 150）
    MINISEC_RATE_LIMIT_LOGIN    登录每分钟上限（默认 10，顺便防暴力猜密码）
    MINISEC_RATE_LIMIT_LAB_QUERY 实验查询每分钟上限（默认 40）
    MINISEC_RATE_LIMIT_LAB_RESET 重置靶子数据每分钟上限（默认 5）
"""

import time
from collections import defaultdict, deque
from functools import wraps

from flask import render_template, request

import config

# 规则名 -> (时间窗口秒数, 窗口内允许次数)
RULES = {
    "global": (60, config.RATE_LIMIT_GLOBAL),
    "login": (60, config.RATE_LIMIT_LOGIN),
    "lab_query": (60, config.RATE_LIMIT_LAB_QUERY),
    "lab_reset": (60, config.RATE_LIMIT_LAB_RESET),
}

# (规则名, IP) -> 请求时间戳队列
_hits = defaultdict(deque)

# 每记录这么多次访问，顺手清理一次过期记录（防止内存无限增长）
_SWEEP_EVERY = 200
_hit_count = 0


def client_ip():
    """取访客 IP。

    默认只用 remote_addr —— 这个值由网络层给出，访客伪造不了。

    只有当你的服务确实跑在可信代理后面时，才设置 MINISEC_TRUST_PROXY=1
    去读 X-Forwarded-For。否则任何人都能随便填这个请求头绕过限速。
    """

    if config.TRUST_PROXY:

        forwarded = request.headers.get("X-Forwarded-For", "")

        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def _sweep(now):
    """清掉过期的记录。"""

    for key in list(_hits.keys()):

        bucket = _hits[key]

        window = RULES[key[0]][0]

        while bucket and now - bucket[0] > window:
            bucket.popleft()

        if not bucket:
            del _hits[key]


def hit(rule):
    """记一次访问。超出限制返回 True。"""

    if not config.RATE_LIMIT_ENABLED:
        return False

    global _hit_count

    window, limit = RULES[rule]

    now = time.time()

    _hit_count += 1

    if _hit_count % _SWEEP_EVERY == 0:
        _sweep(now)

    bucket = _hits[(rule, client_ip())]

    while bucket and now - bucket[0] > window:
        bucket.popleft()

    if len(bucket) >= limit:
        return True

    bucket.append(now)

    return False


def reset_all():
    """清空所有计数（测试用）。"""

    _hits.clear()


def _too_many():
    """返回 429 页面。"""

    response = render_template(
        "error.html",
        code=429,
        title_zh="请求过于频繁",
        title_en="Too Many Requests",
        message_zh=(
            "你在短时间内发送了太多请求，已被暂时限速。"
            "这是为了保护服务器的每日计算额度。请等一分钟再试。"
        ),
        message_en=(
            "Too many requests in a short time, so you have been rate limited. "
            "This protects the server's daily compute quota. Please wait a minute."
        ),
    )

    return response, 429, {"Retry-After": "60"}


def limit(rule):
    """装饰器：给某个视图函数加上限速规则。"""

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):

            if hit(rule):
                return _too_many()

            return func(*args, **kwargs)

        return wrapper

    return decorator


def register(app):
    """整站兜底限速：静态文件不计数，其余请求都算。"""

    @app.before_request
    def _global_limit():

        if request.path.startswith("/static/"):
            return None

        if hit("global"):
            return _too_many()

        return None
