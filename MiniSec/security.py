# -*- coding: utf-8 -*-
"""CSRF 防护（不依赖第三方库）。

CSRF 是什么（白话）：
攻击者做一个陷阱网页，诱导已经登录的你提交一个表单。
浏览器会自动带上你的登录 Cookie，服务器一看"凭证齐全"，
就以为是你在操作——于是攻击者借你的手完成了动作。

防御办法：每个表单里都塞一个只有本站知道的随机令牌（token），
服务器提交时校验。攻击者的陷阱网页拿不到这个令牌，也就伪造不了提交。

用法：
    在模板的表单里加一行：
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    然后在 app.py 里调用 register(app) 开启全局校验。
"""

import secrets

from flask import render_template, request, session

TOKEN_KEY = "_csrf_token"
FORM_FIELD = "csrf_token"

# ---------------------------------------------------------------- 豁免名单
# 故意不校验 CSRF 令牌的路径。
#
# 为什么要有这个名单：
#   CSRF 实验（/labs/csrf/）要演示的正是「不校验令牌会怎样」，
#   所以它的靶子接口必须是"裸"的 —— 否则漏洞根本复现不出来。
#
# ⚠️ 这个名单只给实验靶子用。
#    平台自身的接口（登录、恢复出厂、改数据…）一律照常校验，
#    任何时候都不要把平台接口加进来。
CSRF_EXEMPT_PATHS = {
    "/labs/csrf/level1/profile",
}


def csrf_token():
    """返回当前会话的令牌；没有就生成一个（模板里调用）。"""

    token = session.get(TOKEN_KEY)

    if not token:

        token = secrets.token_urlsafe(32)

        session[TOKEN_KEY] = token

    return token


def _reject():
    """表单令牌不对 —— 拒绝这次提交。"""

    return render_template(
        "error.html",
        code=400,
        title_zh="表单校验失败",
        title_en="Form Validation Failed",
        message_zh=(
            "表单令牌缺失或已过期（这是 CSRF 防护在起作用）。"
            "请返回上一页，刷新页面后重新提交。"
        ),
        message_en=(
            "The form token is missing or expired (CSRF protection). "
            "Go back, refresh the page and submit the form again."
        ),
    ), 400


def register(app):
    """把 CSRF 防护接到 Flask 应用上。"""

    # 让所有模板都能直接调用 csrf_token()
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _protect():

        # 只检查会改变状态或提交数据的请求
        if request.method != "POST":
            return None

        # 实验靶子接口：故意不校验（见上面的豁免名单说明）
        if request.path in CSRF_EXEMPT_PATHS:
            return None

        expected = session.get(TOKEN_KEY)
        sent = request.form.get(FORM_FIELD, "")

        if not expected or not sent:
            return _reject()

        # 先转成字节再比较：
        # 1) compare_digest 比较字符串时只接受 ASCII，攻击者要是塞进任意字符
        #    （比如中文），直接比较会抛异常变成 500 —— 那就成了"拒绝服务"的入口；
        # 2) 转字节后仍是固定时间比较，避免被逐字节试探出令牌。
        if not secrets.compare_digest(
            sent.encode("utf-8", "replace"),
            expected.encode("utf-8")
        ):
            return _reject()

        return None
