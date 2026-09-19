# -*- coding: utf-8 -*-
"""MiniSec 入口：首页、登录、退出、robots.txt、内部接口与错误页。

注意：这里的登录逻辑使用参数化查询（? 占位符），平台自身的代码是安全的。
故意存在漏洞的代码在 routes/ 下面各个实验里 —— 那才是实验靶子。
"""

from flask import Flask, flash, redirect, render_template, request, session

from werkzeug.security import check_password_hash

import config
import progress
import ratelimit
import security
from database import get_platform_db
from routes.cmdi_lab import cmdi_bp
from routes.csrf_lab import csrf_bp
from routes.idor_lab import idor_bp
from routes.labs import labs_bp
from routes.sql_lab import sql_bp
from routes.ssrf_lab import ssrf_bp
from routes.upload_lab import upload_bp
from routes.xss_lab import xss_bp

app = Flask(__name__)

# 会话签名密钥：本地开发用默认值；公网部署必须设置环境变量 MINISEC_SECRET_KEY
app.secret_key = config.SECRET_KEY

# 安全相关：CSRF 表单令牌校验 + 每 IP 限速防刷
security.register(app)
ratelimit.register(app)

app.register_blueprint(labs_bp)
app.register_blueprint(sql_bp)
app.register_blueprint(xss_bp)
app.register_blueprint(upload_bp)
app.register_blueprint(ssrf_bp)
app.register_blueprint(cmdi_bp)
app.register_blueprint(idor_bp)
app.register_blueprint(csrf_bp)


@app.route(
    "/login",
    methods=["GET", "POST"]
)
@ratelimit.limit("login")
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_platform_db()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT username, password, role
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        # 统一提示"用户名或密码错误"：不告诉对方用户名到底存不存在
        if user is None or not check_password_hash(user[1], password):

            flash(
                "用户名或密码错误 Wrong Username or Password",
                "error"
            )

            return redirect("/login")

        session["username"] = user[0]

        flash(
            "登录成功 Welcome " + user[0],
            "success"
        )

        return redirect("/")

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "已退出登录 Logged Out",
        "success"
    )

    return redirect("/")


@app.route("/")
def index():

    return render_template(
        "index.html",
        username=session.get("username"),
        cleared_total=progress.total_cleared(),
        level_total=progress.total_levels()
    )


@app.route("/robots.txt")
def robots():
    """告诉搜索引擎和扫描器：本站不需要被收录。

    公开靶场一旦被收录，会招来大量自动扫描器，
    免费实例的每日额度很快就被刷完。
    """

    body = (
        "User-agent: *\n"
        "Disallow: /\n"
    )

    return app.response_class(body, mimetype="text/plain")


# ---------------------------------------------------------------- 内部接口
# 这一组接口是 SSRF 实验（/labs/ssrf/level1）的靶子：
# 它们模拟"只有服务器自己才够得着的内部资源"。
#
# ⚠️ 故意不加登录校验 —— 真实世界里的内网服务经常就是这样：
#    它"本来"只有内网能访问，所以开发者觉得没必要做认证。
#    而 SSRF 恰恰就是"让外部的你，借服务器的手去访问它"。
#    给这个接口加认证，这一关的教学价值就没了。
#
# 里面的内容全是假数据，不是真配置、也不是真密钥。

@app.route("/internal/admin-config")
def internal_admin_config():
    """模拟的内部配置接口（SSRF 靶子）。"""

    body = (
        "INTERNAL-ONLY\n"
        "service = mini-secret-config\n"
        "flag{ssrf_internal_access}\n"
        "db_password = fake-not-a-real-password\n"
        "note = 这个接口没有登录校验，因为它本来只有内网能访问。\n"
    )

    return app.response_class(body, mimetype="text/plain")


@app.route("/internal/status")
def internal_status():
    """模拟的内部状态页（SSRF 靶子的第二个入口）。"""

    body = (
        "INTERNAL-ONLY\n"
        "status = ok\n"
        "uptime = 42 days\n"
        "note = 内网探针页，同样没有认证。\n"
    )

    return app.response_class(body, mimetype="text/plain")


# ---------------------------------------------------------------- 错误页

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html",
        code=404,
        title_zh="页面不存在",
        title_en="Page Not Found",
        message_zh=(
            "你访问的地址不存在。可能是链接过期，"
            "或者这个功能还没做（未开放的实验会显示「开发中」而不是死链）。"
        ),
        message_en=(
            "That page does not exist. The link may be outdated, or the feature "
            "is not built yet (unfinished labs show a Coming Soon badge instead)."
        ),
    ), 404


@app.errorhandler(500)
def server_error(error):

    return render_template(
        "error.html",
        code=500,
        title_zh="服务器内部错误",
        title_en="Internal Server Error",
        message_zh="服务器处理这个请求时出错了。请稍后重试。",
        message_en="Something went wrong while handling this request. Please try again later.",
    ), 500


if __name__ == "__main__":

    # 只在本地开发时使用：监听 127.0.0.1 = 仅本机可访问。
    # 公网部署走 wsgi.py，由托管平台的正式服务器加载应用。
    #
    # threaded=True 是必须的：SSRF 关卡会让服务器去请求它自己的
    # /internal/... 接口，单线程服务器会把自己锁死（等自己响应自己）。
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        threaded=True
    )
