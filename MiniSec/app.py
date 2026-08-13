from flask import Flask, render_template, request, session, redirect, flash
from database import get_db
from routes.labs import labs_bp


app = Flask(__name__)

app.secret_key = "minisec-secret-key"


app.register_blueprint(labs_bp)



@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():


    if request.method == "POST":


        username = request.form["username"]

        password = request.form["password"]



        conn = get_db()

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



        if user is None:


            flash(
                "用户不存在 User Not Found",
                "error"
            )


            return redirect("/login")



        if user[1] != password:


            flash(
                "密码错误 Wrong Password",
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


    username = session.get("username")


    return render_template(
        "index.html",
        username=username
    )





if __name__ == "__main__":


    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )