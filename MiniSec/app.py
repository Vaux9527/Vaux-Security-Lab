from flask import Flask, render_template


app = Flask(__name__)

LABS = {

    "sql": {
        "title": "SQL注入实验",
        "english": "SQL Injection Lab",
        "description": "学习SQL注入漏洞原理"
    },

    "xss": {
        "title": "XSS跨站脚本实验",
        "english": "Cross Site Scripting Lab",
        "description": "学习XSS漏洞原理"
    }

}

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/labs")
def labs():
    return render_template(
        "labs.html",
        labs=LABS
    )
    
@app.route("/labs/<lab_name>")
def lab(lab_name):

    if lab_name not in LABS:
        return "Lab Not Found", 404


    lab_info = LABS[lab_name]


    return render_template(
        "lab.html",
        lab_info=lab_info
    )

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )