from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def index():

    return render_template("index.html")

@app.route("/labs/<lab_name>")
def lab(lab_name):
    return render_template(
        "lab.html",
        lab_name=lab_name
    )
    
    return render_template("labs.html")

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )