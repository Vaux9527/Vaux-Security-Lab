from flask import Flask, render_template
from database import get_db
from routes.labs import labs_bp

app = Flask(__name__)

app.register_blueprint(labs_bp)

'''@app.route("/testdb")
def testdb():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM labs"
    )

    labs = cursor.fetchall()

    conn.close()

    return str(labs)
'''


@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )