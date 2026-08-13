from flask import Blueprint,render_template
from database import get_db
from auth import login_required

labs_bp = Blueprint(
    "labs",
    __name__
)

@labs_bp.route("/labs")
@login_required
def labs():

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, title, description FROM labs"
    )

    rows = cursor.fetchall()

    conn.close()


    labs = {}

    for row in rows:

        labs[row[0]] = {
            "title": row[1],
            "description": row[2]
        }


    return render_template(
        "labs.html",
        labs=labs
    )

@labs_bp.route("/labs/<lab_name>")
@login_required
def lab(lab_name):

    conn = get_db()

    cursor = conn.cursor()


    cursor.execute(
        """
        SELECT title, description
        FROM labs
        WHERE name = ?
        """,
        (lab_name,)
    )


    lab_info = cursor.fetchone()


    conn.close()


    if lab_info is None:
        return "Lab Not Found", 404


    lab_data = {
        "title": lab_info[0],
        "description": lab_info[1]
    }


    return render_template(
        "lab.html",
        lab_info=lab_data
    )