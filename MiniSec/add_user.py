import sqlite3


conn = sqlite3.connect("minisec.db")

cursor = conn.cursor()


cursor.execute(
    """
    INSERT INTO users(username, password, role)
    VALUES (?, ?, ?)
    """,
    (
        "admin",
        "123456",
        "admin"
    )
)


conn.commit()


conn.close()


print("User created!")