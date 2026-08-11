import sqlite3


conn = sqlite3.connect("minisec.db")


cursor = conn.cursor()


cursor.execute("""
CREATE TABLE labs (
    id INTEGER PRIMARY KEY,
    name TEXT,
    title TEXT,
    description TEXT
)
""")


conn.commit()


conn.close()


print("Labs table created!")