import sqlite3


conn = sqlite3.connect("minisec.db")


cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT
)
""")


conn.commit()


conn.close()


print("Users table created!")