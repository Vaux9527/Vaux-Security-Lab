import sqlite3


conn = sqlite3.connect("minisec.db")


cursor = conn.cursor()


cursor.execute(
    """
    INSERT INTO labs
    (name, title, description)
    VALUES
    ('xss', 'XSS跨站脚本实验', '学习XSS漏洞原理')
    """
)


conn.commit()


conn.close()


print("Data inserted!")