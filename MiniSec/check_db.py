import sqlite3


conn = sqlite3.connect("minisec.db")


cursor = conn.cursor()


# 获取所有表名
cursor.execute(
    """
    SELECT name 
    FROM sqlite_master
    WHERE type='table'
    """
)


tables = cursor.fetchall()


for table in tables:

    table_name = table[0]


    print("\n====================")
    print("Table:", table_name)
    print("====================")


    cursor.execute(
        f"SELECT * FROM {table_name}"
    )


    rows = cursor.fetchall()


    for row in rows:
        print(row)



conn.close()