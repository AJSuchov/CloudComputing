import MySQLdb

def connection():
    conn = MySQLdb.connect(host="localhost",
                            user = "root",
                            passwd = "Homework1",
                            db = "hw1")

    c = conn.cursor()

    return c, conn