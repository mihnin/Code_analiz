import sqlite3
import psycopg2
import mysql.connector




conn = sqlite3.connect('test.db')
cursor = conn.cursor()


user_input = "admin' OR '1'='1"
cursor.execute("SELECT * FROM users WHERE username = '" + user_input + "'")


conn_pg = psycopg2.connect("dbname=test user=test")
cursor_pg = conn_pg.cursor()


table_name = "users; SELECT * FROM passwords --"
cursor_pg.execute(f"SELECT * FROM {table_name}")

conn_mysql = mysql.connector.connect(user='root', database='test')
cursor_mysql = conn_mysql.cursor()


search_term = "test%' UNION SELECT * FROM users --"
cursor_mysql.execute("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")




base_query = "SELECT * FROM logs WHERE "
condition = "1=1; DROP TABLE logs --"
query13 = base_query + condition


filters = []
date = "2024-01-01' OR '1'='1"
filters.append("date > '" + date + "'")

user = "1 UNION SELECT * FROM admin_users --"
filters.append("user_id = " + user)

if filters:
    query14 = "SELECT * FROM events WHERE " + " AND ".join(filters)



proc_name = "sp_getUsers; DROP TABLE users --"
query15 = "EXEC " + proc_name




id_param = "1 AND SLEEP(5)--"
query16 = "SELECT * FROM data WHERE id = " + id_param + " AND SLEEP(5)"


search_param = "test' AND 1=1 --"
query17 = "SELECT * FROM articles WHERE content LIKE '%" + search_param + "%' AND 1=1"



category_id = "1 UNION SELECT username, password FROM users --"
query18 = "SELECT name, price FROM products WHERE category_id = " + category_id


safe_user_id = "1"
safe_query1 = "SELECT * FROM users WHERE id = ?"
cursor.execute(safe_query1, (safe_user_id,))

safe_username = "admin"
safe_query2 = "SELECT * FROM users WHERE username = %s"
cursor.execute(safe_query2, (safe_username,))


from psycopg2 import sql
table_name_safe = "users"
safe_query3 = sql.SQL("SELECT * FROM {}").format(sql.Identifier(table_name_safe))

print("Advanced SQL injection test cases created")