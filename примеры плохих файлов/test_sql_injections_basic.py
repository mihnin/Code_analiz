


user_id = "1 OR 1=1"
query1 = "SELECT * FROM users WHERE id = " + user_id

username = "admin' OR '1'='1"
query2 = "SELECT * FROM users WHERE username = '" + username + "'"


search = "test' UNION SELECT * FROM users --"
query3 = "SELECT * FROM products WHERE name LIKE '%" + search + "%' OR description LIKE '%" + search + "%'"


user_input = "admin' --"
query4 = f"SELECT * FROM customers WHERE name = '{user_input}'"

id_input = "1; DROP TABLE users --"
query5 = f"UPDATE accounts SET balance = 0 WHERE user_id = {id_input}"



email = "test@example.com' OR '1'='1"
query6 = "DELETE FROM subscribers WHERE email = '%s'" % email

category = "books' UNION SELECT * FROM users --"
limit = "10"
query7 = "SELECT * FROM items WHERE category = '%s' LIMIT %s" % (category, limit)



table = "users; DROP TABLE logs --"
query8 = "DROP TABLE {}".format(table)

role = "admin' OR '1'='1"
query9 = "SELECT * FROM users WHERE role = '{}'".format(role)




is_admin = "1 OR 1=1"
query10 = "SELECT * FROM users WHERE is_admin = " + is_admin + " AND status = 'active'"


name = "Robert'); DROP TABLE students; --"
email = "test@example.com"
query11 = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')"


new_password = "newpass' WHERE username = 'admin' --"
user_id = "1"
query12 = "UPDATE users SET password = '" + new_password + "' WHERE id = " + user_id

print("Basic SQL injection test cases created")