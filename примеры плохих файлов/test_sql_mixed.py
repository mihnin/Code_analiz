import sqlite3


DB_PATH = "/path/to/database.db"
DB_PASSWORD = "sqlite_password_123" 

def unsafe_query(user_input):
    """Уязвимая функция с SQL инъекцией"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()


    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query) 

    return cursor.fetchall()

def unsafe_query_with_password(user_input):

    # Хардкод в строке подключения
    connection_string = f"sqlite:///app.db?password={DB_PASSWORD}"


    query = "SELECT * FROM products WHERE name = '%s'" % user_input


    return query

def get_user_data(user_id):
    """Еще один пример уязвимого кода"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()


    base_query = "SELECT * FROM users WHERE id = "


    full_query = base_query + str(user_id)
    cursor.execute(full_query)

    return cursor.fetchall()


DATABASE_CONFIG = {
    'name': 'production_db',
    'user': 'app_user',
    'password': 'production_password_2024',  
    'host': 'db.server.com'
}

print("SQL mixed test file loaded")