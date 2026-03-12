
import os
from typing import Optional

DATABASE_URL: Optional[str] = os.getenv('DATABASE_URL')
API_KEY: Optional[str] = os.getenv('API_KEY')
SECRET_KEY: Optional[str] = os.getenv('SECRET_KEY')


APP_CONFIG = {
    'debug': os.getenv('DEBUG', 'False').lower() == 'true',
    'host': os.getenv('HOST', '0.0.0.0'),
    'port': int(os.getenv('PORT', '8000'))
}

def get_database_config():
    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', '5432')),
        'database': os.getenv('DB_NAME', 'myapp'),
        'username': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD')  
    }

def safe_query(user_id: int):
    import sqlite3

    conn = sqlite3.connect(os.getenv('DB_PATH', 'app.db'))
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    return cursor.fetchall()

class SecureAPIClient:
    

    def __init__(self):
        self.base_url = os.getenv('API_BASE_URL', 'https://api.example.com')
        self.api_key = os.getenv('API_KEY')  
        self.timeout = int(os.getenv('API_TIMEOUT', '30'))

    def make_request(self, endpoint: str):
        import requests

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, headers=headers, timeout=self.timeout)
        return response.json()

DEFAULT_PAGE_SIZE = 20
MAX_RETRY_ATTEMPTS = 3
SUPPORTED_LANGUAGES = ['en', 'es', 'fr']

print("Safe code example loaded")