import sqlite3
import bcrypt
import config

class AuthService:
    def __init__(self):
        self.conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.current_user = None

    def login(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            self.current_user = {
                'id': user[0],
                'email': user[1],
                'full_name': user[3],
                'role': user[4]
            }
            return True
        return False

    def get_current_user_id(self):
        return self.current_user['id'] if self.current_user else None

    def get_current_user_role(self):
        return self.current_user['role'] if self.current_user else None

    def logout(self):
        self.current_user = None

auth_service = AuthService()