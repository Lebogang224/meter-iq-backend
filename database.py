import sqlite3
import config
from datetime import datetime

class DBManager:
    def __init__(self):
        self.conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def execute_commit(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        last_id = cursor.lastrowid
        cursor.close()
        return last_id

    def query_one(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        cursor.close()
        return row

    def query_all(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return rows

    def log_audit(self, user_id, action, target_type, target_id, details=''):
        self.execute_commit(
            "INSERT INTO audit_log (user_id, action, target_type, target_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, target_type, target_id, details, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        )

    def get_user_role(self, user_id):
        row = self.query_one("SELECT role FROM users WHERE id=?", (user_id,))
        return row['role'] if row else None

    def has_permission(self, user_id, required_roles):
        role = self.get_user_role(user_id)
        return role in required_roles

db_manager = DBManager()