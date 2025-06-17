import os
from sqlalchemy import create_engine, text

class DatabaseService:
    def __init__(self, app=None):
        self.SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
        if not self.SQLALCHEMY_DATABASE_URI:
            raise ValueError("DATABASE_URL environment variable is not set.")
        self.engine = create_engine(self.SQLALCHEMY_DATABASE_URI)

    def get_user_permissions(self, username):
        try:
            with self.engine.connect() as connection:
                query = text("SELECT role FROM \"user\" WHERE username = :username")
                result = connection.execute(query, {"username": username}).fetchone()
                if result:
                    return {'status': 'success', 'user_type': result[0]}
                else:
                    return {'status': 'error', 'message': 'User not found'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def get_min_date(self):
        try:
            with self.engine.connect() as connection:
                query = text("SELECT MIN(created_at) FROM \"user\"")
                result = connection.execute(query).fetchone()
                if result and result[0]:
                    return {'status': 'success', 'min_date': result[0]}
                else:
                    return {'status': 'error', 'message': 'No records found'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def fetch_services(self):
        try:
            with self.engine.connect() as connection:
                query = text("SELECT DISTINCT cover_type FROM quote")
                result = connection.execute(query).fetchall()
                services = [row[0] for row in result]
                return {'status': 'success', 'services': services}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}