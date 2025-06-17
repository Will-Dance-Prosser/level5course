from app import create_app, db
from sqlalchemy import text

app = create_app()

with app.app_context():
    with db.engine.connect() as conn:
        conn.execute(text('DROP TABLE IF EXISTS "user" CASCADE;'))
        conn.commit()
    print('Dropped table "user"')