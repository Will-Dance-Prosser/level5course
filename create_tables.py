# create_tables.py
"""
Script to create all tables in the database using SQLAlchemy models.
Usage:
    $env:DATABASE_URL="<your_postgres_url>"
    python create_tables.py
"""
import os
from dotenv import load_dotenv
from app import create_app, db

# Load environment variables from .env if present
load_dotenv()

app = create_app()

with app.app_context():
    db.create_all()
    print("All tables created successfully.")
