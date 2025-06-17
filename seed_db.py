from app import create_app, db
from app.models import User, Quote, QuoteXML, LogEntry
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
import random

app = create_app()

with app.app_context():
    # Drop all tables and recreate them (optional, for a clean start)
    db.drop_all()
    db.create_all()

    # --- Create Users ---
    users = []
    admin = User(
        username="admin",
        email="admin@example.com",
        password_hash=generate_password_hash("adminpass"),
        role="admin"
    )
    users.append(admin)
    db.session.add(admin)

    for i in range(1, 10):
        user = User(
            username=f"user{i}",
            email=f"user{i}@example.com",
            password_hash=generate_password_hash(f"userpass{i}"),
            role="regular"
        )
        users.append(user)
        db.session.add(user)
    db.session.commit()

    # --- Create Quotes ---
    quotes = []
    for i in range(1, 11):
        quote = Quote(
            reference_number=f"REF{i:04d}",
            customer_name=f"Customer {i}",
            vehicle_registration=f"REG{i:04d}",
            postcode=f"AB{i:02d} {random.randint(1,9)}CD",
            start_date=datetime.utcnow() + timedelta(days=random.randint(1, 30)),
            created_by=users[random.randint(0, 9)].user_id,
            created_at=datetime.utcnow(),
            status=random.choice(['pending', 'issued', 'rejected'])
        )
        quotes.append(quote)
        db.session.add(quote)
    db.session.commit()

    # --- Create QuoteXMLs ---
    for i in range(1, 11):
        xml = QuoteXML(
            quote_id=quotes[random.randint(0, 9)].quote_id,
            xml_type=random.choice(['request', 'response']),
            xml_content=f"<xml>Sample XML content {i}</xml>",
            timestamp=datetime.utcnow()
        )
        db.session.add(xml)
    db.session.commit()

    # --- Create LogEntries ---
    for i in range(1, 11):
        log = LogEntry(
            user_id=users[random.randint(0, 9)].user_id,
            quote_id=quotes[random.randint(0, 9)].quote_id,
            action=random.choice(['viewed', 'created', 'updated', 'deleted']),
            timestamp=datetime.utcnow(),
            details=f"Log entry {i}"
        )
        db.session.add(log)
    db.session.commit()

    print("Database seeded with sample data.")