from . import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, String

class User(db.Model, UserMixin):
    """
    Represents a user of the application.

    Attributes:
        user_id (int): Unique identifier for the user.
        username (str): Unique username for the user.
        email (str): Unique email address for the user.
        password_hash (str): Hashed password for secure authentication.
        role (str): Role of the user, either 'admin' or 'regular'.
        created_at (datetime): Timestamp when the user was created.
    """
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    address = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'regular'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    phone = db.Column(db.String(32), nullable=True)

    quotes = db.relationship(
        'Quote',
        backref='creator',
        lazy=True,
        foreign_keys='Quote.created_by'
    )
    customer_quotes = db.relationship(
        'Quote',
        backref='customer',
        lazy=True,
        foreign_keys='Quote.customer_user_id'
    )
    log_entries = db.relationship('LogEntry', back_populates='user', lazy=True)

    def set_password(self, password):
        """Hashes and sets the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks the user's password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Checks if the user has admin role."""
        return self.role == 'admin'

class Quote(db.Model):
    """
    Represents a breakdown cover quote.

    Attributes:
        quote_id (int): Unique identifier for the quote.
        reference_number (str): Unique reference number for the quote.
        customer_name (str): Name of the customer.
        vehicle_registration (str): Vehicle registration number.
        created_by (int): Foreign key referencing the user who created the quote.
        created_at (datetime): Timestamp when the quote was created.
        status (str): Status of the quote, e.g., 'pending', 'issued', 'rejected'.
    """
    __tablename__ = 'quote'
    quote_id = db.Column(db.Integer, primary_key=True)
    reference_number = db.Column(db.String(50), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    customer_user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)
    customer_name = db.Column(db.String(100), nullable=False)
    vehicle_registration = db.Column(db.String(50), nullable=False)
    postcode = db.Column(db.String(20), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # 'pending', 'issued', 'rejected'
    cover_type = db.Column(db.String, nullable=True)  # or db.Text if you want to store as comma-separated
    covered_persons = db.Column(db.Integer, nullable=False, default=1)
    date_of_birth = db.Column(db.Date, nullable=True)
    annual_total = db.Column(db.Numeric(18, 2), nullable=True)
    monthly_total = db.Column(db.Numeric(18, 2), nullable=True)

    quote_xmls = db.relationship('QuoteXML', backref='quote', lazy=True)
    log_entries = db.relationship('LogEntry', back_populates='quote', lazy=True)

class QuoteXML(db.Model):
    """
    Stores XML data related to a quote (request or response).

    Attributes:
        quote_xml_id (int): Unique identifier for the QuoteXML.
        quote_id (int): Foreign key referencing the associated quote.
        xml_type (str): Type of XML, either 'request' or 'response'.
        xml_content (str): Content of the XML.
        timestamp (datetime): Timestamp when the XML was created.
    """
    __tablename__ = 'quote_xml'
    quote_xml_id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote.quote_id'), nullable=False)
    xml_type = db.Column(db.String(10), nullable=False)  # 'request' or 'response'
    xml_content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LogEntry(db.Model):
    """
    Records actions taken in the system for auditing.

    Attributes:
        log_entry_id (int): Unique identifier for the log entry.
        user_id (int): Foreign key referencing the user who performed the action.
        quote_id (int): Foreign key referencing the associated quote.
        action (str): Action taken, e.g., 'viewed', 'created', 'updated', 'deleted'.
        timestamp (datetime): Timestamp when the action was performed.
        details (str, optional): Additional details about the action.
    """
    __tablename__ = 'log_entry'
    log_entry_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote.quote_id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(20), nullable=False)  # 'viewed', 'created', 'updated', 'deleted'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

    user = db.relationship('User', back_populates='log_entries')
    quote = db.relationship('Quote', back_populates='log_entries')

def set_cover_type(cover_type):
    """Sets the cover type as a comma-separated string."""
    return ",".join(cover_type)
