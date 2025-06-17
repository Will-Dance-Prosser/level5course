# Breakdown Cover Quote Management System

A Flask-based web application for managing breakdown cover insurance quotes, with robust backend validation, admin XML editing, and a modern, user-friendly interface.

## Features
- **User Registration & Login**: Secure authentication with session management.
- **Quote Creation**: Multi-step form with validation for vehicle registration, UK postcode, and age.
- **Quote Listing & Filtering**: Search and filter quotes by reference, customer, vehicle, postcode, and status.
- **Quote Summary**: Detailed view of quote, products, and expiry.
- **XML Management**: View, edit (admin only), and delete request/response XMLs for each quote. Changes to XMLs update quote totals.
- **Logging**: All key actions (quote creation, XML edits, user updates) are logged and viewable by admins.
- **Admin Controls**: Only admins can edit/delete XMLs and view logs.
- **Modern UI/UX**: Responsive, accessible, and visually appealing forms and tables.

## Tech Stack
- Python 3.x
- Flask
- SQLAlchemy (ORM)
- Jinja2 (templates)
- HTML/CSS (custom, no heavy frameworks)

## Setup Instructions
1. **Clone the repository**
   ```sh
   git clone <your-repo-url>
   cd Software_course
   ```
2. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```
3. **Initialize the database**
   ```sh
   python seed_db.py
   ```
4. **Run the application**
   ```sh
   python run.py
   ```
5. **Access the app**
   Open your browser to [http://localhost:5000](http://localhost:5000)

## Usage
- Register as a user or log in as an admin (see `seed_db.py` for default admin credentials).
- Create new quotes, view and filter existing ones.
- Admins can view, edit, and delete XMLs for each quote, and view the full log of actions.
- All changes to XMLs are validated and, if valid, update the quote summary and totals.

## Project Structure
- `app/` - Main Flask app (routes, models, validation, templates)
- `quote_creation.py` - XML generation and parsing logic
- `requirements.txt` - Python dependencies
- `run.py` - App entry point
- `seed_db.py` - Script to initialize the database with sample data

## Development Notes
- All validation logic is in `app/validation_service.py`.
- XML pretty-printing is handled in `app/utils.py`.
- Admin checks are session-based (`session['role']`).
- All model instantiations use attribute assignment (not keyword args).
- For deployment, see Flask documentation or use a WSGI server like Gunicorn.

## License
MIT License (or specify your own)

---
For questions or contributions, please open an issue or pull request.
