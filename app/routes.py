from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session, flash
from datetime import datetime
from . import db
from .models import User, Quote, QuoteXML, LogEntry
import uuid
from quote_creation import generate_request_xml, generate_response_xml, parse_response_xml
from sqlalchemy import func
from .utils import prettify_xml, xml_parser, find_field_value
from .search_service import SearchService 
from .validation_service import ValidationService
from functools import wraps 
import xml.etree.ElementTree as ET

bp = Blueprint('main', __name__)

# Instantiate the search service once, after db is available
search_service = SearchService(db)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Session expired. Please log in again.')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@login_required
def index():
    user_id = session.get('user_id')
    if user_id:
        user = db.session.query(User).filter_by(user_id=user_id).first()
        return render_template('dashboard.html', user=user)
    return render_template('login.html')

# --- User Registration ---
@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form['usertype']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # Preserve entered values
        form_data = {
            'usertype': role,
            'username': username,
            'email': email,
        }

        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
            return render_template('register.html', **form_data)

        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another email or login.')
            return render_template('register.html', **form_data)

        validation = ValidationService()
        valid, msg = validation.validate_username(username)
        if not valid:
            flash(msg or 'Invalid username.')
            return render_template('register.html', **form_data)
        valid, msg = validation.validate_password(password)
        if not valid:
            flash(msg or 'Invalid password.')
            return render_template('register.html', **form_data)
        if db.session.query(User).filter_by(username=username).first():
            flash('Username already exists.')
            return render_template('register.html', **form_data)
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html', **form_data)
        if len(username) > 16:
            flash('Username must be at most 16 characters.')
            return render_template('register.html', **form_data)
        if len(password) < 6 or len(password) > 24:
            flash('Password must be between 6 and 24 characters.')
            return render_template('register.html', **form_data)
        user = User()
        user.username = username
        user.email = email
        user.role = role
        user.set_password(password)
        db.session.add(user)
        db.session.commit()  # Commit first to get user.user_id

        log = LogEntry()
        log.user_id = user.user_id
        log.action = 'registered'
        log.timestamp = datetime.utcnow()
        log.details = f'User {username} registered with role {role}'
        db.session.add(log)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('main.login'))
    # For GET or first load, pass empty/default values
    return render_template('register.html', usertype='', username='', email='')

# --- User Login ---
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            session.permanent = True
            session['user_id'] = user.user_id
            session['role'] = user.role
            return redirect(url_for('main.index'))
        flash('Invalid credentials.')
    return render_template('login.html')

# --- User Logout ---
@bp.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('main.login'))

# --- List Quotes ---
@bp.route('/quotes')
@login_required
def list_quotes():
    query = db.session.query(Quote)
    reference = request.args.get('reference')
    customer = request.args.get('customer')
    vehicle = request.args.get('vehicle')
    postcode = request.args.get('postcode')
    status = request.args.get('status')
    if reference:
        query = query.filter(Quote.reference_number.ilike(f"%{reference}%"))
    if customer:
        query = query.filter(Quote.customer_name.ilike(f"%{customer}%"))
    if vehicle:
        query = query.filter(Quote.vehicle_registration.ilike(f"%{vehicle}%"))
    if postcode:
        query = query.filter(Quote.postcode.ilike(f"%{postcode}%"))
    if status:
        query = query.filter(Quote.status == status)

    user_id = session.get('user_id')
    user_role = session.get('role')

    if user_role == 'admin':
        quotes = query.all()  # Admin sees all quotes
    else:
        quotes = query.filter(
            (Quote.created_by == user_id) | (Quote.customer_user_id == user_id)
        ).all()
    return render_template('quotes.html', quotes=quotes)




# --- Create Quote Stage 1 ---
# This is the first step of the quote creation process
@bp.route('/quotes/new', methods=['GET', 'POST'])
@login_required
def create_quote():
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        vehicle_reg = request.form['vehicle_reg']
        postcode = request.form['postcode']
        date_of_birth_str = request.form['date_of_birth']

        validation = ValidationService()
        errors = []
        valid, msg = validation.validate_vehicle_reg(vehicle_reg)
        if not valid:
            errors.append(msg)
        valid, msg = validation.validate_uk_postcode(postcode)
        if not valid:
            errors.append(msg)
        valid, msg = validation.validate_age_over_16(date_of_birth_str)
        if not valid:
            errors.append(msg)

        if errors:
            for error in errors:
                flash(error)
            # Pass previous values back to the form
            return render_template('create_quote.html', 
                                   customer_name=customer_name, 
                                   vehicle_reg=vehicle_reg, 
                                   postcode=postcode, 
                                   date_of_birth=date_of_birth_str)

        session['customer_name'] = customer_name
        session['vehicle_reg'] = vehicle_reg
        session['postcode'] = postcode
        session['date_of_birth'] = date_of_birth_str
        return redirect(url_for('main.select_cover'))
    # For GET or first load, pass empty/default values
    return render_template('create_quote.html', 
                           customer_name='', 
                           vehicle_reg='', 
                           postcode='', 
                           date_of_birth='')

# --- Create Quote Stage 2 ---
# This is the second step of the quote creation process
@bp.route('/quotes/select_cover', methods=['GET', 'POST'])
@login_required
def select_cover():
    cover_types = ["Roadside", "Relay", "HomeStart", "PartsCover"]
    if request.method == 'POST':
        selected_covers = request.form.getlist('cover_type[]')
        if not selected_covers:
            flash('Please select at least one cover type.')
            return render_template('select_cover.html', cover_types=cover_types)
        session['cover_type'] = selected_covers

        customer_name = session.get('customer_name')
        vehicle_reg = session.get('vehicle_reg')
        postcode = session.get('postcode')
        cover_type = session.get('cover_type')
        start_date = session.get('start_date') or datetime.utcnow()
        cover_type_str = ",".join(cover_type) if isinstance(cover_type, list) else cover_type
        date_of_birth_str = session.get('date_of_birth')
        date_of_birth = datetime.strptime(date_of_birth_str, "%Y-%m-%d").date() if date_of_birth_str else None

        quote = Quote()
        quote.reference_number = f"PENDING-{uuid.uuid4()}"
        quote.customer_name = customer_name
        quote.vehicle_registration = vehicle_reg
        quote.postcode = postcode
        quote.cover_type = cover_type_str
        quote.start_date = start_date
        quote.created_at = datetime.utcnow()
        quote.status = 'pending'
        quote.covered_persons = 1
        quote.date_of_birth = date_of_birth
        quote.created_by = session.get('user_id')
        db.session.add(quote)
        db.session.commit()

        # Set product attribute if needed (if your model supports it)
        # quote.product = cover_type if isinstance(cover_type, list) else cover_type_str.split(",")

        request_xml = generate_request_xml(quote)

        quote_xml = QuoteXML()
        quote_xml.quote_id = quote.quote_id
        quote_xml.xml_type = 'request'
        quote_xml.xml_content = request_xml
        quote_xml.timestamp = datetime.utcnow()
        db.session.add(quote_xml)
        db.session.commit()

        response_xml = generate_response_xml(request_xml)
        parsed_response = parse_response_xml(response_xml)
        reference_number = parsed_response[1].get('ref')
        annual_total = parsed_response[0].get('overall_total')
        monthly_total = parsed_response[1].get('overall_total')

        quote.reference_number = reference_number
        quote.created_by = session.get('user_id')
        quote.annual_total = annual_total
        quote.monthly_total = monthly_total
        db.session.commit()

        quote_xml = QuoteXML()
        quote_xml.quote_id = quote.quote_id
        quote_xml.xml_type = 'response'
        quote_xml.xml_content = response_xml
        quote_xml.timestamp = datetime.utcnow()
        db.session.add(quote_xml)

        log = LogEntry()
        log.user_id = session.get('user_id')
        log.quote_id = quote.quote_id
        log.action = 'created'
        log.timestamp = datetime.utcnow()
        log.details = 'created a new quote with reference number {}'.format(quote.reference_number)
        db.session.add(log)
        db.session.commit()

        return redirect(url_for('main.quote_summary', reference_number=quote.reference_number))
    return render_template('select_cover.html', cover_types=cover_types)

# --- Quote Summary by ID ---
@bp.route('/quotes/summary/<reference_number>')
@login_required
def quote_summary(reference_number):
    quote = Quote.query.filter_by(reference_number=reference_number).first_or_404()

    # Only allow the creator, assigned user, or admin to view
    user_id = session.get('user_id')
    user_role = session.get('role')
    if not (
        (quote.created_by == user_id)
        or (hasattr(quote, 'customer_user_id') and quote.customer_user_id == user_id)
        or (user_role == 'admin')
    ):
        flash("You do not have permission to view this quote.")
        return redirect(url_for('main.list_quotes'))

    # Calculate expiry string
    expiry_str = "unknown"
    if quote.start_date:
        expiry_dt = quote.start_date
        days_left = (expiry_dt.date() - datetime.utcnow().date()).days
        if days_left > 0:
            expiry_str = f"in {days_left} days"
        elif days_left == 0:
            expiry_str = "today"
        else:
            expiry_str = "expired"

    # --- Parse products from stored XML ---
    quote_xml = QuoteXML.query.filter_by(quote_id=quote.quote_id, xml_type='response').first()
    annual_products = []
    monthly_products = []
    expiry_str = "unknown"
    if quote_xml:
        parsed_response = parse_response_xml(quote_xml.xml_content)
        annual_products = parsed_response[0].get('products', [])
        monthly_products = parsed_response[1].get('products', [])
        expiry_date_str = parsed_response[0].get('exipiry_date')  # from XML, note the typo
        if expiry_date_str:
            try:
                expiry_dt = datetime.strptime(expiry_date_str, "%Y-%m-%d")
                days_left = (expiry_dt.date() - datetime.utcnow().date()).days
                if days_left > 0:
                    expiry_str = f"in {days_left} days"
                elif days_left == 0:
                    expiry_str = "today"
                else:
                    expiry_str = "expired"
            except Exception:
                expiry_str = expiry_date_str  # fallback to raw string if parsing fails

    log = LogEntry()
    log.user_id = session.get('user_id')
    log.quote_id = quote.quote_id
    log.action = 'viewed'
    log.timestamp = datetime.utcnow()
    log.details = f'Viewed quote summary for reference number {reference_number}'
    db.session.add(log)
    db.session.commit()

    return render_template(
        'quote_summary.html',
        quote=quote,
        customer_name=quote.customer_name,
        vehicle_reg=quote.vehicle_registration,
        postcode=quote.postcode,
        cover_type=quote.cover_type,
        reference_number=quote.reference_number,
        expiry_date=expiry_str,
        annual_products=annual_products,
        monthly_products=monthly_products,
        annual_total=quote.annual_total,
        monthly_total=quote.monthly_total,
    )


# --- List/Add Quote XMLs ---
@bp.route('/quotes/<int:quote_id>/xmls', methods=['GET', 'POST'])
@login_required
def quote_xmls(quote_id):
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.index'))
    xmls = db.session.query(QuoteXML).filter_by(quote_id=quote_id).all()
    for xml in xmls:
        xml.xml_content = prettify_xml(xml.xml_content)
    return render_template('quote_xmls.html', xmls=xmls, quote_id=quote_id)

# --- Edit/Delete Quote XML ---
@bp.route('/xmls/<int:xml_id>', methods=['GET', 'POST', 'DELETE'])
@login_required
def xml_detail(xml_id):
    xml = db.session.query(QuoteXML).filter_by(quote_xml_id=xml_id).first()
    if not xml:
        flash('XML not found.')
        return redirect(url_for('main.list_quotes'))
    if request.method == 'POST':
        if session.get('role') != 'admin':
            flash('Only admins can edit XMLs.')
            return redirect(url_for('main.xml_detail', xml_id=xml_id))
        new_xml_content = request.form['xml_content']
        old_xml_content = xml.xml_content  # Store old content for possible revert
        # Validate XML (well-formed, required fields)
        try:
            root = ET.fromstring(new_xml_content)
            required_tags = ['ResponseHeader', 'CustomerQuoteReference', 'QuoteExpiryDate']
            for tag in required_tags:
                if root.find(tag) is None:
                    flash(f'Missing required XML field: {tag}')
                    return redirect(url_for('main.xml_detail', xml_id=xml_id))
        except Exception as e:
            flash(f'Invalid XML: {e}')
            return redirect(url_for('main.xml_detail', xml_id=xml_id))
        # Save and update
        xml.xml_content = new_xml_content
        db.session.commit()
        # Log the change
        log = LogEntry()
        log.user_id = session.get('user_id')
        log.quote_id = xml.quote_id
        log.action = 'updated'
        log.timestamp = datetime.utcnow()
        log.details = f'Edited {xml.xml_type} XML (id={xml_id})'
        db.session.add(log)
        db.session.commit()
        flash('XML updated.')
        # If this is a response XML, update the quote summary fields
        if xml.xml_type == 'response':
            quote = db.session.query(Quote).filter_by(quote_id=xml.quote_id).first()
            if quote:
                try:
                    from quote_creation import parse_response_xml
                    parsed_response = parse_response_xml(xml.xml_content)
                    annual_total = parsed_response[0].get('overall_total')
                    monthly_total = parsed_response[1].get('overall_total')
                    if annual_total is not None:
                        quote.annual_total = annual_total
                    if monthly_total is not None:
                        quote.monthly_total = monthly_total
                    db.session.commit()
                except Exception as e:
                    # Revert XML content if parsing fails
                    xml.xml_content = old_xml_content
                    db.session.commit()
                    flash(f'Quote update failed: {e}. Changes reverted.')
                    return redirect(url_for('main.xml_detail', xml_id=xml_id))
        return redirect(url_for('main.xml_detail', xml_id=xml_id))
    if request.method == 'DELETE' or request.args.get('delete'):
        if session.get('role') == 'admin':
            db.session.delete(xml)     
            db.session.commit()
            flash('XML deleted.')
        else:
            flash('Only admins can delete XMLs.')
        return redirect(url_for('main.list_quotes'))
    # Render detail view using quote_xmls.html as a single-item list
    return render_template('quote_xmls.html', xmls=[xml], quote_id=xml.quote_id)

# --- List Logs (admin only) ---
@bp.route('/logs')
@login_required
def list_logs():
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.index'))
    query = db.session.query(LogEntry)
    user_id = request.args.get('user_id')
    action = request.args.get('action')
    if user_id:
        if ValidationService.is_int(user_id):
            query = query.filter(LogEntry.user_id == int(user_id))
        else:
            flash('User ID must be a number.')
    if action:
        query = query.filter(LogEntry.action.ilike(f"%{action}%"))
    logs = query.order_by(LogEntry.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

# --- View Log Entry (admin only) ---
@bp.route('/logs/<int:log_id>')
@login_required
def log_detail(log_id):
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.index'))
    log = db.session.query(LogEntry).filter_by(log_entry_id=log_id).first()
    if not log:
        flash('Log not found.')
        return redirect(url_for('main.list_logs'))
    return render_template('log_detail.html', log=log)

# --- Accept Quote ---
@bp.route('/quotes/accept/<reference_number>', methods=['POST'])
@login_required
def accept_quote(reference_number):
    quote = Quote.query.filter_by(reference_number=reference_number).first_or_404()
    user_id = session.get('user_id')
    user_role = session.get('role')
    if not (
        (quote.created_by == user_id)
        or (hasattr(quote, 'customer_user_id') and quote.customer_user_id == user_id)
        or (user_role == 'admin')
    ):
        flash("You do not have permission to accept this quote.")
        return redirect(url_for('main.list_quotes'))
    quote.status = 'accepted'
    log = LogEntry()
    log.user_id = user_id
    log.quote_id = quote.quote_id
    log.action = 'accepted'
    log.timestamp = datetime.utcnow()
    log.details = f'Quote {reference_number} accepted by user {user_id}'
    db.session.add(log)
    db.session.commit()
    flash('Quote accepted!')
    return redirect(url_for('main.quote_summary', reference_number=reference_number))

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.filter_by(user_id=user_id).first_or_404()
    if request.method == 'POST':
        address = request.form.get('address')
        email = request.form.get('email')
        password = request.form.get('password')
        # Remove all logic referencing user.phone
        if address and address != user.address: # stops unnecessary updates
            user.address = address
        if email and email != user.email:
            user.email = email
        if password and password != user.password_hash:
            user.set_password(password)
        log = LogEntry()
        log.user_id = user.user_id
        log.action = 'profile_updated'
        log.timestamp = datetime.utcnow()
        log.details = f'User {user.username} updated their profile.'
        db.session.add(log)
        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('main.profile'))
    return render_template('profile.html', user=user)

@bp.route('/users', methods=['GET'])
@login_required
def view_users():
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.index'))
    users = db.session.query(User).all()
    return render_template('view_users.html', users=users)

@bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.index'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.email = request.form.get('email')
        user.address = request.form.get('address')
        user.role = request.form.get('role')

        log = LogEntry(
            user_id=session.get('user_id'),
            action='user_updated',
            timestamp=datetime.utcnow(),
            details=f'User {user.username} updated by admin {session.get("user_id")}'
        )
        db.session.add(log)
        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('main.view_users'))
    return render_template('edit_user.html', user=user)


@bp.route('/quotes/delete/<reference_number>', methods=['POST'])
@login_required
def delete_quote(reference_number):
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.list_quotes'))
    quote = Quote.query.filter_by(reference_number=reference_number).first_or_404()
    # Delete related quote_xmls first
    QuoteXML.query.filter_by(quote_id=quote.quote_id).delete()
    log = LogEntry(
        user_id=session.get('user_id'),
        quote_id=quote.quote_id,  
        action='deleted',
        timestamp=datetime.utcnow(),
        details=f'Quote {reference_number} (ID {quote.quote_id}) deleted by user {session.get("user_id")}'
    )
    db.session.add(log)
    db.session.delete(quote)
    db.session.commit()
    flash('Quote deleted successfully.')
    return redirect(url_for('main.list_quotes'))

@bp.route('/search', methods=['GET'])
@login_required
def search():
    if session.get('role') != 'admin':
        flash('Admins only.')
        return redirect(url_for('main.dashboard'))

    # Get all search parameters
    customer_name = request.args.get('customer_name')
    vehicle_reg = request.args.get('vehicle_reg')
    postcode = request.args.get('postcode')
    date_of_birth = request.args.get('date_of_birth')
    products = request.args.getlist('products')
    payment_type = request.args.get('payment_type')
    commission = request.args.get('commission')
    arrangment_fee = request.args.get('arrangement_fee')
    net = request.args.get('net')

    # Use the SearchService instance
    if any([customer_name, vehicle_reg, postcode, date_of_birth, products, payment_type, commission, arrangment_fee, net]):
        quotes = search_service.search_quotes(
            customer_name=customer_name,
            vehicle_reg=vehicle_reg,
            postcode=postcode,
            date_of_birth=date_of_birth,
            products=products,
            payment_type=payment_type,
            commission=commission,
            arrangment_fee=arrangment_fee,
            net=net
        )
    else:
        quotes = []

    print(f"Quotes found: {len(quotes)}")
    return render_template('quote_search.html', quotes=quotes)











