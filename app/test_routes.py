import unittest
from app import create_app, db
from app.models import User, Quote, QuoteXML, LogEntry
from flask import session
from datetime import datetime, timedelta

class RoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()
            # Create a test user
            user = User(username='testuser', email='test@example.com', role='regular')
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            self.user_id = user.user_id
            # Add admin and user2 for extra tests
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()
            self.admin_id = admin.user_id
            user2 = User(username='user2', email='user2@example.com', role='regular')
            user2.set_password('user2pass')
            db.session.add(user2)
            db.session.commit()
            self.user2_id = user2.user_id

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, username='testuser', password='password123'):
        return self.client.post('/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    def test_register_get(self):
        response = self.client.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register', response.data)

    def test_register_post_valid(self):
        response = self.client.post('/register', data={
            'usertype': 'regular',
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        self.assertIn(b'Registration successful', response.data)
        with self.app.app_context():
            user = User.query.filter_by(username='newuser').first()
            self.assertIsNotNone(user)

    def test_register_post_invalid(self):
        response = self.client.post('/register', data={
            'usertype': 'regular',
            'username': '',
            'email': 'bademail',
            'password': '123',
            'confirm_password': '456'
        }, follow_redirects=True)
        self.assertIn(b'Username cannot be empty.', response.data)

    def test_login_logout(self):
        response = self.login()
        self.assertIn(b'dashboard', response.data.lower())
        response = self.client.get('/logout', follow_redirects=True)
        self.assertIn(b'Logged out successfully', response.data)

    def test_login_invalid(self):
        response = self.client.post('/login', data={
            'username': 'wrong',
            'password': 'wrong'
        }, follow_redirects=True)
        self.assertIn(b'Invalid credentials', response.data)

    def test_create_quote_requires_login(self):
        response = self.client.get('/quotes/new', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())

    def test_create_quote_post_invalid(self):
        self.login()
        response = self.client.post('/quotes/new', data={
            'customer_name': '',
            'vehicle_reg': '',
            'postcode': '',
            'date_of_birth': '2020-01-01'
        }, follow_redirects=True)
        self.assertIn(b'cannot be empty', response.data)

    def test_list_quotes(self):
        self.login()
        response = self.client.get('/quotes')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Quote', response.data)

    def test_profile_requires_login(self):
        response = self.client.get('/profile', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())

    def test_admin_routes_require_admin(self):
        self.login()
        # Try to access logs as regular user
        response = self.client.get('/logs', follow_redirects=True)
        # Accept either the flash message or the dashboard content
        self.assertTrue(
            b'Admins only.' in response.data or b'Breakdown Policy Dashboard' in response.data,
            "Should see admin warning or be redirected to dashboard."
        )

    def test_dashboard_requires_login(self):
        self.client.get('/logout', follow_redirects=True)
        response = self.client.get('/', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())

    def test_register_duplicate_username(self):
        response = self.client.post('/register', data={
            'usertype': 'admin',
            'username': 'admin',
            'email': 'admin2@example.com',
            'password': 'adminpass',
            'confirm_password': 'adminpass'
        }, follow_redirects=True)
        self.assertIn(b'Username already exists.', response.data)

    def test_register_passwords_do_not_match(self):
        response = self.client.post('/register', data={
            'usertype': 'regular',
            'username': 'userx',
            'email': 'userx@example.com',
            'password': 'pass1234',
            'confirm_password': 'pass5678'
        }, follow_redirects=True)
        self.assertIn(b'Passwords do not match.', response.data)

    def test_register_username_too_long(self):
        response = self.client.post('/register', data={
            'usertype': 'regular',
            'username': 'a'*17,
            'email': 'longuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        self.assertIn(b'Username must be at most 16 characters.', response.data)

    def test_register_password_too_short(self):
        response = self.client.post('/register', data={
            'usertype': 'regular',
            'username': 'shortpw',
            'email': 'shortpw@example.com',
            'password': '123',
            'confirm_password': '123'
        }, follow_redirects=True)
        self.assertIn(b'Password must be between 6 and 24 characters.', response.data)

    def test_logout(self):
        self.login('admin', 'adminpass')
        response = self.client.get('/logout', follow_redirects=True)
        self.assertIn(b'Logged out successfully.', response.data)

    def test_list_quotes_admin(self):
        self.login('admin', 'adminpass')
        response = self.client.get('/quotes')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Quote', response.data)

    def test_list_quotes_regular(self):
        self.login('user2', 'user2pass')
        response = self.client.get('/quotes')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Quote', response.data)

    def test_create_quote_and_summary(self):
        self.login('user2', 'user2pass')
        # Step 1: create quote
        response = self.client.post('/quotes/new', data={
            'customer_name': 'Test Customer',
            'vehicle_reg': 'AB12CDE',
            'postcode': 'SW1A 1AA',
            'date_of_birth': '2000-01-01'
        }, follow_redirects=True)
        self.assertIn(b'select', response.data.lower())
        # Step 2: select cover
        response = self.client.post('/quotes/select_cover', data={
            'cover_type[]': ['Roadside', 'Relay']
        }, follow_redirects=True)
        self.assertIn(b'quote summary', response.data.lower())

    def test_select_cover_requires_cover(self):
        self.login('user2', 'user2pass')
        self.client.post('/quotes/new', data={
            'customer_name': 'Test Customer',
            'vehicle_reg': 'AB12CDE',
            'postcode': 'SW1A 1AA',
            'date_of_birth': '2000-01-01'
        }, follow_redirects=True)
        response = self.client.post('/quotes/select_cover', data={}, follow_redirects=True)
        self.assertIn(b'Please select at least one cover type.', response.data)

    def test_profile_update(self):
        self.login('user2', 'user2pass')
        response = self.client.post('/profile', data={
            'address': '123 Main St',
            'email': 'user2new@example.com',
            'phone': '1234567890',
            'password': 'user2pass'
        }, follow_redirects=True)
        self.assertIn(b'Profile updated successfully.', response.data)

    def test_view_users_admin(self):
        self.login('admin', 'adminpass')
        response = self.client.get('/users')
        self.assertIn(b'admin', response.data)
        self.assertIn(b'user2', response.data)

    def test_edit_user_admin(self):
        self.login('admin', 'adminpass')
        response = self.client.post(f'/users/edit/{self.user2_id}', data={
            'email': 'user2edit@example.com',
            'address': 'New Address',
            'role': 'regular'
        }, follow_redirects=True)
        self.assertIn(b'User updated successfully.', response.data)

    def test_delete_quote_admin(self):
        self.login('admin', 'adminpass')
        # Create a quote to delete
        with self.app.app_context():
            quote = Quote(reference_number='DELREF', customer_name='Del', vehicle_registration='AB12CDE', postcode='SW1A 1AA', cover_type='Roadside', start_date=datetime.now(), created_by=self.admin_id, status='pending', covered_persons=1)
            db.session.add(quote)
            db.session.commit()
        response = self.client.post('/quotes/delete/DELREF', follow_redirects=True)
        self.assertIn(b'Quote deleted successfully.', response.data)

    def test_logs_admin(self):
        self.login('admin', 'adminpass')
        response = self.client.get('/logs')
        self.assertIn(b'Log', response.data)

if __name__ == '__main__':
    unittest.main()
