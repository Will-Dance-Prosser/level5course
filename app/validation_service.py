import re
from datetime import datetime

class ValidationService:
    def validate_vehicle_reg(self, reg):
        # UK vehicle registration: not empty, max 8 chars, alphanumeric (allowing space)
        if not reg or len(reg.strip()) == 0:
            return False, 'Vehicle registration cannot be empty.'
        if len(reg.strip()) > 8:
            return False, 'Vehicle registration must be at most 8 characters.'
        if not re.match(r'^[A-Za-z0-9 ]+$', reg.strip()):
            return False, 'Vehicle registration must be alphanumeric.'
        return True, None

    def validate_uk_postcode(self, postcode):
        # Accepts any valid UK postcode (case-insensitive, with/without space)
        if not postcode or len(postcode.strip()) == 0:
            return False, 'Postcode cannot be empty.'
        uk_postcode_regex = r"^(GIR ?0AA|[A-PR-UWYZ][A-HK-Y]?\d{1,2} ?\d[ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y]?\d[A-HJKPSTUW]? ?\d[ABD-HJLNP-UW-Z]{2})$"
        if not re.match(uk_postcode_regex, postcode.strip().upper()):
            return False, 'Please enter a valid UK postcode.'
        return True, None

    def validate_age_over_16(self, dob_str):
        # dob_str: 'YYYY-MM-DD'
        try:
            dob = datetime.strptime(dob_str, "%Y-%m-%d")
            today = datetime.now()
            age = (today - dob).days // 365
            if age < 16:
                return False, 'Customer must be at least 16 years old.'
            return True, None
        except Exception:
            return False, 'Invalid date of birth.'

    @staticmethod
    def is_int(value):
        try:
            int(value)
            return True
        except (TypeError, ValueError):
            return False

    def validate_username(self, username):
        if not username or len(username.strip()) == 0:
            return False, 'Username cannot be empty.'
        if len(username.strip()) > 16:
            return False, 'Username must be at most 16 characters.'
        if not re.match(r'^[A-Za-z0-9_\-]+$', username.strip()):
            return False, 'Username must be alphanumeric (letters, numbers, _ or -).'
        return True, None

    def validate_password(self, password):
        if not password or len(password) < 6 or len(password) > 24:
            return False, 'Password must be between 6 and 24 characters.'
        return True, None
