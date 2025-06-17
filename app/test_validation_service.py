import unittest
from app.validation_service import ValidationService

class TestValidationService(unittest.TestCase):
    def setUp(self):
        self.validation = ValidationService()

    def test_validate_username_valid(self):
        valid, msg = self.validation.validate_username('user123')
        self.assertTrue(valid)
        self.assertIsNone(msg)

    def test_validate_username_empty(self):
        valid, msg = self.validation.validate_username('')
        self.assertFalse(valid)
        self.assertIn('cannot be empty', msg)

    def test_validate_username_too_long(self):
        valid, msg = self.validation.validate_username('a'*17)
        self.assertFalse(valid)
        self.assertIn('at most 16 characters', msg)

    def test_validate_username_invalid_chars(self):
        valid, msg = self.validation.validate_username('user!@#')
        self.assertFalse(valid)
        self.assertIn('alphanumeric', msg)

    def test_validate_password_valid(self):
        valid, msg = self.validation.validate_password('password123')
        self.assertTrue(valid)
        self.assertIsNone(msg)

    def test_validate_password_too_short(self):
        valid, msg = self.validation.validate_password('123')
        self.assertFalse(valid)
        self.assertIn('between 6 and 24', msg)

    def test_validate_password_too_long(self):
        valid, msg = self.validation.validate_password('a'*25)
        self.assertFalse(valid)
        self.assertIn('between 6 and 24', msg)

    def test_validate_vehicle_reg_valid(self):
        valid, msg = self.validation.validate_vehicle_reg('AB12CDE')
        self.assertTrue(valid)
        self.assertIsNone(msg)

    def test_validate_vehicle_reg_empty(self):
        valid, msg = self.validation.validate_vehicle_reg('')
        self.assertFalse(valid)
        self.assertIn('cannot be empty', msg)

    def test_validate_vehicle_reg_too_long(self):
        valid, msg = self.validation.validate_vehicle_reg('ABCDEFGH1')
        self.assertFalse(valid)
        self.assertIn('at most 8 characters', msg)

    def test_validate_vehicle_reg_invalid_chars(self):
        valid, msg = self.validation.validate_vehicle_reg('AB12!@#')
        self.assertFalse(valid)
        self.assertIn('alphanumeric', msg)

    def test_validate_uk_postcode_valid(self):
        valid, msg = self.validation.validate_uk_postcode('SW1A 1AA')
        self.assertTrue(valid)
        self.assertIsNone(msg)

    def test_validate_uk_postcode_invalid(self):
        valid, msg = self.validation.validate_uk_postcode('12345')
        self.assertFalse(valid)
        self.assertIn('valid UK postcode', msg)

    def test_validate_age_over_16_valid(self):
        valid, msg = self.validation.validate_age_over_16('2000-01-01')
        self.assertTrue(valid)
        self.assertIsNone(msg)

    def test_validate_age_over_16_too_young(self):
        from datetime import datetime, timedelta
        recent = (datetime.now() - timedelta(days=365*10)).strftime('%Y-%m-%d')
        valid, msg = self.validation.validate_age_over_16(recent)
        self.assertFalse(valid)
        self.assertIn('at least 16 years old', msg)

    def test_validate_age_over_16_invalid_date(self):
        valid, msg = self.validation.validate_age_over_16('not-a-date')
        self.assertFalse(valid)
        self.assertIn('Invalid date of birth', msg)

if __name__ == '__main__':
    unittest.main()
