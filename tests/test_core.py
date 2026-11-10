import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"api"))
from core import ValidationError, authorized, is_managed, public_user, valid_id, validate_account

class AccessTests(unittest.TestCase):
    def test_viewer_reads(self):
        self.assertTrue(authorized({"realm_access":{"roles":["viewer"]}},"GET"))
    def test_viewer_cannot_write(self):
        for method in ("POST","PUT","DELETE","PATCH"):
            self.assertFalse(authorized({"realm_access":{"roles":["viewer"]}},method))
    def test_operator_writes(self):
        self.assertTrue(authorized({"realm_access":{"roles":["operator"]}},"POST"))
    def test_missing_role_denied(self):
        self.assertFalse(authorized({},"GET"))
    def test_string_role_denied(self):
        self.assertFalse(authorized({"realm_access":{"roles":"operator"}},"POST"))
    def test_unmanaged_account_denied(self):
        self.assertFalse(is_managed({"username":"admin"}))
    def test_managed_account_allowed(self):
        self.assertTrue(is_managed({"attributes":{"managed_by":["course-project"]}}))

class ValidationTests(unittest.TestCase):
    def test_create_disabled_by_default(self):
        self.assertFalse(validate_account({"username":"new.user"},True)["enabled"])
    def test_create_stamps_marker(self):
        self.assertEqual(validate_account({"username":"test"},True)["attributes"]["managed_by"],["course-project"])
    def test_privilege_injection_denied(self):
        for field in ("realmRoles","credentials","attributes","emailVerified"):
            with self.assertRaises(ValidationError):
                validate_account({"username":"test",field:[]},True)
    def test_wrong_boolean_denied(self):
        with self.assertRaises(ValidationError):validate_account({"enabled":"false"})
    def test_missing_username_denied(self):
        with self.assertRaises(ValidationError):validate_account({"email":"x@y.z"},True)
    def test_username_immutable(self):
        with self.assertRaises(ValidationError):validate_account({"username":"new"})
    def test_bad_username_denied(self):
        for name in ("a","../admin","Space User","1user"):
            with self.assertRaises(ValidationError):validate_account({"username":name},True)
    def test_bad_email_denied(self):
        with self.assertRaises(ValidationError):validate_account({"email":"invalid"})
    def test_control_char_denied(self):
        with self.assertRaises(ValidationError):validate_account({"firstName":"A\x00B"})
    def test_oversize_denied(self):
        with self.assertRaises(ValidationError):validate_account({"firstName":"A"*101})
    def test_invalid_json_denied(self):
        for data in (None,[],"name",{}):
            with self.assertRaises(ValidationError):validate_account(data)
    def test_public_user_does_not_leak_credentials(self):
        self.assertNotIn("credentials",public_user({"credentials":["secret"]}))
    def test_id_path_injection_denied(self):
        self.assertFalse(valid_id("../admin"))
        self.assertFalse(valid_id("-"*36))
        self.assertTrue(valid_id("12345678-1234-1234-1234-123456789abc"))

if __name__ == "__main__":unittest.main()
