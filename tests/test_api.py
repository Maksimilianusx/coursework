"""HTTP/JWT component tests. Run inside the built API image (not a live cluster)."""
import time
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"api"))

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import app as application

class HttpJwtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    def setUp(self):
        self.client=application.app.test_client()
        self.signing=patch.object(application.jwks,"get_signing_key_from_jwt",return_value=SimpleNamespace(key=self.private.public_key()))
        self.signing.start()
        self.addCleanup(self.signing.stop)
    def token(self, role="viewer", overrides=None, key=None, remove=()):
        claims={"sub":"user-test","preferred_username":"test","iat":int(time.time()),"exp":int(time.time())+120,
                "iss":application.ISSUER,"aud":"account-api","realm_access":{"roles":[role]}}
        claims.update(overrides or {})
        for item in remove:claims.pop(item,None)
        return jwt.encode(claims,key or self.private,algorithm="RS256")
    def headers(self,**kwargs):return {"Authorization":"Bearer "+self.token(**kwargs)}
    def test_no_token_is_401(self):
        self.assertEqual(self.client.get("/api/me").status_code,401)
    def test_valid_viewer_reads_identity(self):
        response=self.client.get("/api/me",headers=self.headers())
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json["username"],"test")
        self.assertFalse(response.json["can_write"])
    def test_operator_identity_exposes_write_permission(self):
        response=self.client.get("/api/me",headers=self.headers(role="operator"))
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json["can_write"])
    def test_viewer_cannot_post_even_with_valid_signature(self):
        with patch.object(application,"connect") as db:
            response=self.client.post("/api/users",json={"username":"new.user"},headers=self.headers())
            self.assertEqual(response.status_code,403)
            db.assert_not_called()
    def test_expired_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers=self.headers(overrides={"exp":int(time.time())-5})).status_code,401)
    def test_wrong_issuer_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers=self.headers(overrides={"iss":"https://wrong.test"})).status_code,401)
    def test_wrong_audience_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers=self.headers(overrides={"aud":"different-api"})).status_code,401)
    def test_wrong_signature_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers=self.headers(key=self.other)).status_code,401)
    def test_no_exp_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers=self.headers(remove=("exp",))).status_code,401)
    def test_malformed_is_401(self):
        self.assertEqual(self.client.get("/api/me",headers={"Authorization":"Bearer broken"}).status_code,401)
    def test_unaccepted_algorithm_is_401(self):
        token=jwt.encode({"sub":"x"},"a-secret-that-is-long-enough-for-tests",algorithm="HS256")
        self.assertEqual(self.client.get("/api/me",headers={"Authorization":"Bearer "+token}).status_code,401)
    def test_operator_role_injection_is_400(self):
        response=self.client.post("/api/users",json={"username":"trial.user","realmRoles":["admin"]},headers=self.headers(role="operator"))
        self.assertEqual(response.status_code,400)
    def test_unmanaged_account_is_404(self):
        with patch.object(application,"service_token",return_value="dummy"), patch.object(application,"kc",return_value={"username":"admin"}):
            response=self.client.get("/api/users/12345678-1234-1234-1234-123456789abc",headers=self.headers())
            self.assertEqual(response.status_code,404)

if __name__=="__main__":unittest.main()
