import unittest
from project1 import app as project1
import unittest
import json


class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = project1.test_client()

    def test_connect(self):
        response = self.app.get('/') #test if server is connected
        self.assertEqual(response.status_code, 200)

    def test_auth(self):
        response = self.app.post('/auth') #test if /auth is working
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data)

    def test_auth_expired(self):
        response = self.app.post('/auth?expired=true') #test of the expiration
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data)

    def test_jwks(self):
        response = self.app.get('/.well-known/jwks.json') #test for jwks
        self.assertEqual(response.status_code, 200)
        jwks = json.loads(response.data)

if __name__ == '__main__':
    unittest.main()
