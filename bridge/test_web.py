import unittest
import os

from web import web_auth
from dotenv import load_dotenv


class TestStringMethods(unittest.TestCase):

    def test_web_auth_denied(self):
        self.assertFalse(web_auth("bob@eduvaud.ch", "marely"))

    def test_web_auth_granted(self):
        load_dotenv()
        self.assertTrue(web_auth(os.getenv("ldap_user"), os.getenv("ldap_password")))


if __name__ == '__main__':
    unittest.main()
