import unittest
import os
import logging

from web import web_auth
from dotenv import load_dotenv


class TestStringMethods(unittest.TestCase):

    def test_web_auth_denied(self):
        logging.basicConfig(level=logging.DEBUG)
        self.assertFalse(web_auth("bob@eduvaud.ch", "marely"))

    def test_web_auth_granted(self):
        logging.basicConfig(level=logging.DEBUG)
        load_dotenv()
        self.assertTrue(web_auth(os.getenv("ldap_user"), os.getenv("ldap_password")))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
