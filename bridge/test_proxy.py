import unittest

from bridge.proxy import LdapProxy
from bridge.web import WebAuthenticator
from ldapserver import exceptions
from unittest import mock


class MyTestCase(unittest.TestCase):
    def test_cache(self):
        # Given
        authenticator = WebAuthenticator()
        mock_authenticator = mock.Mock()
        authenticator.do_web_auth = mock_authenticator
        mock_authenticator.return_value = True
        proxy = LdapProxy(authenticator)
        proxy.cache.clear()
        self.assertEqual(0, len(proxy.cache))

        # When
        proxy.do_auth("bob@eduvaud.ch", "password")

        # Then
        self.assertEqual(1, len(proxy.cache))

    def test_no_eduvaud(self):
        try:
            LdapProxy().do_auth("bob@gmail.ch", "password")
            self.fail()
        except exceptions.LDAPInvalidCredentials:
            pass


if __name__ == '__main__':
    unittest.main()
