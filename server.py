import logging
import os
import socketserver
import traceback

import ldapserver
from bridge.web import web_auth
from ldapserver import exceptions

from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)


class RequestHandler(ldapserver.LDAPRequestHandler):

    def do_bind_simple_authenticated(self, dn, password):

        try:
            decoded_password = password.decode()
            logging.log(logging.INFO, "Log attempt: " + dn)

            valid = web_auth(dn, decoded_password)
        except Exception:
            traceback.print_exc()
            raise exceptions.LDAPError

        if not valid:
            raise exceptions.LDAPInvalidCredentials


if __name__ == '__main__':
    load_dotenv()
    loglevel = os.getenv("log","INFO")
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)
    socketserver.ThreadingTCPServer((os.getenv("listen", '127.0.0.1'), int(os.getenv("port", 3890))),
                                    RequestHandler).serve_forever()
