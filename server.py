import logging
import os
import socketserver
import traceback

import ldapserver
from bridge.web import web_auth
from ldapserver import exceptions

logging.basicConfig(level=logging.INFO)


class RequestHandler(ldapserver.LDAPRequestHandler):

    def do_bind_simple_authenticated(self, dn, password):

        try:
            decoded_password = password.decode()
            logging.log(logging.INFO, "Log attempt: " + dn)

            valid = web_auth(dn, decoded_password)

            if not valid:
                raise exceptions.LDAPInvalidCredentials

        except Exception:
            traceback.print_exc()
            raise exceptions.LDAPError


if __name__ == '__main__':
    socketserver.ThreadingTCPServer((os.getenv("listen", '127.0.0.1'), os.getenv("port", 3890)),
                                    RequestHandler).serve_forever()
