import logging
import os
import socketserver


import ldapserver
from bridge.proxy import do_auth


from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class RequestHandler(ldapserver.LDAPRequestHandler):

    def do_bind_simple_authenticated(self, dn, password):
        logger.info(f"BIND AUTH for dn: {dn}")
        do_auth(dn, password.decode())


if __name__ == '__main__':
    load_dotenv()
    loglevel = os.getenv("log", "INFO")
    logging.basicConfig(level=loglevel)
    logging.getLogger().setLevel(loglevel)

    socketserver.ThreadingTCPServer((os.getenv("listen", '127.0.0.1'), int(os.getenv("port", 3890))),
                                    RequestHandler).serve_forever()
