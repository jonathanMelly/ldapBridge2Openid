import logging
import traceback
import os

import bcrypt
from dotenv import load_dotenv

from bridge.cache import PersistentConcurrentCache
from bridge.web import WebAuthenticator
from ldapserver import exceptions


class LdapProxy:
    def __init__(self, delegate_authenticator: WebAuthenticator = WebAuthenticator()):
        self._authenticator = delegate_authenticator
        self._logger = logging.getLogger()
        load_dotenv()

        ttl = PersistentConcurrentCache.DEFAULT_CACHE_TTL * 60 * 60
        env_ttl = os.getenv("cache_ttl")
        if env_ttl is not None:
            try:
                ttl = int(env_ttl)*60*60
            except ValueError:
                self._logger.warning(f"Bad value for cache_ttl{env_ttl}, "
                                     f"using defaults {PersistentConcurrentCache.DEFAULT_CACHE_TTL}")
        self.cache = PersistentConcurrentCache("bridge", ttl)

    def do_auth(self, username: str, password: str):

        if not username.endswith("@eduvaud.ch"):
            self._logger.warning(f"bad username:{username}")
            raise exceptions.LDAPInvalidCredentials

        try:
            salt = bytes.fromhex(os.getenv("salt", "2432622431322467316a566377314a35386e5336472e5a507270514a2e"))

            hashed_username = bcrypt.hashpw(bytes(username, 'UTF-8'), salt).hex()
            hashed_password = bcrypt.hashpw(bytes(password, 'UTF-8'), salt).hex()

            if self.cache.exists(hashed_username) and self.cache[hashed_username] == hashed_password:
                self._logger.debug(f"Found valid entry in self.__cache -> GRANTED")
                return
            else:
                granted = self._authenticator.do_web_auth(password, username)
                if granted:
                    self._logger.debug("Caching entry")
                    self.cache[hashed_username] = hashed_password
                    self._logger.debug("->DONE")
                    return

        except Exception:
            traceback.print_exc()
            raise exceptions.LDAPError

        if not granted:
            raise exceptions.LDAPInvalidCredentials
