import logging
import os
import pickle
import threading
from typing import Union

import cachetools


class PersistentConcurrentCache:
    DEFAULT_CACHE_TTL = 12  # in hours

    def __init__(self, name: str = None, persist: bool = True, ttl: int = 60 * 60 * DEFAULT_CACHE_TTL):
        self._logger = logging.getLogger(self.__class__.__qualname__)
        self._persist = persist
        self._ttl = ttl
        if name is None and persist is True:
            self._logger.warning("No name given for persistent logger, generating a random one")
            name = os.urandom(10).hex()
        self.name = name
        self.filename = f'cache-{name}.pickle'
        self._cache = None  # type: Union[None, cachetools.TTLCache]
        self._lock = threading.RLock()

        self._init_cache()

    def __del__(self):
        if self._persist:
            self.save_to_disk()

    def save_to_disk(self):
        try:
            with open(self.filename, "wb") as fs:
                pickle.dump(self._cache, fs)
            self._logger.debug(f"cache dumped to {self.filename}")
        except (pickle.PickleError, OSError) as error:
            self._logger.warning(f"Cannot persist cache to {self.filename}, error:{error}")

    def _init_cache(self):
        if self._persist and os.path.isfile(self.filename):
            try:
                with open(self.filename, "rb") as fs:
                    self._cache = pickle.load(fs)
                self._logger.debug(f"Cache loaded from {self.filename} with {self._cache.currsize} entries")
            except OSError:
                pass
        else:
            self._logger.debug(f"Initializing cache")
            self._cache = cachetools.TTLCache(maxsize=2345, ttl=self._ttl)
            self._logger.debug(f"->DONE")

    def exists(self, key):
        with self._lock:
            return self._cache.get(key) is not None

    def put_if_absent(self, key, value):
        with self._lock:
            if not self.exists(key):
                self[key] = value
                return value
            return None

    def __setitem__(self, key, value):
        with self._lock:
            self._cache[key] = value
            pass

    def __getitem__(self, item):
        with self._lock:
            return self._cache[item]

    def __len__(self):
        with self._lock:
            return self._cache.currsize

    def clear(self):
        with self._lock:
            return self._cache.clear()
