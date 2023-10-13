import gc
import os
from unittest import TestCase

from bridge.cache import PersistentConcurrentCache

CACHE_NAME = "test"
CACHE_FILE = f'cache-{CACHE_NAME}.pickle'


def clean_cache_file():
    if os.path.isfile(CACHE_FILE):
        os.remove(CACHE_FILE)


class TestPersistentConcurrentCache(TestCase):

    def __int__(self):
        clean_cache_file()

    def __del__(self):
        clean_cache_file()

    def test_instance(self):
        cache = PersistentConcurrentCache(CACHE_NAME)
        self.assertIsInstance(cache, PersistentConcurrentCache)

    def test_put_get(self):
        cache = PersistentConcurrentCache(CACHE_NAME)
        cache["x"] = "y"
        self.assertEqual("y", cache["x"])

    def test_put_if_absent(self):
        cache = PersistentConcurrentCache()
        cache.put_if_absent("x", "y")
        self.assertEqual("y", cache["x"])

    def test_fs_backup(self):
        cache = PersistentConcurrentCache(CACHE_NAME)
        cache["x"] = "y"
        del cache
        self.assertTrue(os.path.isfile(CACHE_FILE))
        cache = PersistentConcurrentCache(CACHE_NAME)
        self.assertEqual("y", cache["x"])
