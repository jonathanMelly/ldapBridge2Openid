import logging
import os
import platform
import shelve
import bcrypt
import cachetools
import pickle
import binascii

from selenium.common import TimeoutException
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from dotenv import load_dotenv

logger = logging.getLogger()

CACHE_FILE = "cache.pickle"


def web_auth(username, password):
    load_dotenv()

    logger.debug(f"WEB auth request for {username}")

    salt = bytes.fromhex(os.getenv("salt", "2432622431322467316a566377314a35386e5336472e5a507270514a2e"))

    hashed_username = bcrypt.hashpw(bytes(username, 'UTF-8'), salt).hex()
    hashed_password = bcrypt.hashpw(bytes(password, 'UTF-8'), salt).hex()

    if os.path.isfile(CACHE_FILE):
        cache = pickle.load(open(CACHE_FILE, "rb"))
        logger.debug(f"Cache loaded")
    else:
        logger.debug(f"Cache initialized")
        cache = cachetools.TTLCache(maxsize=2345, ttl=60 * 60 * 12)

    cached_entry = cache.get(hashed_username)
    if cached_entry is not None and cached_entry == hashed_password:
        logger.debug(f"Valid from cache")
        return True

    options = Options()
    options.add_argument("--incognito")

    # from https://intoli.com/blog/making-chrome-headless-undetectable/
    user_agent = os.getenv("ua", None)
    if user_agent is not None:
        options.add_argument(f'user-agent={user_agent}')

    if os.getenv("detach", 'false').lower() == 'true':
        options.add_experimental_option("detach", True)

    if os.getenv("headless", 'true').lower() == 'true':
        options.add_argument('--headless')

    driver = webdriver.Chrome(options=options)
    logger.debug(f"WebDriver started {driver}")
    # driver.implicitly_wait(int(os.getenv("wait", 5)))

    url = os.getenv("portal_url")
    logger.debug(f"Loading URL {url}")
    driver.get(url)
    logger.debug(f"Loading URL {url} DONE")
    # html = driver.page_source

    ttl = int(os.getenv("ttl", 10))

    # Global ms User part
    xusername = os.getenv("xusername")
    logger.debug(f"waiting for username field {xusername}")
    field_username = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xusername)))
    logger.debug("->DONE")

    logger.debug(f"filling {field_username}")
    field_username.send_keys(username)
    logger.debug("->DONE")

    xsubmit1 = os.getenv("xsubmit1")
    logger.debug(f"waiting for submit {xsubmit1}")
    button_submit = driver.find_element(By.XPATH, xsubmit1)
    logger.debug("->DONE")

    logger.debug(f"clicking on {button_submit}")
    button_submit.click()
    logger.debug("->DONE")

    # Custom portal

    # stores original url
    login_url = driver.current_url

    xpassword = os.getenv("xpassword")
    logger.debug(f"waiting for password field {xpassword}")
    field_password = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xpassword)))
    logger.debug(f"filling {xpassword}")
    field_password.send_keys(password)
    logger.debug("->DONE")

    xsubmit2 = os.getenv("xsubmit2")
    logger.debug(f"waiting for {xsubmit2}")
    button_submit = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xsubmit2)))
    logger.debug("->DONE")

    logger.debug(f"clicking on {button_submit}")
    button_submit.click()
    logger.debug("->DONE")

    xlanded = os.getenv("xlanded", None)
    if xlanded is not None:
        try:
            logger.debug(f"waiting for {xlanded}")
            WebDriverWait(driver, ttl).until(EC.presence_of_element_located((By.XPATH, xlanded)))
            logger.debug("->DONE")
        except TimeoutException:
            logger.debug("->TIMEOUT")
            logger.debug(f"cannot find {xlanded} in {driver.page_source}")
            return False

    landed_url = driver.current_url.lower()
    # if login success => go to microsoft portal o365, otherwise stays on eduvaud sts
    logger.debug(f"Landed url: {landed_url}")

    granted = landed_url != login_url and os.getenv("landed_url_pattern") in landed_url.lower()

    logger.debug("user granted")

    cache[hashed_username] = hashed_password
    pickle.dump(cache, open(CACHE_FILE, "wb"))

    return granted
