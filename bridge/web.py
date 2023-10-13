import logging
import os

from dotenv import load_dotenv
from selenium import webdriver
from selenium.common import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait


class WebAuthenticator:
    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__qualname__)

    def do_web_auth(self, username, password):
        load_dotenv()

        self._logger.debug(f"starting WEB auth request for {username}")

        options = Options()
        options.add_argument("--incognito")

        # Not needed as using xvfb...
        # from https://intoli.com/blog/making-chrome-headless-undetectable/
        user_agent = os.getenv("ua", None)
        if user_agent is not None:
            options.add_argument(f'user-agent={user_agent}')

        if os.getenv("detach", 'false').lower() == 'true':
            options.add_experimental_option("detach", True)

        if os.getenv("headless", 'true').lower() == 'true':
            options.add_argument('--headless')

        driver = webdriver.Chrome(options=options)
        self._logger.debug(f"WebDriver started {driver}")
        # driver.implicitly_wait(int(os.getenv("wait", 5)))

        url = os.getenv("portal_url")
        self._logger.debug(f"Loading URL {url}")
        driver.get(url)
        self._logger.debug(f"Loading URL {url} DONE")
        # html = driver.page_source

        xttl = int(os.getenv("xttl", 10))

        # Global ms User part
        xusername = os.getenv("xusername")
        self._logger.debug(f"waiting for username field {xusername}")
        field_username = WebDriverWait(driver, xttl).until(
            EC.presence_of_element_located((By.XPATH, xusername)))
        self._logger.debug("->DONE")

        self._logger.debug(f"filling {field_username}")
        field_username.send_keys(username)
        self._logger.debug("->DONE")

        xsubmit1 = os.getenv("xsubmit1")
        self._logger.debug(f"waiting for submit {xsubmit1}")
        button_submit = driver.find_element(By.XPATH, xsubmit1)
        self._logger.debug("->DONE")

        self._logger.debug(f"clicking on {button_submit}")
        button_submit.click()
        self._logger.debug("->DONE")

        # Custom portal

        # stores original url
        login_url = driver.current_url

        xpassword = os.getenv("xpassword")
        self._logger.debug(f"waiting for password field {xpassword}")
        field_password = WebDriverWait(driver, xttl).until(
            EC.presence_of_element_located((By.XPATH, xpassword)))
        self._logger.debug(f"filling {xpassword}")
        field_password.send_keys(password)
        self._logger.debug("->DONE")

        xsubmit2 = os.getenv("xsubmit2")
        self._logger.debug(f"waiting for {xsubmit2}")
        button_submit = WebDriverWait(driver, xttl).until(
            EC.presence_of_element_located((By.XPATH, xsubmit2)))
        self._logger.debug("->DONE")

        self._logger.debug(f"clicking on {button_submit}")
        button_submit.click()
        self._logger.debug("->DONE")

        xlanded = os.getenv("xlanded", None)
        if xlanded is not None:
            try:
                self._logger.debug(f"waiting for {xlanded}")
                WebDriverWait(driver, xttl).until(EC.presence_of_element_located((By.XPATH, xlanded)))
                self._logger.debug("->DONE")
            except TimeoutException:
                self._logger.debug("->TIMEOUT")
                self._logger.debug(f"cannot find {xlanded} in {driver.page_source}")
                return False

        landed_url = driver.current_url.lower()
        # if login success => go to microsoft portal o365, otherwise stays on eduvaud sts
        self._logger.debug(f"Landed url: {landed_url}")

        granted = landed_url != login_url and os.getenv("landed_url_pattern") in landed_url.lower()

        self._logger.debug("user granted")

        return granted
