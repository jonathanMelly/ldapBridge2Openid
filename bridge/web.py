import logging
import os
import shelve

from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from dotenv import load_dotenv


def web_auth(username, password):
    logging.log(logging.DEBUG, f"WEB auth request for {username}")

    cache = shelve.open("cache")
    logging.log(logging.DEBUG, f"Cache loaded: {cache}")
    cache.close()

    load_dotenv()

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
    logging.log(logging.DEBUG, f"WebDriver started {driver}")
    #driver.implicitly_wait(int(os.getenv("wait", 5)))

    url = os.getenv("portal_url")
    logging.log(logging.DEBUG, f"Loading URL {url}")
    driver.get(url)
    logging.log(logging.DEBUG, f"Loading URL {url} DONE")
    # html = driver.page_source

    ttl = int(os.getenv("ttl", 30))

    # Global ms User part
    xusername = os.getenv("xusername")
    logging.log(logging.DEBUG, f"waiting for username field {xusername}")
    field_username = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xusername)))
    logging.log(logging.DEBUG, "->DONE")

    logging.log(logging.DEBUG, f"filling {field_username}")
    field_username.send_keys(username)
    logging.log(logging.DEBUG, "->DONE")

    xsubmit1 = os.getenv("xsubmit1")
    logging.log(logging.DEBUG, f"waiting for submit {xsubmit1}")
    button_submit = driver.find_element(By.XPATH, xsubmit1)
    logging.log(logging.DEBUG, "->DONE")

    logging.log(logging.DEBUG, f"clicking on {button_submit}")
    button_submit.click()
    logging.log(logging.DEBUG, "->DONE")

    # Custom portal

    # stores original url
    login_url = driver.current_url

    xpassword = os.getenv("xpassword")
    logging.log(logging.DEBUG, f"waiting for password field {xpassword}")
    field_password = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xpassword)))
    logging.log(logging.DEBUG, f"filling {xpassword}")
    field_password.send_keys(password)
    logging.log(logging.DEBUG, "->DONE")

    xsubmit2=os.getenv("xsubmit2")
    logging.log(logging.DEBUG, f"waiting for {xsubmit2}")
    button_submit = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH, xsubmit2)))
    logging.log(logging.DEBUG, "->DONE")

    logging.log(logging.DEBUG, f"clicking on {button_submit}")
    button_submit.click()
    logging.log(logging.DEBUG, "->DONE")

    xlogout = os.getenv("xlogout")
    logging.log(logging.DEBUG, f"waiting for {xlogout}")
    logout = WebDriverWait(driver, ttl).until(
        EC.presence_of_element_located((By.XPATH,xlogout )))
    logging.log(logging.DEBUG, "->DONE")

    landed_url = driver.current_url.lower()
    # if login success => go to microsoft portal o365, otherwise stays on eduvaud sts
    logging.log(logging.DEBUG, f"Landed url for   {username}: {landed_url}")

    logging.log(logging.DEBUG, f"clicking on {logout}")
    logout.click()
    logging.log(logging.DEBUG, "->DONE")

    return landed_url != login_url and os.getenv("landed_url_pattern") in landed_url.lower()
