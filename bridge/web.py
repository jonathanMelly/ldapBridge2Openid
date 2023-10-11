import logging
import os

from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from dotenv import load_dotenv


def web_auth(username, password):
    load_dotenv()
    options = Options()
    if os.getenv("detach", 'false').lower() == 'true':
        options.add_experimental_option("detach", True)

    if os.getenv("headless", 'true').lower() == 'true':
        options.add_argument('--headless')

    driver = webdriver.Chrome(options=options)
    driver.get(os.getenv("portal_url"))
    # html = driver.page_source

    field_username = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.XPATH, os.getenv("xusername"))))
    field_username.send_keys(username)

    button_submit = driver.find_element(By.XPATH, os.getenv("xsubmit1"))
    button_submit.click()

    field_password = WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((By.XPATH, os.getenv("xpassword"))))
    field_password.send_keys(password)

    login_url = driver.current_url

    button_submit = driver.find_element(By.XPATH, os.getenv("xsubmit2"))
    button_submit.click()

    landed_url = driver.current_url.lower()
    # if login success => go to microsoft portal o365, otherwise stays on eduvaud sts
    logging.log(logging.INFO, "Landed url for   " + username + ": " + landed_url)

    return landed_url != login_url and os.getenv("landed_url_pattern") in landed_url.lower()
