https://portswigger.net/web-security/cross-site-scripting

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Allows an attacker to masquerade as a victim user and perform actions on their behalf. Works by injecting malicious scripts into a website that execute in the victim's browser.

To test for XSS, inject the JavaScript `alert()` or `print()` function to see if they execute. If yes, then XSS is possible.

![warning](https://github.githubassets.com/images/icons/emoji/unicode/26a0.png) Note that `print()` is now preferable as some browsers are disabling `alert()`.

## types of XSS attacks

- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting), where the malicious script comes from the current HTTP request.
- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting), where the malicious script comes from the website's database.
- [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code.

