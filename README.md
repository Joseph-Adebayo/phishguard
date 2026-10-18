# PhishGuard

A Flask web app that checks a link for signs of phishing.

## What it checks

- Brand names in the subdomain (e.g. `paypal.secure-login.example.tk`)
- Endings often used in scams (`.tk`, `.xyz`, `.top` and others)
- Too many subdomains
- An IP address instead of a domain name
- Lots of hyphens
- Numbers next to a brand name (e.g. `paypal123`)

It uses [tldextract](https://github.com/john-kurkowski/tldextract) to split the URL into subdomain, domain and suffix.

## How to run

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then go to http://127.0.0.1:5000.

## Limitations

It only catches the patterns it has checks for, so a link with no red flags isn't guaranteed to be safe.
