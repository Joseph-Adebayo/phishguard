# PhishGuard

A Flask web app that checks a URL for common signs of phishing. It breaks the URL into its parts and tests each one against a set of rules.

## What it checks

- **Brand name in the subdomain**, e.g. `paypal.secure-login.example.tk`, where the real domain isn't PayPal
- **Suspicious top-level domains** often used in scams (`.tk`, `.xyz`, `.top`, ...)
- **Unusually deep subdomains**
- **Raw IP addresses** instead of a domain name
- **Excessive hyphens**
- **Digits mixed with a brand name**, e.g. `paypal123`

It uses [tldextract](https://github.com/john-kurkowski/tldextract) to split the URL into subdomain, domain and suffix.

## Run it

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

## Limitations

This is rule-based, so it only catches patterns I've written checks for. A clean result doesn't mean a link is safe.

Possible improvements: lookalike characters (e.g. `rn` vs `m`) and domain age checks.
