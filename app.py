import tldextract
from urllib.parse import urlsplit
import re
import ipaddress
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/submit", methods=["post"])

def submit():
    url = request.form["url"]
    result = analyse_Url(url)   
    flags = analyse_Phishing(url, result) 

    return render_template("index.html", url=url, flags=flags)

SUSPICIOUS_BRANDS = [
    "paypal", "amazon", "microsoft","apple", "google", "netflix", "bank"
]

SUSPICIOUS_SUFFIXES = ["tk", "ml", "ga", "cf", "gq", "xyz", "top"]

def analyse_Url(url):
    extract = tldextract.TLDExtract()
    split_url = urlsplit(url)
    result_valid = extract.extract_urllib(split_url)
    return result_valid

def check_brand(result):
    subdomain = result.subdomain.lower()
    domain = result.domain.lower()
    for brand in SUSPICIOUS_BRANDS:
        if brand in subdomain and brand != domain:
            return True
    return False

#this is to check the suffix of the url
def check_suspicious_suffix(result):
    return result.suffix.lower() in SUSPICIOUS_SUFFIXES

#this is to check excessive  subdomain
def check_subdomain(result):
    if not result.subdomain:
        return False
    return len(result.subdomain.split(".")) >= 3

#to check if its ip address instead of domain
def check_is_ip(result):
    try:
        ipaddress.ip_address(result.domain)
        return True
    except ValueError:
        return False

# to check for suspicious patterns
def check_hyphens(url):
    return url.count("-") >=3

def check_digit(url):
    return bool(re.search(r"[0-9]", url)) and any(b in url for b in SUSPICIOUS_BRANDS)

# to score the url
def analyse_Phishing(url, result):
    flags = []
    if check_brand(result):
        flags.append("Brand name found in subdomain")
    if check_suspicious_suffix(result):
        flags.append("Suspicious top-level domain")
    if check_subdomain(result):
        flags.append("Unusually deep subdomain")
    if check_is_ip(result):
        flags.append("URL uses raw IP address")
    if check_hyphens(url):
        flags.append("Excessive hyphens in URL")
    if check_digit(url):
        flags.append("Digits mixed with a brand name")
    return flags


if __name__ == "__main__":
    app.run(debug=True)