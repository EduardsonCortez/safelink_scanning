# app.py
import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import validators
import requests
import tldextract
import re
from urllib.parse import urlparse

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# Load Google Safe Browsing API key from environment variable (do NOT hardcode your key)
GSB_API_KEY = os.getenv("GSB_API_KEY")  # set this in your Render or hosting env vars if you use Google API

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "confirm", "update", "password",
    "signin", "banking", "redirect", "free-gift", "claim", "reward"
]

def is_private_host(hostname):
    if not hostname:
        return True
    # basic checks for local / private ranges + ipv6 loopback
    private_prefixes = ("localhost", "127.", "10.", "192.168.", "172.", "::1")
    if hostname.startswith(private_prefixes):
        return True
    # If hostname is an IP-like value with private ranges, treat as private (basic)
    return False

def simple_checks(url):
    result = {"issues": [], "score": 0}

    # valid url?
    if not validators.url(url):
        result["issues"].append("Invalid URL format")
        result["score"] += 50
        return result

    # SSRF / private host prevention (basic)
    try:
        host = urlparse(url).hostname or ""
        if is_private_host(host):
            result["issues"].append("URL points to a private or local address (blocked).")
            result["score"] += 50
            return result
    except Exception:
        result["issues"].append("Could not parse host (treat as suspicious).")
        result["score"] += 20

    # scheme check
    if not url.lower().startswith("https://"):
        result["issues"].append("Not using HTTPS")
        result["score"] += 10

    # contains @ (often used to obfuscate)
    if "@" in url:
        result["issues"].append("Contains '@' character (suspicious)")
        result["score"] += 20

    # suspicious keywords in path or domain
    parsed = tldextract.extract(url)
    domain = parsed.domain + (("." + parsed.suffix) if parsed.suffix else "")
    lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            result["issues"].append(f"Contains suspicious keyword: '{kw}'")
            result["score"] += 10

    # IP address instead of domain?
    if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url):
        result["issues"].append("URL uses raw IP address")
        result["score"] += 15

    # very long URL
    if len(url) > 200:
        result["issues"].append("Extremely long URL (common in obfuscated links)")
        result["score"] += 10

    # check redirects (follow HEAD to count redirects)
    try:
        resp = requests.head(url, allow_redirects=True, timeout=6)
        chain_len = len(resp.history)
        if chain_len >= 3:
            result["issues"].append(f"Multiple redirects detected ({chain_len})")
            result["score"] += 10
        # final URL mismatch domain (shorteners redirect)
        final = resp.url
        final_parsed = tldextract.extract(final)
        final_domain = final_parsed.domain + (("." + final_parsed.suffix) if final_parsed.suffix else "")
        if final_domain != domain:
            result["issues"].append(f"Final destination domain differs: {final_domain}")
            result["score"] += 15
    except Exception:
        # sometimes HEAD blocked, try GET lightly
        try:
            resp = requests.get(url, allow_redirects=True, timeout=6)
            chain_len = len(resp.history)
            if chain_len >= 3:
                result["issues"].append(f"Multiple redirects detected ({chain_len})")
                result["score"] += 10
            final = resp.url
            final_parsed = tldextract.extract(final)
            final_domain = final_parsed.domain + (("." + final_parsed.suffix) if final_parsed.suffix else "")
            if final_domain != domain:
                result["issues"].append(f"Final destination domain differs: {final_domain}")
                result["score"] += 15
        except Exception:
            # network issues — we can't reach the URL, mark as uncertain
            result["issues"].append("Could not fetch URL (network or blocked). Manual caution advised.")
            result["score"] += 10

    return result

def interpret_score(score):
    if score >= 50:
        return "danger", "High risk — likely malicious"
    if score >= 25:
        return "suspicious", "Suspicious — be careful"
    return "safe", "Looks probably safe"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    checks = simple_checks(url)

    # Optional: Google Safe Browsing integration (if GSB_API_KEY present)
    # NOTE: Do not hardcode API keys in repo. Set GSB_API_KEY as environment variable.
    if GSB_API_KEY:
        try:
            gsb_payload = {
                "client": {"clientId": "safelink-scanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
            r = requests.post(gsb_url, json=gsb_payload, timeout=6)
            if r.ok and r.json():
                checks["issues"].append("Google Safe Browsing flagged this URL")
                checks["score"] += 50
        except Exception:
            # ignore GSB failures but note uncertainty
            checks["issues"].append("Safe Browsing lookup failed or timed out (ignored).")
            checks["score"] += 5

    status, message = interpret_score(checks["score"])
    return jsonify({
        "status": status,
        "message": message,
        "score": checks["score"],
        "issues": checks["issues"],
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
