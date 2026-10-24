from flask import Flask, render_template, request
from urllib.parse import urlparse, urljoin
import ipaddress
import socket
import requests

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 3
USER_AGENT = "SecureScan-Portfolio/1.0 (non-intrusive security-header checker)"

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "weight": 20,
        "description": "Helps control which sources browsers may load content from.",
        "recommendation": "Define a Content-Security-Policy suited to your application."
    },
    "Strict-Transport-Security": {
        "weight": 20,
        "description": "Tells browsers to use HTTPS for future visits.",
        "recommendation": "Configure HSTS after confirming HTTPS works across the site."
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "weight": 10,
        "description": "Can help reduce clickjacking risk.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a policy such as strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "weight": 10,
        "description": "Restricts access to selected browser features.",
        "recommendation": "Set a Permissions-Policy appropriate for your application's features."
    },
}

def validate_public_url(url):
    """Accept only public HTTP(S) URLs and reject private/reserved destinations."""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Only http:// and https:// URLs are supported."
        if not parsed.hostname or parsed.username or parsed.password:
            return None, "Enter a valid URL without embedded credentials."
        if parsed.port and not (1 <= parsed.port <= 65535):
            return None, "The URL contains an invalid port."

        host = parsed.hostname.rstrip(".")
        if host.lower() == "localhost":
            return None, "Localhost and private network targets are not allowed."

        try:
            literal_ip = ipaddress.ip_address(host)
            addresses = [literal_ip]
        except ValueError:
            try:
                results = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                             type=socket.SOCK_STREAM)
                addresses = [ipaddress.ip_address(item[4][0]) for item in results]
            except (socket.gaierror, ValueError):
                return None, "The hostname could not be resolved."

        if not addresses:
            return None, "The hostname did not resolve to an address."
        if any(not addr.is_global for addr in addresses):
            return None, "Private, loopback, link-local, and reserved IP destinations are blocked."

        # Remove fragments; they are not sent to the server.
        normalized = parsed._replace(fragment="").geturl()
        return normalized, None
    except ValueError:
        return None, "Enter a valid URL, including its scheme (https://)."


def fetch_limited(url):
    """Make a small number of non-intrusive requests; validate every redirect target."""
    current = url
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            safe_url, error = validate_public_url(current)
            if error:
                return None, error
            try:
                response = session.get(
                    safe_url,
                    timeout=TIMEOUT_SECONDS,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                return None, f"Connection failed: {type(exc).__name__}."
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return None, "The server returned a redirect without a Location header."
                if redirect_count >= MAX_REDIRECTS:
                    return None, "Too many redirects; scan stopped."
                current = urljoin(safe_url, location)
                continue
            return response, None
        return None, "Redirect limit reached."
    finally:
        session.close()


def build_report(url, response):
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings = []
    possible = 0
    earned = 0

    is_https = urlparse(url).scheme.lower() == "https"
    findings.append({
        "name": "HTTPS",
        "status": "pass" if is_https else "warn",
        "detail": "The supplied URL uses HTTPS." if is_https else "The supplied URL uses HTTP, so transport is not encrypted.",
        "recommendation": "Prefer HTTPS for the entire site and redirect HTTP to HTTPS."
    })

    for header, info in SECURITY_HEADERS.items():
        possible += info["weight"]
        present = header.lower() in headers and bool(headers[header.lower()].strip())
        if present:
            earned += info["weight"]
        findings.append({
            "name": header,
            "status": "pass" if present else "warn",
            "detail": info["description"] if present else f"{header} was not present in the response.",
            "recommendation": "Header detected; review its value for suitability." if present else info["recommendation"]
        })

    cookie_values = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    cookie_details = []
    for cookie in cookie_values:
        low = cookie.lower()
        missing = []
        if is_https and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        cookie_details.append({"cookie": cookie.split("=", 1)[0][:80], "missing": missing})

    if cookie_details:
        cookie_missing = any(item["missing"] for item in cookie_details)
        findings.append({
            "name": "Cookie attributes",
            "status": "warn" if cookie_missing else "pass",
            "detail": f"Inspected {len(cookie_details)} Set-Cookie header(s).",
            "recommendation": "Review each cookie and add appropriate Secure, HttpOnly, and SameSite attributes where applicable."
        })
    else:
        findings.append({
            "name": "Cookie attributes",
            "status": "info",
            "detail": "No Set-Cookie headers were observed in this response.",
            "recommendation": "If the site uses cookies on other routes, review those routes separately."
        })

    score = round(100 * earned / possible) if possible else 0
    return {
        "url": url,
        "status_code": response.status_code,
        "final_url": response.url,
        "server": response.headers.get("Server", "Not disclosed"),
        "score": score,
        "findings": findings,
        "cookies": cookie_details,
        "note": "This is a lightweight, non-intrusive check of one response—not a penetration test or guarantee that the site is secure."
    }


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    submitted_url = ""
    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        if len(submitted_url) > 2048:
            error = "URL is too long. Please enter a shorter URL."
        else:
            safe_url, error = validate_public_url(submitted_url)
            if not error:
                response, error = fetch_limited(safe_url)
                if response is not None:
                    try:
                        report = build_report(safe_url, response)
                    finally:
                        response.close()
    return render_template("index.html", report=report, error=error, submitted_url=submitted_url)


if __name__ == "__main__":
    # Debug is intentionally disabled by default.
    app.run(host="127.0.0.1", port=5000, debug=False)
