import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing CSP allows XSS attacks",
    "X-Frame-Options": "Missing XFO allows clickjacking",
    "Strict-Transport-Security": "Missing HSTS allows downgrade attacks",
    "X-Content-Type-Options": "Missing X-Content-Type-Options allows MIME sniffing",
    "Referrer-Policy": "Missing Referrer-Policy may leak sensitive data",
    "Permissions-Policy": "Missing Permissions-Policy allows browser feature abuse"
}

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        missing = {}
        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                missing[header] = description

        return missing

    except requests.RequestException:
        return {"Error": "Could not connect to target"}
