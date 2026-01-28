import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing CSP allows XSS attacks",
    "X-Frame-Options": "Missing XFO allows clickjacking",
    "Strict-Transport-Security": "Missing HSTS allows downgrade attacks",
    "X-Content-Type-Options": "Missing X-Content-Type-Options allows MIME sniffing",
    "Referrer-Policy": "Missing Referrer-Policy may leak sensitive data",
    "Permissions-Policy": "Missing Permissions-Policy allows browser feature abuse"
}


def check_security_headers(url, auth_headers=None):
    """
    Checks for missing HTTP security headers.

    :param url: Base URL (e.g., http://example.com)
    :param auth_headers: Optional authentication headers dict
    :return: dict of missing headers with explanations
    """
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers=auth_headers or {}
        )

        response_headers = response.headers
        missing_headers = {}

        for header, description in SECURITY_HEADERS.items():
            if header not in response_headers:
                missing_headers[header] = description

        return missing_headers

    except requests.RequestException as e:
        return {
            "Error": f"Request failed: {str(e)}"
        }
