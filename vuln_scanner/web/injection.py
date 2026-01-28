import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlstate",
    "sqlite error"
]

XSS_PAYLOAD = "<vulnhawk>"


def _inject_param(url, param, payload):
    """
    Helper: inject payload into a single query parameter.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if param not in params:
        return None

    params[param] = payload
    new_query = urlencode(params, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def scan_injections(url, auth_headers=None):
    """
    Performs safe injection detection:
    - SQLi (error-based)
    - XSS (reflection-based)
    """
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings  # no query params → nothing to test

    for param in params:
        # -------------------
        # SQL Injection Test
        # -------------------
        sqli_url = _inject_param(url, param, "'")
        if not sqli_url:
            continue

        try:
            r = requests.get(
                sqli_url,
                timeout=5,
                headers=auth_headers or {}
            )
            body = r.text.lower()

            for error in SQL_ERRORS:
                if error in body:
                    findings.append({
                        "type": "SQL Injection",
                        "parameter": param,
                        "evidence": error,
                        "severity": "HIGH"
                    })
                    break

        except requests.RequestException:
            pass

        # -------------------
        # XSS Reflection Test
        # -------------------
        xss_url = _inject_param(url, param, XSS_PAYLOAD)
        if not xss_url:
            continue

        try:
            r = requests.get(
                xss_url,
                timeout=5,
                headers=auth_headers or {}
            )

            if XSS_PAYLOAD in r.text:
                findings.append({
                    "type": "Reflected XSS",
                    "parameter": param,
                    "evidence": XSS_PAYLOAD,
                    "severity": "MEDIUM"
                })

        except requests.RequestException:
            pass

    return findings
