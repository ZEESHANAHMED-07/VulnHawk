import os


def get_auth_headers():
    """
    Returns authentication headers if provided via environment variables.
    """
    headers = {}

    token = os.getenv("VULNHAWK_AUTH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    custom_header = os.getenv("VULNHAWK_CUSTOM_HEADER")
    custom_value = os.getenv("VULNHAWK_CUSTOM_VALUE")
    if custom_header and custom_value:
        headers[custom_header] = custom_value

    return headers
