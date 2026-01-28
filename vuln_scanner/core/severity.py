def score_headers(headers):
    scores = {}
    for header in headers:
        if header == "Content-Security-Policy":
            scores[header] = 6.5
        elif header == "Strict-Transport-Security":
            scores[header] = 6.0
        else:
            scores[header] = 4.0
    return scores


def score_sensitive_files(files):
    return {path: 8.0 for path in files}


def score_ports(ports):
    return {port: 2.0 for port in ports}


def severity_label(score):
    if score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"
