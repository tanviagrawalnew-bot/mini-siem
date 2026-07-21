import re

IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
EMAIL_REGEX = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
URL_REGEX = r'https?://[^\s]+'
DOMAIN_REGEX = r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b'
MD5_REGEX = r'\b[a-fA-F0-9]{32}\b'
SHA1_REGEX = r'\b[a-fA-F0-9]{40}\b'
SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'


def extract_iocs(logs):

    iocs = {
        "ips": set(),
        "emails": set(),
        "urls": set(),
        "domains": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set()
    }

    for log in logs:

        message = log.get("message", "")

        for ip in re.findall(IP_REGEX, message):
            iocs["ips"].add(ip)

        for email in re.findall(EMAIL_REGEX, message):
            iocs["emails"].add(email)

        for url in re.findall(URL_REGEX, message):
            iocs["urls"].add(url)

        for domain in re.findall(DOMAIN_REGEX, message):
            iocs["domains"].add(domain)

        for md5 in re.findall(MD5_REGEX, message):
            iocs["md5"].add(md5)

        for sha1 in re.findall(SHA1_REGEX, message):
            iocs["sha1"].add(sha1)

        for sha256 in re.findall(SHA256_REGEX, message):
            iocs["sha256"].add(sha256)

    return {
        key: sorted(list(value))
        for key, value in iocs.items()
    }