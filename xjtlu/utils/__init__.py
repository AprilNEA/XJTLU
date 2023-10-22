from urllib.parse import urlparse, parse_qs


def get_ua() -> str:
    from fake_useragent import UserAgent
    ua = UserAgent(browsers=['edge', 'chrome'])
    return ua.random


def parse_code(url: str) -> str:
    code = parse_qs(urlparse(url).query).get("code")
    if not code:
        raise
    return code[0]
