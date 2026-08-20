import base64
import hashlib
import logging
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import requests
import rsa


CHECK_INTERVAL_SEC = 30  # Interval between connectivity checks (seconds)
FAILURE_THRESHOLD = 5  # Number of consecutive failures before restarting (5 x 30s = 2.5 min)
COOLDOWN_AFTER_RESTART_SEC = 600  # Wait time before resuming checks after a restart
MAX_RESTARTS_PER_DAY = 5  # Max restarts per day (prevents infinite loop during ISP-side outages)
PING_TARGETS = ["8.8.8.8", "1.1.1.1"]

_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV
7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb
1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9
hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc
fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb
GH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w
nwIDAQAB
-----END PUBLIC KEY-----"""

PUB_KEY = rsa.PublicKey.load_pkcs1_openssl_pem(_PUBLIC_KEY_PEM.encode())

logger = logging.getLogger(__name__)



def setup_logger(log_file: str):
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    _console = logging.StreamHandler()
    _console.setLevel(logging.DEBUG)
    logger.addHandler(_console)


def check_internet() -> bool:
    """Check ping connectivity to 8.8.8.8 / 1.1.1.1. Considered healthy if either one succeeds."""
    for target in PING_TARGETS:
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "3", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                logger.info(f"Ping successed. target: {target}")
                return True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Ping execution error ({target}): {e}")
    return False


def get_router_credentials():
    router_ip = os.getenv("ROUTER_LOCAL_IP")
    router_username = os.getenv("ROUTER_USERNAME")
    router_password = os.getenv("ROUTER_PASSWORD")
    if not router_ip or not router_username or not router_password:
        raise ValueError(
            "Router IP, username, or password is not set in the environment variables."
        )
    return router_ip, router_username, router_password


def asy_encode(src_str: str) -> str:
    """
    Python implementation of asyEncode() from index.html.
    Equivalent to JSEncrypt's (v2.3.0, PKCS1v1.5 padding) encrypt():
    RSA encryption -> base64 encoding.
    """
    encrypted = rsa.encrypt(src_str.encode("utf-8"), PUB_KEY)
    return base64.b64encode(encrypted).decode("ascii")


def extract_text_from_xml_or_raw(text: str) -> str:
    """
    Extract text from an XML response (used for login_token).
    The login_token response is treated on index.html as $(xml).text()
    (i.e., parsed as XML and its text nodes concatenated).
    If parsing fails, treat it as plain text instead.
    """
    stripped = text.strip()
    try:
        root = ET.fromstring(stripped)
        joined = "".join(root.itertext()).strip()
        if joined:
            return joined
    except ET.ParseError:
        pass
    return stripped


def extract_reboot_token(text: str) -> str | None:
    """
    Extract the _sessionTmpToken from the rebootAndReset menuView response.

    Actual format observed on the real device:
        _sessionTmpToken = "\\x65\\x7a\\x42\\x65\\x6c...";
    It's embedded as a string with each character hex-escaped as \\xHH
    (presumably to hinder scraping). This is tried first, with a fallback
    to plain-text patterns just in case.
    """
    # (1) Hex-escaped form: _sessionTmpToken = "\x65\x7a...";
    m = re.search(r'_sessionTmpToken\s*=\s*"((?:\\x[0-9A-Fa-f]{2})+)"', text)
    if m:
        hex_escaped = m.group(1)
        token_bytes = bytes(
            int(h, 16) for h in re.findall(r"\\x([0-9A-Fa-f]{2})", hex_escaped)
        )
        try:
            return token_bytes.decode("ascii")
        except UnicodeDecodeError:
            pass

    # (2) Fallback: various plain-text patterns
    patterns = [
        r'_sessionTmpToken\s*=\s*["\']([A-Za-z0-9]+)["\']',
        r'name=["\']_sessionTOKEN["\'][^>]*value=["\']([A-Za-z0-9]+)["\']',
        r'"sess_token"\s*:\s*"([A-Za-z0-9]+)"',
        r'"_sessionTOKEN"\s*:\s*"([A-Za-z0-9]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def login(
    router_ip: str,
    headers_common: dict[str, str],
    router_username: str,
    router_password: str,
    session: requests.Session,
) -> requests.Session | None:
    base_url = f"http://{router_ip}/"

    # (1) Access the top page to obtain the initial SID cookie
    r = session.get(base_url, headers=headers_common, timeout=10)
    logger.debug(f"[1] GET / -> {r.status_code}, cookies={session.cookies.get_dict()}")

    # (2) login_entry (JSON): the sess_token obtained here goes into the
    #     _sessionTOKEN field of the login POST
    r = session.get(
        base_url,
        params={"_type": "loginData", "_tag": "login_entry"},
        headers={**headers_common, "X-Requested-With": "XMLHttpRequest"},
        timeout=10,
    )
    logger.debug(f"[2] login_entry(GET) -> {r.status_code}, body={r.text[:300]!r}")

    try:
        entry_json = r.json()
    except ValueError:
        logger.error("Failed to parse JSON from login_entry.")
        return None

    session_token_for_post = entry_json.get("sess_token")
    locking_time = int(entry_json.get("lockingTime", 0) or 0)
    if not session_token_for_post:
        logger.error("Could not obtain sess_token from login_entry.")
        return None
    if locking_time > 0:
        logger.error(
            f"The account is temporarily locked (approx. {locking_time}s remaining). "
            "Skipping automatic login, since repeated failures could extend the lock. "
            "Manual verification is recommended."
        )
        return None

    # (3) login_token (XML): a separate token from (1), used as material for
    #     the SHA256 hash computation
    ts = int(time.time() * 1000)
    r = session.get(
        base_url,
        params={"_type": "loginData", "_tag": "login_token", "_": ts},
        headers=headers_common,
        timeout=10,
    )
    logger.debug(f"[3] login_token(GET) -> {r.status_code}, body={r.text[:300]!r}")

    hash_token = extract_text_from_xml_or_raw(r.text)
    if not hash_token:
        logger.error("Failed to obtain hash material from login_token.")
        return None

    # (4) Compute password hash: SHA256(raw password + hash_token)
    hashed_pw = hashlib.sha256(
        (router_password + hash_token).encode("utf-8")
    ).hexdigest()

    # (5) Login POST
    login_data = {
        "action": "login",
        "Username": router_username,
        "Password": hashed_pw,
        "_sessionTOKEN": session_token_for_post,
    }
    r = session.post(
        base_url,
        params={"_type": "loginData", "_tag": "login_entry"},
        data=login_data,
        headers={
            **headers_common,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": base_url,
        },
        timeout=10,
    )
    logger.debug(f"[4] login POST -> {r.status_code}, body={r.text[:300]!r}")

    try:
        login_result = r.json()
    except ValueError:
        logger.error("Failed to parse JSON from the login POST.")
        return None

    if login_result.get("login_need_refresh"):
        logger.info("Login succeeded")
        return session

    err_msg = login_result.get("loginErrMsg", "")
    prompt_msg = login_result.get("promptMsg", "")
    logger.error(
        f"Login failed. loginErrMsg={err_msg!r} promptMsg={prompt_msg!r}"
    )
    return None


def request_router_reboot(
    base_url: str, headers_common: dict[str, str], login_session: requests.Session
) -> bool:
    # (6) Access the reboot page (rebootAndReset) to obtain _sessionTmpToken
    ts = int(time.time() * 1000)
    r = login_session.get(
        base_url,
        params={
            "_type": "menuView",
            "_tag": "rebootAndReset",
            "Menu3Location": 0,
            "_": ts,
        },
        headers={**headers_common, "X-Requested-With": "XMLHttpRequest"},
        timeout=10,
    )
    logger.debug(f"[5] rebootAndReset page -> {r.status_code}, body={r.text[:800]!r}")

    reboot_token = extract_reboot_token(r.text)
    if not reboot_token:
        logger.error(
            "Failed to extract the reboot token (_sessionTmpToken). "
            "Check the response body output in the DEBUG_MODE log and adjust "
            "the regex in extract_reboot_token() to match the actual response format."
        )
        return False

    # (7) Build the reboot POST data (this exact string is also what the
    #     Check header's digest is computed from)
    post_data_str = f"IF_ACTION=Restart&Btn_restart=&_sessionTOKEN={reboot_token}"
    digest = hashlib.sha256(post_data_str.encode("utf-8")).hexdigest()
    check_header = asy_encode(digest)

    # (8) Send the reboot POST
    r = login_session.post(
        base_url,
        params={"_type": "menuData", "_tag": "devmgr_restartmgr_lua.lua"},
        data=post_data_str,
        headers={
            **headers_common,
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": base_url,
            "Check": check_header,
        },
        timeout=10,
    )
    logger.debug(f"[6] restart POST -> {r.status_code}, body={r.text[:300]!r}")
    if r.status_code != 200:
        logger.error(f"HTTP status of the restart POST was not 200: {r.status_code}")
        return False

    logger.info("Restart command sent")
    return True


# ========= Restart =========
def restart_router() -> bool:
    router_ip, router_username, router_password = get_router_credentials()
    logger.info("Starting router restart process")
    base_url = f"http://{router_ip}/"

    user_agent = (
        "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    headers_common = {
        "User-Agent": user_agent,
        "Referer": base_url,
    }

    session = requests.Session()
    try:
        login_session = login(
            router_ip, headers_common, router_username, router_password, session
        )
    except requests.RequestException as e:
        logger.error(f"A network error occurred during login: {e}")
        return False

    if not login_session:
        logger.error("Login failed, aborting the restart process.")
        return False
    try:
        request_success = request_router_reboot(base_url, headers_common, login_session)
        if not request_success:
            logger.error("Failed to send the restart request.")
            return False

    except requests.RequestException as e:
        logger.error(f"A network error occurred during the restart process: {e}")
        return False
    return True


def main():
    log_file = os.getenv("ROUTER_REBOOT_LOG")
    setup_logger(log_file)

    consecutive_failures = 0
    restart_timestamps = []  # Restart history for the last 24 hours (for the daily-limit check)

    logger.info("Monitoring script started")

    while True:
        cutoff = datetime.now() - timedelta(days=1)
        restart_timestamps = [t for t in restart_timestamps if t > cutoff]

        if check_internet():
            if consecutive_failures > 0:
                logger.info(
                    f"Connectivity restored (resetting failure count: {consecutive_failures} -> 0)"
                )
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            logger.warning(
                f"Connectivity failure detected ({consecutive_failures}/{FAILURE_THRESHOLD})"
            )

            if consecutive_failures >= FAILURE_THRESHOLD:
                if len(restart_timestamps) >= MAX_RESTARTS_PER_DAY:
                    logger.error(
                        f"The number of restarts in the last 24 hours has reached the limit "
                        f"({MAX_RESTARTS_PER_DAY}). This is likely an ISP-side outage, so "
                        "skipping automatic restart. Manual verification is recommended."
                    )
                    consecutive_failures = 0
                    time.sleep(COOLDOWN_AFTER_RESTART_SEC)
                    continue

                logger.error("Threshold reached, restarting the router")
                success = restart_router()
                if success:
                    restart_timestamps.append(datetime.now())
                consecutive_failures = 0

                logger.info(f"Starting cooldown ({COOLDOWN_AFTER_RESTART_SEC}s wait)")
                time.sleep(COOLDOWN_AFTER_RESTART_SEC)
                continue

        time.sleep(CHECK_INTERVAL_SEC)


if __name__ == "__main__":
    main()
