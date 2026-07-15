"""
browse.py — Single normal user browsing the target website.
One container per persona, each with its own IP address.

Env vars:
  TARGET_IP   — target server IP (default 172.20.0.10)
  USER_NAME   — persona name: alice|bob|carol|dave|eve|frank|grace|heidi
  USER_SPEED  — fast|medium|slow
"""

import os
import time
import random
import requests
from requests.exceptions import RequestException

TARGET_IP  = os.environ.get("TARGET_IP",  "172.20.0.10")
USER_NAME  = os.environ.get("USER_NAME",  "user")
USER_SPEED = os.environ.get("USER_SPEED", "medium")
BASE_URL   = f"http://{TARGET_IP}"

SPEED_MAP = {
    "fast":   (1.0,  4.0),
    "medium": (4.0,  12.0),
    "slow":   (12.0, 30.0),
}
lo_d, hi_d = SPEED_MAP.get(USER_SPEED, (4.0, 12.0))

PAGES = ["/", "/", "/", "/api/v1", "/api/v1"]

UA_MAP = {
    "alice": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "bob":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "carol": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "dave":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "eve":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "frank": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "grace": "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "heidi": "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/120.0 Firefox/120.0",
}
UA = UA_MAP.get(USER_NAME, "Mozilla/5.0 (compatible; Browser/1.0)")

print(f"[{USER_NAME}] Ready — speed={USER_SPEED} target={BASE_URL}")
time.sleep(random.uniform(1.0, 8.0))

session = requests.Session()
session.headers.update({
    "User-Agent":      UA,
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
})

visit = 0
while True:
    n = random.randint(2, 6)
    print(f"[{USER_NAME}] Session {visit+1} — {n} pages")
    for page in random.choices(PAGES, k=n):
        try:
            r = session.get(f"{BASE_URL}{page}", timeout=5)
            print(f"[{USER_NAME}] {page} → {r.status_code} ({len(r.content)}B)")
        except RequestException as e:
            print(f"[{USER_NAME}] {page} → {e}")
        time.sleep(random.uniform(lo_d, hi_d))

    visit += 1
    rest = random.uniform(20.0, 60.0)
    print(f"[{USER_NAME}] Resting {rest:.0f}s")
    time.sleep(rest)
