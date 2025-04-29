import threading
import time
import re

LOG_PATH = "logs/access.log"
ALERT_PATH = "logs/alert.log"

# Adjust as needed
SAFE_PATHS = ["/", "/login", "/register", "/contact", "/admin", "/upload", "/user"]
KEYWORDS_SUSPICIOUS = ["delete", "drop", "shutdown", "passwd", "wget", "curl"]

def is_suspicious(line):
    ip_match = re.search(r"IP: (\S+)", line)
    path_match = re.search(r"PATH: (\S+)", line)

    if not ip_match or not path_match:
        return False, None

    ip = ip_match.group(1)
    path = path_match.group(1).lower()

    if path not in SAFE_PATHS:
        for keyword in KEYWORDS_SUSPICIOUS:
            if keyword in path:
                return True, (ip, path)

    return False, None

def monitor_logs():
    seen_lines = set()

    while True:
        try:
            with open(LOG_PATH, "r") as f:
                lines = f.readlines()

            for line in lines:
                if line in seen_lines:
                    continue
                seen_lines.add(line)

                suspicious, details = is_suspicious(line)
                if suspicious:
                    ip, path = details
                    with open(ALERT_PATH, "a") as alert_file:
                        alert_file.write(f"[ALERT] Suspicious activity from {ip} on path {path}\n")


        except Exception as e:
            print(f"[IDS Error] {e}")

        time.sleep(5)

def start_ids_thread():
    t = threading.Thread(target=monitor_logs, daemon=True)
    t.start()
