import os
import random
import requests
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

BOT_URL = os.getenv("BOT_URL", "").strip()
API_SECRET = os.getenv("API_SECRET", "")
SERVER_NAME = os.getenv("SERVER_NAME", "CyberBot-VM")

if not BOT_URL:
    print("BOT_URL не задан в .env. Укажи адрес сервера и повтори.")
    raise SystemExit(1)

HEADERS = {"Content-Type": "application/json"}
if API_SECRET:
    HEADERS["X-Secret-Key"] = API_SECRET

ATTACK_IPS = [
    "203.0.113.45", "198.51.100.12", "45.33.32.156",
    "185.220.101.33", "192.0.2.99", "91.108.4.11",
    "162.142.125.0", "80.82.77.33", "194.165.16.77",
]
SAFE_IPS = ["192.168.1.5", "192.168.1.20", "10.0.0.5"]
USERS = ["root", "admin", "user", "test", "oracle", "ubuntu", "postgres"]

SCENARIOS = [
    {"event_type": "ssh_failed",      "weight": 30},
    {"event_type": "ssh_brute_force", "weight": 20},
    {"event_type": "ssh_success",     "weight": 10},
    {"event_type": "ssh_success_after_fail", "weight": 5},
    {"event_type": "sudo_attempt",    "weight": 10},
    {"event_type": "firewall_drop",   "weight": 15},
    {"event_type": "http_attack",     "weight": 10},
]

MESSAGES = {
    "ssh_failed":            "Failed password for {user} from {ip} port {port} ssh2",
    "ssh_brute_force":       "Failed password for {user} from {ip} port {port} ssh2 | брутфорс: 5+ попыток за 60с",
    "ssh_success":           "Accepted password for {user} from {ip} port {port} ssh2",
    "ssh_success_after_fail":"Accepted password for {user} from {ip} port {port} ssh2 | вход после ошибок",
    "sudo_attempt":          "sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    "firewall_drop":         "UFW BLOCK: SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
    "http_attack":           "GET /admin/../../../etc/passwd HTTP/1.1 | от {ip}",
}


def random_timestamp(hours_back=24):
    delta = random.uniform(0, hours_back * 3600)
    dt = datetime.now() - timedelta(seconds=delta)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def pick_scenario():
    pool = []
    for s in SCENARIOS:
        pool.extend([s["event_type"]] * s["weight"])
    return random.choice(pool)


def build_event(event_type):
    ip = random.choice(ATTACK_IPS) if event_type not in ("ssh_success", "sudo_attempt") else random.choice(ATTACK_IPS + SAFE_IPS)
    user = random.choice(USERS)
    port = random.randint(22000, 65000)
    msg = MESSAGES[event_type].format(ip=ip, user=user, port=port)
    return {
        "source_ip": ip,
        "event_type": event_type,
        "message": msg,
        "server_name": SERVER_NAME,
        "timestamp": random_timestamp(24),
    }


def send_event(event):
    try:
        resp = requests.post(f"{BOT_URL}/api/event", json=event, headers=HEADERS, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Ошибка отправки: {e}")
        return False


def main():
    count = int(input("Сколько событий сгенерировать? (по умолчанию 100): ").strip() or 100)
    print(f"Генерирую {count} событий за последние 24ч → {BOT_URL}")

    ok = 0
    for i in range(count):
        event_type = pick_scenario()
        event = build_event(event_type)
        if send_event(event):
            ok += 1
            print(f"[{i+1}/{count}] {event['timestamp']} | {event_type} | {event['source_ip']}")
        else:
            print(f"[{i+1}/{count}] Не отправлено")
        time.sleep(0.05)

    print(f"\nГотово: отправлено {ok} из {count} событий.")


if __name__ == "__main__":
    main()
