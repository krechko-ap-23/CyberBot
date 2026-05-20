import os
import re
import time
import json
import sqlite3
import logging
import requests
import threading
import socket
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv
from auto_start import find_bot

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("agent.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

BOT_URL = os.getenv("BOT_URL", "").strip()
SERVER_NAME = os.getenv("SERVER_NAME", socket.gethostname())
API_SECRET = os.getenv("API_SECRET", "")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/auth.log")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
BRUTE_THRESHOLD = int(os.getenv("BRUTE_THRESHOLD", "5"))
BRUTE_WINDOW = int(os.getenv("BRUTE_WINDOW", "60"))
BUFFER_DB = os.path.join(os.path.dirname(__file__), "agent_buffer.db")


def resolve_bot_url():
    if BOT_URL:
        log.info(f"BOT_URL из .env: {BOT_URL}")
        return BOT_URL
    retry = 0
    while True:
        retry += 1
        log.info(f"BOT_URL не задан, запускаю автопоиск (попытка {retry})...")
        found = find_bot()
        if found:
            return found
        log.warning("Сервер не найден. Следующая попытка через 30 секунд...")
        time.sleep(30)

def init_buffer_db():
    conn = sqlite3.connect(BUFFER_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS buffered_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_data TEXT
        )
    """)
    conn.commit()
    conn.close()


def _headers():
    h = {"Content-Type": "application/json"}
    if API_SECRET:
        h["X-Secret-Key"] = API_SECRET
    return h

def send_to_bot(bot_url, event):
    try:
        resp = requests.post(
            f"{bot_url}/api/event",
            json=event,
            headers=_headers(),
            timeout=5,
        )
        if resp.status_code == 200:
            log.info(f"Отправлено: {event['event_type']} от {event['source_ip']}")
            return True
        log.warning(f"Сервер вернул {resp.status_code}")
    except requests.exceptions.RequestException:
        log.warning("Сервер недоступен, буферизую событие.")

    _buffer_event(event)
    return False


def _buffer_event(event):
    conn = sqlite3.connect(BUFFER_DB)
    conn.execute(
        "INSERT INTO buffered_events (timestamp, event_data) VALUES (?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), json.dumps(event)),
    )
    conn.commit()
    conn.close()


def flush_buffer(bot_url):
    conn = sqlite3.connect(BUFFER_DB)
    cur = conn.cursor()
    cur.execute("SELECT id, event_data FROM buffered_events ORDER BY id")
    rows = cur.fetchall()
    if not rows:
        conn.close()
        return

    flushed = 0
    for rid, ej in rows:
        try:
            ev = json.loads(ej)
            resp = requests.post(
                f"{bot_url}/api/event",
                json=ev,
                headers=_headers(),
                timeout=5,
            )
            if resp.status_code == 200:
                cur.execute("DELETE FROM buffered_events WHERE id=?", (rid,))
                conn.commit()
                flushed += 1
        except requests.exceptions.RequestException:
            break 

    conn.close()
    if flushed:
        log.info(f"Из буфера отправлено: {flushed} событий")

def block_ip(ip: str):
    ret = os.system(f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null")
    if ret != 0:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        log.info(f"iptables: заблокирован {ip}")


def block_sync_loop(bot_url):
    applied = set()
    while True:
        try:
            resp = requests.get(
                f"{bot_url}/api/blocked",
                headers=_headers(),
                timeout=5,
            )
            if resp.status_code == 200:
                for ip in resp.json().get("blocked", []):
                    if ip not in applied:
                        block_ip(ip)
                        applied.add(ip)
        except requests.exceptions.RequestException:
            log.warning("block_sync: сервер недоступен")
        time.sleep(60)


def heartbeat_loop(bot_url):
    while True:
        try:
            requests.post(
                f"{bot_url}/api/heartbeat",
                json={"server_name": SERVER_NAME, "os": "linux"},
                headers=_headers(),
                timeout=5,
            )
            log.debug(f"Heartbeat: {SERVER_NAME}")
        except requests.exceptions.RequestException:
            log.warning("Heartbeat потерян")
        time.sleep(HEARTBEAT_INTERVAL)

_fail_times: dict = defaultdict(list)
_fail_lock = threading.Lock()


def _record_fail(ip) -> int:
    now = time.time()
    with _fail_lock:
        _fail_times[ip] = [t for t in _fail_times[ip] if now - t < BRUTE_WINDOW]
        _fail_times[ip].append(now)
        return len(_fail_times[ip])


def _clear_fail(ip):
    with _fail_lock:
        _fail_times.pop(ip, None)

def parse_log(line: str):
    line = line.strip()
    if not line:
        return None

    m = re.search(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        count = _record_fail(ip)
        if count >= BRUTE_THRESHOLD:
            etype = "ssh_brute_force"
            msg = f"{line} | брутфорс: {count} попыток за {BRUTE_WINDOW}с"
        else:
            etype = "ssh_failed"
            msg = f"{line} | попыток: {count}"
        return {"source_ip": ip, "message": msg, "event_type": etype, "server_name": SERVER_NAME}

    m = re.search(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)", line)
    if m:
        user, ip = m.group(1), m.group(2)
        had_fails = len(_fail_times.get(ip, [])) > 0
        _clear_fail(ip)
        etype = "ssh_success_after_fail" if had_fails else "ssh_success"
        return {"source_ip": ip, "message": line, "event_type": etype, "server_name": SERVER_NAME}

    m = re.search(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)", line)
    if m:
        return None
    m = re.search(r"(?:firewalld|UFW BLOCK|kernel.*DROP).*SRC=([\d.]+)", line)
    if m:
        return {"source_ip": m.group(1), "message": line, "event_type": "firewall_drop", "server_name": SERVER_NAME}

    return None

def monitor(bot_url):
    if not os.path.exists(LOG_FILE):
        log.error(f"Файл лога не найден: {LOG_FILE}")
        return

    log.info(f"Мониторинг: {LOG_FILE}")
    flush_counter = 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                event = parse_log(line)
                if event:
                    send_to_bot(bot_url, event)
            else:
                time.sleep(0.5)
                flush_counter += 1
                if flush_counter >= 10: 
                    flush_buffer(bot_url)
                    flush_counter = 0

def main():
    log.info("Agent запускается")
    init_buffer_db()

    bot_url = resolve_bot_url()

    threading.Thread(target=heartbeat_loop, args=(bot_url,), daemon=True).start()
    log.info(f"Heartbeat запущен (каждые {HEARTBEAT_INTERVAL}с)")
    threading.Thread(target=block_sync_loop, args=(bot_url,), daemon=True).start()
    log.info("Синхронизация блокировок запущена (каждые 60с)")

    flush_buffer(bot_url)

    try:
        monitor(bot_url)
    except KeyboardInterrupt:
        log.info("Агент остановлен.")


if __name__ == "__main__":
    main()
