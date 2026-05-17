import os
from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
from .geo import get_geo

app = Flask(__name__)
DB_PATH = "events.db"
API_SECRET = os.getenv("API_SECRET", "")

SEVERITY_MAP = {
    'ssh_brute_force': 'CRITICAL',
    'ssh_failed': 'CRITICAL',
    'sudo_attempt': 'CRITICAL',
    'http_attack': 'CRITICAL',
    'ssh_success_after_fail': 'WARNING',
    'ssh_success': 'WARNING',
    'firewall_drop': 'WARNING',
    'default': 'INFO'
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _check_secret():
    if API_SECRET and request.headers.get("X-Secret-Key") != API_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    return None


def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        event_type TEXT,
        severity TEXT,
        message TEXT,
        server_name TEXT,
        country TEXT,
        city TEXT,
        provider TEXT,
        notified INTEGER DEFAULT 0,
        cooldown_until TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS heartbeats (
        server_name TEXT PRIMARY KEY,
        last_seen TEXT,
        is_online INTEGER DEFAULT 1,
        os TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_at TEXT,
        reason TEXT
    )''')
    conn.commit()
    conn.close()


init_db()


@app.route('/api/event', methods=['POST'])
def receive_event():
    err = _check_secret()
    if err:
        return err
    data = request.json
    if not data or 'source_ip' not in data:
        return jsonify({"status": "error", "message": "Missing source_ip"}), 400

    geo = get_geo(data['source_ip'])
    event_type = data.get('event_type', 'unknown')
    severity = SEVERITY_MAP.get(event_type, SEVERITY_MAP['default'])
    timestamp = data.get('timestamp') or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute(
        '''INSERT INTO events
        (timestamp, source_ip, event_type, severity, message, server_name, country, city, provider)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            timestamp,
            data['source_ip'],
            event_type,
            severity,
            data.get('message', ''),
            data.get('server_name', 'unknown'),
            geo.get('country', '-'),
            geo.get('city', '-'),
            geo.get('provider', '-')
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 200


@app.route('/api/heartbeat', methods=['POST'])
def receive_heartbeat():
    err = _check_secret()
    if err:
        return err
    data = request.json
    if not data or 'server_name' not in data:
        return jsonify({"status": "error"}), 400

    conn = get_db()
    conn.execute(
        '''INSERT OR REPLACE INTO heartbeats (server_name, last_seen, is_online, os)
        VALUES (?, ?, 1, ?)''',
        (data['server_name'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data.get('os', 'unknown'))
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 200


@app.route('/api/blocked', methods=['GET'])
def get_blocked_ips():
    err = _check_secret()
    if err:
        return err
    conn = get_db()
    cursor = conn.execute("SELECT ip FROM blocked_ips")
    ips = [row['ip'] for row in cursor.fetchall()]
    conn.close()
    return jsonify({"blocked": ips}), 200


def get_pending_notifications():
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.execute(
        '''SELECT * FROM events
        WHERE notified = 0 AND (cooldown_until IS NULL OR cooldown_until < ?)
        ORDER BY timestamp DESC LIMIT 50''',
        (now,)
    )
    events = [dict(row) for row in cursor.fetchall()]

    for e in events:
        cooldown = 300 if e['severity'] == 'CRITICAL' else (60 if e['severity'] == 'WARNING' else 0)
        if cooldown > 0:
            conn.execute(
                'UPDATE events SET notified = 1, cooldown_until = datetime(?, ?) WHERE id = ?',
                (now, f'+{cooldown} seconds', e['id'])
            )
        else:
            conn.execute('UPDATE events SET notified = 1 WHERE id = ?', (e['id'],))
    conn.commit()
    conn.close()
    return events
