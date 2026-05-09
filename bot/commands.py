import sqlite3
from datetime import datetime

DB_PATH = "events.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_latest_events(limit=10):
    conn = get_db()
    cursor = conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return events

def get_status_summary():
    conn = get_db()
    cursor = conn.execute('SELECT COUNT(*) FROM events WHERE timestamp >= datetime("now", "-24 hours")')
    events_24h = cursor.fetchone()[0]
    cursor = conn.execute('SELECT server_name, last_seen, is_online FROM heartbeats ORDER BY last_seen DESC')
    servers = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return events_24h, servers