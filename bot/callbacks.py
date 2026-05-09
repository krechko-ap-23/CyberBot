from telegram import InlineKeyboardButton, InlineKeyboardMarkup
import sqlite3
from datetime import datetime

DB_PATH = "events.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def handle_block_ip(ip):
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?, ?, ?)',
                (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'SecBot manual block'))
    conn.commit()
    conn.close()
    return {"message": f"✅ IP {ip} заблокирован (dry-run)"}

def handle_whitelist_ip(ip):
    conn = get_db()
    conn.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
    conn.commit()
    conn.close()
    return {"message": f"✅ IP {ip} добавлен в whitelist"}

def get_ip_history(ip, limit=10):
    conn = get_db()
    cursor = conn.execute('SELECT timestamp, severity, event_type FROM events WHERE source_ip = ? ORDER BY timestamp DESC LIMIT ?', (ip, limit))
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return events

def get_inline_keyboard(ip, server_name):
    keyboard = [
        [InlineKeyboardButton("🚫 Заблокировать", callback_data=f"block_{ip}"),
         InlineKeyboardButton("✅ Whitelist", callback_data=f"whitelist_{ip}")],
        [InlineKeyboardButton("📋 История", callback_data=f"history_{ip}")]
    ]
    return InlineKeyboardMarkup(keyboard)