
import sqlite3
import os
from datetime import datetime
from collections import Counter
from .geo import get_geo

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'events.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_daily_digest() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT severity, COUNT(*) as cnt 
        FROM events 
        WHERE timestamp >= datetime("now", "-24 hours")
        GROUP BY severity
    ''')
    severity_stats = {row['severity']: row['cnt'] for row in cursor.fetchall()}
    total = sum(severity_stats.values())
    
    cursor.execute('''
        SELECT source_ip, COUNT(*) as cnt 
        FROM events 
        WHERE timestamp >= datetime("now", "-24 hours")
        GROUP BY source_ip 
        ORDER BY cnt DESC 
        LIMIT 3
    ''')
    top_ips = cursor.fetchall()
    
    top_ips_with_geo = []
    for row in top_ips:
        geo = get_geo(row['source_ip'])
        top_ips_with_geo.append({
            'ip': row['source_ip'],
            'count': row['cnt'],
            'country': geo.get('country', 'Неизвестно')
        })
    
    cursor.execute('SELECT server_name, last_seen, is_online FROM heartbeats')
    servers = cursor.fetchall()
    
    server_status = []
    now = datetime.now()
    for s in servers:
        last_seen = datetime.strptime(s['last_seen'], "%Y-%m-%d %H:%M:%S")
        diff_sec = (now - last_seen).total_seconds()
        is_online = s['is_online'] if diff_sec <= 60 else 0
        
        offline_text = ""
        if not is_online:
            h = int(diff_sec // 3600)
            m = int((diff_sec % 3600) // 60)
            offline_text = f" ({h}ч {m}м)"
            
        server_status.append({
            'name': s['server_name'],
            'online': is_online,
            'offline_text': offline_text
        })
    
    conn.close()
    
    today = datetime.now().strftime("%d %B %Y")
    text = f" ЕЖЕДНЕВНЫЙ ОТЧЕТ • {today}\n"
    text += f"Всего событий за 24ч: {total}\n"
    text += f"🔴 Критических: {severity_stats.get('CRITICAL', 0)}\n"
    text += f"🟠 Предупреждений: {severity_stats.get('WARNING', 0)}\n"
    text += f" Информационных: {severity_stats.get('INFO', 0)}\n\n"
    
    if top_ips_with_geo:
        text += " Топ атакующих IP:\n"
        for i, ip in enumerate(top_ips_with_geo, 1):
            text += f"{i}. {ip['ip']} — {ip['count']} попыток ({ip['country']})\n"
        text += "\n"
        
    if server_status:
        text += "Статус серверов:\n"
        for srv in server_status:
            icon = "🟢" if srv['online'] else "🔴"
            text += f"{icon} {srv['name']} — {'онлайн' if srv['online'] else 'оффлайн' + srv['offline_text']}\n"
        text += "\n"
        
    text += "\nОтчет сгенерирован автоматически"
    
    from .analytics import generate_attack_chart
    chart_path = generate_attack_chart(hours=24)
    
    return {"text": text, "chart_path": chart_path}