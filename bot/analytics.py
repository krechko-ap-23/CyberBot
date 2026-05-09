import sqlite3
import os
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
from collections import defaultdict

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'events.db')
CHART_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'chart.png')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_attack_chart(hours=24) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        SELECT timestamp, severity 
        FROM events 
        WHERE timestamp >= ?
        ORDER BY timestamp
    ''', (cutoff,))
    rows = cursor.fetchall()
    conn.close()
    
    print(f"График: найдено {len(rows)} событий за {hours}ч")  # Отладка
    
    if not rows:
        return _create_empty_chart()
    
    hourly_counts = defaultdict(lambda: {"CRITICAL": 0, "WARNING": 0, "INFO": 0})
    for row in rows:
        try:
            ts = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S")
            hour_key = ts.replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key][row['severity']] += 1
        except:
            continue  
            
    times = sorted(hourly_counts.keys())
    critical = [hourly_counts[t]["CRITICAL"] for t in times]
    warning = [hourly_counts[t]["WARNING"] for t in times]
    info = [hourly_counts[t]["INFO"] for t in times]
    
    # Рисуем
    fig, ax = plt.subplots(figsize=(10, 5), dpi=100)
    ax.stackplot(times, info, warning, critical, 
                 labels=['INFO', 'WARNING', 'CRITICAL'],
                 colors=['#3498db', '#f39c12', '#e74c3c'], alpha=0.8)
    
    ax.set_xlabel('Время', fontsize=10)
    ax.set_ylabel('Количество событий', fontsize=10)
    ax.set_title(f'Атаки за последние {hours} часов', fontsize=14, fontweight='bold')
    ax.legend(loc='upper left', fontsize=8)
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, hours//6)))
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    plt.savefig(CHART_PATH, bbox_inches='tight')
    plt.close(fig)
    
    # Проверяем, что файл действительно создан
    if os.path.exists(CHART_PATH):
        print(f"График сохранён: {CHART_PATH} ({os.path.getsize(CHART_PATH)} байт)")
    else:
        print("Ошибка: файл графика не создан!")
        
    return CHART_PATH

def _create_empty_chart() -> str:
    fig, ax = plt.subplots(figsize=(10, 5), dpi=100)
    ax.text(0.5, 0.5, 'Нет данных за последние 24 часа', 
            ha='center', va='center', fontsize=14, transform=ax.transAxes)
    ax.set_xlabel('Время')
    ax.set_ylabel('События')
    ax.set_title('Статистика атак')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(CHART_PATH, bbox_inches='tight')
    plt.close(fig)
    return CHART_PATH

def get_summary_stats(hours=24) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        SELECT severity, COUNT(*) as cnt
        FROM events
        WHERE timestamp >= ?
        GROUP BY severity
    ''', (cutoff,))
    stats = {row['severity']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return {
        "critical": stats.get("CRITICAL", 0),
        "warning": stats.get("WARNING", 0),
        "info": stats.get("INFO", 0),
        "total": sum(stats.values())
    }