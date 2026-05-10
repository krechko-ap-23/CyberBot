import os
import sqlite3
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'events.db')
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_model.pkl')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_events(days=7):
    conn = get_db_connection()
    cursor = conn.cursor()
   
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        SELECT timestamp, event_type, severity, source_ip, message
        FROM events 
        WHERE timestamp >= ?
        ORDER BY timestamp
    ''', (cutoff,))
    
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def prepare_features(events):
    if not events:
        return None, None, None, None

    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek

    le_type = LabelEncoder()
    le_sev = LabelEncoder()
    df['event_type_enc'] = le_type.fit_transform(df['event_type'].astype(str))
    df['severity_enc'] = le_sev.fit_transform(df['severity'].astype(str))

    df['ip_hash'] = df['source_ip'].apply(lambda x: sum(ord(c) for c in str(x)) % 100)

    features = df[['hour', 'day_of_week', 'event_type_enc', 'severity_enc', 'ip_hash']].values
    return features, df, le_type, le_sev

def train_model(days=7):
    events = get_events(days)
    features, df, le_type, le_sev = prepare_features(events)
    
    if features is None or len(features) < 10:
        return None, "Недостаточно данных для обучения ML (нужно минимум 10 событий)"

    model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
    model.fit(features)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump({'model': model, 'le_type': le_type, 'le_sev': le_sev}, f)

    return model, None

def load_model():
    if not os.path.exists(MODEL_PATH):
        return None, None, None, "Модель не найдена. Запустите /ml_train."
    with open(MODEL_PATH, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['le_type'], data['le_sev'], None

def detect_anomalies(days=1):
    events = get_events(days)
    features, df, _, _ = prepare_features(events)
    
    if features is None or len(features) < 5:
        return [], "Нет данных для анализа аномалий"

    model, _, _, err = load_model()
    if err:
        return [], err

    predictions = model.predict(features)
    scores = model.decision_function(features)

    anomalies = []
    for i, (pred, score) in enumerate(zip(predictions, scores)):
        if pred == -1:
            row = df.iloc[i]
            anomalies.append({
                'timestamp': str(row['timestamp']),
                'severity': row['severity'],
                'source_ip': row['source_ip'],
                'event_type': row['event_type'],
                'message': str(row['message'])[:100],
                'anomaly_score': round(float(score), 3),
                'reason': _explain_anomaly(row, score)
            })
    return anomalies, None

def _explain_anomaly(row, score):
    reasons = []
    if row['hour'] < 6 or row['hour'] > 23:
        reasons.append(f"Ночное время ({int(row['hour']):02d}:00)")
    if row['severity'] == 'CRITICAL':
        reasons.append("Критический уровень угрозы")
    if score < -0.4:
        reasons.append("Редкая комбинация признаков")
    return " | ".join(reasons) if reasons else "Статистическое отклонение"