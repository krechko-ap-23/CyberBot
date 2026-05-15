CyberBot — Telegram-бот для мониторинга событий безопасности
Система автоматизированного мониторинга событий информационной безопасности с оповещением через Telegram.

Архитектура

Windows (сервер)         
main.py                     
Flask API :5000        
Telegram Bot                 
SQLite DB                      

через  HTTP

Ubuntu (агент)
agent/main.py  
Мониторинг     
/var/log/      
auth.log       


Возможности
Мониторинг SSH-событий в реальном времени (/var/log/auth.log)
Детектирование брутфорса (5+ попыток за 60 секунд)
Классификация событий по уровням: CRITICAL / WARNING / INFO
Геолокация атакующих IP (страна, город, провайдер)
Heartbeat-мониторинг доступности серверов
Интерактивные кнопки: блокировать IP, добавить в whitelist, история
График активности атак за 24 часа
Ежедневный дайджест в 09:00
ML-модуль обнаружения аномалий (Isolation Forest)
Буферизация событий при потере связи с сервером
Автопоиск сервера в локальной сети

1. Сервер (Windows)
git clone https://github.com/твой-логин/CyberBot.git
cd CyberBot
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

Заполни .env:
TOKEN=токен_от_BotFather
ADMIN_USER_ID=твой_telegram_id
API_SECRET=придумай_секретный_ключ
Запуск: python main.py

2. Агент (Ubuntu)
cd agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

Заполни .env:
API_SECRET=тот_же_ключ_что_на_сервере
SERVER_NAME=имя_этого_сервера
Запуск:
sudo venv/bin/python main.py

! `sudo` нужен для чтения `/var/log/auth.log`. Если добавить пользователя в группу `adm` (`sudo usermod -aG adm $USER`), можно запускать без sudo.

3. Генерация тестовых событий (опционально)
cd agent
source venv/bin/activate
python generate_events.py

Структура проекта

CyberBot/
├── main.py              # Точка входа сервера (бот + Flask)
├── requirements.txt     # Зависимости сервера
├── .env.example         # Шаблон конфига сервера
├── bot/
   ├── server.py        # Flask API (приём событий)
   ├── commands.py      # Запросы к БД
   ├── callbacks.py     # Обработка inline-кнопок
   ├── analytics.py     # Генерация графиков
   ├── digest.py        # Ежедневный дайджест
   ├── geo.py           # Геолокация IP
   └── ml_anomaly.py    # ML-модуль (Isolation Forest)
└── agent/
    ├── main.py          # Агент мониторинга логов
    ├── auto_start.py    # Автопоиск сервера в сети
    ├── generate_events.py # Генератор тестовых событий
    ├── requirements.txt
    └── .env.example

Команды бота

/start  Открыть главное меню 
/help Справка по командам |

Технологии

Python 3.11
python-telegram-bot 20.7
Flask 3.0
SQLite3
scikit-learn (Isolation Forest)
matplotlib
pandas / numpy
