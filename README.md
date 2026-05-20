## Данные об авторе

Кречко Ангелина Петровна

krechko_ap_23

3 курс / 6 семестр

Кибербезопасность

Вид проекта — курсовой работа 

# CyberBot — Telegram-бот для мониторинга событий безопасности

Программный комплекс для автоматизированного мониторинга событий информационной безопасности Linux-серверов с оповещением через Telegram в реальном времени. Система обнаруживает SSH-атаки, брутфорс, попытки эскалации привилегий и блокирует атакующих на уровне межсетевого экрана.

## Требования

* Python 3.11+
* pip
* Telegram-аккаунт и бот ([@BotFather](https://t.me/BotFather))
* Linux-сервер с `/var/log/auth.log` (агент)

##  Как запустить

### 1. Клонируйте репозиторий (на Windows — сервер):

git clone https://github.com/krechko-ap-23/CyberBot.git
cd CyberBot

### 2. Установите зависимости сервера:

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

### 3. Настройте конфигурацию сервера:

cp .env.example .env

Заполнить `.env`:

TOKEN=токен_от_BotFather
ADMIN_USER_ID=ваш_telegram_id
API_SECRET=секретный_ключ


### 4. Запустите сервер:

python main.py


### 5. Установите агент (на Ubuntu):

cd agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env


Заполнить `agent/.env`:

API_SECRET=тот_же_секретный_ключ
SERVER_NAME=имя_сервера


### 6. Запустите агент как системный сервис:

sudo cp cyberbot-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyberbot-agent.service


### 7. Генерация тестовых событий (опционально):

cd agent
source venv/bin/activate
python generate_events.py

## Зависимости 

* Python 3.11
* python-telegram-bot 20.7
* Flask 3.0
* SQLite3
* scikit-learn (Isolation Forest)
* matplotlib
* systemd
* iptables
