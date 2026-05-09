import os
import logging
import threading
import sqlite3
import sys
from datetime import datetime, time
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from bot.commands import get_latest_events, get_status_summary
from bot.server import app, get_pending_notifications
from bot.callbacks import handle_block_ip, handle_whitelist_ip, get_ip_history, get_inline_keyboard
from bot.analytics import generate_attack_chart, get_summary_stats
from bot.digest import generate_daily_digest
from bot.ml_anomaly import train_model, detect_anomalies

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
TOKEN = os.getenv("TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_USER_ID"))
DB_PATH = "events.db"

def get_start_button():
    keyboard = [[InlineKeyboardButton("🚀 Начать", callback_data="cmd_start")]]
    return InlineKeyboardMarkup(keyboard)

def get_main_menu():
    keyboard = [
        [InlineKeyboardButton("❓ Помощь", callback_data="cmd_help"), InlineKeyboardButton("📋 Логи", callback_data="cmd_logs")],
        [InlineKeyboardButton("📈 Статус", callback_data="cmd_status"), InlineKeyboardButton("📊 График", callback_data="cmd_graph")],
        [InlineKeyboardButton("🧠 ML: Обучить", callback_data="cmd_ml_train"), InlineKeyboardButton("🔍 ML: Проверить", callback_data="cmd_ml_check")],
        [InlineKeyboardButton("📬 Тест дайджеста", callback_data="cmd_digest")],
        [InlineKeyboardButton("🛑 Остановить бота", callback_data="cmd_stop")]
    ]
    return InlineKeyboardMarkup(keyboard)

async def check_notifications(context: ContextTypes.DEFAULT_TYPE):
    events = get_pending_notifications()
    if not events:
        return
    for e in events:
        icon = {"CRITICAL": "🔴", "WARNING": "🟠", "INFO": "⚪"}.get(e['severity'], "⚪")
        geo_text = ""
        if e.get('country') and e['country'] != "-":
            city_str = f", {e['city']}" if e.get('city') and e['city'] != "-" else ""
            prov_str = f" ({e['provider']})" if e.get('provider') and e['provider'] != "-" else ""
            geo_text = f"\n🌍 {e['country']}{city_str}{prov_str}"
        text = (f"{icon} {e['severity']} | {e['event_type']}\n"
                f"🌐 IP: {e['source_ip']}{geo_text}\n"
                f"🖥️ Сервер: {e['server_name']}\n"
                f"📝 {e['message'][:100]}...")
        keyboard = get_inline_keyboard(e['source_ip'], e['server_name'])
        try:
            await context.bot.send_message(chat_id=ADMIN_ID, text=text, reply_markup=keyboard)
            logger.info(f"Уведомление отправлено: {e['event_type']} от {e['source_ip']}")
        except Exception as ex:
            logger.error(f"Ошибка отправки: {ex}")

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.")
        return
    await update.message.reply_text("🤖 **SecBot** — система мониторинга кибербезопасности.\n\nНажми кнопку ниже, чтобы начать:", reply_markup=get_start_button(), parse_mode='HTML')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    text = "📚 **Справка**:\n📋 `/logs [N]` — последние N событий\n📈 `/status` — статус серверов\n📊 `/graph` — график атак\n🧠 `/ml_train` — обучить ML\n🔍 `/ml_check` — проверить аномалии"
    await update.message.reply_text(text, reply_markup=get_main_menu(), parse_mode='HTML')

async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    limit = int(context.args[0]) if context.args and context.args[0].isdigit() else 10
    events = get_latest_events(min(limit, 50))
    if not events:
        await update.message.reply_text("📭 Журнал пуст.", reply_markup=get_main_menu())
        return
    text = f"📋 Последние {len(events)} событий:\n" + "\n".join([f"• {e['timestamp']} | {e['severity']} | {e['source_ip']}" for e in events])
    await update.message.reply_text(text, reply_markup=get_main_menu())

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    events_24h, servers = get_status_summary()
    text = f"📊 Событий за 24ч: {events_24h}\n"
    if servers:
        text += "\n🖥️ Серверы:\n" + "\n".join([f"{'🟢' if s['is_online'] else '🔴'} {s['server_name']}" for s in servers])
    await update.message.reply_text(text, reply_markup=get_main_menu())

async def graph_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    status_msg = await update.message.reply_text("📊 Генерирую...", reply_markup=get_main_menu())
    try:
        chart_path = generate_attack_chart(hours=24)
        stats = get_summary_stats(hours=24)
        caption = f"📈 Статистика:\n🔴 {stats['critical']} | 🟠 {stats['warning']} | ⚪ {stats['info']}"
        with open(chart_path, 'rb') as photo:
            await update.message.reply_photo(photo=photo, caption=caption, reply_markup=get_main_menu())
        await status_msg.delete()
    except Exception as e:
        logger.error(f"Ошибка графика: {e}")
        await status_msg.edit_text("❌ Ошибка графика", reply_markup=get_main_menu())

async def ml_train_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    await update.message.reply_text("🧠 Обучаю модель...", reply_markup=get_main_menu())
    _, err = train_model(days=7)
    await update.message.reply_text("✅ Готово!" if not err else f"⚠️ {err}", reply_markup=get_main_menu())

async def ml_check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    status_msg = await update.message.reply_text("🔍 Ищу аномалии...", reply_markup=get_main_menu())
    anomalies, err = detect_anomalies(days=1)
    if err or not anomalies:
        await status_msg.edit_text("✅ Аномалий нет" if not err else f"⚠️ {err}", reply_markup=get_main_menu())
        return
    text = "🔍 Аномалии:\n" + "\n".join([f"• {a['source_ip']} | {a['reason']}" for a in anomalies[:3]])
    await status_msg.edit_text(text, reply_markup=get_main_menu())

async def test_digest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Доступ запрещён.", reply_markup=get_main_menu())
        return
    await update.message.reply_text("📬 Генерирую отчёт...", reply_markup=get_main_menu())
    await send_daily_digest(context)

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("⛔ Доступ запрещён.")
        return
    cmd = query.data
    if cmd == "cmd_start":
        await query.edit_message_text("🤖 **SecBot** готов! Выберите действие:", reply_markup=get_main_menu(), parse_mode='HTML')
        return
    if cmd == "cmd_help":
        await query.message.reply_text("📚 **Справка**:\n📋 Логи | 📈 Статус | 📊 График | 🧠 ML", reply_markup=get_main_menu(), parse_mode='HTML')
    elif cmd == "cmd_logs":
        events = get_latest_events(10)
        text = "📋 Последние события:\n" + "\n".join([f"• {e['timestamp']} | {e['severity']} | {e['source_ip']}" for e in events[:5]]) if events else "📭 Пусто"
        await query.message.reply_text(text, reply_markup=get_main_menu())
    elif cmd == "cmd_status":
        events_24h, servers = get_status_summary()
        text = f"📊 Событий: {events_24h}"
        if servers:
            text += "\n🖥️ " + "\n".join([f"{'🟢' if s['is_online'] else '🔴'} {s['server_name']}" for s in servers])
        await query.message.reply_text(text, reply_markup=get_main_menu())
    elif cmd == "cmd_graph":
        await query.message.reply_text("📊 Генерирую...", reply_markup=get_main_menu())
        try:
            chart_path = generate_attack_chart(hours=24)
            stats = get_summary_stats(hours=24)
            caption = f"📈 Статистика:\n🔴 {stats['critical']} | 🟠 {stats['warning']} | ⚪ {stats['info']}"
            with open(chart_path, 'rb') as photo:
                await query.message.reply_photo(photo=photo, caption=caption, reply_markup=get_main_menu())
        except:
            await query.message.reply_text("❌ Ошибка", reply_markup=get_main_menu())
    elif cmd == "cmd_ml_train":
        await query.message.reply_text("🧠 Обучаю...", reply_markup=get_main_menu())
        _, err = train_model(days=7)
        await query.message.reply_text("✅ Готово!" if not err else f"⚠️ {err}", reply_markup=get_main_menu())
    elif cmd == "cmd_ml_check":
        await query.message.reply_text("🔍 Проверяю...", reply_markup=get_main_menu())
        anomalies, err = detect_anomalies(days=1)
        if err or not anomalies:
            await query.message.reply_text("✅ Чисто" if not err else f"⚠️ {err}", reply_markup=get_main_menu())
            return
        text = "🔍 Аномалии:\n" + "\n".join([f"• {a['source_ip']} | {a['reason']}" for a in anomalies[:3]])
        await query.message.reply_text(text, reply_markup=get_main_menu())
    elif cmd == "cmd_digest":
        await query.message.reply_text("📬 Генерирую...", reply_markup=get_main_menu())
        await send_daily_digest(context)
    elif cmd == "cmd_stop":
        await query.message.reply_text("🛑 Остановка...", reply_markup=None)
        if context.job_queue:
            await context.job_queue.stop(wait=True)
        os._exit(0)

async def check_heartbeats(context: ContextTypes.DEFAULT_TYPE):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    now = datetime.now()
    cursor.execute("SELECT server_name, last_seen, is_online FROM heartbeats")
    for s in cursor.fetchall():
        last_seen = datetime.strptime(s['last_seen'], "%Y-%m-%d %H:%M:%S")
        diff = (now - last_seen).total_seconds()
        if diff > 60 and s['is_online'] == 1:
            cursor.execute("UPDATE heartbeats SET is_online = 0 WHERE server_name = ?", (s['server_name'],))
            conn.commit()
            await context.bot.send_message(chat_id=ADMIN_ID, text=f"⚠️ {s['server_name']} оффлайн ({int(diff)}с)")
        elif diff <= 60 and s['is_online'] == 0:
            cursor.execute("UPDATE heartbeats SET is_online = 1 WHERE server_name = ?", (s['server_name'],))
            conn.commit()
            await context.bot.send_message(chat_id=ADMIN_ID, text=f"✅ {s['server_name']} онлайн")
    conn.close()

async def send_daily_digest(context: ContextTypes.DEFAULT_TYPE):
    try:
        digest = generate_daily_digest()
        with open(digest['chart_path'], 'rb') as photo:
            await context.bot.send_photo(chat_id=ADMIN_ID, photo=photo, caption=digest['text'], reply_markup=get_main_menu(), parse_mode='HTML')
    except Exception as e:
        logger.error(f"Ошибка дайджеста: {e}")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("⛔ Доступ запрещён.")
        return
    action, ip = query.data.split("_", 1)
    if action == "block":
        result = handle_block_ip(ip)
        await query.edit_message_text(text=f"{query.message.text}\n\n{result['message']}", reply_markup=get_main_menu())
    elif action == "whitelist":
        result = handle_whitelist_ip(ip)
        await query.edit_message_text(text=f"{query.message.text}\n\n{result['message']}", reply_markup=get_main_menu())
    elif action == "history":
        events = get_ip_history(ip)
        text = f"📋 {ip}:\n" + "\n".join([f"• {e['timestamp']} | {e['severity']}" for e in events[:5]]) if events else "📭 Пусто"
        await query.message.reply_text(text, reply_markup=get_main_menu())

def run_flask():
    app.run(host='0.0.0.0', port=5000, use_reloader=False)

def main():
    print("🚀 Запуск SecBot...")
    threading.Thread(target=run_flask, daemon=True).start()
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CallbackQueryHandler(menu_callback, pattern="^cmd_"))
    application.add_handler(CallbackQueryHandler(button_callback, pattern="^(block|whitelist|history)_"))
    application.job_queue.run_repeating(check_notifications, interval=5, first=5)
    application.job_queue.run_repeating(check_heartbeats, interval=15, first=15)
    application.job_queue.run_daily(send_daily_digest, time=time(hour=9, minute=0), days=list(range(7)), name="daily_digest")
    print("✅ Бот готов. Отправь /start")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()