import socket
import os
from concurrent.futures import ThreadPoolExecutor

ENV_FILE = os.path.join(os.path.dirname(__file__), ".env")


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def _probe(args):
    ip, port = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            if sock.connect_ex((ip, port)) == 0:
                return f"http://{ip}:{port}"
    except Exception:
        pass
    return None


def find_bot(target_port=5000):
    """
    Ищет сервер CyberBot в локальной сети по порту.
    Возвращает URL вида 'http://192.168.x.x:5000' или None.
    """
    my_ip = get_local_ip()
    if not my_ip:
        print("[auto_start] Не удалось определить локальный IP.")
        return None

    print(f"[auto_start] Мой IP: {my_ip}. Сканирую /{target_port}...")
    subnet = ".".join(my_ip.split(".")[:3]) + "."
    candidates = [
        (f"{subnet}{i}", target_port)
        for i in range(1, 255)
        if f"{subnet}{i}" != my_ip
    ]

    with ThreadPoolExecutor(max_workers=50) as ex:
        for result in ex.map(_probe, candidates):
            if result:
                print(f"[auto_start] Сервер найден: {result}")
                _save_to_env(result)
                return result

    print("[auto_start] Сервер не найден в локальной сети.")
    return None


def _save_to_env(url):
    """Записывает найденный BOT_URL в .env, заменяя старое значение."""
    lines = []
    replaced = False

    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("BOT_URL="):
                    lines.append(f"BOT_URL={url}\n")
                    replaced = True
                else:
                    lines.append(line)

    if not replaced:
        lines.append(f"BOT_URL={url}\n")

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"[auto_start] BOT_URL сохранён в .env: {url}")


if __name__ == "__main__":
    url = find_bot()
    if url:
        print(f"Готово: {url}")
    else:
        print("Сервер не найден. Укажи BOT_URL вручную в .env")
