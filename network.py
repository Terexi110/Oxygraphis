import argparse
import subprocess
import os
import socket
import time

def is_port_open():
    """Проверяет, доступен ли порт сервера."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('0.0.0.0', 65433))
        return True
    except ConnectionRefusedError:
        return False
    finally:
        sock.close()

def run_component(force_server=False, force_client=False):
    """Запускает сервер или клиент в зависимости от условий."""
    # Принудительный режим
    if force_server:
        print("🟢 Forcing server mode")
        subprocess.run(["python", "server2.py"])
        return

    if force_client:
        print("🟢 Forcing client mode")
        subprocess.run(["python", "client.py"])
        return

    # Автоопределение режима
    if is_port_open():
        print("🔵 Server is running, starting client...")
        subprocess.run(["python", "client.py"])
    else:
        print("🔵 Server not found, starting server...")
        subprocess.run(["python", "server2.py"])

if __name__ == "__main__":
    # Очистка старых ключей
    for key_file in ["server_key.bin", "client_key.bin"]:
        if os.path.exists(key_file):
            os.remove(key_file)

    # Парсинг аргументов
    parser = argparse.ArgumentParser(description="KEM Protocol Launcher")
    parser.add_argument('--server', action='store_true', help='Force server mode')
    parser.add_argument('--client', action='store_true', help='Force client mode')
    args = parser.parse_args()

    # Запуск с учетом аргументов
    try:
        run_component(
            force_server=args.server,
            force_client=args.client
        )
    except KeyboardInterrupt:
        print("\n🚨 Operation cancelled by user")