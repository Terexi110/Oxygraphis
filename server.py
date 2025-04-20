import socket
import threading

from gostcrypto import gosthash
from gostcrypto import gostcipher
from Oxygraphs import *

# Параметры
q = 2**12
p = 32
n = 8
threshold = 126
d = q // p
offset = d // 2

server_socket = None
shared_key = None


class Peer:
    def __init__(self, host='127.0.0.1', port=65433):
        self.host = host
        self.port = port
        self.shared_key = None
        self.connections = []
        self.listener = None

    def start(self):
        """Запуск в двух потоках: слушатель и возможность подключения к другим пирам"""
        import threading
        self.listener = threading.Thread(target=self._listen)
        self.listener.start()
        print(f"Peer started on {self.host}:{self.port}")

    def _listen(self):
        """Прослушивание входящих соединений"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                print(f"Connected by {addr}")
                self.connections.append(conn)
                threading.Thread(target=self._handle_connection, args=(conn,)).start()

    def _handle_connection(self, conn):
        """Обработка ключей и сообщений для конкретного соединения"""
        try:
            # Обмен ключами
            pk, sk = keygen()
            conn.send(serialize_poly(pk[0]))  # Отправка публичного ключа
            u = deserialize_poly(conn.recv(1024))  # Получение ciphertext
            self.shared_key = decapsulate(u, sk)  # Сохранение ключа для этого соединения

            # Цикл приема сообщений
            while True:
                data = conn.recv(1024)
                if not data: break
                print("Received:", self._decrypt(data))
        finally:
            conn.close()

    def connect(self, peer_host, peer_port):
        """Подключение к другому пиру"""
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((peer_host, peer_port))
        self.connections.append(conn)

        # Обмен ключами
        their_pk = deserialize_poly(conn.recv(1024))
        ciphertext, key = encapsulate(their_pk)
        conn.send(serialize_poly(ciphertext))
        self.shared_key = key  # Сохранение ключа

        threading.Thread(target=self._handle_connection, args=(conn,)).start()

    def send(self, message):
        """Отправка сообщения всем подключенным пирам"""
        if not self.shared_key: return
        encrypted = self._encrypt(message)
        for conn in self.connections:
            conn.send(encrypted)

def cleanup():
    if 'server_socket' in globals() and server_socket:
        print("\nClosing server socket...")
        try:
            server_socket.shutdown(socket.SHUT_RDWR)
            server_socket.close()
            print("Server socket closed successfully")
        except Exception as e:
            print(f"Error closing socket: {e}")


##########################
# Основная функция сервера
##########################

def main():
    HOST = '127.0.0.1'
    PORT = 65433

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        handle_client(conn, addr)

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
