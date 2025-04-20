import socket
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6 import uic
from gostcrypto import gostcipher
from client import main as client_main
#from server2 import main as server_main
from server import Peer

global key


class MainWindow(QMainWindow):
    set_crypto_signal = pyqtSignal(bytes)
    message_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        uic.loadUi('qtGUI.ui', self)
        self.server_thread = None
        self.client_thread = None
        self.init_ui()
        self.peer = Peer()
        self.peer.start()

    def init_ui(self):
        self.start_server_btn.clicked.connect(self.start_connection)
        self.start_client_btn.clicked.connect(self.start_client)
        self.stop_btn.clicked.connect(self.stop_all)
        self.ip_text.setText("127.0.0.1")
        self.port_text.setText("65433")
        self.message_received.connect(self.show_message)
        self.send_btn.clicked.connect(self.send_encrypted_message)

    def start_client(self):
        self.client_thread = ClientThread()
        self.client_thread.message_signal.connect(self.show_message)
        self.client_thread.start()

    def show_message(self, msg):
        self.chat_text.append(msg)

    def stop_all(self):
        global key
        if self.server_thread and self.server_thread.isRunning():
            self.server_thread.stop()
        if self.client_thread and self.client_thread.isRunning():
            self.client_thread.terminate()
        self.show_message("⏹ Соединение остановлено")
        key = None

    def send_encrypted_message(self):
        global key
        message = self.message_input.text()
        if not message or not key:
            return

        encrypted = self.encrypt_message(message, key)

        if self.server_thread and self.server_thread.isRunning():
            # Если запущен сервер - отправляем через клиентский сокет
            self.client_thread.send_message(encrypted)
            self.show_message(f"Сервер: {message}")
        elif self.client_thread and self.client_thread.isRunning():
            # Если запущен клиент - отправляем через серверный сокет
            self.server_thread.send_message(encrypted)
            self.show_message(f"Клиент: {message}")

        self.message_input.clear()

    def start_connection(self):
        peer_host = self.ip_text.text()
        peer_port = int(self.port_text.text())
        self.peer.connect(peer_host, peer_port)

    def send_message(self):
        message = self.message_input.text()
        self.peer.send(message)
        self.chat_text.append(f"You: {message}")

    def encrypt_message(self, message: str, key: bytes) -> bytes:
        cipher = gostcipher.new('kuznechik',
                                key=key,
                                mode=gostcipher.MODE_ECB)
        padded = message.ljust(16 * ((len(message) + 15) // 16), '\0')
        return cipher.encrypt(padded.encode('utf-8'))

    def decrypt_message(self, encrypted: bytes, key: bytes) -> str:
        cipher = gostcipher.new('kuznechik',
                                key=key,
                                mode=gostcipher.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode('utf-8').strip('\0')


class ServerThread(QThread):
    message_signal = pyqtSignal(str)
    key_received = pyqtSignal(bytes)

    def __init__(self):
        super().__init__()
        self.running = True
        self.socket = None
        self.client_socket = None

    def run(self):
        global key
        try:
            self.message_signal.emit("🔄 Сервер запущен...")
            self.socket = server_main()
            self.message_signal.emit("✅ Сервер готов к подключениям")
            self.client_socket, addr = self.socket.accept()
            self.message_signal.emit(f"🔗 Подключен клиент: {addr}")

            while self.running:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                decrypted = self.parent().decrypt_message(data, key)
                self.message_signal.emit(f"Клиент: {decrypted}")

        except Exception as e:
            self.message_signal.emit(f"❌ Ошибка сервера: {str(e)}")
        finally:
            if self.client_socket:
                self.client_socket.close()
            if self.socket:
                self.socket.close()

    def stop(self):
        self.running = False
        self.terminate()

    def send_message(self, data: bytes):
        if self.client_socketsocket:
            self.client_socket.sendall(data)


class ClientThread(QThread):
    message_signal = pyqtSignal(str)
    key_received = pyqtSignal(bytes)
    def __init__(self):
        super().__init__()
        self.running = True
        self.socket = None

    def run(self):
        try:
            self.message_signal.emit("🔄 Подключение к серверу...")
            self.socket, key_shared, success = client_main()
            if success == 1:
                self.message_signal.emit("✅ Ключи успешно обменены!")
                global key
                key = key_shared

                while self.running:
                    data = self.socket.recv(1024)
                    if not data:
                        break
                    decrypted = self.parent().decrypt_message(data, key)
                    self.message_signal.emit(f"Сервер: {decrypted}")

        except Exception as e:
            self.message_signal.emit(f"❌ Ошибка клиента: {str(e)}")
        finally:
            if self.socket:
                self.socket.close()

    def send_message(self, data: bytes):
        if self.socket:
            self.socket.sendall(data)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())