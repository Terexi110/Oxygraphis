import socket
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6 import uic
from gostcrypto import gostcipher
import server2
import client


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('qtGUI.ui', self)
        self.init_ui()
        self.crypto = None
        self.connection = None
        self.server_thread = None
        self.client_thread = None

    def init_ui(self):
        self.start_server_btn.clicked.connect(self.start_server)
        self.start_client_btn.clicked.connect(self.start_client)
        self.send_btn.clicked.connect(self.send_message)
        self.stop_btn.clicked.connect(self.stop_all)

        self.ip_text.setText("0.0.0.0")
        self.port_text.setText("65433")

        self.message_received.connect(self.show_message)

    message_received = pyqtSignal(str)

    def start_server(self):
        ip, port = self.get_connection_params()
        if ip is None:
            return
        self.server_thread = ServerThread(ip, port)
        self.server_thread.main_window = self
        self.server_thread.status_signal.connect(self.show_message)
        self.server_thread.message_received.connect(self.message_received.emit)
        self.server_thread.start()

    def start_client(self):
        ip, port = self.get_connection_params()
        if ip is None:
            return
        self.client_thread = ClientThread(ip, port)
        self.client_thread.main_window = self
        self.client_thread.status_signal.connect(self.show_message)
        self.client_thread.message_received.connect(self.message_received.emit)
        self.client_thread.start()

    def stop_all(self):
        if hasattr(self, 'server_thread') and self.server_thread.isRunning():
            self.server_thread.terminate()
        if hasattr(self, 'client_thread') and self.client_thread.isRunning():
            self.client_thread.terminate()
        self.show_message("⏹ Соединение остановлено")
        self.crypto = None
        self.connection = None
        if self.crypto:
            self.crypto = None

    def send_message(self):
        if not (self.server_thread or self.client_thread):
            self.show_message("🔴 Сначала подключитесь!")
            return

        msg = self.message_input.text()
        if not msg:
            return

        encrypted = self.crypto.encrypt(msg.encode())
        try:
            if self.server_thread:
                self.server_thread.conn.send(len(encrypted).to_bytes(4, 'big') + encrypted)
            else:
                self.client_thread.sock.send(len(encrypted).to_bytes(4, 'big') + encrypted)
                self.show_message(f"Вы: {msg}")
        except Exception as e:
            self.show_message(f"🔴 Ошибка отправки: {str(e)}")

        self.message_input.clear()

    def get_connection_params(self):
        ip = self.ip_text.text().strip()
        port = self.port_text.text().strip()
        if not (ip and port):
            self.show_message("🔴 Введите IP и порт!")
            return None, None
        try:
            return ip, int(port)
        except ValueError:
            self.show_message("🔴 Некорректный порт!")
            return None, None

    def show_message(self, message):
        self.statusBar().showMessage(message)


class ServerThread(QThread):
    message_received = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.running = True

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.ip, self.port))
            self.sock.listen()
            self.status_signal.emit("🟢 Сервер запущен")
            while self.running:
                conn, addr = self.sock.accept()
                self.conn = conn
                self.status_signal.emit(f"🔗 Подключен клиент: {addr}")
                while self.running:
                    data = self.recv_exact(conn, 4)
                    if not data:
                        break
                    length = int.from_bytes(data, 'big')
                    encrypted_msg = self.recv_exact(conn, length)
                    decrypted = self.main_window.crypto.decrypt(encrypted_msg)
                    self.message_received.emit(f"Клиент: {decrypted.decode()}")
        except Exception as e:
            self.status_signal.emit(f"🔴 Ошибка: {str(e)}")

    def recv_exact(self, conn, length):
        data = b''
        while len(data) < length:
            packet = conn.recv(length - len(data))
            if not packet:
                break
            data += packet
        return data

    def stop(self):
        self.running = False
        if hasattr(self, 'sock'):
            self.sock.close()

class ClientThread(QThread):
    message_received = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ip, self.port))
            self.status_signal.emit("🟢 Подключено к серверу")
            while True:
                data = self.recv_exact(4)
                if not data:
                    break
                length = int.from_bytes(data, 'big')
                encrypted_msg = self.recv_exact(length)
                decrypted = self.main_window.crypto.decrypt(encrypted_msg)
                self.message_received.emit(f"Сервер: {decrypted.decode()}")
        except Exception as e:
            self.status_signal.emit(f"🔴 Ошибка: {str(e)}")

    def recv_exact(self, length):
        data = b''
        while len(data) < length:
            packet = self.sock.recv(length - len(data))
            if not packet:
                break
            data += packet
        return data


class KuznechikCipher:
    def __init__(self, key):
        self.key = key
        self.iv = b'\x00'*16  # Для режима CBC требуется IV

    def encrypt(self, plaintext):
        cipher = gostcipher.new('kuznechik', self.key, gostcipher.MODE_CBC, init_vect=self.iv)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        cipher = gostcipher.new('kuznechik', self.key, gostcipher.MODE_CBC, init_vect=self.iv)
        return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())