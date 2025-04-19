import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6 import uic
from gostcrypto import gostcipher
import server2
import client
import base64


class CryptoManager:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        """Шифрование сообщения алгоритмом Кузнечик"""
        cipher_obj = gostcipher.new('kuznechik',
                                    data=message.encode('utf-8'),
                                    key=self.key,
                                    cipher_mode='cbc',
                                    init_vect=b'\x00' * 16)
        return base64.b64encode(cipher_obj.encrypt()).decode('utf-8')

    def decrypt(self, encrypted):
        """Дешифрование сообщения алгоритмом Кузнечик"""
        cipher_obj = gostcipher.new('kuznechik',
                                    data=base64.b64decode(encrypted),
                                    key=self.key,
                                    cipher_mode='cbc',
                                    init_vect=b'\x00' * 16)
        return cipher_obj.decrypt().decode('utf-8').strip()


class ServerThread(QThread):
    message_signal = pyqtSignal(str)
    key_signal = pyqtSignal(bytes)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        server2.HOST = host
        server2.PORT = port

    def run(self):
        try:
            self.message_signal.emit(f"🟢 Сервер запущен на {self.host}:{self.port}")
            server2.main()
        except Exception as e:
            self.message_signal.emit(f"🔴 Ошибка сервера: {str(e)}")


class ClientThread(QThread):
    message_signal = pyqtSignal(str)
    key_signal = pyqtSignal(bytes)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        client.HOST = host
        client.PORT = port

    def run(self):
        try:
            self.message_signal.emit(f"🔵 Подключение к {self.host}:{self.port}...")
            client.main()
            self.key_signal.emit(client.shared_key)
        except Exception as e:
            self.message_signal.emit(f"🔴 Ошибка клиента: {str(e)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi('qtGUI.ui', self)
        self.init_ui()
        self.crypto = None
        self.connection = None

    def init_ui(self):
        self.start_server_btn.clicked.connect(self.start_server)
        self.start_client_btn.clicked.connect(self.start_client)
        self.send_btn.clicked.connect(self.send_message)
        self.stop_btn.clicked.connect(self.stop_all)

        self.ip_text.setText("127.0.0.1")
        self.port_text.setText("65433")

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

    def start_server(self):
        ip, port = self.get_connection_params()
        if not ip or not port: return

        self.server_thread = ServerThread(ip, port)
        self.server_thread.message_signal.connect(self.show_message)
        self.server_thread.key_signal.connect(self.init_crypto)
        self.server_thread.start()
        self.connection = 'server'

    def start_client(self):
        ip, port = self.get_connection_params()
        if not ip or not port: return

        self.client_thread = ClientThread(ip, port)
        self.client_thread.message_signal.connect(self.show_message)
        self.client_thread.key_signal.connect(self.init_crypto)
        self.client_thread.start()
        self.connection = 'client'

    def init_crypto(self, key):
        self.crypto = CryptoManager(key)
        self.show_message("🔑 Криптографическая система активирована")

    def send_message(self):
        if not self.crypto:
            self.show_message("🔴 Сначала установите соединение!")
            return

        message = self.message_input.toPlainText().strip()
        if not message:
            self.show_message("🔴 Введите сообщение!")
            return

        try:
            encrypted = self.crypto.encrypt(message)
            if self.connection == 'client':
                self.client.sock.sendall(encrypted.encode())
            elif self.connection == 'server':
                self.server.conn.sendall(encrypted.encode())
            self.show_message(f"📤 Вы: {message}")
            self.message_input.clear()
        except Exception as e:
            self.show_message(f"🔴 Ошибка отправки: {str(e)}")

    def stop_all(self):
        if hasattr(self, 'server_thread') and self.server_thread.isRunning():
            self.server_thread.terminate()
        if hasattr(self, 'client_thread') and self.client_thread.isRunning():
            self.client_thread.terminate()
        self.show_message("⏹ Соединение остановлено")
        self.crypto = None
        self.connection = None

    def show_message(self, text):
        self.statusBar().showMessage(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())