from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt6 import uic, QtCore
import socket
import threading


class ServerThread(QtCore.QThread):
    message_received = QtCore.pyqtSignal(str)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.message_received.emit(f"🚀 Сервер запущен на {self.host}:{self.port}")

        while self.running:
            client, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client,)).start()

    def handle_client(self, client):
        with client:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                self.message_received.emit(f"Client: {data.decode()}")

    def stop(self):
        self.running = False
        self.server.close()


class ClientThread(QtCore.QThread):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = None

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.host, self.port))
            self.parent().message_received.emit(f"✅ Подключено к {self.host}:{self.port}")
        except Exception as e:
            self.parent().message_received.emit(f"❌ Ошибка подключения: {str(e)}")

    def send_message(self, message):
        if self.sock:
            self.sock.sendall(message.encode())


class MainWindow(QMainWindow):
    message_received = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        uic.loadUi('qtGUI.ui', self)
        self.server_thread = None
        self.client_thread = None
        self.init_ui()

    def init_ui(self):
        self.start_server_btn.clicked.connect(self.start_server)
        self.start_client_btn.clicked.connect(self.start_client)
        self.stop_btn.clicked.connect(self.stop_all)
        self.send_btn.clicked.connect(self.send_message)
        self.message_received.connect(self.show_message)

        # Установка значений по умолчанию
        self.ip_text.setText("0.0.0.0")
        self.port_text.setText("65433")

    def show_message(self, msg):
        self.chat_text.append(msg)

    def start_server(self):
        host = self.ip_text.text()
        port = int(self.port_text.text())
        self.server_thread = ServerThread(host, port)
        self.server_thread.message_received.connect(self.show_message)
        self.server_thread.start()
        self.message_received.emit("Сервер запущен...")

    def start_client(self):
        host = self.ip_text.text()
        port = int(self.port_text.text())
        self.client_thread = ClientThread(host, port)
        self.client_thread.start()

    def send_message(self):
        message = self.message_input.text()
        if self.client_thread and self.client_thread.isRunning():
            self.client_thread.send_message(message)
            self.show_message(f"You: {message}")
            self.message_input.clear()

    def stop_all(self):
        if self.server_thread and self.server_thread.isRunning():
            self.server_thread.stop()
        if self.client_thread and self.client_thread.isRunning():
            self.client_thread.terminate()
        self.message_received.emit("⏹ Все соединения остановлены")


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()