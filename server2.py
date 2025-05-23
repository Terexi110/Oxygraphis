import socket
from gostcrypto import gosthash
import random
import struct

# Параметры
q = 2**12
p = 32
n = 8
threshold = 126
d = q // p
offset = d // 2

##########################
# ФУНКЦИИ ДЛЯ ПОЛИНОМОВ
##########################

def poly_mul(a, b, mod):
    """Умножение двух полиномов в кольце Z_mod[x]/(x^n+1)"""
    result = [0] * n
    for i in range(n):
        for j in range(n):
            k = i + j
            if k < n:
                result[k] = (result[k] + a[i] * b[j]) % mod
            else:
                result[k - n] = (result[k - n] - a[i] * b[j]) % mod
    return [x % mod for x in result]

##########################
# ФУНКЦИИ ОКРУГЛЕНИЯ И HINT
##########################

def poly_round(poly, d, offset):
    return [int((x + offset) / d) % p for x in poly]

def compute_hint(poly_raw, d, threshold):
    return [1 if (x % d) >= threshold else 0 for x in poly_raw]

##########################
# Кодирование/декодирование сообщения
##########################

def encode_message(m):
    """Кодирование: 0 -> 0, 1 -> p//2"""
    return [bit * (p // 2) for bit in m]

def decode_message(poly):
    """Декодирование: значение >= p//2 интерпретируется как 1, иначе 0"""
    return [1 if coeff >= (p // 2) else 0 for coeff in poly]

def serialize_poly(poly):
    return b''.join(struct.pack('!H', coeff % (2**16)) for coeff in poly)

def deserialize_poly(data, n):
    return list(struct.unpack('!{}H'.format(n), data))

def hash_shared(data):
    """
        Хэширование по алгоритму Кузнечик (256-битная версия)
        Поддерживает как байты, так и списки коэффициентов
        """
    if isinstance(data, list):
        data = serialize_poly(data)
    elif not isinstance(data, bytes):
        data = bytes(data)
    return gosthash.new('streebog256', data=data).digest()

##########################
# Функции генерации полиномов
##########################

def generate_uniform_poly(mod):
    return [random.randrange(mod) for _ in range(n)]

def sample_secret():
    return [random.choice([0, 1]) for _ in range(n)]

##########################
# Функция reconcile
##########################

def reconcile(value, hint):
    if hint == 1 and value < (p - 1):
        return value + 1
    elif hint == 0 and value > 0:
        return value - 1
    return value

def keygen(offset):
    a = generate_uniform_poly(q)
    s = sample_secret()  # Секретный ключ для отправителя
    as_product = poly_mul(a, s, q)
    b = poly_round(as_product, d, offset)
    pk = (a, b)
    return pk, s

def encapsulate(pk, offset, threshold):
    a, b = pk
    m = [random.choice([0, 1]) for _ in range(n)]
    m_enc = encode_message(m)
    s_prime = sample_secret()
    u_product = poly_mul(a, s_prime, q)
    u = poly_round(u_product, d, offset)
    b_product = poly_mul(b, s_prime, q)
    hint = compute_hint(b_product, d, threshold)
    v_round = poly_round(b_product, d, offset)
    v = [(v_round[i] + m_enc[i]) % p for i in range(n)]
    ciphertext = (u, v, hint)
    shared_key = hash_shared(serialize_poly(m))
    return ciphertext, shared_key

def decapsulate(ciphertext, sk, offset):
    u, v, hint = ciphertext
    us_product = poly_mul(u, sk, q)
    w = poly_round(us_product, d, offset)
    w_adjusted = [reconcile(w[i], hint[i]) for i in range(n)]
    m_enc_recovered = [(v[i] - w_adjusted[i]) % p for i in range(n)]
    m_recovered = decode_message(m_enc_recovered)
    shared_key = hash_shared(serialize_poly(m_recovered))
    print("[Server] Decapsulated m_recovered:", m_recovered)
    return shared_key

def cleanup():
    global server_socket
    if 'server_socket' in globals() and server_socket:
        print("\nClosing server socket...")
        try:
            server_socket.shutdown(socket.SHUT_RDWR)
            server_socket.close()
            print("Server socket closed successfully")
        except Exception as e:
            print(f"Error closing socket: {e}")

##########################
# Функция для приема одного соединения
##########################

def handle_client(conn, addr):
    print(f"Connected by {addr}")

    def recv_exact(length):
        data = b''
        while len(data) < length:
            packet = conn.recv(length - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive_messages():
        while True:
            try:
                # Прием сообщения
                msg_length_data = recv_exact(4)
                if not msg_length_data:
                    break
                msg_length = int.from_bytes(msg_length_data, 'big')
                message = recv_exact(msg_length).decode('utf-8')
                print(f"[Клиент {addr}]: {message}")
            except:
                break

    def send_messages():
        while True:
            try:
                message = input("Сервер: ")
                if message.lower() == 'exit':
                    conn.close()
                    break
                data = message.encode('utf-8')
                conn.sendall(len(data).to_bytes(4, 'big'))
                conn.sendall(data)
            except:
                break

    try:
        # Генерация ключей
        pk, sk = keygen(offset)
        a, b = pk

        # Сериализация публичного ключа
        a_bytes = serialize_poly(a)
        b_bytes = serialize_poly(b)

        # Отправка публичного ключа с указанием длины
        conn.sendall(len(a_bytes).to_bytes(4, 'big') + a_bytes)
        conn.sendall(len(b_bytes).to_bytes(4, 'big') + b_bytes)

        # Прием ciphertext
        u_len = int.from_bytes(recv_exact(4), 'big')
        u = deserialize_poly(recv_exact(u_len), n)

        v_len = int.from_bytes(recv_exact(4), 'big')
        v = deserialize_poly(recv_exact(v_len), n)

        hint_len = int.from_bytes(recv_exact(4), 'big')
        hint = list(recv_exact(hint_len))

        ciphertext = (u, v, hint)
        shared_key = decapsulate(ciphertext, sk, offset)

        # Отправка подтверждения в виде хэша
        confirmation = gosthash.new('streebog256', data=shared_key).digest()
        conn.sendall(confirmation)
        print("Shared key:", shared_key.hex())

        print("Начало обмена сообщениями...")
        while True:
            # Прием сообщения от клиента
            msg_length = int.from_bytes(recv_exact(4), 'big')
            message = recv_exact(msg_length).decode('utf-8')
            print(f"[{addr}] Сообщение: {message}")

            # Отправка ответа
            response = f"Ответ на: {message}"
            conn.sendall(len(response.encode()).to_bytes(4, 'big'))
            conn.sendall(response.encode())

        with open('server_key.bin', 'wb') as f:
            f.write(shared_key)

        receive_thread = threading.Thread(target=receive_messages)
        send_thread = threading.Thread(target=send_messages)

        receive_thread.start()
        send_thread.start()

        receive_thread.join()
        send_thread.join()
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.\n")

##########################
# Основная функция сервера
##########################

def main():
    HOST = '0.0.0.0'
    PORT = 65433

    # Создаем сокет и разрешаем быстрое переиспользование порта
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on {HOST}:{PORT}")

        # Бесконечный цикл для постоянного приёма соединений
        while True:
            try:
                conn, addr = s.accept()
                handle_client(conn, addr)
            except KeyboardInterrupt:
                print("Server interrupted by user. Shutting down.")
                break
            except Exception as e:
                print(f"Error accepting connections: {e}")
                continue

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
