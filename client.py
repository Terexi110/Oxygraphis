import argparse
import socket
import threading

from gostcrypto import gosthash
import random
import struct

# Параметры
q = 2 ** 12
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
# Кастомизированные функции округления и hint
##########################

def poly_round(poly, d, offset):
    """
    Округление: вычисляем floor((x+offset)/d) для каждого коэффициента.
    Обычно offset выбирают равным d//2.
    """
    return [int((x + offset) / d) % p for x in poly]


def compute_hint(poly_raw, d, threshold):
    """
    Вычисление hint: для каждого коэффициента, если остаток от деления на d больше или равен threshold, возвращаем 1, иначе 0.
    """
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
# Функции для сэмплирования и генерации полиномов
##########################

def generate_uniform_poly(mod):
    """Генерация случайного полинома с коэффициентами из Z_mod."""
    return [random.randrange(mod) for _ in range(n)]


def sample_secret():
    """Сэмплирование секретного полинома с малыми коэффициентами (здесь выбираем 0 или 1)."""
    return [random.choice([0, 1]) for _ in range(n)]


##########################
# Функция reconcile (корректировка)
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
    pk = (a, b)  # Публичный ключ
    # Секретный ключ не передается!
    return pk, s  # Возвращаем только публичный ключ


def encapsulate(pk, offset, threshold):
    a, b = pk
    m = [random.choice([0, 1]) for _ in range(n)]
    m_enc = encode_message(m)
    s_prime = sample_secret()  # Эфемерный секрет для сессии
    u_product = poly_mul(a, s_prime, q)
    u = poly_round(u_product, d, offset)
    b_product = poly_mul(b, s_prime, q)
    hint = compute_hint(b_product, d, threshold)
    v_round = poly_round(b_product, d, offset)
    v = [(v_round[i] + m_enc[i]) % p for i in range(n)]
    ciphertext = (u, v, hint)
    shared_key = hash_shared(serialize_poly(m))  # Общий ключ для проверки

    print("[Client] Original m:", m)
    return ciphertext, shared_key


def decapsulate(ciphertext, sk, offset):
    u, v, hint = ciphertext
    us_product = poly_mul(u, sk, q)
    w = poly_round(us_product, d, offset)
    w_adjusted = [reconcile(w[i], hint[i]) for i in range(n)]
    m_enc_recovered = [(v[i] - w_adjusted[i]) % p for i in range(n)]
    m_recovered = decode_message(m_enc_recovered)
    shared_key = hash_shared(serialize_poly(m_recovered))
    return shared_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='192.168.235.124', help='Server IP address')
    args = parser.parse_args()

    HOST = args.host
    PORT = 65433

    def receive_messages():
        while True:
            try:
                msg_length_data = s.recv(4)
                if not msg_length_data:
                    break
                msg_length = int.from_bytes(msg_length_data, 'big')
                message = s.recv(msg_length).decode('utf-8')
                print(f"\nСервер: {message}\nВы: ", end='')
            except:
                break

    def send_messages():
        while True:
            try:
                message = input("Вы: ")
                if message.lower() == 'exit':
                    s.close()
                    break
                data = message.encode('utf-8')
                s.sendall(len(data).to_bytes(4, 'big'))
                s.sendall(data)
            except:
                break

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        def recv_exact(length):
            data = b''
            while len(data) < length:
                packet = s.recv(length - len(data))
                if not packet:
                    break
                data += packet
            return data

        # Прием публичного ключа в правильном порядке
        a_len = int.from_bytes(recv_exact(4), 'big')  # Сначала длина a
        a_data = recv_exact(a_len)
        a = deserialize_poly(a_data, n)

        b_len = int.from_bytes(recv_exact(4), 'big')  # Затем длина b
        b_data = recv_exact(b_len)
        b = deserialize_poly(b_data, n)

        pk = (a, b)

        # Генерация и отправка ciphertext
        ciphertext, shared_key = encapsulate(pk, offset, threshold)
        u, v, hint = ciphertext

        s.sendall(len(serialize_poly(u)).to_bytes(4, 'big') + serialize_poly(u))
        s.sendall(len(serialize_poly(v)).to_bytes(4, 'big') + serialize_poly(v))
        s.sendall(len(bytes(hint)).to_bytes(4, 'big') + bytes(hint))

        # Проверка хэша
        server_hash = recv_exact(32)
        client_hash = gosthash.new('streebog256', data=shared_key).digest()

        print("Shared key:", shared_key.hex())
        print("Keys match!" if server_hash == client_hash else "Keys mismatch!")
        with open('client_key.bin', 'wb') as f:
            f.write(shared_key)

        print("Начало чата (введите 'exit' для выхода)")
        receive_thread = threading.Thread(target=receive_messages)
        send_thread = threading.Thread(target=send_messages)

        receive_thread.start()
        send_thread.start()

        receive_thread.join()
        send_thread.join()


if __name__ == "__main__":
    main()