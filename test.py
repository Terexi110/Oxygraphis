import random
import hashlib

# Параметры для демонстрации (упрощённые и небезопасные)
#q = 2**8  # Модуль для арифметики в кольце Z_q
#p = 2**4  # Новая точность после округления (результат в Z_p)
#n = 2**2   # Степень полинома (число коэффициентов)
#d = q // p  # Фактор деления для округления (d = 16)
#res = []


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
    """Сериализация полинома (каждый коэффициент – 1 байт)"""
    return bytes(poly)

def hash_shared(data):
    """Хэширование (SHA-256) для получения общего ключа"""
    return hashlib.sha256(data).digest()

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
    """
    Генерация ключей: публичный и секретный ключи.
    offset – смещение для функции округления.
    """
    a = generate_uniform_poly(q)  # Публичный полином
    s = sample_secret()  # Секретный полином
    as_product = poly_mul(a, s, q)
    b = poly_round(as_product, d, offset)  # Публичный ключ b(x)
    pk = (a, b)  # Публичный ключ
    sk = s  # Секретный ключ, который не передается
    return pk, sk

def encapsulate(pk, offset, threshold):
    """
    Инкапсуляция: генерируем эфемерный секрет и вычисляем шифротекст.
    pk – публичный ключ,
    offset – смещение для округления,
    threshold – порог для подсказки (hint).
    """
    a, b = pk
    m = [random.choice([0, 1]) for _ in range(n)]  # Сообщение
    m_enc = encode_message(m)  # Кодирование сообщения
    s_prime = sample_secret()  # Эфемерный секрет для инкапсуляции
    u_product = poly_mul(a, s_prime, q)  # Умножение полиномов
    u = poly_round(u_product, d, offset)
    b_product = poly_mul(b, s_prime, q)  # Вычисление b'(x)
    hint = compute_hint(b_product, d, threshold)  # Вычисление подсказки
    v_round = poly_round(b_product, d, offset)
    v = [(v_round[i] + m_enc[i]) % p for i in range(n)]  # Шифротекст
    ciphertext = (u, v, hint)  # Шифротекст
    shared_key = hash_shared(serialize_poly(m))  # Общий ключ
    return ciphertext, shared_key

def decapsulate(ciphertext, sk, offset):
    """
    Декапсуляция: восстановление общего ключа с использованием только публичного ключа.
    """
    u, v, hint = ciphertext
    us_product = poly_mul(u, sk, q)  # Умножение полиномов с использованием секретного ключа
    w = poly_round(us_product, d, offset)  # Округление
    w_adjusted = [reconcile(w[i], hint[i]) for i in range(n)]  # Корректировка
    m_enc_recovered = [(v[i] - w_adjusted[i]) % p for i in range(n)]  # Восстановление сообщения
    m_recovered = decode_message(m_enc_recovered)  # Декодирование сообщения
    shared_key = hash_shared(serialize_poly(m_recovered))  # Генерация общего ключа
    return shared_key

def test_kem(trials, offset, threshold):
    """
    Функция тестирования КЕМ.
    Возвращает долю успешных итераций.
    """
    success = 0
    for i in range(trials):
        pk, sk = keygen(offset)
        ciphertext, shared_key_enc = encapsulate(pk, offset, threshold)
        shared_key_dec = decapsulate(ciphertext, sk, offset)
        if shared_key_enc == shared_key_dec:
            success += 1
    return success / trials

# Тестирование
trials = 10000
q = 2**12
p = 32
n = 8
threshold = 126
d = q // p
offset = d // 2
print(test_kem(trials, offset, threshold))


# 2**12
#32 8 128 0.73
#32 8 126 0.72