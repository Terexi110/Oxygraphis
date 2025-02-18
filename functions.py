import random
import numpy as np
import hashlib
import matplotlib.pyplot as plt

# Параметры для демонстрации (упрощённые и небезопасные)
q = 2**7  # Модуль для арифметики в кольце Z_q
p = 2**3  # Новая точность после округления (результат в Z_p)
n = 2**4   # Степень полинома (число коэффициентов)
d = q // p  # Фактор деления для округления (d = 16)


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

def poly_round_custom(poly, d, offset):
    """
    Округление: вычисляем floor((x+offset)/d) для каждого коэффициента.
    Обычно offset выбирают равным d//2.
    """
    return [int((x + offset) / d) % p for x in poly]

def compute_hint_custom(poly_raw, d, threshold):
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

##########################
# КЕМ: keygen, encapsulate, decapsulate с параметрами округления
##########################

def keygen_custom(offset):
    """
    Генерация ключей с использованием кастомизированного округления.
    offset – смещение для функции округления.
    """
    a = generate_uniform_poly(q)
    s = sample_secret()
    as_product = poly_mul(a, s, q)
    b = poly_round_custom(as_product, d, offset)
    pk = (a, b)
    sk = s
    return pk, sk

def encapsulate_custom(pk, offset, threshold):
    """
    Инкапсуляция с параметрами:
      offset – смещение для округления,
      threshold – порог для вычисления hint.
    """
    a, b = pk
    m = [random.choice([0, 1]) for _ in range(n)]
    m_enc = encode_message(m)
    s_prime = sample_secret()
    u_product = poly_mul(a, s_prime, q)
    u = poly_round_custom(u_product, d, offset)
    b_product = poly_mul(b, s_prime, q)
    hint = compute_hint_custom(b_product, d, threshold)
    v_round = poly_round_custom(b_product, d, offset)
    v = [(v_round[i] + m_enc[i]) % p for i in range(n)]
    ciphertext = (u, v, hint)
    shared_key = hash_shared(serialize_poly(m))
    return ciphertext, shared_key

def decapsulate_custom(ciphertext, sk, offset):
    """
    Декапсуляция с использованием заданного offset для округления.
    """
    u, v, hint = ciphertext
    us_product = poly_mul(u, sk, q)
    w = poly_round_custom(us_product, d, offset)
    w_adjusted = [reconcile(w[i], hint[i]) for i in range(n)]
    m_enc_recovered = [(v[i] - w_adjusted[i]) % p for i in range(n)]
    m_recovered = decode_message(m_enc_recovered)
    shared_key = hash_shared(serialize_poly(m_recovered))
    return shared_key

def test_kem_custom(trials, offset, threshold):
    """
    Функция тестирования КЕМ:
      trials – количество итераций,
      offset – смещение для округления,
      threshold – порог для compute_hint.
    Возвращает долю успешных итераций.
    """
    success = 0
    for i in range(trials):
        pk, sk = keygen_custom(offset)
        ciphertext, shared_key_enc = encapsulate_custom(pk, offset, threshold)
        shared_key_dec = decapsulate_custom(ciphertext, sk, offset)
        if shared_key_enc == shared_key_dec:
            success += 1
    print(success / trials)

##########################
# Эксперимент и построение графика
##########################

test_kem_custom(1000, d // 2, 17)
