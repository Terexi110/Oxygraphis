import numpy as np
import hashlib

# Параметры протокола Saber
n = 256         # степень полинома
q = 8192        # модуль
p = 1024        # параметр p (используется для квантования: q/p = 8)
k = 3           # размерность (может быть 3, 4 или 6)


def poly_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    """
    Умножение двух полиномов a(x) и b(x) в кольце R_q = Z_q[x]/(x^n+1).
    Полиномы представлены массивами длины n.
    Выполняется свёртка, затем редукция по модулю (x^n+1) с использованием соотношения x^n = -1.
    """
    n = len(a)
    conv = np.convolve(a, b)
    result = np.empty(n, dtype=int)
    result[:n - 1] = conv[:n - 1] - conv[n:2 * n - 1]
    result[n - 1] = conv[n - 1]
    return np.mod(result, q)


def matrix_vector_mult(A: np.ndarray, S: np.ndarray, q: int) -> np.ndarray:
    """
    Умножение матрицы A (размера k x k, элементы-полиномы) на вектор S (k x n, элементы-полиномы)
    с операцией умножения полиномов в кольце R_q.
    """
    k = A.shape[0]
    n = A.shape[2]
    B = np.zeros((k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            B[i] = (B[i] + poly_mul(A[i, j], S[j], q)) % q
    return B


def sample_poly_uniform(n: int, q: int) -> np.ndarray:
    """Генерирует полином длины n с коэффициентами равномерно случайными от 0 до q-1."""
    return np.random.randint(0, q, size=n)


def sample_poly_error(n: int, bound: int = 2) -> np.ndarray:
    """
    Генерирует полином длины n с коэффициентами из распределения ошибок.
    Для большей корректности выбираем bound=2 (значения из диапазона [-2, 2]).
    """
    return np.random.randint(-bound, bound + 1, size=n)


def keygen(k: int, n: int, q: int):
    """
    Процедура KeyGen для Saber.
    Возвращает:
      pk: (A, B), где A имеет форму (k, k, n), B имеет форму (k, n)
      sk: секретный вектор S, форма (k, n)
    """
    A = np.empty((k, k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            A[i, j] = sample_poly_uniform(n, q)
    S = np.empty((k, n), dtype=int)
    E = np.empty((k, n), dtype=int)
    for i in range(k):
        S[i] = sample_poly_error(n)  # используем bound=2
        E[i] = sample_poly_error(n)
    B = (matrix_vector_mult(A, S, q) + E) % q
    pk = (A, B)
    sk = S
    return pk, sk


def vector_inner_product(vec1: np.ndarray, vec2: np.ndarray, q: int) -> np.ndarray:
    """
    Вычисляет скалярное произведение двух векторов полиномов.
    Если vec1 и vec2 имеют форму (k, n), результат — полином (длина n):
      V(x) = Σ (vec1[i](x) * vec2[i](x)) mod q.
    """
    k, n = vec1.shape
    result = np.zeros(n, dtype=int)
    for i in range(k):
        result = (result + poly_mul(vec1[i], vec2[i], q)) % q
    return result


def helprec(v: np.ndarray, q: int, p: int) -> np.ndarray:
    """
    Функция генерации подсказки (hint) для квантования.
    Для параметров q и p шаг квантования равен step = q/p (для q=8192, p=1024 → step=8).
    Подсказка вычисляется как:
       hint = 1, если остаток от деления v на step >= step/2, иначе 0.
    """
    step = q // p   # 8
    half = step // 2  # 4
    base = np.floor_divide(v, step)
    remainder = v - base * step
    hint = (remainder >= half).astype(int)
    return hint


def rec(v_prime: np.ndarray, hint: np.ndarray, q: int, p: int) -> np.ndarray:
    """
    Функция восстановления (reconciliation).
    Принимает:
      v_prime: полученное значение (в decapsulation)
      hint: подсказка, вычисленная в encapsulation
    Вычисляется квантованное значение как:
      base = floor(v_prime / (q/p))
      Если remainder = v_prime - base*(q/p) > (q/p)/2 или равен (q/p)/2 и hint==1, то округляем вверх.
    """
    step = q // p   # 8
    half = step // 2  # 4
    base = np.floor_divide(v_prime, step)
    remainder = v_prime - base * step
    adjustment = ((remainder > half) | ((remainder == half) & (hint == 1))).astype(int)
    return base + adjustment


def quantize(v: np.ndarray, q: int, p: int) -> np.ndarray:
    """
    Простое квантование (без использования подсказки).
    Для сравнения – классическое округление.
    """
    return np.rint(v / (q / p)).astype(int)


def encaps(pk: tuple, k: int, n: int, q: int, p: int, bound: int = 2):
    """
    Процедура Encaps для Saber.
    Вход:
      pk: публичный ключ (A, B), где A имеет форму (k, k, n), а B – (k, n)
      k, n, q, p: параметры протокола
      bound: параметр для генерации ошибок (используем bound=2)
    Выход:
      ct: ciphertext, кортеж (B_prime, hint)
      K: общий секрет, вычисленный как H(quantize(V))
         где V = vector_inner_product(B, S') и hint = helprec(V, q, p)
    """
    A, B = pk
    S_prime = np.empty((k, n), dtype=int)
    E_prime = np.empty((k, n), dtype=int)
    for i in range(k):
        S_prime[i] = sample_poly_error(n, bound)
        E_prime[i] = sample_poly_error(n, bound)
    B_prime = (matrix_vector_mult(A, S_prime, q) + E_prime) % q
    V = vector_inner_product(B, S_prime, q)
    hint = helprec(V, q, p)
    # Для вычисления общего секрета используем стандартное квантование
    mu = quantize(V, q, p)
    V_bytes = mu.astype(np.int32).tobytes()
    K = hashlib.sha256(V_bytes).digest()
    ct = (B_prime, hint)
    return ct, K


def decaps(ct: tuple, sk: np.ndarray, k: int, n: int, q: int, p: int) -> bytes:
    """
    Процедура Decaps для Saber.
    Вход:
      ct: ciphertext (B_prime, hint), где B_prime имеет форму (k, n)
      sk: секретный ключ S (форма (k, n))
      k, n, q, p: параметры протокола
    Выход:
      K: общий секрет, вычисленный как H( rec(V', hint) )
         где V' = vector_inner_product(B_prime, S, q)
    """
    B_prime, hint = ct
    V_prime = vector_inner_product(B_prime, sk, q)
    mu_prime = rec(V_prime, hint, q, p)
    mu_bytes = mu_prime.astype(np.int32).tobytes()
    K = hashlib.sha256(mu_bytes).digest()
    return K


# Пример использования:
if __name__ == "__main__":
    # 1. Генерация ключевой пары
    pk, sk = keygen(k, n, q)
    print("Ключевая пара сгенерирована:")
    print(" - pk (A, B):")
    print("    A shape:", pk[0].shape)
    print("    B shape:", pk[1].shape)
    print(" - sk shape:", sk.shape)
    print()

    # 2. Encapsulation: получение ciphertext и общего секрета (на стороне отправителя)
    ct, shared_secret_enc = encaps(pk, k, n, q, p)
    print("Encapsulation выполнена:")
    print(" - Ciphertext:")
    print("    B_prime shape:", ct[0].shape)
    print("    hint shape:", ct[1].shape)
    print(" - Общий секрет (encapsulation):", shared_secret_enc.hex())
    print()

    # 3. Decapsulation: восстановление общего секрета (на стороне получателя)
    shared_secret_dec = decaps(ct, sk, k, n, q, p)
    print("Decapsulation выполнена:")
    print(" - Общий секрет (decapsulation):", shared_secret_dec.hex())
    print()

    # 4. Проверка совпадения общих секретов
    if shared_secret_enc == shared_secret_dec:
        print("Успех: Общие секреты совпадают!")
    else:
        print("Ошибка: Общие секреты не совпадают!")
