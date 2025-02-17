import numpy as np
import hashlib

# Параметры протокола Saber
n = 256  # степень полинома
q = 8192  # модуль
k = 3  # размерность (может быть 3, 4 или 6)


def poly_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    """
    Умножение двух полиномов a(x) и b(x) в кольце R_q = Z_q[x]/(x^n+1).
    Полиномы представлены массивами длины n.

    Вычисляем свёртку, затем редуцируем по модулю (x^n+1), используя соотношение x^n = -1.
    """
    n = len(a)
    conv = np.convolve(a, b)

    result = np.empty(n, dtype=int)
    # Редукция для коэффициентов с индексами 0 ... n-2
    result[:n - 1] = conv[:n - 1] - conv[n:2 * n - 1]
    # Последний коэффициент
    result[n - 1] = conv[n - 1]

    return np.mod(result, q)


def matrix_vector_mult(A: np.ndarray, S: np.ndarray, q: int) -> np.ndarray:
    """
    Умножение матрицы A (размера k x k, элементы-полиномы) на вектор S (k x 1, элементы-полиномы)
    с операцией умножения полиномов в кольце R_q.

    A имеет форму (k, k, n), S имеет форму (k, n), результат — массив (k, n).
    """
    k = A.shape[0]
    n = A.shape[2]
    B = np.zeros((k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            B[i] = (B[i] + poly_mul(A[i, j], S[j], q)) % q
    return B


def sample_poly_uniform(n: int, q: int) -> np.ndarray:
    """
    Генерирует полином длины n с коэффициентами, выбранными равномерно из диапазона [0, q-1].
    """
    return np.random.randint(0, q, size=n)


def sample_poly_error(n: int, bound: int = 4) -> np.ndarray:
    """
    Генерирует полином длины n с коэффициентами из приближённого распределения ошибок.
    В этом примере коэффициенты выбираются равномерно в диапазоне [-bound, bound].
    """
    return np.random.randint(-bound, bound + 1, size=n)


def vector_inner_product(vec1: np.ndarray, vec2: np.ndarray, q: int) -> np.ndarray:
    """
    Вычисляет скалярное произведение двух векторов полиномов.
    Каждый вектор имеет форму (k, n). Произведение рассчитывается как
    сумма по индексам: result(x) = Σ (vec1[i](x) * vec2[i](x)) mod q.
    """
    k, n = vec1.shape
    result = np.zeros(n, dtype=int)
    for i in range(k):
        result = (result + poly_mul(vec1[i], vec2[i], q)) % q
    return result


def encaps(pk: tuple, k: int, n: int, q: int, bound: int = 4):
    """
    Реализация процедуры Encaps для протокола Saber.

    Вход:
      pk: публичный ключ, представленный кортежем (A, B),
          где A имеет форму (k, k, n), а B — форму (k, n)
      k, n, q: параметры протокола
      bound: верхняя граница для коэффициентов распределения ошибок

    Выход:
      ct: зашифрованное сообщение в виде кортежа (B_prime, c)
      K: общий секрет, полученный как H(V)
    """
    A, B = pk  # A: матрица (k, k, n), B: вектор (k, n)

    # Генерация случайного вектора S' и ошибки E' (по k полиномов)
    S_prime = np.empty((k, n), dtype=int)
    E_prime = np.empty((k, n), dtype=int)
    for i in range(k):
        S_prime[i] = sample_poly_error(n, bound)
        E_prime[i] = sample_poly_error(n, bound)

    # Вычисление B' = A * S' + E' (каждый элемент — полином, операции в R_q)
    B_prime = (matrix_vector_mult(A, S_prime, q) + E_prime) % q

    # Вычисление V = B^T * S', то есть скалярное произведение векторов полиномов
    V = vector_inner_product(B, S_prime, q)

    # Квантование: c = округление V / (q/p), здесь q/p = 8192/1024 = 8
    c = np.rint(V / 8).astype(int)

    # Вычисление общего секрета K = H(V)
    # Преобразуем V в байтовую строку (например, используя представление int32)
    V_bytes = V.astype(np.int32).tobytes()
    K = hashlib.sha256(V_bytes).digest()

    # Формирование ciphertext: кортеж (B_prime, c)
    ct = (B_prime, c)
    return ct, K


# Пример использования:
if __name__ == "__main__":
    # Для демонстрации генерируем публичный и секретный ключи
    def keygen(k: int, n: int, q: int):
        A = np.empty((k, k, n), dtype=int)
        for i in range(k):
            for j in range(k):
                A[i, j] = sample_poly_uniform(n, q)
        S = np.empty((k, n), dtype=int)
        E = np.empty((k, n), dtype=int)
        for i in range(k):
            S[i] = sample_poly_error(n)
            E[i] = sample_poly_error(n)
        B = (matrix_vector_mult(A, S, q) + E) % q
        pk = (A, B)
        sk = S
        return pk, sk


    # Генерация ключевой пары
    pk, sk = keygen(k, n, q)
    # Выполнение encapsulation
    ct, shared_secret = encaps(pk, k, n, q)

    print("Ciphertext B' shape:", ct[0].shape)
    print("Ciphertext c shape:", ct[1].shape)
    print("Shared secret (SHA-256 digest):", shared_secret.hex())
