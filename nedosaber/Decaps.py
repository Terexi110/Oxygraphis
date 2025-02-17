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

    Выполняется свёртка, а затем редукция по модулю (x^n+1) с использованием соотношения x^n = -1.
    """
    n = len(a)
    conv = np.convolve(a, b)
    result = np.empty(n, dtype=int)
    # Для коэффициентов с индексами 0 ... n-2
    result[:n - 1] = conv[:n - 1] - conv[n:2 * n - 1]
    # Последний коэффициент
    result[n - 1] = conv[n - 1]
    return np.mod(result, q)


def vector_inner_product(vec1: np.ndarray, vec2: np.ndarray, q: int) -> np.ndarray:
    """
    Вычисляет скалярное произведение двух векторов полиномов.
    Если vec1 и vec2 имеют форму (k, n), то результат определяется как:
        V(x) = sum_{i=0}^{k-1} [vec1[i](x) * vec2[i](x)] mod q.
    """
    k, n = vec1.shape
    result = np.zeros(n, dtype=int)
    for i in range(k):
        result = (result + poly_mul(vec1[i], vec2[i], q)) % q
    return result


def decaps(ct: tuple, sk: np.ndarray, k: int, n: int, q: int) -> bytes:
    """
    Реализация процедуры Decaps для протокола Saber.

    Входные данные:
      ct: ciphertext, представленный кортежем (B_prime, c),
          где B_prime имеет форму (k, n) (матрица полиномов),
          а c – вектор квантованных коэффициентов.
      sk: секретный ключ S, представленный в виде массива формы (k, n)
      k, n, q: параметры протокола.

    Алгоритм:
      1. Вычисляем V' = (B_prime)^T * S mod q, используя операцию скалярного произведения полиномов.
      2. Применяем функцию reconciliation:
             μ = Rec(V', c) = round(V' / (q/p))
         При p = 1024, q = 8192, получаем q/p = 8.
      3. Вычисляем общий секрет K = H(μ), где H – криптографическая хэш-функция.

    Выход:
      K: общий секрет (хэш от μ) в виде байтовой строки.
    """
    B_prime, c = ct  # Распаковка ciphertext: B_prime – (k, n), c – вектор (n)

    # 1. Вычисляем V' = (B_prime)^T * S (операция скалярного произведения)
    V_prime = vector_inner_product(B_prime, sk, q)

    # 2. Функция reconciliation: округление V' делённого на q/p.
    # Для наших параметров q/p = 8192/1024 = 8.
    mu = np.rint(V_prime / 8).astype(int)

    # 3. Вычисляем общий секрет как SHA-256 от μ.
    # Преобразуем μ в байтовую строку. Здесь используем представление int32.
    mu_bytes = mu.astype(np.int32).tobytes()
    K = hashlib.sha256(mu_bytes).digest()
    return K


# Пример использования:
if __name__ == "__main__":
    # Для демонстрации сначала сгенерируем ключевую пару (KeyGen)
    def keygen(k: int, n: int, q: int):
        """
        Упрощённая процедура генерации ключей:
          - A: равномерно случайная матрица (k x k) полиномов.
          - S, E: векторы полиномов, генерируемые из распределения ошибок.
          - B = A * S + E mod q.
        """

        def sample_poly_uniform(n: int, q: int) -> np.ndarray:
            return np.random.randint(0, q, size=n)

        def sample_poly_error(n: int, bound: int = 4) -> np.ndarray:
            return np.random.randint(-bound, bound + 1, size=n)

        A = np.empty((k, k, n), dtype=int)
        for i in range(k):
            for j in range(k):
                A[i, j] = sample_poly_uniform(n, q)
        S = np.empty((k, n), dtype=int)
        E = np.empty((k, n), dtype=int)
        for i in range(k):
            S[i] = sample_poly_error(n)
            E[i] = sample_poly_error(n)
        B = (sum(poly_mul(A[i, j], S[j], q) for j in range(k)) + E) % q
        pk = (A, B)
        sk = S
        return pk, sk


    # Генерируем ключевую пару
    pk, sk = keygen(k, n, q)


    # Допустим, ciphertext ct = (B_prime, c) уже получен (например, в процессе encapsulation).
    # Для демонстрации сгенерируем его так же, как в encaps.
    def encaps(pk: tuple, k: int, n: int, q: int, bound: int = 4):
        A, B = pk  # A имеет форму (k, k, n), B имеет форму (k, n)

        def sample_poly_error(n: int, bound: int = 4) -> np.ndarray:
            return np.random.randint(-bound, bound + 1, size=n)

        # Генерация случайного вектора S' и ошибки E' (по k полиномов)
        S_prime = np.empty((k, n), dtype=int)
        E_prime = np.empty((k, n), dtype=int)
        for i in range(k):
            S_prime[i] = sample_poly_error(n, bound)
            E_prime[i] = sample_poly_error(n, bound)

        # Вычисление B' = A * S' + E'
        def matrix_vector_mult(A: np.ndarray, S: np.ndarray, q: int) -> np.ndarray:
            B_temp = np.zeros((k, n), dtype=int)
            for i in range(k):
                for j in range(k):
                    B_temp[i] = (B_temp[i] + poly_mul(A[i, j], S[j], q)) % q
            return B_temp

        B_prime = (matrix_vector_mult(A, S_prime, q) + E_prime) % q

        # Вычисление V = B^T * S'
        V = vector_inner_product(B, S_prime, q)

        # Квантование: c = round(V / (q/p)) = round(V / 8)
        c = np.rint(V / 8).astype(int)

        ct = (B_prime, c)
        # Общий секрет, вычисленный на стороне отправителя
        V_bytes = V.astype(np.int32).tobytes()
        K = hashlib.sha256(V_bytes).digest()
        return ct, K


    # Выполним encapsulation для получения ciphertext
    ct, shared_secret_enc = encaps(pk, k, n, q)

    # Теперь выполняем decapsulation с использованием секретного ключа sk
    shared_secret_dec = decaps(ct, sk, k, n, q)

    print("Shared secret (encapsulation):", shared_secret_enc.hex())
    print("Shared secret (decapsulation):", shared_secret_dec.hex())
