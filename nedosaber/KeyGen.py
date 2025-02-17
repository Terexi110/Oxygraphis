import numpy as np

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
    # Вычисляем свёртку, результат имеет длину 2*n - 1
    conv = np.convolve(a, b)

    # Результат будем хранить в массиве длины n
    result = np.empty(n, dtype=int)
    # Для коэффициентов с индексами 0 ... n-2: вычитаем соответствующие коэффициенты свёртки
    result[:n - 1] = conv[:n - 1] - conv[n:2 * n - 1]
    # Последний коэффициент: свёртка даёт только один слагаемый
    result[n - 1] = conv[n - 1]

    # Приводим результат по модулю q
    return np.mod(result, q)


def matrix_vector_mult(A: np.ndarray, S: np.ndarray, q: int) -> np.ndarray:
    """
    Умножение матрицы A (размера k x k, элементы-полиномы) на вектор S (k x 1, элементы-полиномы)
    с операцией умножения полиномов в кольце R_q.

    A имеет форму (k, k, n), S имеет форму (k, n), результат возвращается как массив (k, n).
    """
    k = A.shape[0]
    n = A.shape[2]
    B = np.zeros((k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            # Полиномное умножение: аккумулируем сумму по столбцам
            B[i] = (B[i] + poly_mul(A[i, j], S[j], q)) % q
    return B


def sample_poly_uniform(n: int, q: int) -> np.ndarray:
    """
    Генерирует полином длины n с коэффициентами равномерно случайными от 0 до q-1.
    """
    return np.random.randint(0, q, size=n)


def sample_poly_error(n: int, bound: int = 4) -> np.ndarray:
    """
    Генерирует полином длины n с коэффициентами из распределения ошибок.
    В данном примере коэффициенты выбираются равномерно в диапазоне [-bound, bound].
    """
    return np.random.randint(-bound, bound + 1, size=n)


def keygen(k: int, n: int, q: int):
    """
    Реализация процедуры KeyGen для Saber.

    Возвращает:
        pk: публичный ключ, представленный в виде кортежа (A, B)
        sk: секретный ключ, S
    """
    # Генерация матрицы A: k x k матрица полиномов с коэффициентами из Z_q
    A = np.empty((k, k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            A[i, j] = sample_poly_uniform(n, q)

    # Генерация секретного вектора S и ошибки E: k полиномов из распределения ошибок
    S = np.empty((k, n), dtype=int)
    E = np.empty((k, n), dtype=int)
    for i in range(k):
        S[i] = sample_poly_error(n)
        E[i] = sample_poly_error(n)

    # Вычисляем B = A * S + E по модулю q
    B = (matrix_vector_mult(A, S, q) + E) % q

    # Публичный ключ pk = (A, B), секретный ключ sk = S
    pk = (A, B)
    sk = S
    return pk, sk


# Пример использования:
if __name__ == "__main__":
    pk, sk = keygen(k, n, q)
    print("Публичный ключ (A, B):")
    print("A shape:", pk[0].shape)
    print("B shape:", pk[1].shape)
    print("Секретный ключ S shape:", sk.shape)
