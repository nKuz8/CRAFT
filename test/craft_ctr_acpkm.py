from craft import Craft, make_half_bytes
from craft_cbc import CraftCBC


def int_to_vec(num, size):
    """Переводит число в двоичный вектор определенного размера

    Args:
        num (int): Число для перевода
        size (int): Размер выходного вектора

    Returns:
          (list): Двоичный вектор длины size

    """
    vec = []
    for i in range(size):
        vec.append(num % 2)
        num = num >> 1

    vec.reverse()
    return vec


def vec_to_int(vec):
    """Переводит двоичный вектор в число

    Args:
        vec (list): Двоичный вектор для перевода

    Returns:
          (Int): Число

    """
    number = 0
    for i, val in enumerate(vec):
        number += 2**(len(vec) - i) * val

    return number


def incr(vec):
    """Осуществляет операцию инкрементирования двоичного вектора

    Args:
        vec (list): Вектор для инкременты

    Returns:
          (list)

    """
    return int_to_vec(vec_to_int(vec) + 1, len(vec))


def msb(vec: list, size: int):
    """Возвращает первые size байт vec"""
    return vec[:size]


class Craft_CTR_ACPKM(CraftCBC):
    """Реализут шифрование в режиме CTR-ACPKM"""

    def __init__(self, key, tweak, init_vec, section_len, gamma_len, message=bytes(1)):
        """Начальная инициализация веторов и параметров шифра

        Args:
            key (list): Ключ шифрования/расшифрования
            tweak (list): tweak для генерации ключей
            init_vec (bytes): Вектор инициализации
            section_len (int): Длина секции, на которые разбиваются сообщения (N)
            gamma_len (int): Длина блока гаммы (s)
            message (bytes): Сообщение для шифрования/расшифрования

        """
        super().__init__(key, tweak, init_vec, message)
        self.gamma_len = gamma_len
        self.section_len = section_len
        self.make_blocks()
        self.ctr = [*self.init_vec]
        self.ctr.extend([0] * 8)
        self.D = make_half_bytes(b'\x80\x81\x82\x83')

    def make_blocks(self):
        """Разбивает сообщение на блоки определенной длины

        Args:
            size (int): Длина блока

        """
        self.blocks = []
        for i in range(0, len(self.message), self.gamma_len):
            block = make_half_bytes(self.message[i: i + self.gamma_len])
            self.blocks.append(block)

    def do_block_encr(self, key, message):
        """Производит шифрование блока

        Args:
            key (list): ключ для шифрования
            message (bytes): сообщение для шифрования

        Returns:
               (list): Вектор полубайт

        """
        craft_block = Craft(key, self.tweak, message)
        craft_block.encrypt()
        return craft_block.result_message[0]

    def encript(self):
        """Производит шифрование/расшифрование сообщения"""
        for i, block in enumerate(self.blocks):
            if self.gamma_len // self.section_len * i == self.gamma_len / self.section_len * i:
                key = self.do_block_encr(key=self.key, message=self.D)
                self.key = [*key[:len(key) // 2]]
