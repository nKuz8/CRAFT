def make_half_bytes(byte_vec):
    """Преобразование списка байт в список полубайт LE

    Args:
        byte_vec (bytes): Список байт

    """
    half_bytes_vec = [0] * 16
    for i in range(8):
        half_bytes_vec[2 * i] = (byte_vec[i] & 0xf0) >> 4
        half_bytes_vec[2 * i + 1] = byte_vec[i] & 0xf
    return half_bytes_vec


class Craft:
    """Основной класс, реализующий шифрование сообщения в режиме ECB"""

    def __init__(self, key, tweak, message=bytes(1)):
        """Начальная инициализация векторов

        Args:
            key (list): Ключ шифрования/расшифрования
            tweak (list): tweak для генерации ключей
            message (bytes): Сообщение для шифрования/расшифрования

        """
        self.Q = [0xc, 0xa, 0xf, 0x5, 0xe, 0x8, 0x9, 0x2, 0xb, 0x3, 0x7, 0x4, 0x6, 0x0, 0x1, 0xd]
        self.P = [0xf, 0xc, 0xd, 0xe, 0xa, 0x9, 0x8, 0xb, 0x6, 0x5, 0x4, 0x7, 0x1, 0x2, 0x3, 0x0]
        self.S = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
        self.RC4 = [0x1, 0x8, 0x4, 0x2, 0x9, 0xc, 0x6, 0xb, 0x5, 0xa, 0xd, 0xe, 0xf, 0x7, 0x3, 0x1, 0x8, 0x4, 0x2, 0x9,
                    0xc, 0x6, 0xb, 0x5, 0xa, 0xd, 0xe, 0xf, 0x7, 0x3, 0x1, 0x8]
        self.RC5 = [0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5, 0x6, 0x7,
                    0x3, 0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5]
        self.blocks = []
        self.result_message = []
        self.message = message
        self.key = key
        self.tweak = tweak
        self.tweakey = [[0] * 16, [0] * 16, [0] * 16, [0] * 16]
        self.make_blocks()

    def __bytes__(self):
        if self.result_message:
            result = []
            for block in self.result_message:
                result.extend(bytes([(block[2 * i] << 4) | block[2 * i + 1] for i in range(len(block) // 2)]))
            return bytes(result)
        else:
            return None

    def __str__(self):
        if self.result_message:
            return str(self.__bytes__())

        else:
            return "Результат пока пустой"

    def check_message_len(self):
        """Проверяет длину сообщения на кратность 8 байтам

        Returns:
            bool: True если длина сообщения не кратна 8, False иначе
        """
        return 0 != len(self.message) % 8

    def add_padding(self):
        """Дополняет сообщение до длины, кратной 8"""
        self.message += b'\x80'
        while len(self.message) % 8 != 0:
            self.message += b'\x00'

    def make_blocks(self):
        """Разбивает сообщение на блоки по 64 бита (массив из 16 полубайт)"""
        if self.check_message_len():
            self.add_padding()

        for i in range(0, len(self.message), 8):
            block = make_half_bytes(self.message[i: i+8])
            self.blocks.append(block)

    def initialize_tweakey(self, decrypt=False):
        """Инициализация tweakey.

        Args:
            decrypt (:(bool, optional): Использовать преобразование для шифрования (False) или для расшифрования (True).
                По умолчанию - False

        """
        for i in range(16):
            self.tweakey[0][i] = self.key[0][i] ^ self.tweak[i]
            self.tweakey[1][i] = self.key[1][i] ^ self.tweak[i]
            self.tweakey[2][i] = self.key[0][i] ^ self.tweak[self.Q[i]]
            self.tweakey[3][i] = self.key[1][i] ^ self.tweak[self.Q[i]]

        if decrypt:
            for i in range(4):
                for j in range(4):
                    self.tweakey[i][j] ^= (self.tweakey[i][j + 8] ^ self.tweakey[i][j + 12])
                    self.tweakey[i][j + 4] ^= self.tweakey[i][j + 12]

    def mix_column(self, block):
        """Выполняет начальную перестановку в столбцах матрицы

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора

        Returns:
            list: Результат операции в виде вектора

        """
        for i in range(4):
            block[i] ^= (block[i + 8] ^ block[i + 12])
            block[i + 4] ^= block[i + 12]

        return block

    def add_constant(self, block, rnd):
        """Добавление раундовых констант

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора
            rnd (int): Номер текущего раунда

        Returns:
            list: Результат операции в виде вектора

        """
        block[4] ^= self.RC4[rnd]
        block[5] ^= self.RC5[rnd]
        return block

    def add_tweakey(self, block, rnd):
        """Замешивание ключа

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора
            rnd (int): Номер текущего раунда

        Returns:
            list: Результат операции в виде вектора

        """
        for i in range(16):
            block[i] ^= self.tweakey[rnd % 4][i]
        return block

    def make_permutation(self, block):
        """Перестановки внутри матрицы

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора

        Returns:
            list: Результат операции в виде вектора

        """
        permutated = [0] * 16
        for i in range(16):
            permutated[self.P[i]] = block[i]

        return permutated

    def do_s_box(self, block):
        """Осуществляет подстановку с помощью s_box

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора

        Returns:
            list: Результат операции в виде вектора

        """
        for i in range(16):
            block[i] = self.S[block[i]]
        return block

    def do_round(self, block, rnd, decrypt=False):
        """Выполняет один раунд шифрования/расшифрования

        Args:
            block (list): Матрица текущего обрабатываемого блока, представленная в виде вектора
            rnd (int): Номер текущего раунда
            decrypt(bool): Используется ли раунд для шифрования (False) или для расшифрования (True)

        Returns:
            list: Результат раунда

        """
        if decrypt:
            rnd = 31 - rnd
        block = self.mix_column(block)
        block = self.add_constant(block, rnd)
        block = self.add_tweakey(block, rnd)
        if rnd != 31 and not decrypt or rnd != 0 and decrypt:
            temporary = self.make_permutation(block)
            block = self.do_s_box(temporary)

        return block

    def encrypt(self):
        """Производит шифрование сообщения"""
        self.initialize_tweakey()
        for block in self.blocks:
            for i in range(32):
                block = self.do_round(block, i)
            self.result_message.append(block)

    def decrypt(self):
        """производит расшифрование сообщения"""
        self.initialize_tweakey(decrypt=True)
        for block in self.blocks:
            for i in range(32):
                block = self.do_round(block=block, rnd=i, decrypt=True)
            self.result_message.append(block)


if __name__ == '__main__':
    cypher = Craft(key=[[0x2, 0x7, 0xa, 0x6, 0x7, 0x8, 0x1, 0xa, 0x4, 0x3, 0xf, 0x3, 0x6, 0x4, 0xb, 0xc],
                        [0x9, 0x1, 0x6, 0x7, 0x0, 0x8, 0xd, 0x5, 0xf, 0xb, 0xb, 0x5, 0xa, 0xe, 0xf, 0xe]],
                   tweak=[0x5, 0x4, 0xc, 0xd, 0x9, 0x4, 0xf, 0xf, 0xd, 0x0, 0x6, 0x7, 0x0, 0xa, 0x5, 0x8],
                   message=b'Hello, lets encr this sting')
    cypher.encrypt()
    print(cypher)

    decrypted = Craft(key=cypher.key, tweak=cypher.tweak, message=bytes(cypher))
    decrypted.decrypt()
    print(decrypted)
