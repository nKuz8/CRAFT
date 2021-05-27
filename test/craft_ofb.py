from craft_cbc import CraftCBC


class CraftOFB(CraftCBC):
    """Реализует шифрование сообщения в режиме OFB"""

    def __init__(self, key, tweak, init_vec, message=bytes(1)):
        """Начальная инициализация векторов

            Args:
                key (list): Ключ шифрования/расшифрования
                tweak (list): tweak для генерации ключей
                init_vec (bytes): Вектор инициализации
                message (bytes): Сообщение для шифрования/расшифрования

        """
        super().__init__(key, tweak, init_vec, message)

    def encrypt(self):
        """Производит шифрование и расшифрование сообщения"""
        super().initialize_tweakey()
        to_encrypt = self.init_vec.copy()
        for i, block in enumerate(self.blocks):
            for j in range(32):
                to_encrypt = super().do_round(block=to_encrypt, rnd=j)
            block = super().add_chain_block(to_encrypt, block)
            self.result_message.append(block)


if __name__ == '__main__':
    encr_cbc = CraftOFB(key=[[0x2, 0x7, 0xa, 0x6, 0x7, 0x8, 0x1, 0xa, 0x4, 0x3, 0xf, 0x3, 0x6, 0x4, 0xb, 0xc],
                             [0x9, 0x1, 0x6, 0x7, 0x0, 0x8, 0xd, 0x5, 0xf, 0xb, 0xb, 0x5, 0xa, 0xe, 0xf, 0xe]],
                        tweak=[0x5, 0x4, 0xc, 0xd, 0x9, 0x4, 0xf, 0xf, 0xd, 0x0, 0x6, 0x7, 0x0, 0xa, 0x5, 0x8],
                        init_vec=b'AAAAAAAA',
                        message=b'Hello, lets encr this sting')
    encr_cbc.encrypt()
    print(encr_cbc)

    decr_cbc = CraftOFB(key=encr_cbc.key, tweak=encr_cbc.tweak, init_vec=b'AAAAAAAA', message=bytes(encr_cbc))
    decr_cbc.encrypt()
    print(decr_cbc)

