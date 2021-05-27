from craft import Craft, make_half_bytes


class CraftCBC(Craft):
    """Класс, реализующий шифрование сообщения в режиме CBC"""
    def __init__(self, key, tweak, init_vec, message=bytes(1)):
        """Начальная инициализация векторов

        Args:
            key (list): Ключ шифрования/расшифрования
            tweak (list): tweak для генерации ключей
            init_vec (bytes): Вектор инициализации
            message (bytes): Сообщение для шифрования/расшифрования

        """
        super().__init__(key=key, tweak=tweak, message=message)
        self.init_vec = make_half_bytes(init_vec)
        self.chain_block = []

    def add_chain_block(self, block, chain):
        """Реализует сложение по mod2 двух векторов

        Args:
            block (list): Очередной блок открытого или защифрованного текста
            chain (list): Блок с предыдущей итерации

        """
        return [i ^ j for i, j in zip(block, chain)]

    def encrypt(self):
        """Производит шифрование сообщения"""
        super().initialize_tweakey()
        for i, block in enumerate(self.blocks):
            if i == 0:
                block = self.add_chain_block(block, self.init_vec)
            else:
                block = self.add_chain_block(block, self.chain_block)

            for j in range(32):
                block = super().do_round(block=block, rnd=j)
            self.chain_block = block
            self.result_message.append(block)

    def decrypt(self):
        """Производит расшифрование блока"""
        super().initialize_tweakey(decrypt=True)
        for i, block in enumerate(self.blocks):
            temp = block.copy()
            for j in range(32):
                block = super().do_round(block=block, rnd=j, decrypt=True)
            if i == 0:
                block = self.add_chain_block(block=block, chain=self.init_vec)
            else:
                block = self.add_chain_block(block=block, chain=self.chain_block)
            self.result_message.append(block)
            self.chain_block = temp


if __name__ == '__main__':
    encr_cbc = CraftCBC(key=[[0x2, 0x7, 0xa, 0x6, 0x7, 0x8, 0x1, 0xa, 0x4, 0x3, 0xf, 0x3, 0x6, 0x4, 0xb, 0xc],
                        [0x9, 0x1, 0x6, 0x7, 0x0, 0x8, 0xd, 0x5, 0xf, 0xb, 0xb, 0x5, 0xa, 0xe, 0xf, 0xe]],
                        tweak=[0x5, 0x4, 0xc, 0xd, 0x9, 0x4, 0xf, 0xf, 0xd, 0x0, 0x6, 0x7, 0x0, 0xa, 0x5, 0x8],
                        init_vec=b'AAAAAAAA',
                        message=b'Hello, lets encr this sting')
    encr_cbc.encrypt()
    print(encr_cbc)

    decr_cbc = CraftCBC(key=encr_cbc.key, tweak=encr_cbc.tweak, init_vec=b'AAAAAAAA', message=bytes(encr_cbc))
    decr_cbc.decrypt()
    print(decr_cbc)







