import struct
import time
key = [[0x2, 0x7, 0xa, 0x6, 0x7, 0x8, 0x1, 0xa, 0x4, 0x3, 0xf, 0x3, 0x6, 0x4, 0xb, 0xc],
        [0x9, 0x1, 0x6, 0x7, 0x0, 0x8, 0xd, 0x5, 0xf, 0xb, 0xb, 0x5, 0xa, 0xe, 0xf, 0xe]]
# key = [[0]*16, [0]*16]
tweak = [0x5, 0x4, 0xc, 0xd, 0x9, 0x4, 0xf, 0xf, 0xd, 0x0, 0x6, 0x7, 0x0, 0xa, 0x5, 0x8]
# tweak = [0]*16
TK = [[0]*16, [0]*16, [0]*16, [0]*16]
Q = [0xc, 0xa, 0xf, 0x5, 0xe, 0x8, 0x9, 0x2, 0xb, 0x3, 0x7, 0x4, 0x6, 0x0, 0x1, 0xd]
P = [0xf, 0xc, 0xd, 0xe, 0xa, 0x9, 0x8, 0xb, 0x6, 0x5, 0x4, 0x7, 0x1, 0x2, 0x3, 0x0]
S = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
RC4 = [0x1, 0x8, 0x4, 0x2, 0x9, 0xc, 0x6, 0xb, 0x5, 0xa, 0xd, 0xe, 0xf, 0x7, 0x3, 0x1, 0x8, 0x4, 0x2, 0x9, 0xc, 0x6,
       0xb, 0x5, 0xa, 0xd, 0xe, 0xf, 0x7, 0x3, 0x1, 0x8]
RC5 = [0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1,
       0x4, 0x2, 0x5, 0x6, 0x7, 0x3, 0x1, 0x4, 0x2, 0x5]


def initialize_tweakey(decrypt=False):
    global key, Q, TK
    for i in range(16):
        TK[0][i] = key[0][i] ^ tweak[i]
        TK[1][i] = key[1][i] ^ tweak[i]
        TK[2][i] = key[0][i] ^ tweak[Q[i]]
        TK[3][i] = key[1][i] ^ tweak[Q[i]]
    if decrypt:
        for i in range(4):
            for j in range(4):
                TK[i][j] ^= (TK[i][j + 8] ^ TK[i][j + 12])
                TK[i][j + 4] ^= TK[i][j + 12]


def mix_column(state):
    for i in range(4):
        state[i] ^= (state[i + 8] ^ state[i + 12])
        state[i + 4] ^= state[i + 12]
    return state


def add_constant(state, rnd):
    global RC4, RC5
    state[4] ^= RC4[rnd]
    state[5] ^= RC5[rnd]
    return state


def add_tweakey(state, rnd):
    global TK
    for i in range(16):
        state[i] ^= TK[rnd % 4][i]
    return state


def permutation(state):
    global P
    permutated = [0] * 16
    for i in range(16):
        permutated[P[i]] = state[i]

    return permutated


def s_box(state):
    for i in range(16):
        state[i] = S[state[i]]
    return state


def Round(state, rnd, decrypt=False):
    if decrypt:
        rnd = 31 - rnd
    state = mix_column(state)
    state = add_constant(state, rnd)
    state = add_tweakey(state, rnd)
    if rnd != 31 and not decrypt or rnd != 0 and decrypt:
        temporary = permutation(state)
        state = s_box(temporary)

    return state


def encrypt(input, output):
    with open(input, "rb") as file_in:
        with open(output, "wb") as file_out:
            block = "abcdefgh"
            flag = False
            while not flag:
                block = file_in.read(8)
                if len(block) < 8:
                    flag = True
                    block = struct.pack('8s', block)

                state = [0] * 16
                for i in range(8):
                    state[2 * i] = (block[i] & 0xf0) >> 4
                    state[2 * i + 1] = block[i] & 0xf
                for i in range(32):
                    state = Round(state, i)
                to_print = [0] * 8
                for i in range(8):
                    to_print[i] = (state[2 * i] << 4) | state[2 * i + 1]

                # test = bytes(to_print)
                # print(test)
                file_out.write(bytes(to_print))


def decrypt(input, output):
    with open(input, "rb") as file_in:
        with open(output, "wb") as file_out:
            block = "abcdefgh"
            flag = False
            while not flag:
                block = file_in.read(8)
                length = len(block)
                if len(block) < 8:
                    flag = True
                    block = struct.pack('8s', block)

                state = [0] * 16
                for i in range(8):
                    state[2 * i] = (block[i] & 0xf0) >> 4
                    state[2 * i + 1] = block[i] & 0xf
                for i in range(32):
                    state = Round(state, i, True)
                to_print = [0] * length
                for i in range(length):
                    to_print[i] = (state[2 * i] << 4) | state[2 * i + 1]

                # test = bytes(to_print)
                # print(test)
                file_out.write(bytes(to_print))


def main():
    # encrypt("picture.png", "CT.txt")
    # decrypt("CT.txt", "result.png")

    # state = [0]*16
    start_time = time.time()
    initialize_tweakey()
    # for item in TK:
        # print(list(map(lambda x: hex(x), item)))
    for j in range(10**6):
        state = [0x5, 0x7, 0x3, 0x4, 0xf, 0x0, 0x0, 0x6, 0xd, 0x8, 0xd, 0x8, 0x8, 0xa, 0x3, 0xe]
        for i in range(32):
            state = Round(state, i)
    end_time = time.time()
    print("1 block cypher time: {}".format(end_time - start_time))
    #     print("Round {}: {}".format(i, list(map(lambda x: hex(x), state))))
    # print()
    # initialize_tweakey(True)
    # for i in range(32):
    #     state = Round(state, i, True)
    #     print("Round {}: {}".format(i, list(map(lambda x: hex(x), state))))


if __name__ == "__main__":
    main()
