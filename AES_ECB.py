import numpy as np


class AES_ECB:
    def __init__(self, digits, key=None):
        """
        初始化密钥,轮密钥,轮数,密钥长度,轮常数,密钥盒,逆密钥盒
        digits:密钥长度
        key:密钥,默认为None,随机生成,否则需要用户输入密码列表
        """
        if key is None:
            self.key = np.random.randint(0, 256, 4 * digits // 32, dtype=np.uint8).tolist()
        else:
            self.key = np.array(np.uint8(key), dtype=np.uint8).tolist()
        if digits not in [128, 192, 256]:
            raise ValueError("Invalid key size")
        self.digits = digits
        self.rounds = (digits // 32) + 6
        self.nk = digits // 32

        Rcon0 = np.array([0x01, 0x00, 0x00, 0x00], dtype=np.uint8).reshape(4, 1)
        Rcon = np.zeros((4, self.rounds), dtype=np.uint8)
        Rcon[..., 0] = Rcon0[..., 0]
        for i in range(1, self.rounds):
            Rcon[0, i] = self.xtime(Rcon[0, i - 1])
        self.Rcon = Rcon

        self.Sbox = np.array([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
            0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96,
            0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
            0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
            0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
            0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32,
            0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
            0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
            0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
            0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
            0xB0, 0x54, 0xBB, 0x16], dtype=np.uint8).reshape(16, 16)

        self.InvSbox = np.array([
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
            0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
            0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9,
            0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
            0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15,
            0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
            0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13,
            0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1,
            0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
            0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07,
            0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB,
            0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
            0x55, 0x21, 0x0C, 0x7D,], dtype=np.uint8).reshape(16, 16)
        self.roundskey = self.generate_roundkeys()

    def generate_roundkeys(self):
        """
        生成轮密钥
        """
        roundkeys = np.empty((self.rounds + 1, 4, self.nk), dtype=np.uint8)
        if (self.nk <= 6):
            roundkeys[0] = np.array(self.key).reshape(self.nk, 4).T
            for i in range(1, self.rounds + 1):
                for j in range(self.nk):
                    if (j != 0):
                        roundkeys[i][..., j] = roundkeys[i - 1][..., j] ^ roundkeys[i][..., j - 1]
                    else:
                        roundkeys[i][..., j] = np.roll(roundkeys[i - 1][..., -1], -1)
                        roundkeys[i][..., j] = self.Sbox[roundkeys[i][..., j] >> 4, roundkeys[i][..., j] & 0x0f]
                        roundkeys[i][..., j] ^= self.Rcon[..., i - 1]
                        roundkeys[i][..., j] ^= roundkeys[i - 1][..., j]
        else:
            roundkeys[0] = np.array(self.key).reshape(self.nk, 4).T
            for i in range(1, self.rounds + 1):
                for j in range(self.nk):
                    if (j == 0):
                        roundkeys[i][..., j] = np.roll(roundkeys[i - 1][..., j], -1)
                        roundkeys[i][..., j] = self.Sbox[roundkeys[i][..., j] >> 4, roundkeys[i][..., j] & 0x0f]
                        roundkeys[i][..., j] ^= self.Rcon[..., i - 1]
                        roundkeys[i][..., j] ^= roundkeys[i - 1][..., j]
                    elif (j == 4):
                        roundkeys[i][..., j] = self.Sbox[roundkeys[i][..., j - 1] >> 4, roundkeys[i][..., j - 1] & 0x0f] ^ roundkeys[i - 1][..., j]
                    else:
                        roundkeys[i][..., j] = roundkeys[i - 1][..., j] ^ roundkeys[i][..., j - 1]
        return roundkeys

    def ByteSub(self, state: np.ndarray, inv=False):
        if (inv):
            return self.InvSbox[state >> 4, state & 0x0f]
        else:
            return self.Sbox[state >> 4, state & 0x0f]

    def ShiftRow(self, state: np.ndarray, inv=False):
        if (inv):
            i = 1
        else:
            i = -1
        if (self.nk <= 6):
            state[1] = np.roll(state[1], i * 1, axis=0)
            state[2] = np.roll(state[2], i * 2, axis=0)
            state[3] = np.roll(state[3], i * 3, axis=0)
        else:
            state[1] = np.roll(state[1], i * 1, axis=0)
            state[2] = np.roll(state[2], i * 3, axis=0)
            state[3] = np.roll(state[3], i * 3, axis=0)
        return state

    def xtime(self, num: np.uint8):
        if (num & 0x80):
            return np.uint8((num << 1) ^ 0x1b)
        else:
            return np.uint8(num << 1)

    def GFMul(self, a: np.uint8, b: np.uint8):
        """
        定义在GF(2^8)上的乘法
        这里由于我们只用到一些特殊的值,所以直接列出来了
        """

        if a == 0x01:
            return b
        elif a == 0x02:
            return self.xtime(b)
        elif a == 0x03:
            return self.xtime(b) ^ b
        elif a == 0x09:
            return self.xtime(self.xtime(self.xtime(b))) ^ b
        elif a == 0x0b:
            return self.xtime(self.xtime(self.xtime(b))) ^ b ^ self.xtime(b)
        elif a == 0x0d:
            return self.xtime(self.xtime(self.xtime(b))) ^ b ^ self.xtime(self.xtime(b))
        elif a == 0x0e:
            return self.xtime(self.xtime(self.xtime(b))) ^ self.xtime(self.xtime(b)) ^ self.xtime(b)
        else:
            raise ValueError("Invalid value of a")

    def MixColumn(self, state: np.ndarray, inv=False):
        if (inv):
            c_matrix = np.array([0x0e, 0x0b, 0x0d, 0x09], dtype=np.uint8).reshape(1, 4)
        else:
            c_matrix = np.array([0x02, 0x03, 0x01, 0x01], dtype=np.uint8).reshape(1, 4)
        for _ in range(3):
            c_matrix = np.append(c_matrix, np.roll(c_matrix[-1], 1, axis=0).reshape(1, 4), axis=0)

        result = np.empty((4, self.nk), dtype=np.uint8)

        for i in range(4):
            for j in range(self.nk):
                result[i][j] = self.GFMul(c_matrix[i][0], state[0][j]) ^ self.GFMul(c_matrix[i][1],
                                                                                    state[1][j]) ^ self.GFMul(
                    c_matrix[i][2], state[2][j]) ^ self.GFMul(c_matrix[i][3], state[3][j])
        return result

    def AddRoundKey(self, state: np.ndarray, roundkey: np.ndarray):
        return state ^ roundkey

    def encrypt(self, plaintext: bytes):
        """
        加密函数
        对输入字节串进行填充分组,ECB加密
        """

        if (len(plaintext) % (self.nk * 4) != 0):
            plaintext = plaintext + bytes([0] * (self.nk * 4 - (len(plaintext) % (self.nk * 4))))
        plain_texts = [plaintext[i:i + self.nk * 4] for i in range(0, len(plaintext), self.nk * 4)]
        cipher_texts = b''
        for plain_text in plain_texts:
            state = np.array(list(plain_text), dtype=np.uint8).reshape(self.nk, 4).T
            state = self.AddRoundKey(state, self.roundskey[0])

            for r in range(1, self.rounds):
                state = self.ByteSub(state)
                state = self.ShiftRow(state)
                state = self.MixColumn(state)
                state = self.AddRoundKey(state, self.roundskey[r])

            state = self.ByteSub(state)
            state = self.ShiftRow(state)
            state = self.AddRoundKey(state, self.roundskey[self.rounds])

            cipher_texts += bytes(state.T.flatten())
        return cipher_texts

    def decrypt(self, ciphertext: bytes):
        """
        解密函数
        对输入字节串进行填充分组,ECB解密
        """

        if (len(ciphertext) % (self.nk * 4) != 0):
            ciphertext = ciphertext + bytes([0] * (self.nk * 4 - (len(ciphertext) % (self.nk * 4))))
        cipher_texts = [ciphertext[i:i + self.nk * 4] for i in range(0, len(ciphertext), self.nk * 4)]
        plain_texts = b''
        for cipher_text in cipher_texts:
            state = np.array(list(cipher_text), dtype=np.uint8).reshape(self.nk, 4).T
            state = self.AddRoundKey(state, self.roundskey[self.rounds])

            for r in range(self.rounds - 1, 0, -1):
                state = self.ShiftRow(state, inv=True)
                state = self.ByteSub(state, inv=True)
                state = self.AddRoundKey(state, self.roundskey[r])
                state = self.MixColumn(state, inv=True)

            state = self.ShiftRow(state, inv=True)
            state = self.ByteSub(state, inv=True)
            state = self.AddRoundKey(state, self.roundskey[0])

            plain_texts += bytes(state.T.flatten())
        return plain_texts.rstrip(b'\x00')
