import random


class RC4:
    def __init__(self, seed=None) -> None:
        self.S = [i for i in range(256)]
        if seed is None:
            self.seed = [random.randint(0, 256) for _ in range(256)]
        else:
            if isinstance(seed, bytes):
                self.seed = [i for i in seed]
                if len(seed) < 256:
                    for i in range(256 - len(seed)):
                        self.seed.append(seed[i % len(seed)])
                else:
                    print("The length of the seed is too long, we only intercepted the first 256 bytes")
                    self.seed = self.seed[0:256]
            else:
                raise TypeError("seed must be bytes")
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.seed[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.s_en = self.s_encrypt()

    def full_encrypt(self, msg: bytes):
        i = 0
        j = 0
        cipher = b""
        S = self.S.copy()
        for m in msg:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            cipher += bytes([m ^ S[t]])
        return cipher

    def s_encrypt(self):
        i = 0
        j = 0
        S = self.S.copy()

        def encrypt(msg):
            nonlocal i, j, S
            cipher = b""
            for m in msg:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                t = (S[i] + S[j]) % 256
                cipher += bytes([m ^ S[t]])
            return cipher

        return encrypt

    def stream_encrypt(self, msg: bytes):
        return self.s_en(msg)

    def reset(self):
        self.s_en = self.s_encrypt()

    def decrypt(self, cipher: bytes):
        return self.full_encrypt(cipher)
