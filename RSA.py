from crypto.Util.number import inverse, getPrime


class RSA:
    def __init__(self, digits, public_key=None, private_key=None):
        """
        初始化函数
        digits: 密钥位数
        public_key: 公钥
        private_key: 私钥

        如果不传入公钥和私钥,则会自动生成
        """
        if digits not in [128, 256, 512, 1024, 2048, 4096]:
            raise ValueError("k must be 128,256, 512, 1024, 2048, 4096")
        if public_key is None or private_key is None:
            print("because the public_key or private_key is None,we will generate the key")
            self.digits = digits
            self.public_key, self.private_key = self.generate_key(digits)
        else:
            self.digits = len(bin(public_key[1])[2:]) + 7  # 加7是为了方便分组时不会出现截断太多导致溢出
            self.public_key = public_key
            self.private_key = private_key

    def encrypt(self, message: bytes, public_key=None):
        """
        加密函数
        """
        if self.public_key is None and public_key is None:
            raise ValueError("public_key is None")
        if public_key is not None:
            digits = len(bin(public_key[1])[2:]) + 7
            ekey = public_key[0]
            nkey = public_key[1]
        else:
            digits = self.digits
            ekey = self.public_key[0]
            nkey = self.public_key[1]
        k = digits // 8
        cipher = ""
        for m in [message[i: i + k - 1] for i in range(0, len(message), k - 1)]:
            plaintext = int.from_bytes(m, "big")
            ciphertext = pow(plaintext, ekey, nkey)
            formattext = format(ciphertext, "x").zfill(k * 2)
            cipher += formattext
        return cipher

    def decrypt(self, cipher: str, private_key=None):
        """
        解密函数
        """
        if self.private_key is None and private_key is None:
            raise ValueError("private_key is None")
        if private_key is not None:
            digits = len(bin(private_key[1])[2:]) + 7
            dkey = private_key[0]
            nkey = private_key[1]
        else:
            dkey = self.private_key[0]
            nkey = self.private_key[1]
            digits = self.digits
        k = digits // 8
        cipher_text = [int(cipher[i: i + k * 2], 16) for i in range(0, len(cipher), k * 2)]
        m_string = b""
        for x in cipher_text:
            plaintext = pow(x, dkey, nkey)
            plaintext = plaintext.to_bytes(plaintext.bit_length() // 8 + 1, "big")
            for i in plaintext:
                if i == 0:
                    plaintext = plaintext[1:]
            m_string += plaintext
        return m_string

    def generate_key(self, k) -> tuple:
        """
        生成公私钥
        k: 密钥位数
        """
        if k not in [128, 256, 512, 1024, 2048, 4096]:
            raise ValueError("k must be 128,256, 512, 1024, 2048, 4096")
        ekey = 65537
        p = getPrime(k // 2)
        q = getPrime(k // 2)
        nkey = p * q
        fn = (p - 1) * (q - 1)
        dkey = inverse(ekey, fn)
        return (ekey, nkey), (dkey, nkey)


def decrypt(cipher: str, private_key):
    """
    解密函数
    """
    private_key = tuple(private_key)
    if len(private_key) != 2 or not isinstance(private_key[0], int) or not isinstance(private_key[1], int):
        raise ValueError("private_key is error")
    dkey = private_key[0]
    nkey = private_key[1]
    digits = len(bin(private_key[1])[2:]) + 7
    k = digits // 8
    cipher_text = [int(cipher[i: i + k * 2], 16) for i in range(0, len(cipher), k * 2)]
    m_string = b""
    for x in cipher_text:
        plaintext = pow(x, dkey, nkey)
        plaintext = plaintext.to_bytes(plaintext.bit_length() // 8 + 1, "big")
        for i in plaintext:
            if i == 0:
                plaintext = plaintext[1:]
        m_string += plaintext
    return m_string


def encrypt(message: bytes, public_key):
    """
    加密函数
    """
    public_key = tuple(public_key)
    if len(public_key) != 2 or not isinstance(public_key[0], int) or not isinstance(public_key[1], int):
        raise ValueError("public_key is error")
    ekey = public_key[0]
    nkey = public_key[1]
    digits = len(bin(public_key[1])[2:]) + 7
    k = digits // 8
    cipher = ""
    for m in [message[i: i + k - 1] for i in range(0, len(message), k - 1)]:
        plaintext = int.from_bytes(m, "big")
        ciphertext = pow(plaintext, ekey, nkey)
        formattext = format(ciphertext, "x").zfill(k * 2)
        cipher += formattext
    return cipher
