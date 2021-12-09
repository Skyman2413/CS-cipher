import random


class CSCipher:
    plain_file: str
    crypto_file: str
    key: str
    decrypt_mode: bool
    key_length = 32
    c = 0xb7e151628aed2a6a
    cc = 0xbf7158809cf4f3c7
    ci = [
        0x290d61409ceb9e8f,
        0x1f855f585b013986,
        0x972ed7d635ae1716,
        0x21b6694ea5728708,
        0x3c18e6e7faadb889,
        0xb700f76f73841163,
        0x3f967f6ebf149dac,
        0xa40e7ef6204a6230,
        0x03c54b5a46a34465
    ]
    subkeys = []
    Fx = [0xf, 0xd, 0xb, 0xb, 0x7, 0x5, 0x7, 0x7, 0xe, 0xd, 0xa, 0xb, 0xe, 0xd, 0xe, 0xf]
    Gx = [0xa, 0x6, 0x0, 0x2, 0xb, 0xe, 0x1, 0x8, 0xd, 0x4, 0x5, 0x3, 0xf, 0xc, 0x7, 0x9]

    def __init__(self, file: str, decrypt: bool, key=None, ):
        self.key = key
        self.decrypt_mode = decrypt
        buf = file.encode().hex()
        if len(buf) % 16 != 0:
            buf = self.fill_to_full(buf, len(buf) + len(buf) % 16)
        if decrypt:
            self.crypto_file = buf
        else:
            self.plain_file = buf
            if key is None:
                self.key = self.generate_key()
        self.generate_subkeys()

    def encrypt(self):
        file = self.plain_file
        for i in range(0, len(file), 16):
            # TODO
            pass

    def generate_subkeys(self):
        self.subkeys.append(self.key[0:int(self.key_length / 2)])
        self.subkeys.append(self.key[int(self.key_length / 2):self.key_length])
        for i in range(2, 11):
            xor = int(self.subkeys[i - 1], 16) ^ self.ci[i - 2]
            xor = hex(xor).replace('0x', '')
            xor = self.fill_to_full(xor, 16)
            sub = int(self.subkeys[i - 2], 16) ^ int(self.T(self.P8(xor)), 16)
            self.subkeys.append(sub)

    def generate_key(self) -> str:
        st = '0123456789abcdef'
        key = ''.join(random.choice(st) for _ in range(self.key_length))
        return key

    def P(self, x) -> str:
        xl = int(x[0], 16)
        xr = int(x[1], 16)
        y = xl ^ self.Fx[xr]
        zr = xr ^ self.Gx[y]
        zl = y ^ self.Fx[zr]
        return hex(zl).replace('0x', '') + hex(zr).replace('0x', '')

    def P8(self, x) -> str:
        x = self.fill_to_full(x, 16)
        res = ''
        for i in range(0, 16, 2):
            res += self.P(x[i:i + 2])
        return res

    def fill_to_full(self, x, count) -> str:
        while len(x) < count:
            x = '0' + x
        return x

    def T(self, x) -> str:
        res = ''
        for i in range(8):
            for j in range(8):
                res += x[63 - i - j * 8]
        return res


if __name__ == '__main__':
    cs = CSCipher('asdfasdfasdfasdfasdfasdfasdfasdfasdfasdf', False)
    print(cs.P('a1'))
