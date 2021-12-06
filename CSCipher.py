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
    Fx = [0xf, 0xd, 0xb, 0xb, 0x7, 0x5, 0x7, 0x7, 0xe, 0xd, 0xa, 0xb, 0xe, 0xd,	0xe, 0xf]
    Gx = [0xa, 0x6, 0x0, 0x2, 0xb, 0xe, 0x1, 0x8, 0xd, 0x4, 0x5, 0x3, 0xf, 0xc, 0x7, 0x9]

    def __init__(self, file: str, decrypt: bool, key=None, ):
        self.key = key
        self.decrypt_mode = decrypt
        if decrypt:
            self.crypto_file = file
        else:
            self.plain_file = file
            if key is None:
                key = self.generate_keys()

    def generate_keys(self):
        st = '0123456789abcdef'
        key = ''.join(random.choice(st) for _ in range(self.key_length))
        self.subkeys.append(key[0:int(self.key_length / 2)])
        self.subkeys.append(key[int(self.key_length / 2):self.key_length])
        return key

    def P(self, x):
        xl = int(x[0], 16)
        xr = int(x[1], 16)
        y = xl ^ self.Fx[xr]
        zr = xr ^ self.Gx[y]
        zl = y ^ self.Fx[zr]
        return hex(zl).replace('0x','') + hex(zr).replace('0x','')


if __name__ == '__main__':
    cs = CSCipher('asdfasdfasdfasdfasdfasdfasdfasdfasdfasdf', False)
    print(cs.P('a1'))
