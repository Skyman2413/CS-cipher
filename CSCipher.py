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
        buf = file
        if len(buf) % 16 != 0:
            buf = self.fill_to_full(buf, len(buf) + len(buf) % 16)
        if decrypt:
            self.crypto_file = buf
        else:
            self.plain_file = buf
            if key is None:
                self.key = self.generate_key()

    def encrypt(self):
        file = self.plain_file
        encrypted = ''
        self.generate_subkeys()
        for i in range(0, len(file), 16):
            m0 = file[i:i + 16]
            m0 = self.fill_to_full(m0, 16)
            print(m0)
            m05 = self.fill_to_full(hex(int(self.subkeys[2], 16) ^ int(m0, 16)).replace('0x', ''), 16)
            m1 = hex(int(self.subkeys[3], 16) ^ int(self.E(m05), 16)).replace('0x', '')
            m1 = self.fill_to_full(m1, 16)
            print(m1)
            m2 = hex(int(self.subkeys[4], 16) ^ int(self.E(m1), 16)).replace('0x', '')
            m2 = self.fill_to_full(m2, 16)
            print(m2)
            m3 = hex(int(self.subkeys[5], 16) ^ int(self.E(m2), 16)).replace('0x', '')
            m3 = self.fill_to_full(m3, 16)
            print(m3)
            m4 = hex(int(self.subkeys[6], 16) ^ int(self.E(m3), 16)).replace('0x', '')
            m4 = self.fill_to_full(m4, 16)
            print(m4)
            m5 = hex(int(self.subkeys[7], 16) ^ int(self.E(m4), 16)).replace('0x', '')
            m5 = self.fill_to_full(m5, 16)
            print(m5)
            m6 = hex(int(self.subkeys[8], 16) ^ int(self.E(m5), 16)).replace('0x', '')
            m6 = self.fill_to_full(m6, 16)
            print(m6)
            m7 = hex(int(self.subkeys[9], 16) ^ int(self.E(m6), 16)).replace('0x', '')
            m7 = self.fill_to_full(m7, 16)
            print(m7)
            m8 = hex(int(self.E(m7), 16) ^ int(self.subkeys[10], 16)).replace('0x', '')
            m8 = self.fill_to_full(m8, 16)
            print(m8)
            encrypted += m8
        self.crypto_file = encrypted
        return encrypted


    def decrypt(self):
        file = self.crypto_file
        self.generate_subkeys()
        decrypted = ''
        for i in range(0, len(file), 16):
            block = file[i:i + 16]
            block = self.fill_to_full(block, 16)
            for j in range(10, 2, -1):
                block = hex(int(block, 16) ^ int(self.subkeys[j], 16)).replace('0x', '')
                block = self.fill_to_full(block, 16)
                block = self.E_rev(block)
            block = hex(int(block, 16) ^ int(self.subkeys[2], 16)).replace('0x', '')
            block = self.fill_to_full(block, 16)
            decrypted += block
        return decrypted

    def phi(self, x):
        x = bin(int(x, 16)).replace('0b', '')
        res = (int(self.shift(x, -1), 2) & 0x55) ^ int(x, 2)
        return self.fill_to_full(hex(res).replace('0x', ''), 2)

    def phi_rev(self, x):
        x = bin(int(x, 16)).replace('0b', '')
        x = self.fill_to_full(x, 8)
        res = (int(self.shift(x, -1), 2) & 0xaa) ^ int(x, 2)
        return self.fill_to_full(hex(res).replace('0x', ''), 2)

    def M(self, x):
        xl = self.fill_to_full(bin(int(x[0:2], 16)).replace('0b', ''), 8)
        xr = x[2:4]
        a = hex(int(self.phi(xl), 2) ^ int(xr, 16)).replace('0x', '')
        a = self.fill_to_full(a, 2)
        yl = self.P(a)

        b = self.shift(xl, -1)
        b = hex(int(b, 16) ^ int(xr, 16)).replace('0x', '')
        b = self.fill_to_full(b, 2)
        yr = self.P(b)
        return yl + yr

    def M_rev(self, y):
        yl = y[0:2]
        yr = y[2:4]
        a = hex(int(self.P(yl), 16) ^ int(self.P(yr),16)).replace('0x', '')
        a = self.fill_to_full(a, 2)
        xl = self.phi_rev(a)
        xr = self.fill_to_full(hex(int(self.shift(xl, -1), 16) ^ int(self.P(yr),16)).replace('0x', ''), 2)
        return xl + xr

    def E(self, x):
        t = ''
        for i in range(0, 16, 4):
            t += self.M(x[i:i+4])
        t = t[0:2] + t[4:6] + t[8:10] + t[12:14] + t[2:4] + t[6:8] + t[10:12] + t[14:16]
        print(t)
        t = hex(int(t, 16) ^ self.c).replace('0x', '')
        t = self.fill_to_full(t, 16)
        t1 = ''
        for i in range(0, 16, 4):
            t1 += self.M(t[i:i+4])
        t1 = t1[0:2] + t1[4:6] + t1[8:10] + t1[12:14] + t1[2:4] + t1[6:8] + t1[10:12] + t1[14:16]
        print(t1)
        t1 = hex(int(t1, 16) ^ self.cc).replace('0x', '')
        t1 = self.fill_to_full(t1, 16)
        t2 = ''
        for i in range(0, 16, 4):
            t2 += self.M(t1[i:i+4])
        t2 = t2[0:2] + t2[4:6] + t2[8:10] + t2[12:14] + t2[2:4] + t2[6:8] + t2[10:12] + t2[14:16]

        return t2

    def E_rev(self, x):
        t = x[0:2] + x[8:10] + x[2:4] + x[10:12] + x[4:6] + x[12:14] + x[6:8] + x[14:16]
        t1 = ''
        for i in range(0, 16, 4):
            t1 += self.M_rev(t[i:i + 4])

        t1 = hex(int(t1, 16) ^ self.cc).replace('0x', '')
        t1 = t1[0:2] + t1[8:10] + t1[2:4] + t1[10:12] + t1[4:6] + t1[12:14] + t1[6:8] + t1[14:16]
        t1 = self.fill_to_full(t1, 16)
        t2 = ''

        for i in range(0, 16, 4):
            t2 += self.M_rev(t1[i:i + 4])

        t2 = hex(int(t2, 16) ^ self.c).replace('0x', '')
        t2 = t2[0:2] + t2[8:10] + t2[2:4] + t2[10:12] + t2[4:6] + t2[12:14] + t2[6:8] + t2[14:16]
        t2 = self.fill_to_full(t2, 16)
        t3 = ''
        for i in range(0, 16, 4):
            t3 += self.M_rev(t2[i:i + 4])
        return t3

    def generate_subkeys(self):
        self.subkeys.clear()
        self.subkeys.append(self.key[int(self.key_length / 2):self.key_length])
        self.subkeys.append(self.key[0:int(self.key_length / 2)])
        for i in range(2, 11):
            a = hex(self.ci[i-2])
            xor = int(self.subkeys[i - 1], 16) ^ self.ci[i - 2]
            xor = hex(xor).replace('0x', '')
            xor = self.fill_to_full(xor, 16)
            P8 = self.P8(xor)
            T = self.T(P8)
            sub = hex(int(self.subkeys[i - 2], 16) ^ int(T, 16)).replace('0x', '')
            self.subkeys.append(self.fill_to_full(sub, 16))

    def generate_key(self) -> str:
        st = '0123456789abcdef'
        key = ''.join(random.choice(st) for _ in range(self.key_length))
        return key

    def shift(self, lst, steps):
        lst_res = list(lst)
        if steps < 0:
            steps = abs(steps)
            for i in range(steps):
                lst_res.append(lst_res.pop(0))
        else:
            for i in range(steps):
                lst_res.insert(0, lst_res.pop())
        res = ''
        for symb in lst_res:
            res += symb
        return res


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
        x = bin(int(x, 16)).replace('0b', '')
        x = self.fill_to_full(x, 64)
        for i in range(8):
            for j in range(8):
                ind = i + j * 8
                res += x[ind]
        return self.fill_to_full(hex(int(res, 2)).replace('0x', '0'), 16)


if __name__ == '__main__':
    key = '0123456789abcdeffedcba9876543210'
    text = ''
    b1 = '0123456789abcdef'
    cs = CSCipher(b1, False, key)

    a = cs.encrypt()
    print(cs.subkeys)
    cs1 = CSCipher(a, True, key)
    b = cs.decrypt()
    print(b1)
    print(a)
    print(b)
