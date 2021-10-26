class CSCipher:
    plain_file: str
    crypto_file: str
    key: str
    decrypt_mode: bool

    def __init__(self, file: str, key: str, decrypt: bool):
        self.key = key
        self.decrypt_mode = decrypt
        if decrypt:
            self.crypto_file = file
        else:
            self.plain_file = file

    @staticmethod
    def generate_key():
        key = ""
        return key
