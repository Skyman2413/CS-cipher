class CSCipher:
    plain_file: str
    crypto_file: str
    key: str

    def __init__(self, crypto_file: str, key: str):
        self.key = key
        self.crypto_file = crypto_file

    def __int__(self, plain_file: str, key: str):
        self.plain_file = plain_file
        self.key = key

    @staticmethod
    def generate_key():
        key = ""
        return key

    