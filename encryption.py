import base64
import hashlib
import os

class SimpleEncryption:
    def __init__(self, key=None):
        if key is None:
            self.key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        else:
            self.key = hashlib.sha256(key.encode()).hexdigest()[:32]

    def encrypt(self, text):
        result = []
        for i, char in enumerate(text):
            key_char = self.key[i % len(self.key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        encrypted_text = ''.join(result)
        return base64.b64encode(encrypted_text.encode()).decode()

    def decrypt(self, encrypted_b64):
        encrypted_text = base64.b64decode(encrypted_b64).decode()
        result = []
        for i, char in enumerate(encrypted_text):
            key_char = self.key[i % len(self.key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        return ''.join(result)
