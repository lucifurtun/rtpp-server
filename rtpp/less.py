import os
import re

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rtpp import utils


class ServerAuth:
    def __init__(self, secret):
        self.secret = secret
        self.server_rand = os.urandom(12)
        self.client_rand = None
        self.k_c = os.urandom(16)
        self.k_s = os.urandom(16)

        self._last_step_done = False

    def step_2(self, message):
        cipher = Cipher(algorithms.AES(self.secret), modes.ECB(), backend=backends.default_backend())
        encryptor = cipher.encryptor()

        init_headers = message[:11]

        try:
            match = re.search(r'HELLO-(?P<id>.+)-', init_headers.decode())
        except UnicodeDecodeError:
            print('Error: {}'.format(init_headers))
            return

        if not match:
            return

        client_id = match.groupdict().get('id')
        hello_rand = message[11:]
        ext_hello_rand = hello_rand + hello_rand[:4]

        k_c_obfuscated = utils.xor_for_bytes(ext_hello_rand, self.k_c)

        unencrypted = k_c_obfuscated + self.server_rand + b'0000'
        encrypted = encryptor.update(unencrypted) + encryptor.finalize()

        return encrypted

    def step_4(self, message):
        cipher = Cipher(algorithms.AES(self.k_c), modes.ECB(), backend=backends.default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(message) + decryptor.finalize()

        server_rand = decrypted_message[:12]
        client_rand = decrypted_message[12:24]

        if server_rand == self.server_rand:
            print('Server Rand is ok')
        else:
            print('Server Rand is wrong')

        ext_server_rand = server_rand + server_rand[:4]
        k_s_obfuscated = utils.xor_for_bytes(ext_server_rand, self.k_s)

        unencrypted = k_s_obfuscated + client_rand + b'0000'

        cipher = Cipher(algorithms.AES(self.secret), modes.ECB(), backend=backends.default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(unencrypted) + encryptor.finalize()

        self._last_step_done = True

        return encrypted

    def get_decryption_key(self):
        assert self._last_step_done is True

        return self.k_c

    def get_encryption_key(self):
        assert self._last_step_done is True

        return self.k_s


class ClientAuth:
    def __init__(self, secret):
        self.secret = secret
        self.hello_rand = os.urandom(12)  # 96 bit random number
        self.client_rand = os.urandom(12)
        self.server_rand = None
        self.k_c = None
        self.k_s = None

        self._last_step_done = False

    def step_1(self):
        hello_rand = self.hello_rand

        message = b'HELLO-1234-' + hello_rand

        return message

    def step_3(self, message):
        cipher = Cipher(algorithms.AES(self.secret), modes.ECB(), backend=backends.default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(message) + decryptor.finalize()

        k_c_obfuscated = decrypted_message[:16]
        self.server_rand = decrypted_message[16:28]

        unencrypted = self.server_rand + self.client_rand + b'00000000'
        ext_hello_rand = self.hello_rand + self.hello_rand[:4]

        self.k_c = utils.xor_for_bytes(ext_hello_rand, k_c_obfuscated)

        cipher = Cipher(algorithms.AES(self.k_c), modes.ECB(), backend=backends.default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(unencrypted) + encryptor.finalize()

        return encrypted

    def step_5(self, message):
        cipher = Cipher(algorithms.AES(self.secret), modes.ECB(), backend=backends.default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(message) + decryptor.finalize()

        k_s_obfuscated = decrypted_message[:16]
        ext_server_rand = self.server_rand + self.server_rand[:4]
        self.k_s = utils.xor_for_bytes(ext_server_rand, k_s_obfuscated)

        client_rand = decrypted_message[16:28]

        if client_rand == self.client_rand:
            print('Client Rand is ok')
        else:
            print('Client Rand is wrong')

        self._last_step_done = True

    def get_decryption_key(self):
        assert self._last_step_done is True

        return self.k_s

    def get_encryption_key(self):
        assert self._last_step_done is True

        return self.k_c
