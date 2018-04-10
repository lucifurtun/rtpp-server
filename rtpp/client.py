import argparse
import binascii
import socket
from time import sleep

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from rtpp import less

IP = '127.0.0.1'
PORT = 9999

SECRET = binascii.unhexlify(b'8fd8a79dad96c50093a150a2ead30d86')

MESSAGE = b'Test Message'


def _send_tcp_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP, PORT))
    print('Connected over TCP to {}'.format((IP, PORT)))

    auth = less.ClientAuth(SECRET)

    message = auth.step_1()
    sock.send(message)

    data = sock.recv(32)

    data = auth.step_3(data)
    sock.send(data)

    data = sock.recv(32)

    auth.step_5(data)

    key = auth.get_encryption_key()

    unencrypted = b'46.1497877,21.5864098' + b'00000000000'

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backends.default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(unencrypted) + encryptor.finalize()

    for x in range(10):
        sock.send(encrypted)
        sleep(2)


def _send_udp_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(MESSAGE, (IP, PORT))

    print('Connected over UDP to {}'.format((IP, PORT)))
    print('Sent: {}'.format(MESSAGE))


def main(protocol):
    global loop

    if protocol == 'tcp':
        _send_tcp_data()
    elif protocol == 'udp':
        _send_udp_data()
    else:
        raise Exception('Unknown base protocol')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTPP Client')
    parser.add_argument('--protocol', action='store', type=str, choices=('tcp', 'udp'))

    arguments = parser.parse_args()

    main(arguments.protocol)
