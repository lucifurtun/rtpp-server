import argparse
import asyncio
import binascii

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rtpp import less

HOST = '127.0.0.1'
PORT = 9999

SECRET = binascii.unhexlify(b'8fd8a79dad96c50093a150a2ead30d86')

loop = None


class TCPProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data
        hex_message = binascii.hexlify(message)

        print('Received {!r} from {!s}'.format(hex_message, self.transport.get_extra_info('peername')))

        auth = less.ServerAuth(SECRET)
        encrypted = auth.step_2(message)

        if not encrypted:
            self.transport.close()
            return

        print('Send {!r} to {!s}'.format(binascii.hexlify(encrypted), self.transport.get_extra_info('peername')))
        self.transport.write(encrypted)

        data = self.transport.read(32)

        print('Received: {}'.format(data))

        print('Closing client socket')
        self.transport.close()

    @classmethod
    def start_server(cls):
        global loop

        # listen = loop.create_server(cls, HOST, PORT)
        # server = loop.run_until_complete(listen)
        # print('Starting RTPP server over TCP on {}'.format(server.sockets[0].getsockname()))

        coro = asyncio.start_server(handle_tcp, HOST, PORT, loop=loop)
        server = loop.run_until_complete(coro)
        print('Starting RTPP server over TCP on {}'.format(server.sockets[0].getsockname()))

        return server


class UDPProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = data.decode()
        print('Received {!r} from {!s}'.format(message, addr))
        print('Send {!r} to {!s}'.format(message, addr))
        self.transport.sendto(data, addr)

    @classmethod
    def start_server(cls):
        global loop

        listen = loop.create_datagram_endpoint(cls, local_addr=(HOST, PORT))
        server, _ = loop.run_until_complete(listen)
        print('Starting RTPP server over UDP on {}'.format(server._extra['sockname']))

        return server


async def handle_tcp(reader, writer):
    auth = less.ServerAuth(SECRET)

    message = await reader.read(32)
    encrypted = auth.step_2(message)

    writer.write(encrypted)
    await writer.drain()

    data = await reader.read(32)
    encrypted = auth.step_4(data)

    writer.write(encrypted)
    await writer.drain()

    key = auth.get_decryption_key()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backends.default_backend())
    decryptor = cipher.decryptor()

    while True:
        encrypted = await reader.read(32)
        if not encrypted:
            break

        decrypted_message = decryptor.update(encrypted)
        print('Received: {}'.format(decrypted_message))

    print('Closing client socket')
    writer.close()


def main(protocol):
    global loop
    loop = asyncio.get_event_loop()

    if protocol == 'tcp':
        server = TCPProtocol.start_server()
    elif protocol == 'udp':
        server = UDPProtocol.start_server()
    else:
        raise Exception('Unknown base protocol')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('\nThe server has been stopped')

    server.close()
    loop.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RTPP Server')
    parser.add_argument('--protocol', action='store', type=str, choices=('tcp', 'udp'))

    arguments = parser.parse_args()

    main(arguments.protocol)
