import argparse
import asyncio

HOST = '127.0.0.1'
PORT = 9999

loop = None


class TCPProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Received {!r} from {!s}'.format(message, self.transport.get_extra_info('peername')))
        print('Send {!r} to {!s}'.format(message, self.transport.get_extra_info('peername')))
        self.transport.write(data)

        print('Closing client socket')
        self.transport.close()

    @classmethod
    def start_server(cls):
        global loop

        listen = loop.create_server(cls, HOST, PORT)
        server = loop.run_until_complete(listen)
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
