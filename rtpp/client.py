import argparse
import socket

IP = '127.0.0.1'
PORT = 9999

MESSAGE = b'Hello, World!'


def _send_tcp_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP, PORT))
    sock.send(MESSAGE)

    print('Connected over TCP to {}'.format((IP, PORT)))
    print('Message: {}'.format(MESSAGE))


def _send_udp_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(MESSAGE, (IP, PORT))

    print('Connected over UDP to {}'.format((IP, PORT)))
    print('Message: {}'.format(MESSAGE))


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
