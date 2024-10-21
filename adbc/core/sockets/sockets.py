import socket, select
import ssl
import time
from dataclasses import dataclass
import errno
import fcntl
import array
import sys
from threading import Thread, Lock, Condition

CHUNK_MAX_SIZE      = 1000000000
SELECT_TIMEOUT      = 3

def get_outgoing_bytes(sock):
    # Use the SIOCOUTQ ioctl command to get the number of bytes in the send queue
    SIOCOUTQ = 0x5411
    buf = array.array('i', [0])
    fcntl.ioctl(sock, SIOCOUTQ, buf)
    return buf[0]

class DBConnectionError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

verbose = False

@dataclass
class Socket_wrapper:
    def __init__(self, ip, port, scheme):
        self.ip = ip
        self.port = port
        self.socket = None
        self.mutex = Lock()
        self.scheme = scheme
        self.connect()

    def connect(self):
        if self.scheme == 'HTTP':
            try:
                self.connect_HTTP()
            except DBConnectionError as e:
                raise DBConnectionError(f'ERROR: connect: connection error: 1010')
        else:
            try:
                self.connect_HTTPS()
            except DBConnectionError as e:
                raise DBConnectionError(f'ERROR: connect: connection error: 1020')

    def connect_HTTP(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.ip, self.port))
            self.socket.setblocking(False)
        except Exception as e:
            raise DBConnectionError(f'ERROR: connect_HTTP: connection error: 1030')

    def connect_HTTPS(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_socket = context.wrap_socket(raw_socket, server_hostname=self.ip)
            secure_socket.connect((self.ip, self.port))
            secure_socket.setblocking(False)
            self.socket = secure_socket
        except Exception as e:
            raise DBConnectionError(f'ERROR: connect_HTTPS: connection error: 1040')

    def write(self, byte_array):
        total_sent = 0
        try:
            while total_sent < len(byte_array):
                try:
                    sent = self.socket.send(byte_array[total_sent:])
                    if verbose:
                        print(f'LOGGING: sockets: write: sent: {sent} bytes')
                    if sent == 0:
                        # This means the connection is closed
                        raise DBConnectionError("ERROR: write: connection closed unexpectedly.")
                    total_sent += sent
                except (BlockingIOError, socket.error) as e:
                    if e.errno == socket.errno.EWOULDBLOCK:
                        # The socket is non-blocking and would block, return the bytes written so far
                        return total_sent
                    else:
                        raise DBConnectionError(f"ERROR: write: connection error: 1050")
        except Exception as e:
            raise DBConnectionError(f'ERROR: write: connection error: 1060')

        return total_sent

    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def read(self):
        buffer_end = False
        buffer = b''
        while not buffer_end:
            try:
                chunk = self.socket.recv(CHUNK_MAX_SIZE)
                buffer += chunk
                if chunk.__len__() < CHUNK_MAX_SIZE:
                    buffer_end = True
            except BlockingIOError:
                buffer_end = True
            except Exception as e:
                #raise DBConnectionError(f'ERROR: read: connection error: {str(e)}')
                buffer_end = True
                pass
        return buffer
