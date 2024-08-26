import socket, select
import ssl
import time
from dataclasses import dataclass
import fcntl
import array
from threading import Thread, Lock, Condition


CHUNK_MAX_SIZE = 65536
WRAPPER_TIMER_SEC = 0.00005  # 50us

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

@dataclass
class CherrySocketWrapper:
    def __init__(self, ip, port, scheme):
        self.ip = ip
        self.port = port
        self.n_reconnections = 5
        self.reconnection_timer_s = 5
        self.socket = None
        self.mutex = Lock()
        self.scheme = scheme
        self.connect()

    def connect(self):
        if self.scheme == 'HTTP':
            self.connect_HTTP()
        else:
            self.connect_HTTPS()

    def connect_HTTP(self):
        attempt = 0
        while attempt < self.n_reconnections:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.ip, self.port))
                self.socket.setblocking(False)
                print("LOGGING: CherrySocketWrapper: Connection established.")
                return
            except socket.error as e:
                print(f"LOGGING: CherrySocketWrapper: Connection attempt {attempt + 1} failed: {e}")
                attempt += 1
                time.sleep(self.reconnection_timer_s)
        print("LOGGING: CherrySocketWrapper: All connection attempts failed. Exiting.")
        raise DBConnectionError(f"Could not connect to DB")

    def connect_HTTPS(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_socket = context.wrap_socket(raw_socket, server_hostname=self.ip)
            secure_socket.connect((self.ip, self.port))
            self.socket = secure_socket
            self.socket.setblocking(False)
            print("LOGGING: CherrySocketWrapper: Connection established.")
            return
        except socket.error as e:
            print(f"LOGGING: CherrySocketWrapper: Connection failed")
            raise DBConnectionError(f"Could not connect to DB")

    def is_socket_connected(self):
        try:
            #_, writable, _ = select.select([], [self.socket], [], 0)
            writable = True
            r, w, e=select.select([self.socket],[],[self.socket], 0)
            if r or e:
                #print("LOGGING: WARNING: the socket is closed")
                writable = False
            if not writable:
                return False
            self.socket.send(b'')  # Try to send an empty byte string
        except socket.error as e:
            print(f"LOGGING: CherrySocketWrapper: socket error in select: {e}")
            if e.errno in (socket.errno.ECONNRESET, socket.errno.ENOTCONN, socket.errno.EPIPE):
                return False
        except Exception as e:
            print(f"LOGGING: CherrySocketWrapper: unknown error in select: {e}")
        return True

    def write(self, byte_array):
        if not self.is_socket_connected():
            #print("LOGGING: WARNING: Socket is not connected, attempting to reconnect.")
            #res_connect = 0
            #with self.mutex:
            #    res_connect = self.connect()
            #if res_connect != 0:
            #    return -1
            raise DBConnectionError('write failed: socket is not connected')
        try:
            self.socket.send(byte_array)
            n = get_outgoing_bytes(self.socket)
            #print(f'n bytes in socket tx buf: {n}')
        except socket.error as e:
            if e.errno in (socket.errno.ECONNRESET, socket.errno.ENOTCONN, socket.errno.EPIPE):
                print("LOGGING: WARNING: Connection reset by peer or not connected. Attempting to reconnect.")
                return_code = 0
                with self.mutex:
                    res_connect = self.connect()
                    if res_connect == 0:
                        try:
                            self.socket.send(byte_array)
                            n = get_outgoing_bytes(self.socket)
                            #print(f'n bytes in socket tx buf: {n}')
                        except socket.error as e:
                            print(f"LOGGING: WARNING: Error sending data after reconnect: {e}")
                            return_code = -1
                    else:
                        print("LOGGING: WARNING: Reconnection failed.")
                        return_code = -1
                if return_code != 0:
                    return -1
            else:
                print(f"LOGGING: WARNING: Error sending data: {e}")
                return -1

        try:
            _, writable, _ = select.select([], [self.socket], [], 0)
        except socket.error as e:
            print(f"LOGGING: WARNING: Select error: {e}")
            return -1

        while len(writable) == 0:
            try:
                _, writable, _ = select.select([], [self.socket], [], 0)
                time.sleep(WRAPPER_TIMER_SEC)  # 50us
            except socket.error as e:
                print(f"LOGGING: WARNING: Select error in loop: {e}")
                return -1

        return 0

    def close(self):
        print(f"LOGGING: CherrySocketWrapper: closing socket")
        self.socket.close()
        self.connected = False

    def read_available_bytes(self):
        #print(f'LOGGING: wrapper: read_available_bytes: start')
        buffer_end = False
        buffer = b''
        while not buffer_end:
            #print(f'LOGGING: {time.time()}: wrapper: read available_bytes: loop start')
            try:
                chunk = self.socket.recv(CHUNK_MAX_SIZE)
                buffer += chunk
                if chunk.__len__() < CHUNK_MAX_SIZE:
                    buffer_end = True
            except BlockingIOError:
                buffer_end = True
            except socket.error as e:
                #print(f'LOGGING: wrapper.py: read_available_bytes: Socket error: {e}')
                buffer_end = True
        #print(f'LOGGING: wrapper: read_available_bytes: end: buffer: {buffer}')
        return buffer

    #def write(self, byte_array):
    #    self.socket.send(byte_array)
    #    _, writable, _ = select.select([], [self.socket], [])
    #    while writable.__len__()<=0:
    #        _, writable, _ = select.select([], [self.socket], [])
