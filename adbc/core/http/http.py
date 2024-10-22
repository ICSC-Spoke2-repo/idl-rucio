__all__ = ['HTTPMessage', 'HTTP_rx_buffer', 'HTTP_tx_buffer']

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Dict
from enum import Enum
import logging
import time
import threading
from threading import Lock

from adbc.core.sockets.sockets import Socket_wrapper, DBConnectionError

verbose = False
verbose_parse_message = False
verbose_thread = False
verbose_thread_responses = False
verbose_get_next_response = False

SLEEP_TIME_50_US = 0.00005 # 50 microseconds
TIMEOUT_RESPONSE = 100     # 100 seconds
PIPELINE_SIZE = 24         # for the pipelined HTTP_connection

class HTTPMessageNotWellFormedError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class HTTPConnectionBusyError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class HTTPConnectionResponseTimeoutError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class HTTP_header:
    HOST              = "Host"
    CONTENT_LENGTH    = "Content-Length"
    CONNECTION        = "Connection"
    CHERRY_REQUEST_ID = "Cherrydata_request_tag"
    TRANSFER_ENCODING = 'Transfer-Encoding'
    AUTHORIZATION     = 'Authorization'
    LOCATION          = 'Location'

class HTTP_method(Enum):
    CONNECT = 0
    DELETE  = 1
    GET     = 2
    HEAD    = 3
    OPTIONS = 4
    POST    = 5
    PUT     = 6
    TRACE   = 7

HTTP_method_name = {
        HTTP_method.CONNECT: 'CONNECT',
        HTTP_method.DELETE:  'DELETE',
        HTTP_method.GET:     'GET',
        HTTP_method.HEAD:    'HEAD',
        HTTP_method.OPTIONS: 'OPTIONS',
        HTTP_method.POST:    'POST',
        HTTP_method.PUT:     'PUT',
        HTTP_method.TRACE:   'TRACE' }

class HTTP_message_type(Enum):
    REQUEST  = 0
    RESPONSE = 1
    EMPTY    = 2

class HTTP_parsing_constants:
    # for response messages
    HTTP_MIN_PARSABLE_LENGTH          = 8
    HTTP_PROTO_BYTES_SIZE             = 8
    HTTP_STATUS_CODE_FIRST_BYTE_IDX   = 9
    HTTP_STATUS_MSG_FIRST_BYTE_IDX    = 13
    HTTP_RESPONSE_MIN_FIRST_LINE_SIZE = 14
    HTTP_LINE_TERMINATOR              = b'\x0d\x0a'
    HTTP_PROTO_TOKEN                  = b'\x48\x54\x54\x50\x2F\x31\x2e\x31'
    HTTP_CONNECT_TOKEN                = b'\x43\x4f\x4e\x4e\x45\x43\x54'
    HTTP_DELETE_TOKEN                 = b'\x44\x45\x4c\x45\x54\x45'
    HTTP_GET_TOKEN                    = b'\x47\x45\x54'
    HTTP_HEAD_TOKEN                   = b'\x48\x45\x41\x44'
    HTTP_OPTIONS_TOKEN                = b'\x4f\x50\x54\x49\x4f\x4e\x53'
    HTTP_POST_TOKEN                   = b'\x50\x4f\x53\x54'
    HTTP_PUT_TOKEN                    = b'\x50\x55\x54'
    HTTP_TRACE_TOKEN                  = b'\x54\x52\x41\x43\x45'

def create_authorization_header_complete(token):
    value = f'{HTTP_header.AUTHORIZATION}: Bearer {token}'
    return value

def create_authorization_header_value(token):
    value = f'Bearer {token}'
    return value

@dataclass
class HTTPMessage:
    message_type: HTTP_message_type = -1
    method: HTTP_method = -1
    request_uri: str = None
    status_code: int = -1
    reason_phrase: str = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''
    is_chunked: bool = False
    is_last_chunk: bool = False

    def __init__(self, \
            message_type: HTTP_message_type, \
            headers: Optional[Dict[str, str]] = None, \
            body: Optional[bytes] = None, \
            method: Optional[HTTP_method] = -1, \
            request_uri: Optional[str] = None, \
            status_code: Optional[int] = -1, \
            reason_phrase: Optional[str] = None, \
            is_chunked: Optional[bool] = False, \
            is_last_chunk: Optional[bool] = False):
        if message_type == HTTP_message_type.REQUEST:
            self.message_type = message_type
            if method == -1:
                raise HTTPMessageNotWellFormedError('trying to instantiate a request HTTP message with no method')
            self.method = method
            if request_uri is None:
                raise HTTPMessageNotWellFormedError('trying to instantiate a request HTTP message with no request_uri')
            self.request_uri = request_uri
        elif message_type == HTTP_message_type.RESPONSE:
            self.message_type = message_type
            if status_code == -1:
                raise HTTPMessageNotWellFormedError('trying to instantiate a response HTTP message with no status_code')
            self.status_code = status_code
            if reason_phrase is None:
                raise HTTPMessageNotWellFormedError('trying to instantiate a response HTTP message with no reason_phrase')
            self.reason_phrase = reason_phrase
            self.is_chunked = is_chunked
            self.is_last_chunk = is_last_chunk
        else:
            raise HTTPMessageNotWellFormedError('trying to instantiate an HTTP message with wrong message type')

        if headers:
            self.headers = headers
        if body:
            self.body = body

    def get_location_header_value(self):
        location = None
        location_header = self.headers.get(Header.LOCATION)
        if location_header:
            location = location_header
        return location

    def to_byte_array(self):
        byte_array = bytearray()
        if self.message_type == HTTP_message_type.REQUEST:
            # line 1: request line
            byte_array += bytearray(HTTP_method_name[self.method], 'utf-8')
            byte_array += b' '
            byte_array += bytearray(self.request_uri, 'utf-8')
            byte_array += b' '
            byte_array += HTTP_parsing_constants.HTTP_PROTO_TOKEN
            byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR

            # headers
            for header, h_value in self.headers.items():
                byte_array += bytearray(header, 'utf-8')
                byte_array += b': '
                byte_array += bytearray(str(h_value), 'utf-8')
                byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR
            byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR

            # body
            byte_array += self.body
        elif self.message_type == HTTP_message_type.RESPONSE:
            # line 1: status line
            byte_array += HTTP_parsing_costants.HTTP_PROTO_TOKEN
            byte_array += b' '
            byte_array += bytearray(str(self.status_code), 'utf-8')
            byte_array += b' '
            byte_array += bytearray(self.reason_phrase, 'utf-8')
            byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR

            # headers
            for header, h_value in self.headers.items():
                byte_array += bytearray(header, 'utf-8')
                byte_array += b': '
                byte_array += bytearray(str(h_value), 'utf-8')
                byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR
            byte_array += HTTP_parsing_constants.HTTP_LINE_TERMINATOR

            # body
            byte_array += self.body
        return byte_array

    def print(self):
        print('HTTP message:', end='')
        if self.message_type == HTTP_message_type.RESPONSE:
            print('RESPONSE')
            print(f'    status_code: {self.status_code}: {self.reason_phrase}')
        elif self.message_type == HTTP_message_type.REQUEST:
            print('REQUEST')
            print(f'    method: {self.method}: {self.request_uri}')

        print('    headers:')
        for h in self.headers:
            print(f'        {h}: {self.headers[h]}')

        print(f'    body: (length = {len(self.body)})')
        if self.message_type == HTTP_message_type.RESPONSE:
            print(f'    body is chunked: {self.is_chunked}', end='')
            if self.is_chunked == True:
                print(f'    last chunk of body: {self.is_last_chunk}')
            else:
                print('')
        print(f'    {self.body}')

class HTTP_rx_buffer:
    def __init__(self):
        self.byte_array = bytearray()
        self.byte_array_mutex = Lock()

    def _seek_sub_slice(self, sub_slice, start=0):
        # Start searching from the start position
        idx = start
        sub_sl_len = sub_slice.__len__()
        # Search up for the first sub slice byte 
        # up to (byte_array.length - sub_slice.length) byte
        # After that we don't have enough byte to find the pattern
        while idx + sub_sl_len - 1 < self.byte_array.__len__():
            if self.byte_array[idx] == sub_slice[0]:
                # First byte of the pattern found
                idx += 1
                # Move to next and check remaining bytes
                if self.byte_array[idx:idx + sub_sl_len - 1] == sub_slice[1:]:
                    # Pattern found (Move back to original position)
                    return idx - 1
            else:
                idx += 1
        # Pattern not found
        return -1

    def _seek_line_terminator(self, start=0):
        return self._seek_sub_slice(HTTP_parsing_constants.HTTP_LINE_TERMINATOR, start=start)

    def __retrieve_chunk_length(self, start, end):
        # Retrieve chunk length and convert it to int
        chunk_length = self.byte_array[start:end].decode('ascii')
        return int(chunk_length, 16)  # The length is in HEX notation, that is why we insert 16.

    def parse_message(self):
        message = None
        message_type = HTTP_message_type.EMPTY
        method = None
        status_code = -1
        header_buffer_seek_pos = -1
        flag_headers_ok = False
        flag_body_ok = False
        next_rn_position = None
        headers = {}
        chunked = False
        last_chunk = False
        body_parsing_start_pos = -1
        parsable_bytes = 0
        body = bytearray()
        keep_parsing = True
        with self.byte_array_mutex:
            if verbose_parse_message:
                if len(self.byte_array) > 0:
                    print(f'LOGGING: parse_message: parsing the byte array: {self.byte_array}, length: {len(self.byte_array)}')
            len_byte_array = len(self.byte_array)
            if len_byte_array < HTTP_parsing_constants.HTTP_MIN_PARSABLE_LENGTH:
                keep_parsing = False
            else:
                # Line 1, token 1
                if verbose_parse_message:
                    print(f'LOGGING: parse_message: parsing line 1')
                if self.byte_array[0:HTTP_parsing_constants.HTTP_PROTO_BYTES_SIZE] == b'\x48\x54\x54\x50\x2F\x31\x2e\x31':
                    message_type = HTTP_message_type.RESPONSE
                elif self.byte_array[0:3] == HTTP_parsing_constants.HTTP_GET_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.GET
                elif self.byte_array[0:3] == HTTP_parsing_constants.HTTP_PUT_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.PUT
                elif self.byte_array[0:6] == HTTP_parsing_constants.HTTP_DELETE_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.DELETE
                elif self.byte_array[0:4] == HTTP_parsing_constants.HTTP_POST_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.POST
                elif self.byte_array[0:4] == HTTP_parsing_constants.HTTP_HEAD_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.HEAD
                elif self.byte_array[0:7] == HTTP_parsing_constants.HTTP_CONNECT_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.CONNECT
                elif self.byte_array[0:7] == HTTP_parsing_constants.HTTP_OPTIONS_TOKEN:
                    message_type = HTTP_message_type.REQUEST
                    method = HTTP_method.OPTIONS
                else:
                    keep_parsing = False
                    raise HTTPMessageNotWellFormedError('Message not well-formed, line 1, token 1')

            if keep_parsing == True:
                if message_type == HTTP_message_type.RESPONSE:
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: message is response')
                    if len_byte_array < HTTP_parsing_constants.HTTP_RESPONSE_MIN_FIRST_LINE_SIZE:
                        # Not enough bytes to check status
                        keep_parsing = False
                    if keep_parsing == True:
                        # Check that a space is present after HTTP/1.1
                        if self.byte_array[HTTP_parsing_constants.HTTP_PROTO_BYTES_SIZE] != 0x20:
                            # Case space not present (malformed message)
                            keep_parsing = False
                            raise HTTPMessageNotWellFormedError('Message not well-formed, line 1, token 1, RESPONSE, space missing')
                    if keep_parsing == True:
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: parsing status_code')
                        # Check http status code
                        status_bytes = self.byte_array[
                                       HTTP_parsing_constants.HTTP_STATUS_CODE_FIRST_BYTE_IDX:HTTP_parsing_constants.HTTP_STATUS_CODE_FIRST_BYTE_IDX + 3]
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: parsing status_code: status bytes: {status_bytes}')
                        digit_string = status_bytes.decode('ascii')
                        status_code = int(digit_string)
                    if keep_parsing == True:
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: status_code: {status_code}')
                        # Check that a space is present after the status
                        if self.byte_array[HTTP_parsing_constants.HTTP_STATUS_CODE_FIRST_BYTE_IDX + 3] != 0x20:
                            # Space not present (malformed message)
                            keep_parsing = False
                            raise HTTPMessageNotWellFormedError('Message not well-formed, line 1, token 2, RESPONSE, missing space after status code')
                    if keep_parsing == True:
                        # Start parsing from status message first byte position
                        status_msg_pos = HTTP_parsing_constants.HTTP_STATUS_MSG_FIRST_BYTE_IDX
                        # Seek next \r\n
                        next_rn_position = self._seek_line_terminator(start=status_msg_pos)
                        if next_rn_position == -1:
                            # \r\n not found (not enough bytes)
                            keep_parsing = False
                        else:
                            # Decode status msg
                            status_message = self.byte_array[status_msg_pos:next_rn_position].decode('utf8')
                            # Start searching for the headers from the first byte
                            # after the line terminator
                            if verbose_parse_message:
                                print(f'LOGGING: parse_message: status_message: {status_message}')
                            header_buffer_seek_pos = next_rn_position + HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()
                            if verbose_parse_message:
                                print(f'LOGGING: parse_message: header_buffer_seek_pos: {header_buffer_seek_pos}')
                elif message_type == HTTP_message_type.REQUEST:
                    raise HTTPMessageNotWellFormedError('Request messages are not parsed at the moment')
                else:
                    raise HTTPMessageNotWellFormedError('Type of message not recognized')

            # Headers
            while not flag_headers_ok and keep_parsing == True:
                # Header still not parsed
                if verbose_parse_message:
                    print(f'LOGGING: parse_message: parsing headers')

                # Seek next \r\n starting from the first not parsed
                # byte of the headers
                next_rn_position = self._seek_line_terminator(start=header_buffer_seek_pos)
                if next_rn_position == -1:
                    # \r\n not found (not enough bytes)
                    keep_parsing = False

                if keep_parsing == True and next_rn_position == header_buffer_seek_pos:
                    # This \r\n is preceded by another \r\n
                    # Double line terminator means headers end
                    # Since a HTTP message has at least 1 header (Content-Length)
                    # we can skip the case with 0 headers
                    flag_headers_ok = True
                    body_parsing_start_pos = header_buffer_seek_pos + HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()
                    break
                # Decode header row
                header_row = self.byte_array[header_buffer_seek_pos:next_rn_position].decode('utf8')
                # Split header in key value
                splitted_header = header_row.split(':')
                if splitted_header[1][0] == ' ':
                    # Remove whitespace before adding key value pair to headers
                    headers[splitted_header[0]] = splitted_header[1][1:]
                else:
                    # Add key value pair to headers
                    headers[splitted_header[0]] = splitted_header[1]
                # Move header start position after \r\n
                header_buffer_seek_pos = next_rn_position + HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()

            if keep_parsing == True:
                if verbose_parse_message:
                    print('LOGGING: parse_message: response headers:')
                    for h in headers:
                        print(f'LOGGING: parse_message: Header: {h}, {headers[h]}')

            if keep_parsing == True:
                if headers.get(HTTP_header.TRANSFER_ENCODING) == 'chunked':
                    chunked = True
                    # There may be multiple chunks in the body of the current message
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: body_parsing_start_pos: {body_parsing_start_pos}')
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: next 6 bytes: {self.byte_array[body_parsing_start_pos:body_parsing_start_pos+5]}')
                    # here, the cursor on the byte array is at the beginning of the hex-coded chunk length
                    while not flag_body_ok and keep_parsing == True:
                        # here, the cursor on the byte array is at the beginning of the hex-coded chunk length
                        next_rn_position = self._seek_line_terminator(start=body_parsing_start_pos)
                        if next_rn_position == -1:
                            # \r\n not found (not enough bytes)
                            keep_parsing = False
                        # chunk_start_pos if the position of the first byte of the chunk
                        chunk_start_pos = next_rn_position + HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()
                        if next_rn_position == body_parsing_start_pos:
                            # Case end of message (but not last chunk)
                            flag_body_ok = True
                            body_parsing_start_pos += HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()
                        else:
                            # Retrieve chunk length and convert it to int
                            chunk_length = self.__retrieve_chunk_length(body_parsing_start_pos, next_rn_position)
                            if chunk_length == 0:
                                # Case last chunk
                                last_chunk = True
                                flag_body_ok = True
                            elif self.byte_array.__len__() < (chunk_start_pos + chunk_length):
                                # Case NOT enough bytes in the buffer to parse the chunk
                                keep_parsing = False
                            else:
                                # Case enough bytes to parse the chunk
                                body += (self.byte_array[chunk_start_pos:chunk_start_pos + chunk_length])
                            # Update parsing start position for next iteration
                            body_parsing_start_pos = chunk_start_pos + chunk_length + HTTP_parsing_constants.HTTP_LINE_TERMINATOR.__len__()

                    if keep_parsing == True:
                        # left shift the buffer
                        next_start_pos = body_parsing_start_pos
                        self.byte_array = self.byte_array[next_start_pos:]
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: body: {body}')
                else:
                    # Get message length
                    content_length = int(headers.get(HTTP_header.CONTENT_LENGTH))
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: content_length: {content_length}')
                    missing_bytes = content_length - body.__len__()
                    if verbose_parse_message:
                        print(f'LOGGING: parse_message: missing_bytes: {missing_bytes}')
                    if self.byte_array.__len__() < body_parsing_start_pos + missing_bytes:
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: not enough body bytes')
                        # Case not enough bytes to parse the whole body
                        keep_parsing = False
                    else:
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: enough body bytes')
                        parsable_bytes = missing_bytes
                        body += self.byte_array[body_parsing_start_pos:body_parsing_start_pos + parsable_bytes]
                        if verbose_parse_message:
                            print(f'LOGGING: parse_message: body: {body}')
                        # shift left the buffer
                        next_start_pos = body_parsing_start_pos + parsable_bytes
                        self.byte_array = self.byte_array[next_start_pos:]
        if keep_parsing == True:
            # we have collected all the elements to build the message
            if verbose_parse_message:
                print(f'LOGGING: parse_message: message_type: {message_type}')
            if verbose_parse_message:
                print(f'LOGGING: parse_message: headers: {headers}')
            if message_type == HTTP_message_type.RESPONSE:
                if verbose_parse_message:
                    print(f'LOGGING: parse_message: instantiating response message')
                message = HTTPMessage(message_type, headers=headers, body=body, status_code=status_code, reason_phrase=status_message, is_chunked=chunked, is_last_chunk=last_chunk)
            elif message_type == HTTP_message_type.REQUEST:
                if verbose_parse_message:
                    print(f'LOGGING: parse_message: instantiating request message')
                message = HTTPMessage(message_type, headers=headers, body=body, method=method, request_uri=request_uri)

        if verbose_parse_message:
            if message is not None:
                print(f'LOGGING: parse_message: returning the message: {message}')
        return message

class HTTP_tx_buffer:
    def __init__(self):
        self.byte_array = bytearray()
        self.byte_array_mutex = Lock()

    def dump_to_socket(self, socket_wrapper: Socket_wrapper):
        #print(f'LOGGING: HTTP_tx_buffer: dump_to_socket: acquiring the lock on self.byte_array_mutex')
        with self.byte_array_mutex:
            l = len(self.byte_array)
            if l > 0:
                try:
                    bytes_sent = socket_wrapper.write(self.byte_array)
                    if bytes_sent > 0:
                        self.byte_array = self.byte_array[bytes_sent:]
                except DBConnectionError as e:
                    raise DBConnectionError(f'ERROR: HTTP_tx_buffer->dump_to_socket: connection error: 0010')
        #print(f'LOGGING: HTTP_tx_buffer: dump_to_socket: releasing the lock on self.byte_array_mutex')

class Thread_status(Enum):
    AWAITING_REQUEST   = 0
    AWAITING_RESPONSE  = 1

class HTTP_connection:
    def __init__(self, ip, port, scheme):
        if verbose:
            print(f'HTTP_connection: initing')
        self.ip = ip
        self.port = port
        self.scheme = scheme
        self.socket_rx_buf = HTTP_rx_buffer()
        self.socket_tx_buf = HTTP_tx_buffer()
        self.socket_wrapper = None

        self.is_thread_running = False
        self.is_thread_running_mutex = Lock()

        self.cancel_thread = False
        self.cancel_thread_mutex = Lock()

        self.response_fifo = deque()
        self.response_fifo_mutex = Lock()

        self.thread = None


        try:
            self.socket_wrapper = Socket_wrapper(self.ip, self.port, self.scheme)
        except Exception as e:
            raise DBConnectionError(f'ERROR: HTTP_connection: connection error: 0020')

        if verbose:
            print(f'socket_wrapper: {self.socket_wrapper} {self.socket_wrapper.socket}')

        # launch permanent thread
        if verbose:
            print("HTTP_connection: launching daemon thread: thread_func_connection__blocking")
        self.thread = threading.Thread(target=self.thread_func_connection__blocking)
        self.thread.daemon = True
        self.thread.start()
        if verbose:
            print("HTTP_connection: daemon thread launched: thread_func_connection__blocking")

        # wait for complete start of the thread before continuing
        thread_started = False
        while thread_started == False:
            with self.is_thread_running_mutex:
                if self.is_thread_running == True:
                    thread_started = True

        # instantiation over
        if verbose:
            print("HTTP_connection: instantiation over")

    def shut_down(self):
        if verbose:
            print(f'HTTP_connection: shut_down')
        # communicate to the thread that it must return
        with self.cancel_thread_mutex:
            self.cancel_thread= True

        # wait that the thread has actually stopped
        wait_thread = True
        while wait_thread == True:
            with self.is_thread_running_mutex:
                if self.is_thread_running == False:
                    wait_thread = False
            time.sleep(SLEEP_TIME_50_US)

        # disconnect the socket
        if verbose:
            print(f'HTTP_connection: shut_down: disconnetting')
        self.socket_wrapper.disconnect()

        # join the thread
        if verbose:
            print(f'HTTP_connection: shut_down: joining thread')
        self.thread.join()
        if verbose:
            print(f'HTTP_connection: shut_down: thread joined')

    def submit_request_message(self, message: HTTPMessage):
        if verbose:
            print("HTTP_connection: submit_request_message")
        byte_array = message.to_byte_array()
        if verbose:
            print(f"HTTP_connection: submitting the byte array: {byte_array}")
        with self.socket_tx_buf.byte_array_mutex:
            self.socket_tx_buf.byte_array += byte_array

    def get_next_response_message(self):
        message = None
        response_fetched = False
        with self.response_fifo_mutex:
            if len(self.response_fifo) > 0:
                message = self.response_fifo.popleft() # Pop message from the head
                response_fetched = True
        return message

    def get_next_response_message_wrapper(self, timeout=None):
        message = None
        error = None
        try:
            if timeout is not None:
                time_start_wait = time.time()
            keep_waiting = True
            while keep_waiting == True:
                if verbose:
                    print('get_next_response_message_wrapper: checking for response')
                message = self.get_next_response_message()
                if message is not None:
                    if verbose or verbose_get_next_response:
                        print('get_next_response_message_wrapper: received a response message')
                        message.print()
                    keep_waiting = False
                else:
                    if verbose:
                        print('get_next_response_message_wrapper: locking is_thread_running_mutex')
                    with self.is_thread_running_mutex:
                        if self.is_thread_running == False:
                            error = 'get_next_response_message_wrapper: connection error'
                            keep_waiting = False
                    if verbose:
                        print(f'get_next_response_message_wrapper: keep_waiting: {keep_waiting}')
                    if timeout is not None:
                        time_now = time.time()
                        delta_time = time_now - time_start_wait
                        if verbose:
                            print(f'get_next_response_message_wrapper: delta_time: {delta_time}')
                        if delta_time > timeout:
                            error = 'get_next_response_message_wrapper: wait response timeout'
                            keep_waiting = False
                    if verbose:
                        print(f'get_next_response_message_wrapper: keep_waiting: {keep_waiting}')
                    if keep_waiting == True:
                        time.sleep(SLEEP_TIME_50_US)
            if verbose:
                print(f'get_next_response_message_wrapper: returning with error {error}')
        except Exception as e:
            if verbose:
                print(f'get_next_response_message_wrapper: Exception {e}')
                res = False
                error = f'ERROR: get_next_response_message_wrapper: Exception {e}'

        return message, error

    def thread_func_connection__blocking(self):
        logging.basicConfig(level=logging.INFO)
        try:
            if verbose_thread:
                logging.info('thread_func_connection_blocking: start')
            with self.is_thread_running_mutex:
                self.is_thread_running = True

            connection_error = False
            connection_error_string = None
            while True:
                if verbose_thread:
                    logging.info(f'thread_func_connection_blocking: checking thread cancellation: starting loop')
                # dump the connection's tx_buffer onto the socket's buffer
                try:
                    self.socket_tx_buf.dump_to_socket(self.socket_wrapper)
                except DBConnectionError as e:
                    connection_error = True
                    connection_error_string = str(e)
                    logging.info(f'thread_func_connection__blocking: Exception: {e}')

                # read bytes from the socket's buffer into the rx_buffer's byte array
                try:
                    if verbose_thread:
                        logging.info('thread_func_connection_blocking: reading rx buffer')
                    read_chunk = self.socket_wrapper.read()
                    if len(read_chunk) > 0:
                        if verbose_thread:
                            logging.info(f'LOGGING: thread_func_connection__blocking: read from socket: {read_chunk}')
                        with self.socket_rx_buf.byte_array_mutex:
                            self.socket_rx_buf.byte_array += read_chunk
                except DBConnectionError as e:
                    connection_error = True
                    connection_error_string = str(e)
                    logging.info(f'thread_func_connection__blocking: Exception: {e}')
                    
                # get a response message from the rx_buffer
                try:
                    if verbose_thread:
                        logging.info('thread_func_connection_blocking: trying to parse message from rx buffer')
                    message = self.socket_rx_buf.parse_message()
                    if message is not None:
                        if verbose_thread or verbose_thread_responses:
                            logging.info(f'LOGGING: thread_func_connection__blocking: parsed message:')
                            message.print()
                        if message.message_type == HTTP_message_type.RESPONSE:
                            time_last_bytes_received = time.time()
                            if message.status_code <= 199:
                                # this response is provisional
                                if verbose_thread:
                                    logging.info(f'LOGGING: thread_func_connection__blocking: the message is provisional: skipping')
                                    message.print()
                                pass
                            else:
                                # this is a non-provisional response message
                                with self.response_fifo_mutex:
                                    self.response_fifo.append(message)
                    else:
                        if verbose_thread:
                            logging.info('thread_func_connection_blocking: no response message found')

                except Exception as e:
                    # any exception in parsing the rx buffer is interpreted as a connection error
                    connection_error = True
                    connection_error_string = str(e)
                    logging.info(f'thread_func_connection__blocking: Exception: {e}')
                
                # a small sleep time of 50 us at each loop
                if verbose_thread:
                    logging.info('thread_func_connection_blocking: short sleep')
                time.sleep(SLEEP_TIME_50_US)

                # thread cancellation
                if verbose_thread:
                    logging.info(f'thread_func_connection_blocking: checking thread cancellation: connection_error: {connection_error}')
                thread_returns = False
                if connection_error == True:
                    thread_returns = True
                else:
                    with self.cancel_thread_mutex:
                        if self.cancel_thread == True:
                            thread_returns = True
                if verbose_thread:
                    logging.info(f'thread_func_connection_blocking: checking thread cancellation: thread_returns: {thread_returns}')

                # the thread returns here, if it is cancelled from
                # outside or if there is a connection error
                if thread_returns == True:
                    with self.is_thread_running_mutex:
                        self.is_thread_running = False
                    break
        except Exception as e:
            logging.info(f'thread_func_connection__blocking: Exception: {e}')

class HTTP_pipelined_connection:
    def __init__(self, ip, port, scheme):
        self.ip = ip
        self.port = port
        self.scheme = scheme
        self.socket_rx_buf = HTTP_rx_buffer()
        self.socket_tx_buf = HTTP_tx_buffer()
        self.socket_wrapper = None
        self.pipeline = deque(maxlen=PIPELINE_SIZE)
        self.pipeline_mutex = Lock()
        self.response_fifo = deque()
        self.response_fifo_mutex = Lock()

        self.is_thread_running = False
        self.is_thread_running_mutex = Lock()

        self.cancel_thread = False
        self.cancel_thread_mutex = Lock()

        self.thread = None
        verbose = False

        try:
            self.socket_wrapper = Socket_wrapper(self.ip, self.port, self.scheme)
        except Exception as e:
            raise DBConnectionError(f'ERROR: HTTP_connection: connection error: 0020')

        if verbose:
            print(f'socket_wrapper: {self.socket_wrapper} {self.socket_wrapper.socket}')

        # launch permanent thread
        self.thread = threading.Thread(target=self.thread_func_connection__nonblocking)
        self.thread.daemon = True
        self.thread.start()

        # wait for complete start of the thread before continuing
        thread_started = False
        while thread_started == False:
            with self.is_thread_running_mutex:
                if self.is_thread_running == True:
                    thread_started = True

        # instantiation over
        if verbose:
            print("HTTP_connection: instantiation over")

    def shut_down(self):
        thread_running = False
        with self.is_thread_running_mutex:
            if self.is_thread_running == True:
                thread_running = True
        if thread_running == True:
            with self.cancel_thread_mutex:
                self.cancel_thread = True

        while thread_running == True:
            with self.is_thread_running_mutex:
                if self.is_thread_running == False:
                    thread_running = False


        if verbose:
            print(f'HTTP_connection: shut_down: disconnetting')
        self.socket_wrapper.disconnect()

        if verbose:
            print(f'HTTP_connection: shut_down: joining thread')
        self.thread.join()
        if verbose:
            print(f'HTTP_connection: shut_down: thread joined')

    def submit_request_message(self, message: HTTPMessage):
        res = True
        with self.pipeline_mutex:
            if len(self.pipeline) < PIPELINE_SIZE:
                self.pipeline.append(message)  # Insert message at the tailof the pipeline
            else:
                res = False

        if res == True:
            byte_array = message.to_byte_array()
            with self.socket_tx_buf.byte_array_mutex:
                self.socket_tx_buf.byte_array += byte_array

        return res

    def get_next_response_message(self):
        message = None
        response_fetched = False
        with self.response_fifo_mutex:
            if len(self.response_fifo) > 0:
                message = self.response_fifo.popleft() # Pop message from the head
                response_fetched = True
        if response_fetched == True:
            # also fetch a message from the pipeline
            with self.pipeline_mutex:
                if len(self.pipeline) > 0:
                    m = self.pipeline.popleft() # Pop message from the head
        return message

    def thread_func_connection__nonblocking(self):
        verbose = False
        with self.is_thread_running_mutex:
            self.is_thread_running = True

        time_last_bytes_received = time.time()
        connection_error = False
        connection_error_string = None
        shut_down_thread_due_to_error = False
        while True:
            # dump the connection's tx_buffer onto the socket's buffer
            #print(f'LOGGING: thread_func_connection__nonblocking: PHASE 1: dump_to_socket')
            try:
                self.socket_tx_buf.dump_to_socket(self.socket_wrapper)
            except DBConnectionError as e:
                connection_error = True
                connection_error_string = str(e)
                print(f'thread_func_connection_blocking: Exception: {e}')

            # read bytes from the socket's buffer into the rx_buffer's byte array
            #print(f'LOGGING: thread_func_connection__nonblocking: PHASE 2: read from socket')
            try:
                #print(f'LOGGING: thread_func_connection__nonblocking: PHASE 2: self.socket_wrapper.read(): start')
                read_chunk = self.socket_wrapper.read()
                #print(f'LOGGING: thread_func_connection__nonblocking: PHASE 2: self.socket_wrapper.read(): end')
                if len(read_chunk) > 0:
                    if verbose:
                        print(f'LOGGING: thread_func_connection__nonblocking: read from socket: {read_chunk}')
                    with self.socket_rx_buf.byte_array_mutex:
                        self.socket_rx_buf.byte_array += read_chunk
            except DBConnectionError as e:
                connection_error = True
                connection_error_string = str(e)
                print(f'thread_func_connection_blocking: Exception: {e}')
                
            # get a response message from the rx_buffer
            #print(f'LOGGING: thread_func_connection__nonblocking: PHASE 3: parse rx buffer')
            try:
                message = self.socket_rx_buf.parse_message()
                if message is not None:
                    if verbose:
                        print(f'LOGGING: thread_func_connection__nonblocking: parsed message:')
                        message.print()
                    if message.message_type == HTTP_message_type.RESPONSE:
                        time_last_bytes_received = time.time()
                        if message.status_code <= 199:
                            # this response is provisional
                            if verbose:
                                print(f'LOGGING: thread_func_connection__nonblocking: the message is provisional: skipping')
                                message.print()
                            pass
                        else:
                            # this is a non-provisional response message
                            if verbose:
                                print(f'LOGGING: thread_func_connection__nonblocking: the message is not provisional')

                            with self.response_fifo_mutex:
                                self.response_fifo.append(message)
                else:
                    #print(f'LOGGING: thread_func_connection__nonblocking: the message is None')
                    pass

            except Exception as e:
                # any exception in parsing the rx buffer is interpreted as a connection error
                connection_error = True
                connection_error_string = str(e)
                print(f'thread_func_connection_blocking: Exception: {e}')
            
            # a small sleep time of 50 us at each loop
            time.sleep(SLEEP_TIME_50_US)

            # thread cancellation
            shut_down_thread_now = False
            with self.cancel_thread_mutex:
                if self.cancel_thread == True:
                    #self.is_thread_running = False
                    shut_down_thread_now = True
            if shut_down_thread_now == False:
                if shut_down_thread_due_to_error == True:
                    shut_down_thread_now = True
            if shut_down_thread_now == True:
                with self.is_thread_running_mutex:
                    self.is_thread_running = False

                # get out of the main loop
                break

            # raise exception in case of connection error
            if connection_error == True and shut_down_thread_now == False:
                raise DBConnectionError(f'ERROR: thread_func_connection__nonblocking: connection error: {connection_error_string}')
                    




