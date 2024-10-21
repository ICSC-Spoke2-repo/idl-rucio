from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Optional, Dict, Any
from adbc.core.http.http import HTTP_header, HTTP_method, HTTP_method_name, HTTPMessage, HTTP_message_type, HTTP_connection, create_authorization_header_value
from adbc.core.http.http import HTTPConnectionResponseTimeoutError

verbose = False

def convert_error(error_string: str) -> str:
    converted_error = None
    if 'TFA_EEPA_019' in error_string:
        converted_error = 'The target table does not exist'
    elif 'TFA_MDAI_016.003' in error_string:
        tokens = error_string.split(':')
        last_token = tokens[-1].strip()
        converted_error = f'The field {last_token} does not exist'
    if converted_error is None:
        converted_error = error_string
    return converted_error

@dataclass
class Response:
    status_code:                int = -1
    reason_phrase:              str = None
    headers:                    Dict[str, Any] = field(default_factory=dict, init=False)
    body:                       bytes = b''
    is_chunked:                 Optional[bool] = False
    is_last_chunk:              Optional[bool] = False
    authorization_header_value: str  = None
    authorization_token:        str  = None
    location_header_value:      str  = None
    error:                      str  = None
    def __init__(self, \
            status_code: int, \
            reason_phrase: str, \
            headers: Dict[str, Any], \
            body: bytes, \
            is_chunked: Optional[bool] = False, \
            is_last_chunk: Optional[bool] = False):
        self.status_code     = status_code
        self.reason_phrase   = reason_phrase
        self.headers         = headers
        self.body            = body
        self.is_chunked      = is_chunked
        self.is_last_chunk   = is_last_chunk
        self.error = None

        # location
        location = None
        location_header = self.headers.get(HTTP_header.LOCATION)
        if location_header:
            self.location_header_value = location_header

        # authorization
        authorization = None
        authorization_header = self.headers.get(HTTP_header.AUTHORIZATION)
        if authorization_header:
            self.authorization_header_value = authorization_header
            self.authorization_token = authorization_header.split(' ')[1]

        # error
        if self.status_code >= 400:
            error_converted = convert_error(self.body.decode('utf-8'))
            self.error = error_converted

    def to_HTTP_message(self) -> HTTPMessage:
        mes = HTTPMessage(\
                HTTP_message_type.RESPONSE, \
                status_code = self.status_code, \
                reason_phrase = self.reason_phrase, \
                headers=self.headers, \
                body=self.body,
                is_chunked = self.is_chunked, \
                is_last_chunk = self.is_last_chunk)
        return mes

    def submit(self, connection: HTTP_connection):
        message = self.to_HTTP_message()
        connection.submit_request_message(message)

    def print(self):
        print(f'Response:')
        print(f'    status_code: {self.status_code}')
        print(f'    reason_phrase: {self.reason_phrase}')
        print(f'    headers:')
        for h_name in self.headers:
            print(f'       {h_name}: {self.headers[h_name]}') 

        if self.authorization_token:
            print(f'    authorization token: {self.authorization_token}')

        if self.body is not None:
            print(f'    body: {self.body}')

        if self.error is not None:
            print(f'    error: {self.error}')

def create_response_from_HTTP_message(message: HTTPMessage) -> Response:
    if verbose:
        print(f'LOGGING: create_response_from_HTTP_message: start')
    response = None

    if message is not None:
        response = Response (
            message.status_code, \
            message.reason_phrase, \
            message.headers, \
            message.body, \
            is_chunked=message.is_chunked, \
            is_last_chunk=message.is_last_chunk)

    return response

# UTILITY FUNCTIONS: UNESCAPING OF FIELDS
class FieldUnescapingError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
ESCAPE_BYTE=b'\x5c'
DOUBLE_ESCAPE_BYTE=b'\x5c\x5c'
UNESCAPE_BYTE_DICT={
    0x7A: b'\x00', #null 	\z 0x5c 0x7a
    0x71: b'\x22', #" \q 0x5c 0x71
    0x73: b'\x3B', #; \s 0x5c 0x73
    0x5C: b'\x5C', #\ \\ 0x5c 0x5c
    0x6E: b'\x0A', #line-feed \n 0x5c 0x6e
    0x66: b'\x0C', #form-feed \f 0x5c 0x66
    0x63: b'\x0D', #carriage-return \c 0x5c 0x63
}
def unescape(string:bytes):
    str_len=string.__len__()
    idx=0
    splitted_response = string.split(DOUBLE_ESCAPE_BYTE)
    # Unescape splitted response [0]
    current_split=splitted_response[0].split(ESCAPE_BYTE)
    splitted_response[0]=current_split[0]
    for idx in range(1,current_split.__len__()):
        # For every sub array of splitted_response[0] splitted at \
        to_unescape = current_split[idx][0]
        unescaped_byte = UNESCAPE_BYTE_DICT.get(to_unescape)
        if unescaped_byte is None:
            # Error in escaping or unescaping (unexpected char)
            raise FieldUnescapingError("Unescape char not found")
        # Modify byte to unescape
        splitted_response[0]+=unescaped_byte+current_split[idx][1:]
    # Unescape splitted response [1:]
    for cursor in range(1,splitted_response.__len__()):
        # For each array splitted at \\
        current_split=splitted_response[cursor].split(ESCAPE_BYTE)
        splitted_response[cursor]=current_split[0]
        for idx in range(1,current_split.__len__()):
            # For each sub array splitted at \
            to_unescape = current_split[idx][0]
            unescaped_byte = UNESCAPE_BYTE_DICT.get(to_unescape)
            if unescaped_byte is None:
                # Error in escaping or unescaping (unexpected char)
                raise FieldUnescapingError("Unescape char not found")
            # Modify byte to unescape
            splitted_response[cursor]+=unescaped_byte+current_split[idx][1:]
        # Add unescaped slash (double slash in escaped version)
        splitted_response[0]+=b'\x5c'+splitted_response[cursor]
    return splitted_response[0]
