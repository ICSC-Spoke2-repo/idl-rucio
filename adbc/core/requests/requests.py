from dataclasses import dataclass, field
from enum import Enum
import json
import re
import sys
from typing import Optional, Dict, Any, List
from adbc.core.http.http import HTTP_header, HTTP_method, HTTP_method_name, HTTPMessage, HTTP_message_type, HTTP_connection, create_authorization_header_value

verbose = False

class Request_type(Enum):
    LOGIN                          = 0
    KEEP_ALIVE                     = 1
    WRITE_RECORD                   = 2
    DELETE_RECORD                  = 3
    SQL                            = 4
    GET_SERVERS                    = 5
    ADD_USER                       = 6
    DELETE_USER                    = 7
    LIST_USERS                     = 8
    DUMP_TABLE                     = 9
    READ_RECORD                    = 10
    GET_TABLE_ALLOCATION_STRUCTURE = 11
    GET_N_ONLINE_CPUS              = 12
    MANAGE_SQL_BLOCK_STATUS_FLAG   = 13

Request_name = {
    Request_type.LOGIN:                          'LOGIN',
    Request_type.KEEP_ALIVE:                     'KEEP_ALIVE',
    Request_type.WRITE_RECORD:                   'WRITE_RECORD',
    Request_type.DELETE_RECORD:                  'DELETE_RECORD',
    Request_type.SQL:                            'SQL',
    Request_type.GET_SERVERS:                    'GET_SERVERS',
    Request_type.ADD_USER:                       'ADD_USER',
    Request_type.DELETE_USER:                    'DELETE_USER',
    Request_type.LIST_USERS:                     'LIST_USERS',
    Request_type.DUMP_TABLE:                     'DUMP_TABLE',
    Request_type.READ_RECORD:                    'READ_RECORD',
    Request_type.GET_TABLE_ALLOCATION_STRUCTURE: 'GET_TABLE_ALLOCATION_STRUCTURE',
    Request_type.GET_N_ONLINE_CPUS:              'GET_N_ONLINE_CPUS',
    Request_type.MANAGE_SQL_BLOCK_STATUS_FLAG:   'MANAGE_SQL_BLOCK_STATUS_FLAG' }

Request_method = {
    Request_type.LOGIN:                          HTTP_method.POST,
    Request_type.KEEP_ALIVE:                     HTTP_method.GET,
    Request_type.WRITE_RECORD:                   HTTP_method.PUT,
    Request_type.DELETE_RECORD:                  HTTP_method.DELETE,
    Request_type.SQL:                            HTTP_method.POST,
    Request_type.GET_SERVERS:                    HTTP_method.POST,
    Request_type.ADD_USER:                       HTTP_method.POST,
    Request_type.DELETE_USER:                    HTTP_method.POST,
    Request_type.LIST_USERS:                     HTTP_method.POST,
    Request_type.DUMP_TABLE:                     HTTP_method.POST,
    Request_type.READ_RECORD:                    HTTP_method.GET,
    Request_type.GET_TABLE_ALLOCATION_STRUCTURE: HTTP_method.POST,
    Request_type.GET_N_ONLINE_CPUS:              HTTP_method.POST ,
    Request_type.MANAGE_SQL_BLOCK_STATUS_FLAG:   HTTP_method.POST }

Request_endpoint = {
    Request_type.LOGIN:                          '/system',
    Request_type.KEEP_ALIVE:                     '/system',
    Request_type.WRITE_RECORD:                   '/tables',
    Request_type.DELETE_RECORD:                  '/tables',
    Request_type.SQL:                            '/system',
    Request_type.GET_SERVERS:                    '/system',
    Request_type.ADD_USER:                       '/system',
    Request_type.DELETE_USER:                    '/system',
    Request_type.LIST_USERS:                     '/system',
    Request_type.DUMP_TABLE:                     '/system',
    Request_type.READ_RECORD:                    '/tables',
    Request_type.GET_TABLE_ALLOCATION_STRUCTURE: '/system',
    Request_type.GET_N_ONLINE_CPUS:              '/system',
    Request_type.MANAGE_SQL_BLOCK_STATUS_FLAG:   '/system' }

Request_action = {
    Request_type.LOGIN:                          'ayradb_login',
    Request_type.KEEP_ALIVE:                     'keep_alive',
    Request_type.WRITE_RECORD:                   'table_insert_row',
    Request_type.DELETE_RECORD:                  'table_delete_row',
    Request_type.SQL:                            'sqlq',
    Request_type.GET_SERVERS:                    'set_get_system_parameter',
    Request_type.ADD_USER:                       'set_get_system_parameter',
    Request_type.DELETE_USER:                    'set_get_system_parameter',
    Request_type.LIST_USERS:                     'set_get_system_parameter',
    Request_type.DUMP_TABLE:                     'set_get_system_parameter',
    Request_type.READ_RECORD:                    'table_read_row',
    Request_type.GET_TABLE_ALLOCATION_STRUCTURE: 'set_get_system_parameter',
    Request_type.GET_N_ONLINE_CPUS:              'set_get_system_parameter',
    Request_type.MANAGE_SQL_BLOCK_STATUS_FLAG:   'set_get_system_parameter' }

# to create a Request instance, do not use directly the constructor of the class, instead use
# the helper functions:
#     create_request__login()
#     create_request__keep_alive()
#     create_request__write_record()
#     create_request__delete_record()
#     create_request__sqlq()
#     create_request__get_servers()
#     ...

@dataclass
class Request:
    request_type:    Request_type
    parameters:      Optional[Dict[str, Any]] = None
    special_headers: Optional[Dict[str, Any]] = None
    headers:         Dict[str, Any] = field(default_factory=dict, init=False)
    body:            Optional[bytes] = None
    token:           Optional[str] = None
    credentials:     Optional[Dict[str, str]] = None
    def __init__(self, request_type, parameters = None, special_headers=None, body=None, token=None, credentials=None):
        self.request_type    = request_type
        self.parameters      = parameters
        self.token           = token
        self.credentials     = credentials
        self.request_uri     = self.create_request_uri()
        self.request_body    = body
        self.special_headers = special_headers
        self.headers         = None

        if self.special_headers is not None:
            self.headers = {}
            for h_name in self.special_headers:
                self.headers[h_name] = self.special_headers[h_name]

        if self.headers is None:
            self.headers = {}

        if self.request_body is None:
            content_length = 0
        else:
            content_length = len(self.request_body)

        self.headers[HTTP_header.CONTENT_LENGTH] = content_length
        self.headers[HTTP_header.CONNECTION]     = 'keep-alive'

        if token is not None:
            hval = create_authorization_header_value(token)
            self.headers[HTTP_header.AUTHORIZATION] = hval

    def create_request_uri(self):
        uri = Request_endpoint[self.request_type]
        uri += '?action='
        uri += Request_action[self.request_type]
        if self.parameters is not None:
            for par_name in self.parameters:
                uri += '&'
                uri += par_name
                uri += '='
                uri += str(self.parameters[par_name])
        return uri

    def to_HTTP_message(self) -> HTTPMessage:
        mes = HTTPMessage(\
                HTTP_message_type.REQUEST, \
                headers=self.headers, \
                body=self.request_body, \
                method=Request_method[self.request_type], \
                request_uri=self.request_uri)
        return mes

    def submit(self, connection: HTTP_connection):
        if verbose:
            print(f'Request: submit: submitting request')
        message = self.to_HTTP_message()
        connection.submit_request_message(message)
        if verbose:
            print(f'Request: submit: request submitted')

    def print(self):
        print(f'Request: {Request_name[self.request_type]}')
        print(f'    method: {HTTP_method_name[Request_method[self.request_type]]}')
        print(f'    uri:    {self.request_uri}')
        print(f'    headers:')
        for h_name in self.headers:
            print(f'       {h_name}: {self.headers[h_name]}') 

        if self.request_body is not None:
            print(f'    body: {self.request_body}')

# UTILITY FUNCTIONS
# UTILITY FUNCTIONS: VALIDATION OF FIELDS
def validate_field(field: str):
    if field is not None and re.fullmatch('[a-zA-Z0-9_.-]+', field):
        return True
    return False

# UTILITY FUNCTIONS: ESCAPING OF FIELDS
ESCAPE_DICT = {
    b'\x00': rb'\z',    # null        -> \z 0x5c 0x7a
    b'"': rb'\q',       # "           -> \q 0x5c 0x71
    b';': rb'\s',       # ;           -> \s 0x5c 0x73
    b'\\': rb'\\',      # \           -> \\ 0x5c 0x5c
    b'\n': rb'\n',      # line-feed   -> \n 0x5c 0x6e
    b'\f': rb'\f',      # form-feed   -> \f 0x5c 0x66
    b'\r': rb'\c',      # carr-return -> \c 0x5c 0x63
}
ESCAPE_CLASS = '[' + ''.join(r'\x' + x.hex() for x in ESCAPE_DICT) + ']'
ESCAPE_REGEX = re.compile(ESCAPE_CLASS.encode())
FIELD_VALUE_SEPARATOR = b';'
FIELD_KEY_SEPARATOR = ","
def escape(string: bytes) -> bytes:
    return re.sub(ESCAPE_REGEX, lambda m: ESCAPE_DICT[m.group(0)], string)


# UTILITY FUNCTIONS: FORMAT KEY
def format_key(key: str):
    return ''.join([char.encode('utf-8').hex() for char in key])

class InvalidFieldLabelError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

#
#    REQUESTS: helper functions to create requests
#

# REQUEST LOGIN:
#     credentials are mandatory
def create_request__login(credentials: Dict[str, str]) -> Request:
    body = bytearray(json.dumps(credentials).encode('ascii'))
    req = Request(Request_type.LOGIN, body=body, credentials=credentials)
    return req

# REQUEST KEEP_ALIVE
def create_request__keep_alive(token: str = None) -> Request:
    req = Request(Request_type.KEEP_ALIVE, token=token)
    return req

# REQUEST DELETE_RECORD
def create_request_delete_record_core(table_name: str, key: str, field_labels: List = None, token: str = None) -> Request:
    req = None

    formatted_key = format_key(key)

    # optional fields, for nosql tables only
    if field_labels is not None:
        fields_string = ''
        for label in field_labels:
            if not validate_field(label):
                raise InvalidFieldLabelError(f'The field label {label} is not valid')
            if first_el:
                fields_string = label
                first_el = False
            else:
                fields_string = fields_string + ',' + label

    if field_labels is not None:
        parameters = {
                "table_name": table_name,
                "key_column_name": "key_column",
                "key_value": formatted_key,
                "fields": fields_string }
    else:
        parameters = {
                "table_name": table_name,
                "key_column_name": "key_column",
                "key_value": formatted_key }

    req = Request (\
        Request_type.DELETE_RECORD, \
        parameters=parameters, \
        body=None, \
        token=token)
    return req

# REQUEST WRITE_RECORD
def create_request_write_record_core(table_name: str, key: str, fields: dict, token: str = None) -> Request:
    req = None

    formatted_key = format_key(key)

    # standardize the format of fields
    fields_bytes = {}
    first_el = True
    fields_string = ''
    for label in fields:
        if not validate_field(label):
            raise InvalidFieldLabelError(f'The field label {label} is not valid')
        value = fields[label]
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        else:
            value_str = str(value)
            value_bytes = value_str.encode('utf-8')
        fields_bytes[label] = value_bytes
        if first_el:
            fields_string = label
            first_el = False
        else:
            fields_string = fields_string + ',' + label

    query_fields = ""
    body = bytearray()
    first_el = True
    for field_key, field_value in fields_bytes.items():
        # Generate body and fields query argument
        if first_el:
            field_value_escaped = escape(field_value)
            body += field_value_escaped
            query_fields = field_key
            first_el = False
        else:
            body += FIELD_VALUE_SEPARATOR+escape(field_value)
            query_fields = f'{query_fields}{FIELD_KEY_SEPARATOR}{field_key}'

    parameters = {
            "table_name": table_name,
            "key_column_name": "key_column",
            "key_value": formatted_key,
            "fields": fields_string,
            "imode": "drop_older_record_with_same_key" }

    req = Request (\
        Request_type.WRITE_RECORD, \
        parameters=parameters, \
        body=body, \
        token=token)
    return req

# REQUEST READ_RECORD
def create_request_read_record_core(table_name: str, key: str, fields: str, token: str = None) -> Request:
    req = None

    formatted_key = format_key(key)

    parameters = {
            "table_name": table_name,
            "key_column_name": "key_column",
            "key_value": formatted_key,
            "fields": fields}

    req = Request (\
        Request_type.READ_RECORD, \
        parameters=parameters, \
        token=token)
    return req

# REQUEST SQL
def create_request_sql(sql_query: str, warehouse_query: bool = True, token: str = None) -> Request:
    req = None
    body_json = {}
    if warehouse_query == True:
        body_json['warehouse_query'] = 'y'
    body_json['sql_query'] = sql_query
    body = bytearray(json.dumps(body_json).encode('ascii'))
    req = Request(Request_type.SQL, body=body, token=token)
    return req

# REQUEST GET_SERVERS
def create_request_get_servers(token: str = None) -> Request:
    req = None
    body_json = {}
    body_json['action'] = 'get'
    body_json['target_parameter'] = 'servers_coordinates'
    body = bytearray(json.dumps(body_json).encode('ascii'))
    req = Request(Request_type.GET_SERVERS, body=body, token=token)
    return req

# REQUEST MANAGE_SQL_BLOCK_STATUS_FLAG
def create_request_manage_sql_block_status_flag(operation: str, flag_value: str = None, token: str = None) -> Request:
    req = None
    body_json = {}
    body_json['action'] = 'set'
    body_json['target_parameter'] = 'sql_block_status'
    body_json['manage_action'] = operation
    if flag_value is not None:
        body_json['value'] = flag_value
    body = bytearray(json.dumps(body_json).encode('ascii'))
    req = Request(Request_type.MANAGE_SQL_BLOCK_STATUS_FLAG, body=body, token=token)
    return req

# REQUEST ADD_USER
def create_request_add_user(servers: List, username: str, password: str, group: str, level: str, token: str = None) -> Request:
    req = None
    keep_going = True

    destination_servers = []
    for serv in servers:
        if not 'name' in serv:
            keep_going = False
            break
        else:
            serv_item = {}
            serv_item['server_name'] = serv['name']
            destination_servers.append(serv_item)

    if keep_going == True:
        body_json = {}
        body_json['action'] = 'get'
        body_json['target_parameter'] = 'add_user'
        body_json['destination_servers'] = destination_servers
        body_json['username'] = username
        body_json['password'] = password
        body_json['group']    = group
        body_json['level']    = level
        body = bytearray(json.dumps(body_json).encode('ascii'))
        req = Request(Request_type.ADD_USER, body=body, token=token)
    return req

# REQUEST DELETE_USER
def create_request_delete_user(servers: List, username: str, token: str = None) -> Request:
    req = None
    keep_going = True

    destination_servers = []
    for serv in servers:
        if not 'name' in serv:
            keep_going = False
            break
        else:
            serv_item = {}
            serv_item['server_name'] = serv['name']
            destination_servers.append(serv_item)

    if keep_going == True:
        body_json = {}
        body_json['action'] = 'get'
        body_json['target_parameter'] = 'delete_user'
        body_json['destination_servers'] = destination_servers
        body_json['username'] = username
        body = bytearray(json.dumps(body_json).encode('ascii'))
        req = Request(Request_type.ADD_USER, body=body, token=token)
    return req

# REQUEST LIST_USERS
def create_request_list_users(token: str = None) -> Request:
    req = None
    keep_going = True

    if keep_going == True:
        body_json = {}
        body_json['action'] = 'get'
        body_json['target_parameter'] = 'list_users'
        body = bytearray(json.dumps(body_json).encode('ascii'))
        req = Request(Request_type.LIST_USERS, body=body, token=token)
    return req

# REQUEST DUMP_TABLE_TO_WAREHOUSE
def create_request_dump_table_to_warehouse(table_name: str, field_labels: str, token: str = None) -> Request:
    req = None
    keep_going = True

    if keep_going == True:
        field_labels_list = field_labels.split(',')
        body_json = {}
        body_json['action'] = 'set'
        body_json['target_parameter'] = 'dump_table_to_warehouse'
        body_json['table_name'] = table_name
        body_json['dumped_table_name'] = table_name
        body_json['fields'] = field_labels_list
        body = bytearray(json.dumps(body_json).encode('ascii'))
        req = Request(Request_type.DUMP_TABLE, body=body, token=token)
    return req

# REQUEST GET_TABLE_ALLOCATION_STRUCTURE
def create_request_get_table_allocation_structure(target_table_name: str = None, token: str = None) -> Request:
    req = None
    body_json = {}
    body_json['action'] = 'get'
    body_json['target_parameter'] = 'full_disk_allocation_structure'
    if target_table_name is not None:
        body_json['target_table_name'] = target_table_name

    body = bytearray(json.dumps(body_json).encode('ascii'))
    req = Request(Request_type.GET_TABLE_ALLOCATION_STRUCTURE, body=body, token=token)
    return req

# REQUEST GET_N_ONLINE_CPUS
def create_request_get_n_online_cpus(token: str = None) -> Request:
    req = None
    keep_going = True

    if keep_going == True:
        body_json = {}
        body_json['action'] = 'get'
        body_json['target_parameter'] = 'n_online_cpus'
        body = bytearray(json.dumps(body_json).encode('ascii'))
        req = Request(Request_type.ADD_USER, body=body, token=token)
    return req
