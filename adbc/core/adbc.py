__all__ = ['ADBC']
from adbc.core.http.http import HTTP_connection
from adbc.core.sockets.sockets import DBConnectionError
from adbc.core.requests.requests import Request, create_request__login, create_request__keep_alive, create_request_write_record_core, create_request_delete_record_core, create_request_sql
from adbc.core.requests.requests import create_request_get_servers, create_request_get_n_online_cpus, create_request_add_user, create_request_delete_user, create_request_list_users
from adbc.core.requests.requests import create_request_dump_table_to_warehouse, create_request_read_record_core
from adbc.core.requests.requests import create_request_get_table_allocation_structure, create_request_manage_sql_block_status_flag
from adbc.core.responses.responses import Response, create_response_from_HTTP_message, FieldUnescapingError, unescape
from adbc.core.utilities.utilities import is_valid_datetime64

import binascii
from dataclasses import dataclass
import hashlib
import json
import math
import random
import sys
import time
from typing import Dict, Any, List, Optional, Union

from adbc.core.http.http import HTTPConnectionResponseTimeoutError

verbose = False
FIELD_SEPARATOR = b'\x3b'
RECORD_SEPARATOR = b'\x0a'
RESPONSE_TIMEOUT_BASIC    = 10 # seconds
RESPONSE_TIMEOUT_MODERATE = 30 # seconds

class AyraDB_parameters:
    HTTP_PORT = 10019
    HTTPS_PORT = 10021

class AyraDBError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

@dataclass
class ADBC:
    def __init__(self, ip, port, scheme, credentials=None):
        self.ip = ip
        self.port = port
        self.scheme = scheme
        self.credentials = credentials
        try:
            if verbose:
                print(f'LOGGING: adbc.py: ADBC: connecting')
            self.connection = HTTP_connection(self.ip, self.port, self.scheme)
            if verbose:
                print(f'LOGGING: adbc.py: ADBC: connected')
        except Exception as e:
            print(f'LOGGING: adbc.py: ADBC: connection attempt failed')
            raise DBConnectionError(f'ERROR: ADBC: connection error: 2040')

    def get_next_response(self):
        pass

    def shut_down(self):
        if self.connection:
            self.connection.shut_down()
# keep_alive goes automatically on the HTTP port

def adbc_1liner__keep_alive(ip: str) -> bool:
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTP_PORT, 'HTTP')
        req_keep_alive = create_request__keep_alive()
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__keep_alive: request:' )
            req_keep_alive.print()
        req_keep_alive.submit(connector.connection)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__keep_alive: request submitted' )
        resp_mes, error = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__keep_alive: received response message:' )
            resp_mes.print()
        if resp_mes is None:
            if error is None:
                error = 'No response message'
            else:
                pass
        else:
            if error is not None:
                pass
            else:
                res = True
        connector.shut_down()
    except Exception as e:
        res = False
        error = f'Exception: {e}'
    return res, error

# get_servers goes automatically on the HTTPS port
def adbc_1liner__get_servers(ip: str, credentials: Dict[str, str]) -> List:
    res = False
    error = None
    servers = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__get_servers: req_login: {req_login}' )
        req_login.submit(connector.connection)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__get_servers: req_login: submitted' )
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__get_servers: resp_mes: {resp_mes} error_get: {error_get}' )
            if resp_mes is not None and error_get is None:
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__get_servers: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_get_servers = create_request_get_servers(\
                            response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__get_servers: get_servers request:' )
                            req_get_servers.print()
                        req_get_servers.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__get_servers: get_servers response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        if resp_mes.body is None:
                                            res = False
                                            error = f'response with no body'
                                        else:
                                            res = True
                                            servers_string = resp_mes.body.decode('utf-8')
                                            fields = servers_string.split(';')
                                            servers = []
                                            for i in range(0, len(fields), 2):
                                                server = {
                                                    "name": fields[i],
                                                    "ip": fields[i+1]
                                                }
                                                servers.append(server)
                                    else:
                                        response_get_servers = create_response_from_HTTP_message(resp_mes)
                                        if response_get_servers is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__get_servers: get_servers response:' )
                                                response_get_servers.print()
                                            if response_get_servers.error:
                                                error = response_get_servers.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'dbc: adbc_1liner__get_servers: unknow error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                        except Exception as e:
                            print(f'LOGGING: adbc: adbc_1liner__get_servers: Exception: {e}' )
                            res = False
                            error = str(e)
                    else:
                        res = False
                        error =  f'ERROR: ADBC: adbc_1liner__get_servers: no authorization token in response'
                else:
                    res = False
                    error =  f'ERROR: ADBC: adbc_1liner__get_servers: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'

        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__get_servers: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'adbc_1liner__get_servers: DBConnectionError Exception: {e}'
        except Exception as e:
            res = False
            error = f'adbc_1liner__get_servers: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'Exception: {e}'
    return res, error, servers

def adbc_1liner__get_servers__wrapper(ayradb_servers: List[Dict[str, Union[str, int, str]]], credentials: Dict[str, str]):
    keep_going = True
    res = True
    error = None
    servers = []

    if keep_going == True:
        if ayradb_servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: servers: None'

    if keep_going == True:
        if len(ayradb_servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(ayradb_servers)-1)
        serv = ayradb_servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_servers__wrapper: argument: server: port: out of range'

    if keep_going == True:
        res, error, servers = adbc_1liner__get_servers(serv['ip'], credentials)

    return res, error, servers

# manage_sql_block_status_flag goes automatically on the HTTPS port
def adbc_1liner__manage_sql_block_status_flag(ip: str, credentials: Dict[str, str], operation: str, flag_value: str = None):
    res = False
    error = None
    result = None

    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: req_login: {req_login}' )
        req_login.submit(connector.connection)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: req_login: submitted' )
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: resp_mes: {resp_mes} error_get: {error_get}' )
            if resp_mes is not None and error_get is None:
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_msbsf = create_request_manage_sql_block_status_flag(\
                            operation,\
                            flag_value=flag_value,\
                            token=response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: request:' )
                            req_msbsf.print()
                        req_msbsf.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        if resp_mes.body is None:
                                            res = False
                                            error = f'response with no body'
                                        else:
                                            res = True
                                            body_string = resp_mes.body.decode('utf-8')
                                            try:
                                                response_body_json = json.loads(body_string)
                                                result = response_body_json
                                            except json.JSONDecodeError as e:
                                                res = False
                                                error = f'ERROR: adbc_1liner__manage_sql_block_status_flag: the response is not a well-formed json: {e}'
                                    else:
                                        response_msbsf = create_response_from_HTTP_message(resp_mes)
                                        if response_msbsf is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: response:' )
                                                response_msbsf.print()
                                            if response_msbsf.error:
                                                error = response_msbsf.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'dbc: adbc_1liner__manage_sql_block_status_flag: unknow error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                        except Exception as e:
                            print(f'LOGGING: adbc: adbc_1liner__manage_sql_block_status_flag: Exception: {e}' )
                            res = False
                            error = str(e)
                    else:
                        res = False
                        error =  f'ERROR: ADBC: adbc_1liner__manage_sql_block_status_flag: no authorization token in response'
                else:
                    res = False
                    error =  f'ERROR: ADBC: adbc_1liner__manage_sql_block_status_flag: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'

        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__manage_sql_block_status_flag: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'adbc_1liner__manage_sql_block_status_flag: DBConnectionError Exception: {e}'
        except Exception as e:
            res = False
            error = f'adbc_1liner__manage_sql_block_status_flag: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'Exception: {e}'
    return res, error, result

def adbc_1liner__manage_sql_block_status_flag__wrapper(ayradb_servers: List[Dict[str, Union[str, int, str]]], credentials: Dict[str, str], operation: str, flag_value: str = None):
    keep_going = True
    res = True
    error = None
    result = {}

    if keep_going == True:
        if ayradb_servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: servers: None'

    if keep_going == True:
        if len(ayradb_servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(ayradb_servers)-1)
        serv = ayradb_servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: server: port: out of range'

    if keep_going == True:
        if operation is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: operation: None'

    if keep_going == True:
        if not isinstance(operation, str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: operation: not a string'

    if keep_going == True:
        if operation == 'write':
            if flag_value is None:
                keep_going = False
                res = False
                error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: flag_value: must be not None with operation write'
            if keep_going == True:
                if not isinstance(flag_value, str):
                    keep_going = False
                    res = False
                    error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: flag_value: not a string'
            if keep_going == True:
                if flag_value == 'block':
                    pass
                elif flag_value == 'release':
                    pass
                else:
                    keep_going = False
                    res = False
                    error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: flag_value: wrong value: block|release'

        elif operation == 'read':
            if flag_value is not None:
                keep_going = False
                res = False
                error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: flag_value: must be None with operation write'
        else:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__manage_sql_block_status_flag__wrapper: argument: operation: wrong value: write|read'


    if keep_going == True:
        res, error, result = adbc_1liner__manage_sql_block_status_flag(serv['ip'], credentials, operation, flag_value=flag_value)

    return res, error, result

# get_n_online_cpus goes automatically on the HTTPS port
def adbc_1liner__get_n_online_cpus(ip: str, credentials: Dict[str, str]) -> List:
    res = False
    error = None
    json_result = {}
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: req_login: {req_login}' )
        req_login.submit(connector.connection)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: req_login: submitted' )
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: resp_mes: {resp_mes} error_get: {error_get}' )
            if resp_mes is not None and error_get is None:
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_get_cpus = create_request_get_n_online_cpus(\
                            response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: get_n_online_cpus request:' )
                            req_get_cpus.print()
                        req_get_cpus.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: get_cpus response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        if resp_mes.body is None:
                                            res = False
                                            error = f'response with no body'
                                        else:
                                            res = True
                                            body_string = resp_mes.body.decode('utf-8')
                                            try:
                                                body_json = json.loads(body_string)
                                                if not 'n_online_cpus' in body_json:
                                                    res = False
                                                    error = f'ERROR: adbc_1liner__get_n_online_cpus: response json->n_online_cpus: missing'
                                                else:
                                                    n_online_cpus = body_json['n_online_cpus']
                                                    if isinstance(n_online_cpus, int):
                                                        json_result = body_json
                                                    elif isinstance(n_online_cpus, str):
                                                        try:
                                                            body_json['n_online_cpus'] = int(n_online_cpus)
                                                            json_result = body_json
                                                        except ValueError:
                                                            res = False
                                                            error = f'ERROR: adbc_1liner__get_n_online_cpus: response json->n_online_cpus: not well-formed'
                                                    else:
                                                        res = False
                                                        error = f'ERROR: adbc_1liner__get_n_online_cpus: response json->n_online_cpus: not well-formed'

                                            except json.JSONDecodeError as e:
                                                res = False
                                                error = f'ERROR: adbc_1liner__get_n_online_cpus: the response is not a well-formed json: {e}'
                                    else:
                                        response_get_cpus = create_response_from_HTTP_message(resp_mes)
                                        if response_get_cpus is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: get_cpus response:' )
                                                response_get_cpus.print()
                                            if response_get_cpus.error:
                                                error = response_get_cpus.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'dbc: adbc_1liner__get_n_online_cpus: unknow error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                        except Exception as e:
                            print(f'LOGGING: adbc: adbc_1liner__get_n_online_cpus: Exception: {e}' )
                            res = False
                            error = str(e)
                    else:
                        res = False
                        error =  f'ERROR: ADBC: adbc_1liner__get_n_online_cpus: no authorization token in response'
                else:
                    res = False
                    error =  f'ERROR: ADBC: adbc_1liner__get_n_online_cpus: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'

        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__get_n_online_cpus: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'adbc_1liner__get_n_online_cpus: DBConnectionError Exception: {e}'
        except Exception as e:
            res = False
            error = f'adbc_1liner__get_n_online_cpus: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'Exception: {e}'
    return res, error, json_result

def adbc_1liner__get_n_online_cpus__wrapper(ayradb_servers: List[Dict[str, Union[str, int, str]]], credentials: Dict[str, str]):
    keep_going = True
    res = True
    error = None
    n_online_cpus = 0

    if keep_going == True:
        if ayradb_servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: servers: None'

    if keep_going == True:
        if len(ayradb_servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(ayradb_servers)-1)
        serv = ayradb_servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_n_online_cpus__wrapper: argument: server: port: out of range'

    if keep_going == True:
        res, error, result_json = adbc_1liner__get_n_online_cpus(serv['ip'], credentials)
        if res == True:
            n_online_cpus = result_json['n_online_cpus']

    return res, error, n_online_cpus

# add_user goes automatically on the HTTPS port
def adbc_1liner__add_user(ip: str, credentials: Dict[str, str], servers: List, username: str, password: str, group: str, level: str):
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__add_user: resp_mes: {resp_mes} error_get: {error_get}' )
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__add_user: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_add_user = create_request_add_user(\
                            servers, \
                            username, \
                            password, \
                            group, \
                            level, \
                            token = response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__add_user: add_user request:' )
                            req_add_user.print()
                        req_add_user.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__add_user: add_user response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        res = True
                                    else:
                                        response_add_user = create_response_from_HTTP_message(resp_mes)
                                        if response_add_user is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__add_user: add_user response:' )
                                                response_add_user.print()
                                            if response_add_user.error:
                                                error = response_add_user.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__add_user: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            if verbose:
                                print(f'LOGGING: adbc: adbc_1liner__add_user: response timeout: 2010' )
                            error = 'ERROR: ADBC: adbc_1liner__add_user: connection time out'
                        except DBConnectionError as e:
                            pass
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = 'ERROR: ADBC: adbc_1liner__add_user: authorization error'
                else:
                    res = False
                    error = 'ERROR: ADBC: adbc_1liner__add_user: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'

        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = 'ERROR: ADBC: adbc_1liner__add_user: connection time out'
        except DBConnectionError as e:
            res = False
            error = 'ERROR: ADBC: adbc_1liner__add_user: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = 'ERROR: ADBC: adbc_1liner__add_user: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'Exception: {e}'
    return res, error

# delete_user goes automatically on the HTTPS port
def adbc_1liner__delete_user(ip: str, credentials: Dict[str, str], servers: List, username: str):
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__delete_user: resp_mes: {resp_mes} error_get: {error_get}' )
            if resp_mes is not None and error_get is None:
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__delete_user: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_delete_user = create_request_delete_user(\
                            servers, \
                            username, \
                            token = response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__delete_user: delete_user request:' )
                            req_delete_user.print()
                        req_delete_user.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__delete_user: delete_user response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        res = True
                                    else:
                                        response_delete_user = create_response_from_HTTP_message(resp_mes)
                                        if response_delete_user is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__delete_user: delete_user response:' )
                                                response_delete_user.print()
                                            if response_delete_user.error:
                                                error = response_delete_user.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__delete_user: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_user: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_user: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_user: Exception: {e}'
                    else:
                        res= False
                        if response.error:
                            error = response.error
                        else:
                            error = f'ERROR: ADBC: adbc_1liner__delete_user: authorization error'
                else:
                    res = False
                    error = f'ERROR: ADBC: adbc_1liner__delete_user: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_user: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_user: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_user: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__delete_user: Exception: {e}'
    return res, error

# list_users goes automatically on the HTTPS port
def adbc_1liner__list_users(ip: str, credentials: Dict[str, str]):
    res = False
    error = None
    users_json = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__list_users: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_list_users = create_request_list_users(\
                            token = response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__list_users: list_users request:' )
                            req_list_users.print()
                        req_list_users.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__list_users: list_users response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        response_list_users = create_response_from_HTTP_message(resp_mes)
                                        if response_list_users is None:
                                            error = f'ERROR: adbc_1liner__list_users: could not create response from message'
                                        else:
                                            if response_list_users.body is None:
                                                error = f'ERROR: adbc_1liner__list_users: the response has no body'
                                            else:
                                                body_string = response_list_users.body.decode('utf-8')
                                                try:
                                                    users_json = json.loads(body_string)
                                                    res = True
                                                except json.JSONDecodeError as e:
                                                    error = f'ERROR: adbc_1liner__list_users: the response message does not carry a valid json'
                                    else:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'ERROR: adbc_1liner__list_users: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__list_users: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__list_users: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__list_users: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = f'error in authorization procedure'
                else:
                    res = False
                    error = f'ERROR: ADBC: adbc_1liner__list_users: Could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__list_users: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__list_users: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__list_users: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__list_users: Exception: {e}'

    return res, error, users_json

# write_record goes automatically on the HTTPS port
def adbc_1liner__write_record(ip: str, credentials: Dict[str, str], table_name: str, key: str, fields: Dict[str, Any]) -> bool:
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__write_record: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_write = create_request_write_record_core(\
                            table_name, \
                            key, \
                            fields, \
                            response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__write_record: write_record request:' )
                            req_write.print()
                        req_write.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__write_record: write response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        res = True
                                    else:
                                        response_write = create_response_from_HTTP_message(resp_mes)
                                        if response_write is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__write_record: write response:' )
                                                response_write.print()
                                            if response_write.error:
                                                error = response_write.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__write_record: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__write_record: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__write_record: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__write_record: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = f'ERROR: ADBC: adbc_1liner__write_record: authorization error'
                else:
                    res = False
                    error = f'ERROR: ADBC: adbc_1liner__write_record: could not create error from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__write_record: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__write_record: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__write_record: Exception: {e}'
        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__write_record: Exception: {e}'

    return res, error

def adbc_1liner__write_record__wrapper(servers: List[Dict[str, Union[str, int]]], credentials: Dict[str, str], table_name: str, key: str, fields: Dict[str, Any]) -> bool:
    keep_going = True
    res = True
    error = None

    if keep_going == True:
        if servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: servers: None'

    if keep_going == True:
        if len(servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(servers)-1)
        serv = servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: server: port: out of range'

    if keep_going == True:
        if table_name is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: table_name: None'

    if keep_going == True:
        if not isinstance(table_name, str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: table_name: not a string'

    if keep_going == True:
        if len(table_name) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: table_name: empty'

    if keep_going == True:
        if fields is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: fields: None'

    if keep_going == True:
        if len(fields) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__write_record__wrapper: argument: fields: empty'

    if keep_going == True:
        res, error = adbc_1liner__write_record(serv['ip'], credentials, table_name, key, fields)

    return res, error

# read_record goes automatically on the HTTPS port
def adbc_1liner__read_record(ip: str, credentials: Dict[str, str], table_name: str, key: str, fields_string: str):
    res = False
    record = None
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__read_record: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_read = create_request_read_record_core(\
                            table_name, \
                            key, \
                            fields_string, \
                            response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__read_record: read_record request:' )
                            req_read.print()
                        req_read.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__read_record: read response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        if verbose:
                                            print(f'LOGGING: adbc: adbc_1liner__read_record: read response message: status_code: 200' )
                                        res = True
                                        rec = resp_mes.body
                                        if rec is None:
                                            record = {}
                                        else:
                                            if len(rec) == 0:
                                                record = {}
                                            else:
                                                splitted_rec = rec.split(FIELD_SEPARATOR)
                                                if verbose:
                                                    print(f'LOGGING: adbc: adbc_1liner__read_record: splitted_rec: {splitted_rec}' )
                                                lsplitrec = len(splitted_rec)
                                                if lsplitrec % 2 != 0:
                                                    record = {}
                                                else:
                                                    record = {}
                                                    for cursor in range(0, lsplitrec, 2):
                                                        # splitted rec is organized as [key, value, key, value,...]
                                                        field_key = splitted_rec[cursor]
                                                        field_value = unescape(splitted_rec[cursor+1])
                                                        record[field_key.decode('utf-8')] = field_value
                                    else:
                                        response_read = create_response_from_HTTP_message(resp_mes)
                                        if response_read is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__read_record: read response:' )
                                                response_read.print()
                                            if response_read.error:
                                                error = response_read.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__read_record: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__read_record: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__read_record: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__read_record: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = f'ERROR: ADBC: adbc_1liner__read_record: authorization error'
                else:
                    res = False
                    error = f'ERROR: ADBC: adbc_1liner__read_record: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__read_record: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__read_record: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__read_record: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__read_record: Exception: {e}'

    return res, error, record

def adbc_1liner__read_record__wrapper(servers: List[Dict[str, Union[str, int]]], credentials: Dict[str, str], table_name: str, key: str, field_labels: List):
    keep_going = True
    res = True
    error = None

    if keep_going == True:
        if servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: servers: None'

    if keep_going == True:
        if len(servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(servers)-1)
        serv = servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: server: port: out of range'

    if keep_going == True:
        if table_name is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: table_name: None'

    if keep_going == True:
        if not isinstance(table_name, str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: table_name: not a string'

    if keep_going == True:
        if len(table_name) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: table_name: empty'

    if keep_going == True:
        if field_labels is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: field_labels: None'

    if keep_going == True:
        if len(field_labels) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__read_record__wrapper: argument: field_labels: empty'
        else:
            for label in field_labels:
                if label is None:
                    keep_going = False
                    res = False
                    error = f'ERROR: adbc_1liner__read_record__wrapper: argument: field_labels: a label is None'
                else:
                    if len(label) == 0:
                        keep_going = False
                        res = False
                        error = f'ERROR: adbc_1liner__read_record__wrapper: argument: field_labels: a label is empty'

    if keep_going == True:
        fields_string = ','.join(map(str, field_labels))

    if keep_going == True:
        res, error, record = adbc_1liner__read_record(serv['ip'], credentials, table_name, key, fields_string)

    return res, error, record

# delete_record goes automatically on the HTTPS port
def adbc_1liner__delete_record(ip: str, credentials: Dict[str, str], table_name: str, key: str, field_labels: List[str] = None) -> bool:
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__delete_record: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_delete = create_request_delete_record_core(\
                            table_name, \
                            key, \
                            field_labels=field_labels, \
                            token=response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__delete_record: delete_record request:' )
                            req_delete.print()
                        req_delete.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__delete_record: delete response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        res = True
                                    else:
                                        response_delete = create_response_from_HTTP_message(resp_mes)
                                        if response_delete is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__delete_record: delete response:' )
                                                response_delete.print()
                                            if response_delete.error:
                                                error = response_delete.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__delete_record: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = f'adbc_1liner__write_record: unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_record: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_record: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__delete_record: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = f'ERROR: ADBC: adbc_1liner__delete_record: authorization error'
                else:
                    res = False
                    error =  f'ERROR: ADBC: adbc_1liner__delete_record: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_record: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_record: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__delete_record: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__delete_record: Exception: {e}'

    return res, error

def adbc_1liner__delete_record__wrapper(servers: List[Dict[str, Union[str, int]]], credentials: Dict[str, str], table_name: str, key: str, fields: List = None) -> bool:
    keep_going = True
    res = True
    error = None

    if keep_going == True:
        if servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: servers: None'

    if keep_going == True:
        if len(servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(servers)-1)
        serv = servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: server: port: out of range'

    if keep_going == True:
        if table_name is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: table_name: None'

    if keep_going == True:
        if not isinstance(table_name, str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: table_name: not a string'

    if keep_going == True:
        if len(table_name) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: table_name: empty'

    if keep_going == True:
        if fields is not None:
            if len(fields) == 0:
                keep_going = False
                res = False
                error = f'ERROR: adbc_1liner__delete_record__wrapper: argument: fields: empty; if you do not want to delete specific fields, set fields to None'

    if keep_going == True:
        res, error = adbc_1liner__delete_record(serv['ip'], credentials, table_name, key, fields)

    return res, error

def adbc_1liner__sql(ip: str, credentials: Dict[str, str], sql_query: str, warehouse_query: bool=True) -> bool:
    res = True
    error = None
    records = []

    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__sql: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_sql = create_request_sql(\
                            sql_query, \
                            warehouse_query, \
                            response.authorization_token)
                        if req_sql is None:
                            res = False
                            if verbose:
                                print(f'LOGGING: adbc: adbc_1liner__sql: could not create the sql request' )
                            error = 'ERROR: adbc_1liner__sql: could not create the sql request'
                        else:
                            if verbose:
                                print(f'LOGGING: adbc: adbc_1liner__sql: sql request:' )
                                req_sql.print()
                            req_sql.submit(connector.connection)
                            is_first_response = True
                            keep_waiting_responses = True
                            while keep_waiting_responses == True and res == True:
                                try:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__sql: calling get_next_response_message_wrapper' )
                                    resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_BASIC)
                                    if resp_mes is not None and error_get is None:
                                        if resp_mes is None:
                                            keep_waiting_responses = False
                                        else:
                                            response_sql = create_response_from_HTTP_message(resp_mes)
                                            if response_sql is None:
                                                if verbose:
                                                    print(f'LOGGING: adbc: adbc_1liner__sql: sql response is None' )
                                                keep_waiting_responses = False
                                            else:
                                                if verbose:
                                                    print(f'LOGGING: adbc: adbc_1liner__sql: sql response:' )
                                                    response_sql.print()
                                                if response_sql.status_code != 200:
                                                    if verbose:
                                                        print(f'LOGGING: adbc: adbc_1liner__sql: sql response status_code is not 200' )
                                                    res = False
                                                    keep_waiting_responses = False
                                                    error = response_sql.error
                                                else:
                                                    if verbose:
                                                        print(f'LOGGING: adbc: adbc_1liner__sql: sql response status_code is 200, body length: {len(response_sql.body)}' )
                                                    if len(response_sql.body) > 0:
                                                        try:
                                                            if verbose:
                                                                print(f'LOGGING: adbc: adbc_1liner__sql: body: {response_sql.body}' )
                                                                print(f'LOGGING: adbc: adbc_1liner__sql: splitting the body' )
                                                            body: bytes = response_sql.body
                                                            body = body.rstrip(b'\n')
                                                            #splitted_body = body.split(FIELD_SEPARATOR)
                                                            splitted_body = body.split(RECORD_SEPARATOR)
                                                            if verbose:
                                                                print(f'LOGGING: adbc: adbc_1liner__sql: splitted_body: {splitted_body}' )

                                                            if verbose:
                                                                for rec in splitted_body:
                                                                    if verbose:
                                                                        print(f'LOGGING: adbc: adbc_1liner__sql: rec: {rec}' )

                                                            for rec in splitted_body:
                                                                if verbose:
                                                                    print(f'LOGGING: adbc: adbc_1liner__sql: rec: {rec}' )
                                                                splitted_rec = rec.split(FIELD_SEPARATOR)
                                                                if verbose:
                                                                    print(f'LOGGING: adbc: adbc_1liner__sql:     splitted rec: {splitted_rec}' )

                                                                lsplitrec = len(splitted_rec)
                                                                if verbose:
                                                                    print(f'LOGGING: adbc: adbc_1liner__sql:     lsplitrec: {lsplitrec}' )
                                                                # Parse rec
                                                                if lsplitrec == 0:
                                                                    if verbose:
                                                                        print(f'LOGGING: adbc: adbc_1liner__sql:     lsplitrec: {lsplitrec}' )
                                                                else:
                                                                    if lsplitrec % 2 == 0:
                                                                        content = {}
                                                                        for cursor in range(0, lsplitrec, 2):
                                                                            # splitted rec is organized as [key, value, key, value,...]
                                                                            field_key = splitted_rec[cursor]
                                                                            field_value = unescape(splitted_rec[cursor+1])
                                                                            content[field_key.decode('utf-8')] = field_value
                                                                            if verbose:
                                                                                print(f'LOGGING: adbc: adbc_1liner__sql:     splitted rec:     label: {field_key} value: {field_value}' )
                                                                                print(f'LOGGING: adbc: adbc_1liner__sql:     content: {content}' )
                                                                        records.append(content)
                                                                    else:
                                                                        if verbose:
                                                                            print(f'LOGGING: adbc: adbc_1liner__sql: the length of splitted_rec is not an even number: {lsplitrec}' )


                                                        except FieldUnescapingError as e:
                                                            print(f'LOGGING: FieldUnescapingError: {e}' )
                                                        except Exception as e:
                                                            print(f'LOGGING: Exception: {e}' )


                                                    if response_sql.is_chunked == False:
                                                        if verbose:
                                                            print(f'LOGGING: adbc: adbc_1liner__sql: sql response is not chunked' )
                                                        res = False
                                                        keep_waiting_responses = False
                                                    else:
                                                        if verbose:
                                                            print(f'LOGGING: adbc: adbc_1liner__sql: sql response is chunked' )
                                                        if response_sql.is_last_chunk == False: 
                                                            if verbose:
                                                                print(f'LOGGING: adbc: adbc_1liner__sql: sql response is_last_chunk: False' )
                                                        else:
                                                            if verbose:
                                                                print(f'LOGGING: adbc: adbc_1liner__sql: sql response is_last_chunk: True' )
                                                            keep_waiting_responses = False
                                    else:
                                        if resp_mes is not None:
                                            if resp_mes.status_code != 200:
                                                if resp_mes.body is not None:
                                                    res = False
                                                    error = resp_mes.body.decode('utf-8')
                                                else:
                                                    res = False
                                                    error = 'inconsistent response'
                                            else:
                                                pass
                                        else:
                                            if error_get is not None:
                                                res = False
                                                error = error_get
                                            else:
                                                res = False
                                                error = 'unknown error'
                                except HTTPConnectionResponseTimeoutError as e:
                                    res = False
                                    error = f'ERROR: ADBC: adbc_1liner__sql: connection time out'
                                except DBConnectionError as e:
                                    res = False
                                    error = f'ERROR: ADBC: adbc_1liner__sql: DBConnectionError: {e}'
                                except Exception as e:
                                    res = False
                                    error = f'ERROR: ADBC: adbc_1liner__sql: Exception: {e}'
                            if verbose:
                                print(f'LOGGING: adbc: adbc_1liner__sql: out of responses loop with result: {res}')
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = 'ERROR: ADBC: adbc_1liner__sql: authorization error'
                else:
                    res = False
                    error = 'ERROR: ADBC: adbc_1liner__sql: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__sql: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__sql: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__sql: Exception: {e}'

        connector.shut_down()

    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__sql: Exception: {e}'

    if verbose:
        print(f'adbc_1liner__sql: returning with res: {res} error: {error}')
    return res, error, records

def adbc_1liner__sql__wrapper(servers: List, credentials: Dict[str, str], sql_query: str, warehouse_query: bool=True):
    keep_going = True
    res = True
    error = None
    records = []

    if keep_going == True:
        if servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: servers: None'

    if keep_going == True:
        if len(servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: servers: empty'

    if keep_going == True:
        #serv_idx = random.randint(0, len(servers)-1)
        #serv = servers[serv_idx]
        # PATCH 1.0.1
        serv = servers[0]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__sql_wrapper: argument: server: port: out of range'

    if keep_going == True:
            res, error, records = adbc_1liner__sql(serv['ip'], credentials, sql_query, warehouse_query)

    return res, error, records

def adbc_1liner__dump_table_to_warehouse(ip: str, credentials: Dict[str, str], table_name: str, field_labels_string: str):
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=1000000)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: login response:' )
                        response.print()
                    if response.authorization_token:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: creating req_dump_table:' )
                        req_dump_table = create_request_dump_table_to_warehouse(\
                            table_name, \
                            field_labels_string, \
                            token=response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: dump_table_to_warehouse request:' )
                            req_dump_table.print()
                        req_dump_table.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=1000000)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: dump_table_to_warehouse response message:' )
                                        resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        res = True
                                    else:
                                        response_dump_table = create_response_from_HTTP_message(resp_mes)
                                        if response_dump_table is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: dump_table response:' )
                                                response_dump_table.print()
                                            if response_dump_table.error:
                                                error = response_dump_table.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__dump_table_to_warehouse: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'

                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = 'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: authorization error'
                else:
                    res= False
                    error = 'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: received NULL response'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: Exception: {e}'
    return res, error

def adbc_1liner__dump_table_to_warehouse__wrapper(servers: List, credentials: Dict[str, str], table_name: str, field_labels_string: str):
    keep_going = True
    res = True
    error = None

    if keep_going == True:
        if servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: servers: None'

    if keep_going == True:
        if len(servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: servers: empty'

    if keep_going == True:
        #serv_idx = random.randint(0, len(servers)-1)
        #serv = servers[serv_idx]
        # PATCH 1.0.1
        serv = servers[0]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: argument: server: port: out of range'

    if keep_going == True:
        if table_name is None or table_name == '':
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: table_name: void'

    if keep_going == True:
        if field_labels_string is None or field_labels_string == '':
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__dump_table_to_warehouse_wrapper: field_labels_string: void'

    if keep_going == True:
            res, error = adbc_1liner__dump_table_to_warehouse(serv['ip'], credentials, table_name, field_labels_string)

    return res, error

# get_table_allocation_structure goes automatically on the HTTPS port
def adbc_1liner__get_table_allocation_structure(ip: str, credentials: Dict[str, str], target_table_name: str = None) -> List:
    res = False
    error = None
    table_allocation_structure = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        if verbose:
            print(f'LOGGING: adbc: adbc_1liner__get_table_allocation_structure: req_login: {req_login}' )
        req_login.submit(connector.connection)
        try:
            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_MODERATE)
            if resp_mes is not None and error_get is None:
                # build the response from the HTTP message
                response = create_response_from_HTTP_message(resp_mes)
                if response is not None:
                    if verbose:
                        print(f'LOGGING: adbc: adbc_1liner__get_table_allocation_structure: login response:' )
                        response.print()
                    if response.authorization_token:
                        req_gtas = create_request_get_table_allocation_structure(\
                            target_table_name = target_table_name, token = response.authorization_token)
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__get_table_allocation_structure: get_table_allocation_structure request:' )
                            req_gtas.print()
                        req_gtas.submit(connector.connection)
                        try:
                            resp_mes, error_get = connector.connection.get_next_response_message_wrapper(timeout=RESPONSE_TIMEOUT_MODERATE)
                            if resp_mes is not None and error_get is None:
                                if resp_mes is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__get_table_allocation_structure: get_table_allocation_structure response message:' )
                                        #resp_mes.print()
                                    if resp_mes.status_code == 200:
                                        if resp_mes.body is None:
                                            res = False
                                            error = f'response with no body'
                                        else:
                                            res = True
                                            try:
                                                table_allocation_structure = json.loads(resp_mes.body.decode('utf-8'))
                                                if verbose:
                                                    #print(f'{table_allocation_structure}')
                                                    pass
                                            except json.JSONDecodeError as e:
                                                res = False
                                                error = f'The response body is not a valid json'
                                                if verbose:
                                                    print(f'adbc_1liner__get_table_allocation_structure: ERROR: {error}')
                                    else:
                                        response_get_servers = create_response_from_HTTP_message(resp_mes)
                                        if response_get_servers is not None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__get_table_allocation_structure: response:' )
                                                response_get_servers.print()
                                            if response_get_servers.error:
                                                error = response_get_servers.error
                                        else:
                                            if resp_mes.body is not None:
                                                error = resp_mes.body.decode('utf-8')
                                            else:
                                                error = f'adbc_1liner__get_table_allocation_structure: unknown error'
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                            else:
                                if resp_mes is not None:
                                    if resp_mes.status_code != 200:
                                        if resp_mes.body is not None:
                                            res = False
                                            error = resp_mes.body.decode('utf-8')
                                        else:
                                            res = False
                                            error = 'inconsistent response'
                                    else:
                                        pass
                                else:
                                    if error_get is not None:
                                        res = False
                                        error = error_get
                                    else:
                                        res = False
                                        error = 'unknown error'
                        except HTTPConnectionResponseTimeoutError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: connection time out'
                        except DBConnectionError as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: DBConnectionError: {e}'
                        except Exception as e:
                            res = False
                            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: Exception: {e}'
                    else:
                        res = False
                        if response.error:
                            error = response.error
                        else:
                            error = 'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: authorization error'
                else:
                    res = False
                    error = 'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: could not create response from message'
            else:
                if resp_mes is not None:
                    if resp_mes.status_code != 200:
                        if resp_mes.body is not None:
                            res = False
                            error = resp_mes.body.decode('utf-8')
                        else:
                            res = False
                            error = 'inconsistent response in authentication phase'
                    else:
                        pass
                else:
                    if error_get is not None:
                        res = False
                        error = error_get
                    else:
                        res = False
                        error = 'unknown error in authentication phase'
        except HTTPConnectionResponseTimeoutError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: connection time out'
        except DBConnectionError as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: DBConnectionError: {e}'
        except Exception as e:
            res = False
            error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: Exception: {e}'

        connector.shut_down()
    except Exception as e:
        res = False
        error = f'ERROR: ADBC: adbc_1liner__get_table_allocation_structure: Exception: {e}'
    return res, error, table_allocation_structure

def adbc_1liner__get_table_allocation_structure__wrapper(ayradb_servers: List[Dict[str, Union[str, int, str]]], credentials: Dict[str, str], target_table_name: str = None):
    keep_going = True
    res = True
    error = None
    table_allocation_structure = None

    if keep_going == True:
        if ayradb_servers is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: servers: None'

    if keep_going == True:
        if len(ayradb_servers) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: servers: empty'

    if keep_going == True:
        if credentials is None:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: None'

    if keep_going == True:
        if len(credentials) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: empty'

    if keep_going == True:
        if not 'username' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: username: missing'

    if keep_going == True:
        if not isinstance(credentials['username'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: username: not a string'

    if keep_going == True:
        if len(credentials['username']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: username: empty'

    if keep_going == True:
        if not 'password' in credentials:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: password: missing'

    if keep_going == True:
        if not isinstance(credentials['password'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: password: not a string'

    if keep_going == True:
        if len(credentials['password']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: credentials: password: empty'

    if keep_going == True:
        serv_idx = random.randint(0, len(ayradb_servers)-1)
        serv = ayradb_servers[serv_idx]
        if not 'ip' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: ip: missing'

    if keep_going == True:
        if not isinstance(serv['ip'], str):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: ip: not a string'

    if keep_going == True:
        if len(serv['ip']) == 0:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: ip: empty'

    if keep_going == True:
        if not 'port' in serv:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: port: missing'

    if keep_going == True:
        if not isinstance(serv['port'], int):
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: port: not an integer'

    if keep_going == True:
        if serv['port'] < 0 or serv['port'] > 65535:
            keep_going = False
            res = False
            error = f'ERROR: adbc_1liner__get_table_allocation_structure__wrapper: argument: server: port: out of range'

    if keep_going == True:
        res, error, table_allocation_structure = adbc_1liner__get_table_allocation_structure(serv['ip'], credentials, target_table_name=target_table_name)

    return res, error, table_allocation_structure

def adbc_1liner__dump_table_ild_metadata_to_warehouse(servers: List, credentials: Dict[str, str]):
    res = True
    error = None

    table_name = 'metadata'
    field_labels_string = 'IDL_L4_VERS,COMMENT,CREATION_DATE,ORIGINATOR,TIME_SYSTEM,EPOCH,PARTICIPANT_1,PARTICIPANT_2,PATH,REFERENCE_FRAME,MEAS_TYPE,MEAS_FORMAT,MEAS_UNIT,DATA_QUALITY,LINK'

    res, error = adbc_1liner__dump_table_to_warehouse__wrapper(servers, credentials, table_name, field_labels_string)

    return res, error

def adbc__generate_record_key_from_field(input_string):
    hash_object = hashlib.sha256(input_string.encode())
    hex_hash = hash_object.hexdigest()
    return hex_hash
