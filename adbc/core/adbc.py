__all__ = ['ADBC', 'adbc_1liner__keep_alive']
from adbc.core.http.http import HTTP_connection
from adbc.core.sockets.sockets import DBConnectionError
from adbc.core.requests.requests import Request, create_request__login, create_request__keep_alive, create_request_write_record_core, create_request_delete_record_core, create_request_sql
from adbc.core.requests.requests import create_request_get_servers, create_request_add_user, create_request_delete_user, create_request_list_users
from adbc.core.requests.requests import create_request_dump_table_to_warehouse
from adbc.core.responses.responses import Response, create_response_from_HTTP_message, FieldUnescapingError, unescape

import binascii
from dataclasses import dataclass
import hashlib
import json
import random
import time
from typing import Dict, Any, List, Optional, Union
import sys

from adbc.core.http.http import HTTPConnectionResponseTimeoutError

verbose = False
FIELD_SEPARATOR = b'\x3b'



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
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTP_PORT, 'HTTP')
        req_keep_alive = create_request__keep_alive()
        req_keep_alive.submit(connector.connection)
        try:
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__keep_alive: received response message:' )
                resp_mes.print()
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__keep_alive: response timeout: 2050' )
        connector.shut_down()
    except Exception as e:
        raise DBConnectionError(f'ERROR: ADBC: adbc_1liner__keep_alive: connection error: 2060')
    return res

# get_servers goes automatically on the HTTPS port
def adbc_1liner__get_servers(ip: str, credentials: Dict[str, str]) -> List:
    res = False
    error = None
    servers = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__get_servers: received response message:' )
                resp_mes.print()
            # build the response from the HTTP message
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__get_servers: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__get_servers: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res = False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__get_servers: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__get_servers: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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

# add_user goes automatically on the HTTPS port
def adbc_1liner__add_user(ip: str, credentials: Dict[str, str], servers: List, username: str, password: str, group: str, level: str):
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__add_user: received response message:' )
                resp_mes.print()
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

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
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__add_user: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__add_user: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__delete_user: received response message:' )
                resp_mes.print()
            # build the response from the HTTP message
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__delete_user: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__delete_user: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res= False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__delete_user: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__delete_user: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__list_users: received response message:' )
                resp_mes.print()
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                response_list_users = create_response_from_HTTP_message(resp_mes)
                                if response_list_users is not None:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__list_users: list_users response:' )
                                        response_list_users.print()
                                    if response_list_users.error:
                                        error = response_list_users.error
                                else:
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__list_users: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__list_users: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res = False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__list_users: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__list_users: connection time out'
        except DBConnectionError as e:
            print(f'XXXX EXCEPTION: {e}')
            pass
        connector.shut_down()
    except Exception as e:
        print(f'XXXX EXCEPTION: {e}')
        pass
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
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__write_record: received response message:' )
                resp_mes.print()
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__write_record: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__write_record: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res = False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__write_record: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__write_record: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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

# delete_record goes automatically on the HTTPS port
def adbc_1liner__delete_record(ip: str, credentials: Dict[str, str], table_name: str, key: str, field_labels: List[str] = None) -> bool:
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__delete_record: received response message:' )
                resp_mes.print()
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__delete_record: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__delete_record: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res = False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__delete_record: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__delete_record: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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

    if res == True:
        try:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__sql: connecting' )
            connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
            req_login = create_request__login(credentials)
            req_login.submit(connector.connection)
            try:
                resp_mes = connector.connection.get_next_response_message()
                if verbose:
                    print(f'LOGGING: adbc: adbc_1liner__sql: received response message:' )
                    resp_mes.print()
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
                            while keep_waiting_responses == True:
                                try:
                                    resp_mes = connector.connection.get_next_response_message()
                                    if resp_mes is None:
                                        keep_waiting_responses = False
                                    else:
                                        response_sql = create_response_from_HTTP_message(resp_mes)
                                        if response_sql is None:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__sql: sql response is None' )
                                            keep_waiting_responses = False
                                            res = False
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
                                                    content = {}
                                                    try:
                                                        if verbose:
                                                            print(f'LOGGING: adbc: adbc_1liner__sql: body: {response_sql.body}' )
                                                        body: bytes = response_sql.body
                                                        splitted_body = body.split(FIELD_SEPARATOR)
                                                        lbody = len(splitted_body)
                                                        # Parse body
                                                        if lbody % 2 == 0:
                                                            for cursor in range(0, lbody, 2):
                                                                # splitted body is organized as [key, value, key, value,...]
                                                                field_key = splitted_body[cursor]
                                                                field_value = unescape(splitted_body[cursor+1])
                                                                content[field_key.decode('utf-8')] = field_value
                                                    except FieldUnescapingError as e:
                                                        print(f'LOGGING: FieldUnescapingError: {e}' )
                                                        content = {}
                                                    if len(content) > 0:
                                                        records.append(content)
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
                                except HTTPConnectionResponseTimeoutError as e:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__sql: response timeout: 2090' )
                                    error = 'ERROR: ADBC: adbc_1liner__sql: connection time out'
                                    res = False
                                except DBConnectionError as e:
                                    pass
                    else:
                        res = False
                        if response.error:
                            error = response.error

            except HTTPConnectionResponseTimeoutError as e:
                if verbose:
                    print(f'LOGGING: adbc: adbc_1liner__sql: response timeout: 2020' )
                error = 'ERROR: ADBC: adbc_1liner__sql: connection time out'
                res = False
            except DBConnectionError as e:
                pass
            connector.shut_down()
        except Exception as e:
            pass
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
        serv_idx = random.randint(0, len(servers)-1)
        serv = servers[serv_idx]
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

def adbc_1liner__sql_noauth(ip: str, sql_query: str, warehouse_query: bool=True) -> bool:
    res = True
    error = None
    records = []

    if res == True:
        try:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__sql_noauth: connecting' )
            connector = ADBC(ip, AyraDB_parameters.HTTP_PORT, 'HTTP')
            req_sql = create_request_sql(\
                sql_query, \
                warehouse_query)
            if req_sql is None:
                if verbose:
                    print(f'LOGGING: adbc: adbc_1liner__sql_noauth: could not create the sql request' )
                error = 'ERROR: adbc_1liner__sql_noauth: could not create the sql request'
            else:
                if verbose:
                    print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql request:' )
                    req_sql.print()
                req_sql.submit(connector.connection)
                is_first_response = True
                keep_waiting_responses = True
                while keep_waiting_responses == True:
                    try:
                        resp_mes = connector.connection.get_next_response_message()
                        if resp_mes is None:
                            keep_waiting_responses = False
                        else:
                            response_sql = create_response_from_HTTP_message(resp_mes)
                            if response_sql is None:
                                if verbose:
                                    print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response is None' )
                                keep_waiting_responses = False
                                res = False
                            else:
                                if verbose:
                                    print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response:' )
                                    response_sql.print()
                                if response_sql.status_code != 200:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response status_code is not 200' )
                                    res = False
                                    keep_waiting_responses = False
                                    error = response_sql.error
                                else:
                                    if verbose:
                                        print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response status_code is 200, body length: {len(response_sql.body)}' )
                                    if len(response_sql.body) > 0:
                                        content = {}
                                        try:
                                            print(f'LOGGING: adbc: adbc_1liner__sql_noauth: body: {response_sql.body}' )
                                            body: bytes = response_sql.body
                                            splitted_body = body.split(FIELD_SEPARATOR)
                                            lbody = len(splitted_body)
                                            # Parse body
                                            if lbody % 2 == 0:
                                                for cursor in range(0, lbody, 2):
                                                    # splitted body is organized as [key, value, key, value,...]
                                                    field_key = splitted_body[cursor]
                                                    field_value = unescape(splitted_body[cursor+1])
                                                    content[field_key.decode('utf-8')] = field_value
                                        except FieldUnescapingError as e:
                                            print(f'LOGGING: FieldUnescapingError: {e}' )
                                            content = {}
                                        if len(content) > 0:
                                            records.append(content)
                                    if response_sql.is_chunked == False:
                                        if verbose:
                                            print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response is not chunked' )
                                        res = False
                                        keep_waiting_responses = False
                                    else:
                                        if verbose:
                                            print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response is chunked' )
                                        if response_sql.is_last_chunk == False: 
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response is_last_chunk: False' )
                                        else:
                                            if verbose:
                                                print(f'LOGGING: adbc: adbc_1liner__sql_noauth: sql response is_last_chunk: True' )
                                            keep_waiting_responses = False
                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__sql_noauth: response timeout: 2090' )
                        error = 'ERROR: ADBC: adbc_1liner__sql_noauth: connection time out'
                        res = False
                    except DBConnectionError as e:
                        pass
            connector.shut_down()

        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__sql_noauth: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__sql_noauth: connection time out'
            res = False
        except DBConnectionError as e:
            pass
        except Exception as e:
            pass
    return res, error, records

def adbc_1liner__dump_table_to_warehouse(ip: str, credentials: Dict[str, str], table_name: str, field_labels_string: str):
    res = False
    error = None
    try:
        connector = ADBC(ip, AyraDB_parameters.HTTPS_PORT, 'HTTPS')
        req_login = create_request__login(credentials)
        req_login.submit(connector.connection)
        try:
            resp_mes = connector.connection.get_next_response_message()
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: received response message:' )
                resp_mes.print()
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
                        resp_mes = connector.connection.get_next_response_message()
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
                                    error = str(resp_mes)

                    except HTTPConnectionResponseTimeoutError as e:
                        if verbose:
                            print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: response timeout: 2010' )
                        error = 'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: connection time out'
                    except DBConnectionError as e:
                        pass
                else:
                    res = False
                    if response.error:
                        error = response.error
        except HTTPConnectionResponseTimeoutError as e:
            if verbose:
                print(f'LOGGING: adbc: adbc_1liner__dump_table_to_warehouse: response timeout: 2020' )
            error = 'ERROR: ADBC: adbc_1liner__dump_table_to_warehouse: connection time out'
        except DBConnectionError as e:
            pass
        connector.shut_down()
    except Exception as e:
        pass
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
        serv_idx = random.randint(0, len(servers)-1)
        serv = servers[serv_idx]
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
