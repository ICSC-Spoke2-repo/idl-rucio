__all__ = ['ADBC_pipelined']
from adbc.core.http.http import HTTP_pipelined_connection
from adbc.core.sockets.sockets import DBConnectionError
from adbc.core.requests.requests import Request, create_request__login, create_request__keep_alive, create_request_write_record_core, create_request_delete_record_core
from adbc.core.requests.requests import create_request_read_record_core
from adbc.core.responses.responses import Response, create_response_from_HTTP_message, FieldUnescapingError, unescape
from adbc.core.utilities.utilities import parse_sgsyspar_full_allocation_res, ghash_3_section_hash, hash_to_int

import binascii
from dataclasses import dataclass
import hashlib
import json
import math
import multiprocessing
import psutil
import random
import time
from typing import Dict, Any, List, Optional, Union
import sys

from adbc.core.http.http import HTTPConnectionResponseTimeoutError
from adbc.core.sockets.sockets import DBConnectionError
from adbc.core.adbc import adbc_1liner__get_servers__wrapper, adbc_1liner__get_table_allocation_structure__wrapper, adbc_1liner__get_n_online_cpus__wrapper


verbose = False
FIELD_SEPARATOR = b'\x3b'
RECORD_SEPARATOR = b'\x0a'
SLEEP_TIME_50_US = 0.00005 # 50 microseconds

class AyraDB_parameters:
    HTTP_PORT = 10019
    HTTPS_PORT = 10021

class AyraDBError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

@dataclass
class ADBC_pipelined:
    def __init__(self, ip, port, scheme, credentials=None):
        self.ip = ip
        self.port = port
        self.scheme = scheme
        self.credentials = credentials
        self.token = None
        try:
            self.connection = HTTP_pipelined_connection(self.ip, self.port, self.scheme)
            if verbose:
                print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connected')
        except Exception as e:
            print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connection attempt failed')
            raise DBConnectionError(f'ERROR: ADBC_pipelined: connection error: 2040')
        if credentials is not None:
            try:
                self.get_token(credentials)
                if verbose:
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connected')
            except Exception as e:
                print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: exception in get_token(): {e}')
                raise DBConnectionError(f'ERROR: ADBC_pipelined: connection error: 2041')

    def get_token(self, credentials):
        if verbose:
            print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: get_token: start')
        res = True
        req_login = create_request__login(credentials)
        req_login_mes = req_login.to_HTTP_message()
        if verbose:
            print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: req_login_mes: {req_login_mes}')

        res_submit = True
        time_start_token_req = time.time()
        while True:
            res_submit = self.connection.submit_request_message(req_login_mes)
            if res_submit == True:
                if verbose:
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: get_token: login request submitted')
                break
            else:
                time_now = time.time()
                delta_time = time_now - time_start_token_req
                if delta_time > 10:
                    res_submit = False
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: timeout in get_token()')
                    break

        if res_submit == True:
            login_res_mes = None
            try:
                while True:
                    #print(f'LOGGING: adbc_pipelined: get_token: calling get_next_response_message()' )
                    login_res_mes = self.connection.get_next_response_message()
                    #print(f'LOGGING: adbc_pipelined: get_token: get_next_response_message() returned' )
                    if login_res_mes is None:
                        time.sleep(SLEEP_TIME_50_US)
                    else:
                        login_response = None
                        if login_res_mes is not None:
                            if verbose:
                                print(f'LOGGING: adbc_pipelined: get_token: login_res_mes: {login_res_mes}' )

                            login_response = create_response_from_HTTP_message(login_res_mes)
                        if login_response is not None:
                            if verbose:
                                print(f'LOGGING: adbc_pipelined: get_token: login response:' )
                                login_response.print()
                            if login_response.authorization_token:
                                self.token = login_response.authorization_token
                                break
                            else:
                                if verbose:
                                    print(f'LOGGING: adbc_pipelined: get_token: the login response has no authorization token' )
                                break
                        else:
                            if verbose:
                                print(f'LOGGING: adbc_pipelined: get_token: could not create login response from message' )
                            break
            except HTTPConnectionResponseTimeoutError as e:
                if verbose:
                    print(f'LOGGING: adbc_pipelined: get_token: response timeout: 2020' )
                error = 'ERROR: adbc_pipelined: get_token: connection time out'
            except DBConnectionError as e:
                print(f'LOGGING: adbc_pipelined: get_token: exception: {e}' )
                pass

    def shut_down(self):
        try:
            if self.connection:
                if verbose:
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connection active')
                self.connection.shut_down()
                if verbose:
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: closed')
            else:
                if verbose:
                    print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connection not active')
        except Exception as e:
            print(f'LOGGING: adbc_pipelined.py: ADBC_pipelined: connection error')
            raise DBConnectionError(f'ERROR: ADBC_pipelined: connection error: 2050')

    def pipelined_read(self, table_name: str, field_labels: List, keys: List, MEM_budget: float):
        res = True
        error = ''
        records = []
        n_keys = len(keys)

        verbose_perf = False

        req_block_size = 1000

        if verbose_perf:
            last_time_meas = time.time()

        if n_keys > 0:
            n_keys_submitted = 0
            n_keys_responded = 0
            n_keys_responded_success = 0
            n_keys_responded_failure = 0
            fields_string = ','.join(map(str, field_labels))
            request_messages = []

            if verbose_perf:
                print(f'creating the request messages')
            for i, key in enumerate(keys):
                req_read = create_request_read_record_core(\
                    table_name, \
                    key, \
                    fields_string, \
                    token = self.token)
                req_read_mes = req_read.to_HTTP_message()
                request_messages.append(req_read_mes)
            if verbose_perf:
                print(f'request messages created')

            keep_going = True
            next_key_index = 0
            while keep_going == True:
                # try submitting a request message
                if next_key_index < n_keys:
                    if verbose:
                        #print(f'request_message: {request_messages[next_key_index]}')
                        pass
                    res_submit = self.connection.submit_request_message(request_messages[next_key_index])
                    if res_submit == True:
                        if  verbose:
                            print(f'LOGGING: pipelined_read(): request submitted for the key {keys[next_key_index]}')
                        n_keys_submitted += 1
                        next_key_index += 1

                # try fetching a response message
                read_res_mes = self.connection.get_next_response_message()
                if read_res_mes is not None:
                    if verbose:
                        #print(f'read_res_mes: headers: {read_res_mes}')
                        pass
                    n_keys_responded += 1
                    if verbose_perf:
                        if n_keys_responded % req_block_size == 0:
                            time_now = time.time()
                            delta_t = time_now - last_time_meas
                            last_time_meas = time_now
                            throughput = req_block_size / delta_t
                            print(f'n_keys_responded: {n_keys_responded} throughput: {throughput}')

                    if n_keys_responded % req_block_size == 0:
                        # measure memory
                        if MEM_budget > 0:
                            process = psutil.Process()
                            memory_info = process.memory_info()
                            MEM_used = memory_info.rss 
                            if MEM_used > MEM_budget:
                                keep_going = False
                                res = False
                                error = 'Not enough memory on the client machine'

                    #print(f'XXXX n_keys_responded: {n_keys_responded} n_keys_submitted: {n_keys_submitted}')

                    if read_res_mes.status_code == 200:
                        rec = read_res_mes.body
                        if rec is None:
                            record = {}
                        else:
                            if len(rec) == 0:
                                record = {}
                            else:
                                splitted_rec = rec.split(FIELD_SEPARATOR)
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
                        records.append(record)
                    else:
                        n_keys_responded_failure += 1
                    
                if n_keys_submitted == n_keys and n_keys_responded == n_keys:
                    keep_going = False
                else:
                    time.sleep(SLEEP_TIME_50_US)

        return res, error, records

    def pipelined_write(self, table_name: str, keys: List, values: List, MEM_budget: float):
        res = True
        error = ''
        n_keys = len(keys)

        verbose_perf = False

        req_block_size = 1000

        if verbose_perf:
            last_time_meas = time.time()

        if n_keys > 0:
            n_keys_submitted = 0
            n_keys_responded = 0
            n_keys_responded_success = 0
            n_keys_responded_failure = 0
            request_messages = []

            if verbose_perf:
                print(f'creating the request messages')
            for i, key in enumerate(keys):
                value = values[i]
                req_write = create_request_write_record_core(\
                    table_name, \
                    key, \
                    value, \
                    token = self.token)
                req_write_mes = req_write.to_HTTP_message()
                request_messages.append(req_write_mes)
            if verbose_perf:
                print(f'request messages created')

            keep_going = True
            next_key_index = 0
            while keep_going == True:
                # try submitting a request message
                if next_key_index < n_keys:
                    if verbose:
                        #print(f'request_message: {request_messages[next_key_index]}')
                        pass
                    res_submit = self.connection.submit_request_message(request_messages[next_key_index])
                    if res_submit == True:
                        if  verbose:
                            print(f'LOGGING: pipelined_write(): request submitted for the key {keys[next_key_index]}')
                        n_keys_submitted += 1
                        next_key_index += 1

                # try fetching a response message
                write_res_mes = self.connection.get_next_response_message()
                if write_res_mes is not None:
                    if verbose:
                        #print(f'write_res_mes: headers: {write_res_mes}')
                        pass
                    n_keys_responded += 1
                    if verbose_perf:
                        if n_keys_responded % req_block_size == 0:
                            time_now = time.time()
                            delta_t = time_now - last_time_meas
                            last_time_meas = time_now
                            throughput = req_block_size / delta_t
                            print(f'n_keys_responded: {n_keys_responded} throughput: {throughput}')

                    if n_keys_responded % req_block_size == 0:
                        # measure memory
                        if MEM_budget > 0:
                            process = psutil.Process()
                            memory_info = process.memory_info()
                            MEM_used = memory_info.rss 
                            if MEM_used > MEM_budget:
                                keep_going = False
                                res = False
                                error = 'Not enough memory on the client machine'

                    if write_res_mes.status_code == 200:
                        pass
                    else:
                        n_keys_responded_failure += 1
                    
                if n_keys_submitted == n_keys and n_keys_responded == n_keys:
                    keep_going = False
                else:
                    time.sleep(SLEEP_TIME_50_US)

        return res, error

def multi_pipelined_calculate_n_processes_core(n_servers, n_online_cpus_server, n_online_cpus_client):
    weight_process_client  = 0.6
    weight_process_server = 0.3

    n_processes_final = 0

    # take off 2 online cpus from servers
    n_online_cpus_server -= 2
    if n_online_cpus_server < 1:
        n_online_cpus_server = 1

    n_max_processes_client = int(n_online_cpus_client / weight_process_client)
    n_max_processes_server = int(n_online_cpus_server / weight_process_server)
    n_max_processes_all_servers = n_max_processes_server * n_servers

    n_processes_final = n_servers
    for n_processes in range(n_servers, n_max_processes_all_servers+1, n_servers):
        if n_processes > n_max_processes_client or n_processes > n_max_processes_all_servers:
            break
        else:
            n_processes_final = n_processes

    return n_processes_final


def multi_pipelined_calculate_n_connections_per_server(ayradb_servers, credentials=None):
    res = True
    error = ''
    n_processes_final = 0

    if res == True:
        res_get_servers, error, servers = adbc_1liner__get_servers__wrapper(ayradb_servers, credentials)
        if res_get_servers == False:
            res = False
            error = f'ERROR: multi_pipelined_calculate_n_connections_per_server: error in adbc_1liner__get_servers__wrapper: {error}'
    
    if res == True:
        res_get_cpus, error, n_online_cpus_server = adbc_1liner__get_n_online_cpus__wrapper(ayradb_servers, credentials)
        if res_get_cpus == False:
            res = False
            error = f'ERROR: multi_pipelined_calculate_n_connections_per_server: error in adbc_1liner__get_n_online_cpus__wrapper: {error}'

    if res == True:
        n_servers = len(servers)
        n_online_cpus_client = psutil.cpu_count(logical=True)
        n_processes_final = multi_pipelined_calculate_n_processes_core(n_servers, n_online_cpus_server, n_online_cpus_client)

        n_connections_per_server = int(n_processes_final / n_servers)
        if n_connections_per_server < 1:
            n_connections_per_server = 1

    return res, error, n_connections_per_server

def multi_pipelined_read_worker_function(\
        server_index: int,\
        connection_index: int,\
        table_name: str,\
        field_labels: List,\
        keys: List,\
        server_ip_address: str,\
        server_port: int,\
        scheme: str,\
        MEM_budget: float,\
        shared_list,\
        credentials=None):
    result_list = []
    try:
        connector = ADBC_pipelined(server_ip_address, server_port, scheme, credentials=credentials)
        res, error, records = connector.pipelined_read(table_name, field_labels, keys, MEM_budget)

        # the last item of the list 'records' is the description of the return status of the
        # function 'pipelined_read'
        if res == True:
            if records is not None:
                result_list = records
            status_record = {}
            status_record['result'] = 'success'
            result_list.append(status_record)
        else:
            result_list = []
            status_record = {}
            status_record['result'] = 'failure'
            if error is None:
                error = 'unknown error'
            status_record['error'] = error
            result_list.append(status_record)

    except Exception as e:
        print(f'LOGGING: multi_pipelined_read_worker_function: ADBC_pipelined.pipelined_read: Exception: {e}')
        result_list = []
        status_record = {}
        status_record['result'] = 'failure'
        if e is None:
            error = 'unknown error'
        else:
            error = str(e)
        status_record['error'] = error
        result_list.append(status_record)

    shared_list.append(result_list)

def multi_pipelined_assign_keys_to_connectors(n_servers, n_connections_per_server, keys):
    key_lists = []
    total_length = len(keys)
    if verbose:
        print(f'multi_pipelined_read: number of keys: {total_length}')
        print(f'multi_pipelined_read: n_servers: {n_servers}')
    n_connectors = n_servers * n_connections_per_server
    base_size = total_length // n_connectors
    remainder = total_length % n_connectors
    list_index = 0
    start = 0
    for s in range(0, n_servers):
        for c in range(0, n_connections_per_server):
            end = start + base_size + (1 if list_index < remainder else 0)
            key_lists.append(keys[start:end])
            start = end
            list_index += 1
    return key_lists

def multi_pipelined_assign_keys_to_connectors_v2(n_connections_per_server, keys, table_allocation_structure):
    res = True
    error = None
    key_lists = []
    server_ip_addresses_list = []
    res_map, error, n_servers, server_index, server_name, server_ip_address, n_tables, table_name, \
        n_allocation_servers, allocation_server_index, n_server_hash_codes, \
        map_server_hash_code_server_metaindex = parse_sgsyspar_full_allocation_res(table_allocation_structure)
    if res_map != 0:
        res = False
        error = f'multi_pipelined_assign_keys_to_connectors_v2: error in parse_sgsyspar_full_allocation_res: {error}'
    else:
        # postprocess the allocation structure of the table
        target_table_index = 0
        max_server_index   = -1
        for i in range(0, n_servers):
            if server_index[i] > max_server_index:
                max_server_index = server_index[i]
        n_server_slots = max_server_index + 1
        server_index_new      = [-1]   * n_server_slots
        server_name_new       = [None] * n_server_slots
        server_ip_address_new = [None] * n_server_slots

        for i in range(0, n_servers):
            server_index_new[server_index[i]]      = server_index[i]
            server_name_new[server_index[i]]       = server_name[i]
            server_ip_address_new[server_index[i]] = server_ip_address[i]
        server_index      = server_index_new
        server_name       = server_name_new
        server_ip_address = server_ip_address_new

        # here we organize the lists of keys in n_server_slots sections, with
        # n_connections_per_server lists in each section
        # let us initialize the empty lists
        # mind that n_server_slots might be larger that n_servers and, in this
        # case, some sections will be empty
        klists = []
        for s in range(0, n_server_slots):
            kl = []
            klists.append(kl)
        for s in range(0, n_server_slots):
            for c in range(0, n_connections_per_server):
                kl = []
                klists[s].append(kl)
        # for each server, we distribute keys as uniformly as possible among
        # the connections of the server; we need an index of the next
        # connection to be populated for each server
        next_connection = [0] * n_servers
        gh24hashbuf_server_length   = 2
        gh24hashbuf_tabgroup_length = 2
        gh24hashbuf_key_length      = 16

        for key in keys:
            #print(f'XXXX key: {key}')
            gh24hashbuf_server, gh24hashbuf_tabgroup, gh24hashbuf_key = ghash_3_section_hash(\
                key, gh24hashbuf_server_length, gh24hashbuf_tabgroup_length, gh24hashbuf_key_length)
            server_hash_code = hash_to_int(gh24hashbuf_server)
            #print(f'XXXX     server_hash_code: {server_hash_code}')
            base_server_metaindex = map_server_hash_code_server_metaindex[target_table_index][server_hash_code]
            #print(f'XXXX     base_server_metaindex: {base_server_metaindex}')
            if base_server_metaindex < 0 or base_server_metaindex >= n_servers:
                res = False
                error = f'multi_pipelined_assign_keys_to_connectors_v2: base_server_metaindex: out of range'
                break
            else:
                sidx = allocation_server_index[target_table_index][base_server_metaindex]
                #print(f'XXXX     sidx: {sidx}')
                if sidx < 0 or sidx >= n_server_slots:
                    res = False
                    error = f'multi_pipelined_assign_keys_to_connectors_v2: sidx: out of range'
                    break
                else:
                    if server_index[sidx] == -1:
                        res = False
                        error = f'multi_pipelined_assign_keys_to_connectors_v2: inconsistent server index'
                        break
                    else:
                        #print(f'XXXX     inserting key in klists[{server_index[sidx]}][{next_connection[server_index[sidx]]}]')
                        klists[server_index[sidx]][next_connection[server_index[sidx]]].append(key)
                        next_connection[server_index[sidx]] = (next_connection[server_index[sidx]] + 1)%n_connections_per_server

        if res == True:
            for slot_index in range(0, n_server_slots):
                if server_index[slot_index] >= 0:
                    for c in range(0, n_connections_per_server):
                        key_lists.append(klists[slot_index][c])
                        server_ip_addresses_list.append(server_ip_address[slot_index])
        if res == True:
            if verbose:
                for i in range(0, len(key_lists)):
                    print(f'XXXX key_lists[{i}]: {len(key_lists[i])} keys, server ip address: {server_ip_addresses_list[i]}')

    return res, error, key_lists, server_ip_addresses_list, n_servers

def multi_pipelined_assign_keys_values_to_connectors_v2(n_connections_per_server, keys, values, table_allocation_structure):
    res = True
    error = None
    key_lists = []
    value_lists = []
    server_ip_addresses_list = []
    res_map, error, n_servers, server_index, server_name, server_ip_address, n_tables, table_name, \
        n_allocation_servers, allocation_server_index, n_server_hash_codes, \
        map_server_hash_code_server_metaindex = parse_sgsyspar_full_allocation_res(table_allocation_structure)
    if res_map != 0:
        res = False
        error = f'multi_pipelined_assign_keys_values_to_connectors_v2: error in parse_sgsyspar_full_allocation_res: {error}'
    else:
        # postprocess the allocation structure of the table
        target_table_index = 0
        max_server_index   = -1
        for i in range(0, n_servers):
            if server_index[i] > max_server_index:
                max_server_index = server_index[i]
        n_server_slots = max_server_index + 1
        server_index_new      = [-1]   * n_server_slots
        server_name_new       = [None] * n_server_slots
        server_ip_address_new = [None] * n_server_slots

        for i in range(0, n_servers):
            server_index_new[server_index[i]]      = server_index[i]
            server_name_new[server_index[i]]       = server_name[i]
            server_ip_address_new[server_index[i]] = server_ip_address[i]
        server_index      = server_index_new
        server_name       = server_name_new
        server_ip_address = server_ip_address_new

        # here we organize the lists of keys in n_server_slots sections, with
        # n_connections_per_server lists in each section
        # let us initialize the empty lists
        # mind that n_server_slots might be larger that n_servers and, in this
        # case, some sections will be empty
        klists = []
        for s in range(0, n_server_slots):
            kl = []
            klists.append(kl)
        for s in range(0, n_server_slots):
            for c in range(0, n_connections_per_server):
                kl = []
                klists[s].append(kl)
        vlists = []
        for s in range(0, n_server_slots):
            kl = []
            vlists.append(kl)
        for s in range(0, n_server_slots):
            for c in range(0, n_connections_per_server):
                kl = []
                vlists[s].append(kl)
        # for each server, we distribute keys as uniformly as possible among
        # the connections of the server; we need an index of the next
        # connection to be populated for each server
        next_connection = [0] * n_servers
        gh24hashbuf_server_length   = 2
        gh24hashbuf_tabgroup_length = 2
        gh24hashbuf_key_length      = 16

        for key_index, key in enumerate(keys):
            value = values[key_index]
            gh24hashbuf_server, gh24hashbuf_tabgroup, gh24hashbuf_key = ghash_3_section_hash(\
                key, gh24hashbuf_server_length, gh24hashbuf_tabgroup_length, gh24hashbuf_key_length)
            server_hash_code = hash_to_int(gh24hashbuf_server)
            #print(f'XXXX     server_hash_code: {server_hash_code}')
            base_server_metaindex = map_server_hash_code_server_metaindex[target_table_index][server_hash_code]
            #print(f'XXXX     base_server_metaindex: {base_server_metaindex}')
            if base_server_metaindex < 0 or base_server_metaindex >= n_servers:
                res = False
                error = f'multi_pipelined_assign_keys_values_to_connectors_v2: base_server_metaindex: out of range'
                break
            else:
                sidx = allocation_server_index[target_table_index][base_server_metaindex]
                #print(f'XXXX     sidx: {sidx}')
                if sidx < 0 or sidx >= n_server_slots:
                    res = False
                    error = f'multi_pipelined_assign_keys_values_to_connectors_v2: sidx: out of range'
                    break
                else:
                    if server_index[sidx] == -1:
                        res = False
                        error = f'multi_pipelined_assign_keys_values_to_connectors_v2: inconsistent server index'
                        break
                    else:
                        #print(f'XXXX     inserting key in klists[{server_index[sidx]}][{next_connection[server_index[sidx]]}]')
                        klists[server_index[sidx]][next_connection[server_index[sidx]]].append(key)
                        vlists[server_index[sidx]][next_connection[server_index[sidx]]].append(value)
                        next_connection[server_index[sidx]] = (next_connection[server_index[sidx]] + 1)%n_connections_per_server

        if res == True:
            for slot_index in range(0, n_server_slots):
                if server_index[slot_index] >= 0:
                    for c in range(0, n_connections_per_server):
                        key_lists.append(klists[slot_index][c])
                        value_lists.append(vlists[slot_index][c])
                        server_ip_addresses_list.append(server_ip_address[slot_index])
        if res == True:
            if verbose:
                for i in range(0, len(key_lists)):
                    print(f'XXXX key_lists[{i}]: {len(key_lists[i])} keys, server ip address: {server_ip_addresses_list[i]}')

    return res, error, key_lists, value_lists, server_ip_addresses_list, n_servers

def multi_pipelined_read(table_name: str, field_labels: List, ayradb_servers: List[Dict[str, Union[str, int, str]]], n_connections_per_server: int, keys: List, credentials=None):
    res = True
    error = ''
    records = []
    optimized = True
    if verbose:
        print(f'multi_pipelined_read: ayradb_servers: {ayradb_servers}')
    try:
        if optimized == False:
            # in the case of no optimization, the servers list can simply be the list of servers
            # returned by the API adbc_1liner__get_servers__wrapper
            res_get_servers, error, servers = adbc_1liner__get_servers__wrapper(ayradb_servers, credentials)
            if res_get_servers == False:
                res = False
                error = f'multi_pipelined_read: error in adbc_1liner__get_servers__wrapper: {error}'
                if verbose:
                    print(f'multi_pipelined_read: res_get_servers: {res_get_servers} error: {error} servers: {servers}')
                return res, error, records
            key_lists = multi_pipelined_assign_keys_to_connectors(len(servers), n_connections_per_server, keys)
            server_ip_addresses_list = []
            for s in range(0,len(servers)):
                for c in range(0, n_connections_per_server):
                    server_ip_addresses_list.append(servers[s]['ip'])
            n_servers = len(servers)
        else:
            # in the optimized case, the server_ip_addresses_list is provided by the local function
            # multi_pipelined_assign_keys_to_connectors_v2
            res_tas, error, table_allocation_structure = adbc_1liner__get_table_allocation_structure__wrapper(ayradb_servers, credentials, target_table_name=table_name)
            if res_tas == False or table_allocation_structure is None:
                res = False
                error = f'multi_pipelined_read: error in adbc_1liner__get_table_allocation_structure__wrapper: {error}'
                return res, error, records
            else:
                res_kass, error, key_lists, server_ip_addresses_list, n_servers = multi_pipelined_assign_keys_to_connectors_v2(n_connections_per_server, keys, table_allocation_structure)
                if res_kass == False:
                    res = False
                    error = f'multi_pipelined_read: error in multi_pipelined_assign_keys_to_connectors_v2: {error}'
                    return res, error, records
                else:
                    if verbose:
                        print(f'multi_pipelined_read: optimized: ')
                        for i in range(0, len(key_lists)):
                            print(f'key_lists[{i}]: {len(key_lists[i])} keys, server ip address: {server_ip_addresses_list[i]}')

        if res == True:
            if verbose:
                for klist in key_lists:
                    print(klist)
            # launch the processes
            with multiprocessing.Manager() as manager:

                port = AyraDB_parameters.HTTPS_PORT
                scheme = 'HTTPS'

                MEM_total = psutil.virtual_memory().total
                process = psutil.Process()
                memory_info = process.memory_info()
                MEM_used = memory_info.rss 
                MEM_budget = 0.3 * (MEM_total - MEM_used) / (n_servers * n_connections_per_server)

                shared_list = manager.list()  # The shared list is for returning the results to the main process

                processes = []
                process_index = 0
                for s in range(0, n_servers):
                    for c in range(0, n_connections_per_server):
                        p = multiprocessing.Process(\
                            target=multi_pipelined_read_worker_function,\
                            args=(\
                                s,\
                                c,\
                                table_name,\
                                field_labels,\
                                key_lists[process_index],\
                                server_ip_addresses_list[process_index],\
                                port,\
                                scheme,\
                                MEM_budget,\
                                shared_list),\
                                kwargs={'credentials': credentials})
                        process_index += 1
                        p.start()
                        processes.append(p)
                n_processes_joined = 0
                for p in processes:
                    p.join()
                    n_processes_joined += 1
                    if verbose:
                        print(f'multi_pipelined_read: joined {n_processes_joined}/{len(processes)}')

                # get the status records from the sublists and determine the final result
                final_result = True
                for sublist in shared_list:
                    if len(sublist) == 0:
                        final_result = False
                        error = f'{error} --- a results sublist has zero length'
                    else:
                        status_record = sublist[-1]
                        if status_record is None:
                            final_result = False
                            error = f'{error} --- the status record of a sublist is None'
                        else:
                            if not isinstance(status_record, dict):
                                final_result = False
                                error = f'{error} --- the status record of a sublist is not a dictionary'
                            else:
                                if not 'result' in status_record:
                                    final_result = False
                                    error = f'{error} --- the status record of a sublist does not have the result field'
                                else:
                                    if status_record['result'] != 'success':
                                        final_result = False
                                        if 'error' in status_record:
                                            error = f'{error} --- {status_record["error"]}'
                                        else:
                                            error = f'{error} --- unknown error'

                if final_result == False:
                    res = False
                    # error is already set

                if res == True:
                    if verbose:
                        print(f'multi_pipelined_read: building records')
                    records = [item for sublist in shared_list for item in sublist]
                    for sublist in shared_list:
                        if len(sublist) > 0:
                            records.extend(sublist[:-1])
                    if verbose:
                        print(f'multi_pipelined_read: records built')
                return res, error, records

    except DBConnectionError as e:
        res = False
        records = []
        error = f'multi_pipelined_read: connection error: {e}'
    except (MemoryError, OSError) as e:
        res = False
        records = []
        error = f'multi_pipelined_read: not enough memory on the client machine to perform this operation'
    except Exception as e:
        res = False
        records = []
        error = f'multi_pipelined_read: unexpected exception: {e}'

    return res, error, records

def multi_pipelined_read__wrapper(table_name: str, field_labels: List, ayradb_servers: List[Dict[str, Union[str, int, str]]], keys: List, credentials=None):
    res = True
    error = None
    records = []

    if res == True:
        res_conn, error_conn, n_connections_per_server = multi_pipelined_calculate_n_connections_per_server(ayradb_servers, credentials)
        if res_conn == False:
            res = False
            error = f'ERROR: multi_pipelined_read__wrapper: error in multi_pipelined_calculate_n_connections_per_server: {error_conn}'

    if res == True:
        res_read, error_read, records = multi_pipelined_read(table_name, field_labels, ayradb_servers, n_connections_per_server, keys, credentials=credentials)
        if res_read == False:
            res = False
            error = f'ERROR: multi_pipelined_read__wrapper: error in multi_pipelined_read: {error_read}'

    return res, error, records

def multi_pipelined_write_worker_function(\
        server_index: int,\
        connection_index: int,\
        table_name: str,\
        keys: List,\
        values: List,\
        server_ip_address: str,\
        server_port: int,\
        scheme: str,\
        MEM_budget: float,\
        shared_list,\
        credentials=None):
    result_list = []
    try:
        connector = ADBC_pipelined(server_ip_address, server_port, scheme, credentials=credentials)
        res, error = connector.pipelined_write(table_name, keys, values, MEM_budget)

        # the last item of the list 'records' is the description of the return status of the
        # function 'pipelined_write'
        if res == True:
            status_record = {}
            status_record['result'] = 'success'
            result_list.append(status_record)
        else:
            result_list = []
            status_record = {}
            status_record['result'] = 'failure'
            if error is None:
                error = 'unknown error'
            status_record['error'] = error
            result_list.append(status_record)

    except Exception as e:
        print(f'LOGGING: multi_pipelined_write_worker_function: ADBC_pipelined.pipelined_write: Exception: {e}')
        result_list = []
        status_record = {}
        status_record['result'] = 'failure'
        if e is None:
            error = 'unknown error'
        else:
            error = str(e)
        status_record['error'] = error
        result_list.append(status_record)

    shared_list.append(result_list)

def multi_pipelined_write(table_name: str, ayradb_servers: List[Dict[str, Union[str, int, str]]], n_connections_per_server: int, keys: List, values: List, credentials=None):
    res = True
    error = ''
    optimized = True
    if verbose:
        print(f'multi_pipelined_write: ayradb_servers: {ayradb_servers}')
    try:
        if len(keys) != len(values):
            res = False
            error = f'multi_pipelined_write: keys and values have different lengths'

        if res == True:
            if optimized == False:
                # in the case of no optimization, the servers list can simply be the list of servers
                # returned by the API adbc_1liner__get_servers__wrapper
                res_get_servers, error, servers = adbc_1liner__get_servers__wrapper(ayradb_servers, credentials)
                if res_get_servers == False:
                    res = False
                    error = f'multi_pipelined_write: error in adbc_1liner__get_servers__wrapper: {error}'
                    if verbose:
                        print(f'multi_pipelined_write: res_get_servers: {res_get_servers} error: {error} servers: {servers}')
                    return res, error
                key_lists = multi_pipelined_assign_keys_to_connectors(len(servers), n_connections_per_server, keys)
                server_ip_addresses_list = []
                for s in range(0,len(servers)):
                    for c in range(0, n_connections_per_server):
                        server_ip_addresses_list.append(servers[s]['ip'])
                n_servers = len(servers)
            else:
                # in the optimized case, the server_ip_addresses_list is provided by the local function
                # multi_pipelined_assign_keys_to_connectors_v2
                res_tas, error, table_allocation_structure = adbc_1liner__get_table_allocation_structure__wrapper(ayradb_servers, credentials, target_table_name=table_name)
                if res_tas == False or table_allocation_structure is None:
                    res = False
                    error = f'multi_pipelined_write: error in adbc_1liner__get_table_allocation_structure__wrapper: {error}'
                    return res, error
                else:
                    res_kass, error, key_lists, value_lists, server_ip_addresses_list, n_servers = \
                            multi_pipelined_assign_keys_values_to_connectors_v2(n_connections_per_server, keys, values, table_allocation_structure)
                    if res_kass == False:
                        res = False
                        error = f'multi_pipelined_write: error in multi_pipelined_assign_keys_to_connectors_v2: {error}'
                        return res, error
                    else:
                        if verbose:
                            print(f'multi_pipelined_write: optimized: ')
                            for i in range(0, len(key_lists)):
                                print(f'key_lists[{i}]: {len(key_lists[i])} keys, server ip address: {server_ip_addresses_list[i]}')
        if res == True:
            if verbose:
                for klist in key_lists:
                    print(klist)
            # launch the processes
            with multiprocessing.Manager() as manager:

                port = AyraDB_parameters.HTTPS_PORT
                scheme = 'HTTPS'

                MEM_total = psutil.virtual_memory().total
                process = psutil.Process()
                memory_info = process.memory_info()
                MEM_used = memory_info.rss 
                MEM_budget = 0.3 * (MEM_total - MEM_used) / (n_servers * n_connections_per_server)

                shared_list = manager.list()  # The shared list is for returning the results to the main process

                processes = []
                process_index = 0
                for s in range(0, n_servers):
                    for c in range(0, n_connections_per_server):
                        p = multiprocessing.Process(\
                            target=multi_pipelined_write_worker_function,\
                            args=(\
                                s,\
                                c,\
                                table_name,\
                                key_lists[process_index],\
                                value_lists[process_index],\
                                server_ip_addresses_list[process_index],\
                                port,\
                                scheme,\
                                MEM_budget,\
                                shared_list),\
                                kwargs={'credentials': credentials})
                        process_index += 1
                        p.start()
                        processes.append(p)
                n_processes_joined = 0
                for p in processes:
                    p.join()
                    n_processes_joined += 1
                    if verbose:
                        print(f'multi_pipelined_write: joined {n_processes_joined}/{len(processes)}')

                # get the status records from the sublists and determine the final result
                final_result = True
                for sublist in shared_list:
                    if len(sublist) == 0:
                        final_result = False
                        error = f'{error} --- a results sublist has zero length'
                    else:
                        status_record = sublist[-1]
                        if status_record is None:
                            final_result = False
                            error = f'{error} --- the status record of a sublist is None'
                        else:
                            if not isinstance(status_record, dict):
                                final_result = False
                                error = f'{error} --- the status record of a sublist is not a dictionary'
                            else:
                                if not 'result' in status_record:
                                    final_result = False
                                    error = f'{error} --- the status record of a sublist does not have the result field'
                                else:
                                    if status_record['result'] != 'success':
                                        final_result = False
                                        if 'error' in status_record:
                                            error = f'{error} --- {status_record["error"]}'
                                        else:
                                            error = f'{error} --- unknown error'

                if final_result == False:
                    res = False
                    # error is already set

                return res, error

    except DBConnectionError as e:
        res = False
        error = f'multi_pipelined_write: connection error: {e}'
    except (MemoryError, OSError) as e:
        res = False
        error = f'multi_pipelined_write: not enough memory on the client machine to perform this operation'
    except Exception as e:
        res = False
        error = f'multi_pipelined_write: unexpected exception: {e}'

    return res, error

def multi_pipelined_write__wrapper(table_name: str, ayradb_servers: List[Dict[str, Union[str, int, str]]], keys: List, values: List, credentials=None):
    res = True
    error = None

    if res == True:
        res_conn, error_conn, n_connections_per_server = multi_pipelined_calculate_n_connections_per_server(ayradb_servers, credentials)
        if res_conn == False:
            res = False
            error = f'ERROR: multi_pipelined_wite__wrapper: error in multi_pipelined_calculate_n_connections_per_server: {error_conn}'

    if res == True:
        res_write, error_write = multi_pipelined_write(table_name, ayradb_servers, n_connections_per_server, keys, values, credentials=credentials)
        if res_write == False:
            res = False
            error = f'ERROR: multi_pipelined_write__wrapper: error in multi_pipelined_write: {error_write}'

    return res, error

