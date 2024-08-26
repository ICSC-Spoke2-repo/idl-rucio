from datetime import datetime
from enum import Enum
import json
import hashlib
import string

def is_valid_datetime64(date_string):
    try:
        datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S.%f')
        return True
    except ValueError:
        return False

def ghash_3_section_hash(gh24str, gh24hashbuf_server_length, gh24hashbuf_tabgroup_length, gh24hashbuf_key_length):
    if isinstance(gh24str, str):
        gh24str = gh24str.encode('utf-8')
    gh24hash = hashlib.sha256(gh24str).digest()  # Returns a 32-byte hash

    gh24hashbuf_server = gh24hash[:gh24hashbuf_server_length]
    gh24hashbuf_tabgroup = gh24hash[gh24hashbuf_server_length:gh24hashbuf_server_length + gh24hashbuf_tabgroup_length]
    gh24hashbuf_key = gh24hash[gh24hashbuf_server_length + gh24hashbuf_tabgroup_length:
                               gh24hashbuf_server_length + gh24hashbuf_tabgroup_length + gh24hashbuf_key_length]

    return gh24hashbuf_server, gh24hashbuf_tabgroup, gh24hashbuf_key

def hash_to_int(gh26hashbuf):
    gh26res = -1

    if gh26hashbuf is not None:
        gh26res = 0
        gh26mul = 1  # The multiplication factor (256^i)

        for gh26i in range(len(gh26hashbuf)):
            gh26x = gh26hashbuf[gh26i]  # Get the byte value (it will be int in Python)
            gh26res += gh26x * gh26mul  # Add the byte value, multiplied by the factor
            gh26mul *= 256  # Move to the next byte position (256 for the next byte)

    return gh26res

def parse_sgsyspar_full_allocation_res (jobj):
    n_servers = 0
    server_index = []
    server_name = []
    server_ip_address = []
    n_tables = 0
    table_name= []
    n_allocation_servers = []
    allocation_server_index = []
    map_server_hash_code_server_metaindex = []
    n_server_hash_codes = 0

    res = 0
    error = ''

    jarr_s = None
    jarr_t = None

    if res == 0:
        if jobj is None:
            res = -1
            error = f'parse_sgsyspar_full_allocation_res: jobj: None'

    if res == 0:
        if not 'servers' in jobj:
            res = -1
            error = f'parse_sgsyspar_full_allocation_res: jobj->servers: None'
        else:
            jarr_s = jobj['servers']
            n_servers = len(jarr_s)
            if n_servers == 0:
                res = -1
                error = f'parse_sgsyspar_full_allocation_res: jobj->servers: empty'

        for i, server in enumerate(jarr_s):
            jobj_s = jarr_s[i]
            if jobj_s is None:
                res = -1
                error = f'parse_sgsyspar_full_allocation_res: jobj->servers[]->jobj_s: None'
                break
            if res == 0:
                if not 'index' in jobj_s:
                    res = -1
                    error = f'parse_sgsyspar_full_allocation_res: jobj->servers[]->jobj_s->index: missing'
                    break
                else:
                    server_index.append(int(jobj_s['index']))
            if res == 0:
                if not 'name' in jobj_s:
                    res = -1
                    error = f'parse_sgsyspar_full_allocation_res: jobj->servers[]->jobj_s->name: missing'
                    break
                else:
                    server_name.append(jobj_s['name'])
            if res == 0:
                if not 'ip_address' in jobj_s:
                    res = -1
                    error = f'parse_sgsyspar_full_allocation_res: jobj->servers[]->jobj_s->ip_address: missing'
                    break
                else:
                    server_ip_address.append(jobj_s['ip_address'])

    if res == 0:
        if not 'tables' in jobj:
            res = -1
            error = f'parse_sgsyspar_full_allocation_res: jobj->tables: None'
        else:
            jarr_t = jobj['tables']
            n_tables = len(jarr_t)
            if n_tables == 0:
                res = -1
                error = f'parse_sgsyspar_full_allocation_res: jobj->tables: empty'

    if res == 0:
        for i, table in enumerate(jarr_t):
            jobj_t = jarr_t[i]
            if not 'table_name' in jobj_t:
                res = -1
                error = f'parse_sgsyspar_full_allocation_res: jobj_t->table_name: missing'
                break
            else:
                table_name.append(jobj_t['table_name'])
            if res == 0:
                if not 'allocation_server_index' in jobj_t:
                    res = -1
                    error = f'parse_sgsyspar_full_allocation_res: jobj_t->allocation_server_index: missing'
                    break
                else:
                    if len(jobj_t['allocation_server_index']) == 0:
                        res = -1
                        error = f'parse_sgsyspar_full_allocation_res: jobj_t->allocation_server_index: empty'
                        break
            if res == 0:
                n_allocation_servers.append(len(jobj_t['allocation_server_index']))
                current_allocation_server_index = []
                for asidx in jobj_t['allocation_server_index']:
                    current_allocation_server_index.append(int(asidx))
                allocation_server_index.append(current_allocation_server_index)
            if res == 0:
                if not 'map_server_hash_code_server_metaindex' in jobj_t:
                    res = -1
                    error = f'parse_sgsyspar_full_allocation_res: jobj_t->map_server_hash_code_server_metaindex: missing'
                    break
                else:
                    n_server_hash_codes = len(jobj_t['map_server_hash_code_server_metaindex'])
                    if n_server_hash_codes == 0:
                        res = -1
                        error = f'parse_sgsyspar_full_allocation_res: jobj_t->map_server_hash_code_server_metaindex: empty'
                        break
            if res == 0:
                current_map_server_hash_code_server_metaindex = []
                for j in range(0, n_server_hash_codes):
                    current_map_server_hash_code_server_metaindex.append(int(jobj_t['map_server_hash_code_server_metaindex'][j]))
                map_server_hash_code_server_metaindex.append(current_map_server_hash_code_server_metaindex)

    return res, error, n_servers, server_index, server_name, server_ip_address, n_tables, table_name, n_allocation_servers, allocation_server_index, n_server_hash_codes, map_server_hash_code_server_metaindex


