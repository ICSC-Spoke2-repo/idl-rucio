# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################################
# For the following didmeta plugin to work correctly, it must be used with the IDL API Client #
###############################################################################################

# Includes for AyraDB connection 1.0.0
# import random
# import string
# import sys
# import time 

# from adbc.core.adbc import adbc_1liner__write_record__wrapper
# from adbc.core.adbc import adbc_1liner__delete_record__wrapper
# from adbc.core.adbc import adbc_1liner__sql__wrapper
# from adbc.core.adbc import adbc_1liner__dump_table_to_warehouse__wrapper
# from adbc.core.adbc import adbc_1liner__dump_table_ild_metadata_to_warehouse
# from adbc.core.adbc import adbc__generate_record_key_from_field

# Includes for AyraDB connection 1.0.1
import copy
import random
import string
import sys
import time

from adbc.core.adbc import adbc_1liner__write_record__wrapper
from adbc.core.adbc import adbc_1liner__delete_record__wrapper
from adbc.core.adbc import adbc_1liner__read_record__wrapper
from adbc.core.adbc import adbc_1liner__sql__wrapper
from adbc.core.adbc import adbc_1liner__dump_table_to_warehouse__wrapper, adbc_1liner__dump_table_ild_metadata_to_warehouse
from adbc.core.adbc_pipelined import multi_pipelined_read__wrapper
from adbc.core.adbc_pipelined import multi_pipelined_write__wrapper
from adbc.core.adbc import adbc__generate_record_key_from_field

# For conversion of metadata CREATION_DATE and EPOCH
from datetime import datetime

# Old includes for postgres did-meta plugin
import json
import os
import operator
from typing import TYPE_CHECKING

import psycopg2
import psycopg2.extras

from rucio.common import config, exception
from sqlalchemy.exc import CompileError, InvalidRequestError, NoResultFound
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_list, json_parameters, json_parse, param_get, parse_scope_name, response_headers, try_stream
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from sqlalchemy.sql.expression import true

# Includes to get the checksum/hash of the data file for blockchain and for communication with blockchain
from rucio.client.didclient import DIDClient
import requests

# Include to get the coordinates and credentials of the AyraDB cluster
import configparser

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any, Optional, Union

    from sqlalchemy.orm import Session
    from rucio.db.sqla.models import ModelBase

    from rucio.common.types import InternalScope

class CustomDidMetaPlugin(DidMetaPlugin):
    """
    Interface for plugins managing metadata of DIDs
    """
    def __init__(self):
        super(CustomDidMetaPlugin, self).__init__()
        self.plugin_name = "IDL"

        config = configparser.ConfigParser()
        config.read('/tmp/AyraDB_cluster_credentials.cfg')

        # AyraDB cluster INFN coordinates
        self.ayradb_servers = [ {
                "ip": config.get('server1', 'ip'),
                "port": int(config.get('server1', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
                "name": config.get('server1', 'name')
            },
            {
                "ip": config.get('server2', 'ip'),
                "port": int(config.get('server2', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
                "name": config.get('server2', 'name')
            }
        ]

        # INFN cluster credentials
        self.credentials = { "username": config.get('credentials', 'username'), "password": config.get('credentials', 'password')}


        self.table_name = 'metadata'

# Example metadata file for testing
# {
#     "IDL_L4_VERS": "0.1",
#     "COMMENT": "FENGYUN 1C DEB",
#     "CREATION_DATE": "2024-09-14T00:00:00",
#     "ORIGINATOR": "CELESTRAK", 
#     "TIME_SYSTEM": "UTC",
#     "EPOCH": "2024-09-14T23:20:02.120928",
#     "PARTICIPANT_1": "NORAD",
#     "PARTICIPANT_2": "1999-025APG",
#     "PATH": "1,2,1",
#     "REFERENCE_FRAME": "EME2000",
#     "MEAS_TYPE": "ORBIT",
#     "MEAS_FORMAT": "KEP",
#     "MEAS_UNIT": "km, deg, deg, deg, deg",
#     "DATA_QUALITY": "L4",
#     "LINK": ""
# }

        # Field labels for the table dump in the internal warehouse of AyraDB (you can omit the fixed value labels)
        self.field_labels_string = 'IDL_L4_VERS,COMMENT,CREATION_DATE,ORIGINATOR,TIME_SYSTEM,EPOCH,PARTICIPANT_1,PARTICIPANT_2,PATH,REFERENCE_FRAME,MEAS_TYPE,MEAS_FORMAT,MEAS_UNIT,DATA_QUALITY,LINK'
        self.field_labels = ['*']

        ########## blockchain ##################
        self.blockchainUrl = "https://vm-131-154-99-190.cloud.cnaf.infn.it:3000"
        self.headers = {"content-type": "application/x-www-form-urlencoded"}
        ########################################

    # Method to convert results of the DB queries into strings
    def convert_bytearrays(self, data):
        if isinstance(data, dict):
            # Recursively process each key-value pair in the dictionary
            return {keys: self.convert_bytearrays(values) for keys, values in data.items()}
        elif isinstance(data, list):
            # Recursively process each element in the list
            return [self.convert_bytearrays(item) for item in data]
        elif isinstance(data, bytearray):
            try:
                # Attempt to decode the bytearray to a string
                decoded_string = data.decode('utf-8')  # Change 'utf-8' if needed
        
                # Try to convert the string to a datetime object
                #try:
                #    # Adjust the format string as needed for your datetime format
                #    return datetime.strptime(decoded_string, '%Y-%m-%d %H:%M:%S.%f')
                #except ValueError:
                return decoded_string  # Return as string if it can't be parsed as datetime
            
            except UnicodeDecodeError:
                return str(data)  # Return as a string representation if decoding fails
        else:
            return data  # Return as is if it's not a bytearray, list, or dict 

    def set_metadata(self, scope: "InternalScope", name: str, key: str, value: str, 
                     recursive: bool = False, *, session: "Optional[Session]" = None): # -> None:
        """
        Add metadata to data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key.
        :param value: the value.
        :param did: The data identifier info.
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        if key == "JSON":
            try:
                # Use this Python dict to add the DID, which is unique in Rucio, in the "LINK" field or, in general,to edit the fields if needed 
                dict = json.loads(value) 

                print(value)
                print(type(value))
                
                self.fields = {keys: values for keys, values in dict.items() if keys != 'sha256'}

                # Debug
                print(dict)
                print(type(dict))
                print('################################')
                print(self.fields)
                print(type(self.fields))
                print('################################')

                # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
                key = adbc__generate_record_key_from_field(self.fields['LINK'])

                print(key)
                print(type(key))

                # Write the record
                #error = None
                try:
                    res, error = adbc_1liner__write_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key, self.fields)
                except CompileError as e:
                    print(f'{error}')
                    raise exception.InvalidMetadata(e)
                except InvalidRequestError:
                    raise exception.InvalidMetadata("Some of the keys are not accepted")
        
                    
                #print(res)

                # Dump of the metadata table to the internal warehouse (at the moment it can create some issues for the queries)
                res_dump_table, error_dump = adbc_1liner__dump_table_to_warehouse__wrapper(self.ayradb_servers, self.credentials, self.table_name, self.field_labels_string)
                #res_dump_table, error_dump = adbc_1liner__dump_table_ild_metadata_to_warehouse(self.ayradb_servers, self.credentials)

                print(res_dump_table)

                # Check result of dumping table
                if res_dump_table == False:
                    print(f'ERROR: dumping table: {error_dump}')
                    #raise exception.DatabaseException("Dump of the table failed")
                    e = f'ERROR: dumping table: {error_dump}'
                    return generate_http_error_flask(406, e) 
                elif res_dump_table == True:
                   print('Successfully dumped the table!')

                # Check result of writing record
                if res == False:
                    print(f'ERROR: writing a record: {error}')
                    raise exception.DatabaseException("Failed to write the metadata")
                elif res == True:
                    print('Successfully wrote the metadata!')

                ######## blockchain ###########
                try:
                    self.set_blockchain(value)
                except:
                    # Exception management to avoid internal errors due to possible blockchain server errors
                    print('ERROR: contacting blockchain')
                    raise exception.DatabaseException("Failed to contact the blockchain")
                
                ###########################
                
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("Key must be 'JSON'")

    def get_metadata(self, scope, name, *, session: "Optional[Session]" = None):
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: the metadata for the did
        """
        # For now, I am passing the hash_data and did_name in the argument "name" in the Client as "{hash_data}:{did_name}". Here in the plugin I split the two infos
        hash_data = name.split(':')[0]
        clean_name = name.split(':')[1]

        #print(self.ayradb_servers)
        #print(self.credentials)
        
        # Constant SQL query to retrieve the metadata of a DID
        # const_sql_query = f"SELECT * FROM ayradb.metadata WHERE LINK='{scope.internal}:{clean_name}';"

        # Debug
        # print(const_sql_query)

        key = adbc__generate_record_key_from_field('{}:{}'.format(scope.internal, clean_name))

        # res, error, records = adbc_1liner__sql__wrapper(self.ayradb_servers, self.credentials, const_sql_query, warehouse_query=True)          
        res, error, record = adbc_1liner__read_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key, self.field_labels)

        # Debug
        print(record)

        # Convert the Python dict from bytearrays to strings
        converted_dict = self.convert_bytearrays(record)

        # Debug
        print('###############################')
        print(str(converted_dict))
        print('###############################')

        ######## blockchain ###########
        # Computation of metadata_hash for the get_from_blockchain method  
        metahash_dict = {keys: values for keys, values in converted_dict.items()}

        print(metahash_dict)

        # string = metahash_dict["EPOCH"]
        # metahash_dict["EPOCH"] = metahash_dict["EPOCH"].strftime("%Y-%m-%dT%H:%M:%S") + f".{string.microsecond:06d}"
        # The next two lines are needed because during set_metadata the metadata_hash for the blockchain has been computed with "2024-09-14T23:20:02.120928" format, but when it is returned by the DB cluster it has a space instead of the 'T'
        # If you don't do this replacement, the metadata_hash computed in line 292 will be different and the validate_data will return Fals
        # metahash_dict["EPOCH"] = metahash_dict["EPOCH"].replace(' ', 'T')
        # metahash_dict["CREATION_DATE"] = metahash_dict["CREATION_DATE"].replace(' ', 'T')

        metadata_hash = adbc__generate_record_key_from_field(str(metahash_dict))

        # print(metahash_dict)

        try: 
            print(self.get_from_blockchain(data_hash=hash_data, metadata_hash=metadata_hash)) 
        except:
            # Exception management to avoid internal errors due to possible blockchain server errors
            print('ERROR: contacting blockchain')
        
        ###########################
            
        # Check result of getting the metadata for a DID
        if res == False:
            print(f'ERROR: retrieving the metadata: {error}')
        elif res == True:
            return converted_dict
        
    # def get_metadata_bulk(self, dids):
    #     hash_data_list = []
    #     keys = []
    #     for did in dids:
    #         hash_data = did['name'].split('$')[0]
    #         hash_data_list.append(hash_data)
    #         did['name'] = did['name'].split('$')[1]
    #         key = adbc__generate_record_key_from_field('{}:{}'.format(did['scope'], did['name']))
    #         keys.append(key)
        
    #     res_read, error, records = multi_pipelined_read__wrapper(self.table_name, self.field_labels, self.ayradb_servers, keys, credentials=self.credentials)

    #     if res_read == False:
    #         print(f'Error: {error}')
    #     else:
    #         converted_dicts = self.convert_bytearrays(records)
    #         for idx, record in enumerate(converted_dicts):
    #             metadata_hash = adbc__generate_record_key_from_field(str(record))
    #             try: 
    #                 print(self.get_from_blockchain(data_hash=hash_data_list[idx], metadata_hash=metadata_hash)) 
    #             except:
    #                 # Exception management to avoid internal errors due to possible blockchain server errors
    #                 print('ERROR: contacting blockchain')
    #         return converted_dicts

    def delete_metadata(self, scope, name, key, *, session: "Optional[Session]" = None):
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        :param session: the database session in use
        """
        # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
        key = adbc__generate_record_key_from_field('{}:{}'.format(scope.internal, name))

        # Delete record from the SQL table
        res, error = adbc_1liner__delete_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key)

        # Check result of deleting the record
        if res == False:
            print(f'ERROR: deleting the record: {error}' )
        elif res == True:
            print('Successfully deleted record')
        
        res_dump_table, error_dump = adbc_1liner__dump_table_to_warehouse__wrapper(self.ayradb_servers, self.credentials, self.table_name, self.field_labels_string)
                
        # Check result of dumping table
        if res_dump_table == False:
            print(f'ERROR: dumping table: {error_dump}')
        elif res_dump_table == True:
            print('Successfully dumped the table!')

    def list_dids(self, scope, filters, did_type='all', ignore_case=False, limit=None, 
                  offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Optional[Session]" = None):

        # Backwards compatibility for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # Debug
        #print(filters)
        #print(type(filters))
        
        # I am passing the SELECTs in the filters in the Client as a list in the list of dicts that is the filters. Here in the plugin I split the two infos
        select_list = [elem for elem in filters if 'sql_select' in elem]
        # print(select_list)
        select = select_list[0]['sql_select']
        # print(select)

        filters = [elem for elem in filters if 'sql_select' not in elem]
        #for fil in filters:
        #    for key in fil:
        #        if key.startswith("EPOCH"):
        #            
        #        elif key.startswith("CREATION_DATE"): 

        # print(filters)

        # Build SQL query
        def build_sql_query(filter):
            conditions = []
            for filter_dict in filter:
                and_conditions = []
                for key, value in filter_dict.items():
                    if key != 'name':
                        #if '.' in key:
                        field, operator = key.split(".")    #field, operator = key.split(".")
                            # Map back to the actual SQL operators
                            #operator_map = {
                            #    'gte': '>=',
                            #    'lte': '<=',
                            #    'gt': '>',
                            #    'lt': '<',
                            #    'ne': '!='
                            #}
                            #sql_operator = operator_map[operator]
                        #else:
                            #field = key
                            #sql_operator = '='
                        and_conditions.append(f"{field}{operator}'{value}'") #and_conditions.append(f"{field}{sql_operator}'{value}'")
                    else:
                        pass
                conditions.append(f"{' AND '.join(and_conditions)}")
    
            # Join OR conditions
            where_clause = ' OR '.join(conditions)
            query = f"SELECT {select} FROM ayradb.metadata WHERE {where_clause};"
            return query

        query = build_sql_query(filters)

        # Debug
        # print(query)

        res, error, records = adbc_1liner__sql__wrapper(self.ayradb_servers, self.credentials, query, warehouse_query=True)          

        # Debug
        #print(records)
        #print(records[0])
        #print(records[len(records)-1])

        # Convert the Python dicts from bytearrays to strings and append to a list
        results = []
        for dicts in records:
            converted_dict = self.convert_bytearrays(dicts)
            if converted_dict['LINK'].split(':')[0] == f"{scope}":
                results.append(converted_dict)

        # Debug
        #print(results)

        # Check result of getting the metadata for a DID
        if res == False:
            print(f'ERROR: listing the DIDs: {error}')
        elif res == True:
            return results

    def manages_key(self, key, *, session: "Optional[Session]" = None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this
        plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name

####### blockchain ###########
    def manage_request(self, callType, functionName, args):
        params = {
            "channelid": "mychannel",
            "chaincodeid": "basic",
            "function": functionName,
            "args": args,
        }
        try:
            res = requests.get(
                f"{self.blockchainUrl}/{callType}", headers=self.headers, params=params
            )

            if res.status_code == 200:
                return {
                    "message": res.text,
                    "status": 200,
                }
            return {
                "message": "Error",
                "status": res.status_code,
            }
        except requests.exceptions.ConnectionError:
            return {
                "message": "Error contacting the server",
                "status": 503,
            }


    def set_blockchain(self, value: str):
        dict = json.loads(value)
        data_hash = dict["sha256"]

        self.fields = {keys: values for keys, values in dict.items() if keys != 'sha256'}

        metadata_hash = adbc__generate_record_key_from_field(str(self.fields))
        # LINK ex DID
        DID = dict["LINK"]

        args_createDataset = [
            data_hash,
            metadata_hash,
            DID
        ]
        response = self.manage_request(
            callType="invoke",
            functionName="CreateDataset",
            args=args_createDataset,
        #    headers=self.headers,
        )
        return response

    def validate_data(self, asset, metadata_hash):
        if isinstance(asset, dict) and asset["metadataHash"] == metadata_hash:
            return True
        return False
    
    def get_from_blockchain(self, data_hash, metadata_hash):

        response = self.manage_request(callType="query", args=[data_hash], functionName="ReadDataset")
        message = response["message"]
        if "not exist" in message:
            print("Hash is not present in blockchain")
        # respons_operation = manage_request("query", args=[operationHash], function="ReadOperation")
        asset = json.loads(message[10:])
        if self.validate_data(asset, metadata_hash):
            return asset
        else:
            print("The metadata hash is not the same")



