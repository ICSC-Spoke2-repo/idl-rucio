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

# This code has been modified for the ICSC Spoke2 IDL project 

###############################################################################################
# For the following didmeta plugin to work correctly, it must be used with the IDL API Client #
###############################################################################################

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
        config.read('/tmp/metaDB_credentials_template.cfg') # change with the real one

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

        # Field labels for the table dump in the internal warehouse of AyraDB (you can omit the fixed value labels)
        self.field_labels_string = 'IDL_L4_VERS,COMMENT,CREATION_DATE,TIME_SYSTEM,TIMETAG_REF,EPOCH,START_TIME,STOP_TIME,ORIGINATOR,PARTICIPANT_1,PARTICIPANT_2,PARTICIPANT_3,PARTICIPANT_4,PARTICIPANT_5,PARTICIPANT_N,PATH,REFERENCE_FRAME,SENSOR_TYPE,MEAS_TYPE,MEAS_FORMAT_ANGLE_AZEL,MEAS_RANGE_MIN_AZEL_0,MEAS_RANGE_MAX_AZEL_0,MEAS_RANGE_MIN_AZEL_1,MEAS_RANGE_MAX_AZEL_1,MEAS_FORMAT_ANGLE_RADEC,MEAS_RANGE_MIN_RADEC_0,MEAS_RANGE_MAX_RADEC_0,MEAS_RANGE_MIN_RADEC_1,MEAS_RANGE_MAX_RADEC_1,MEAS_FORMAT_ANGLE_XEYN,MEAS_RANGE_MIN_ANGLE_XEYN_0,MEAS_RANGE_MAX_ANGLE_XEYN_0,MEAS_RANGE_MIN_ANGLE_XEYN_1,MEAS_RANGE_MAX_ANGLE_XEYN_1,MEAS_FORMAT_ANGLE_XSYS,MEAS_RANGE_MIN_ANGLE_XSYS_0,MEAS_RANGE_MAX_ANGLE_XSYS_0,MEAS_RANGE_MIN_ANGLE_XSYS_1,MEAS_RANGE_MAX_ANGLE_XSYS_1,MEAS_FORMAT_ORBIT_XYZ,MEAS_XYZ_0,MEAS_XYZ_1,MEAS_XYZ_2,MEAS_FORMAT_ORBIT_KEP,MEAS_ORBIT_KEP_0,MEAS_ORBIT_KEP_1,MEAS_ORBIT_KEP_2,MEAS_ORBIT_KEP_3,MEAS_ORBIT_KEP_4,MEAS_ORBIT_KEP_5,MEAS_FORMAT_ORBIT_COV,MEAS_FORMAT_RF_SAMPLES,MEAS_FORMAT_RF_PC_NO,MEAS_RANGE_MIN_RF_PC_NO_0,MEAS_RANGE_MAX_RF_PC_NO_0,MEAS_FORMAT_RF_CARRIER_POWER,MEAS_RANGE_MIN_RF_CARRIER_POWER_0,MEAS_RANGE_MAX_RF_CARRIER_POWER_0,MEAS_FORMAT_RF_CARRIER_FREQUENCY,MEAS_RANGE_MIN_RF_CARRIER_FREQUENCY_0,MEAS_RANGE_MAX_RF_CARRIER_FREQUENCY_0,MEAS_FORMAT_RF_OBW,MEAS_RANGE_MIN_RF_OBW_0,MEAS_RANGE_MAX_RF_OBW_0,MEAS_FORMAT_RF_DOPPLER_INSTANTANEOUS,MEAS_RANGE_MIN_RF_DOPPLER_INSTANTANEOUS_0,MEAS_RANGE_MAX_RF_DOPPLER_INSTANTANEOUS_0,MEAS_FORMAT_RF_DOPPLER_INTEGRATED,MEAS_RANGE_MIN_RF_DOPPLER_INTEGRATED_0,MEAS_RANGE_MAX_RF_DOPPLER_INTEGRATED_0,MEAS_FORMAT_RF_MODULATION,MEAS_FORMAT_RCS,MEAS_RANGE_MIN_RCS_0,MEAS_RANGE_MAX_RCS_0,MEAS_FORMAT_RANGE,MEAS_RANGE_MIN_RANGE_0,MEAS_RANGE_MAX_RANGE_0,MEAS_FORMAT_PHOTO_MAG,MEAS_RANGE_MIN_PHOTO_MAG_0,MEAS_RANGE_MAX_PHOTO_MAG_0,MEAS_FORMAT_PHOTO_TEMPERATURE,MEAS_RANGE_MIN_PHOTO_TEMPERATURE_0,MEAS_RANGE_MAX_PHOTO_TEMPERATURE_0,MEAS_OTHER_IMAGE,MEAS_RANGE_DESC,MEAS_RANGE_UNIT,DATA_QUALITY,LINK'
        # OLD SCHEMA
        # self.field_labels_string = 'IDL_L4_VERS,COMMENT,CREATION_DATE,ORIGINATOR,TIME_SYSTEM,EPOCH,PARTICIPANT_1,PARTICIPANT_2,PATH,REFERENCE_FRAME,MEAS_TYPE,MEAS_FORMAT,MEAS_UNIT,DATA_QUALITY,LINK'
        
        # Wildcard for the get-metadata
        self.field_labels = ['*']

        ########## blockchain ##################
        self.blockchainUrl = "https://<BLOCKCHAIN_URL>:3000"
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

    def set_metadata(self, scope: "InternalScope", name: str, key: str, value: str, recursive: bool = False, *, session: "Optional[Session]" = None) -> None:
        """
        Add metadata to data identifier.

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key is fixed to JSON.
        :param value: the value is the output of the .json metadata file to write.
        :param recursive: Option to propagate the metadata change to content.
        :param session: The database session in use.
        """
        if key == "JSON":
            try:
                # Use this Python dict to add the DID, which is unique in Rucio, in the "LINK" field or, in general,to edit the fields if needed 
                dict = json.loads(value) 
                
                self.fields = {keys: values for keys, values in dict.items() if keys != 'sha256'}

                # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
                try:
                    key = adbc__generate_record_key_from_field(self.fields['LINK'])
                except Exception as e:
                    raise Exception(f'Failed to generate key for AyraDB: {str(e)}')

                # Write the record on AyraDB
                try:
                    res, error = adbc_1liner__write_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key, self.fields)
                    
                    if res == False:
                        raise Exception(f"Failed to write the metadata record: {error}")
                    elif res == True:
                        print('Successfully wrote the metadata record!')
                except Exception as e:
                    print(f'Error writing metadata record: {str(e)}')  # Display in the server logs the raised error message
                    raise  # Re-raise the original exception
        
                # Dump the metadata table to the internal warehouse
                try:
                    res_dump_table, error_dump = adbc_1liner__dump_table_to_warehouse__wrapper(self.ayradb_servers, self.credentials, self.table_name, self.field_labels_string)

                    if res_dump_table == False:
                        raise Exception(f"Failed to dump the table: {error_dump}")
                    elif res_dump_table == True:
                        print('Successfully dumped the table!')
                except Exception as e:
                    print(f'Error dumping the table: {str(e)}') # Display in the server logs the raised error message
                    raise  # Re-raise the original exception

                ######## blockchain ###########
                try:
                    self.set_blockchain(value)
                except Exception as e:
                    # TO-DO: implement the raise error when in production/on ICSC resources
                    # Exception management to avoid internal errors due to possible blockchain server errors
                    print(f'Error contacting blockchain. ERROR: {str(e)}')
                    #raise exception.DatabaseException("Failed to contact the blockchain")
                
                ###########################
                
            except Exception as e:
                raise
        else:
            print('Key must be "JSON"')
            #raise Exception("Key must be 'JSON'")

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

        # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
        try:
            key = adbc__generate_record_key_from_field('{}:{}'.format(scope.internal, clean_name))
        except Exception as e:
            raise Exception(f'Failed to generate key for AyraDB: {str(e)}')

        # Get the record from AyraDB
        try:
            res, error, record = adbc_1liner__read_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key, self.field_labels)
            
            if res == False:
                raise Exception(f"Failed to get the records: {error}")
            elif res == True:
                print('Successfully read the metadata records!')

                # Convert the Python dict from bytearrays to strings
                try:
                    converted_dict = self.convert_bytearrays(record)
                except Exception as e:
                    raise Exception(f'Error converting the records from bytearrays: {str(e)}')
                

                if hash_data == "get-metadata_handling":
                    # Return the converted metadata record
                    return converted_dict
                else:
                    ######## blockchain ###########
                    try:
                        # Computation of metadata_hash for the get_from_blockchain method  
                        metahash_dict = {keys: values for keys, values in converted_dict.items()}

                        # Values wrangling 
                        # string = metahash_dict["EPOCH"]
                        # metahash_dict["EPOCH"] = metahash_dict["EPOCH"].strftime("%Y-%m-%dT%H:%M:%S") + f".{string.microsecond:06d}"
                        # The next two lines are needed because during set_metadata the metadata_hash for the blockchain has been computed with "2024-09-14T23:20:02.120928" format, but when it is returned by the DB cluster it has a space instead of the 'T'
                        # If you don't do this replacement, the metadata_hash computed in line 292 will be different and the validate_data will return Fals
                        # metahash_dict["EPOCH"] = metahash_dict["EPOCH"].replace(' ', 'T')
                        # metahash_dict["CREATION_DATE"] = metahash_dict["CREATION_DATE"].replace(' ', 'T')

                        metadata_hash = adbc__generate_record_key_from_field(str(metahash_dict))
                        print(self.get_from_blockchain(data_hash=hash_data, metadata_hash=metadata_hash))

                        if self.get_from_blockchain(data_hash=hash_data, metadata_hash=metadata_hash) == "The metadata hash is not the same":
                            raise Exception("The hashes are different from the ones in the blockchain!")
                        else:
                            # Return the validated metadata record
                            return converted_dict
                    except Exception as e:
                        # TO-DO: implement the raise error when in production/on ICSC resources
                        # Exception management to avoid internal errors due to possible blockchain server errors
                        print(f'Error contacting blockchain. ERROR: {str(e)}')
                        raise #exception.DatabaseException("Failed to contact the blockchain")
                    ###########################
            
        except Exception as e:
            print(f'Error getting records: {str(e)}')  # Display in the server logs the raised error message
            raise  # Re-raise the original exception

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

        try:
            # Backwards compatibility for filters as single {}.
            if isinstance(filters, dict):
                filters = [filters]
            
            # Workaround to call delete-metadata for an external metadata DB
            if any("del_select" in elem for elem in filters):
                did_name = next((d["del_select"] for d in filters if "del_select" in d), None)
                self.delete_metadata(scope=scope, name=did_name, key="Placeholder")
                return {"delete": "Success"}

            # I am passing the SELECTs in the filters in the Client as a list in the list of dicts that is the filters. Here in the plugin I split the two infos
            select_list = [elem for elem in filters if 'sql_select' in elem]
            select = select_list[0]['sql_select']

            filters = [elem for elem in filters if 'sql_select' not in elem]

            # Build SQL query
            def build_sql_query(filter):
                conditions = []
                for filter_dict in filter:
                    and_conditions = []
                    for key, value in filter_dict.items():
                        if key != 'name':
                            field, operator = key.split(".") 
                            and_conditions.append(f"{field}{operator}'{value}'") 
                        else:
                            pass
                    conditions.append(f"{' AND '.join(and_conditions)}")
        
                # Join OR conditions
                where_clause = ' OR '.join(conditions)
                query = f"SELECT {select} FROM ayradb.metadata WHERE {where_clause};"
                return query

            try:
                query = build_sql_query(filters)
            except:
                raise Exception("The builfing of the SQL query went wrong")

            try:
                # Management of temporary failures of SQL queries
                max_attempts = 30 # set the maximum number of attempts, or 0 for unlimited attempts
                n_attempts = 0
                keep_trying = True
                while keep_trying:
                    res, error, records = adbc_1liner__sql__wrapper(self.ayradb_servers, self.credentials, query, warehouse_query=True)       
                    if res == False and error is not None and 'AYRADB_TEMPORARY_ERROR' in error:
                        n_attempts += 1
                        if max_attempts > 0 and n_attempts > max_attempts:
                            keep_trying = False
                        else:
                            time.wait(10)
                    else:
                        keep_trying = False
                
                # Convert the Python dicts from bytearrays to strings and append to a list
                results = []
                for dicts in records:
                    converted_dict = self.convert_bytearrays(dicts)
                    if converted_dict['LINK'].split(':')[0] == f"{scope}":
                        results.append(converted_dict)

                # Check result of getting the metadata for a DID
                if res == False:
                    raise Exception(f'ERROR: listing the DIDs: {error}')
                elif res == True:
                    return results
            except:
                raise
        except:
            raise

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



