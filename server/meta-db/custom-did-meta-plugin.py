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
import shutil
import operator
from typing import TYPE_CHECKING

import psycopg2
import psycopg2.extras
import threading
import asyncio
import aiohttp

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
        config.read('/tmp/metaDB_credentials_template.cfg')

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
            dir_path = "/mnt/" + "_".join(name.split("_")[:-1])

            if name.split("_")[-1] == "START.json":
                os.makedirs(dir_path)
                print(f"Directory '{dir_path}' created successfully! SET-METADATA")
            if name.split("_")[-1] == "END.json":
                import subprocess
                result = subprocess.run(["pipelined_utils.py", "set", "--dir", f"{dir_path}", "--scope", f"{name.split('_')[0]}"], capture_output=True, text=True)
                results = eval(result.stdout)
                print("Error:", result.stderr)
                # tmp commented due to lack of manpower to mantain it
                # if result.stderr == "":
                #     try:
                #         loop = asyncio.get_running_loop()
                #         coro = self._run_blockchain_tasks(results)
                #         loop.create_task(coro)  # fire and forget (non-blocking)
                #     except RuntimeError:
                #         asyncio.run(self._run_blockchain_tasks(results))
                    # tasks = []
                    # for value in results:
                    #     ######## BLOCKCHAIN ###########
                    #     try:
                    #         tasks.append(threading.Thread(target=self.set_blockchain, args=(value,)))
                    #     except Exception as e:
                    #         # print(f'Error contacting blockchain. ERROR: {str(e)}')
                    #         raise Exception("Failed to contact the blockchain.")
                    #     ###########################
                    # for task in tasks:
                    #     task.start()
            if name.split("_")[-1] != "START.json" and name.split("_")[-1] != "END.json":
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)
                dict = json.loads(value) # writes also the sha256 to the tmp file!
                tmp_file_path = os.path.join(dir_path, name)
                with open(tmp_file_path, 'w') as f:
                    json.dump(dict, f, indent=4)
                print(f"Metadata file '{tmp_file_path}' saved in '{dir_path}'!")
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
        dir_name = name.split('|')[0]
        name = name.split('|')[1]
        hash_data = name.split(':')[0]
        clean_name = name.split(':')[1]

        dir_path = "/mnt/" + f"get-metadata_{dir_name}"
        
        if clean_name == "START":
            os.makedirs(dir_path)
            print(f"Directory '{dir_path}' created successfully!")
            return {"First": "Success"}
        if clean_name == "END":
            import subprocess
            result = subprocess.run(["pipelined_utils.py", "get", "--dir", f"{dir_path}", "--scope", f"{dir_name.split('_')[0]}"], capture_output=True, text=True)
            results = eval(result.stdout)
            print("Error:", result.stderr)
            results = self.convert_bytearrays(results)
            output = {"Output": results}
            if hash_data == "get-metadata_handling":
                # Return the converted metadata record
                return output
            else:
                ######## blockchain ########### tmp commented due to lack of manpower to mantain it
                # try:
                #     for converted_dict in output["Output"]:
                #         # Computation of metadata_hash for the get_from_blockchain method  
                #         metahash_dict = {keys: values for keys, values in converted_dict.items()}

                #         metadata_hash = adbc__generate_record_key_from_field(str(metahash_dict))
                #         print(self.get_from_blockchain(data_hash=hash_data, metadata_hash=metadata_hash))

                #         if self.get_from_blockchain(data_hash=hash_data, metadata_hash=metadata_hash) == "The metadata hash is not the same":
                #             raise Exception("The hashes are different from the ones in the blockchain!")
                    # Return the validated metadata record
                return output
                # except Exception as e:
                #     # TO-DO: implement the raise error when in production/on ICSC resources
                #     # Exception management to avoid internal errors due to possible blockchain server errors
                #     print(f'Error contacting blockchain. ERROR: {str(e)}')
                #     raise #exception.DatabaseException("Failed to contact the blockchain")
                ###########################
        if clean_name != "START" and clean_name != "END":
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            file_path = os.path.join(dir_path, dir_name)
            with open(file_path, 'a') as f:
                f.write(f"{scope}:{clean_name}\n")
            print(f"DID '{scope}:{clean_name}' written in '{file_path}'!")
            return {"Middle": "Success"}

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

        if scope in ["fermi", "birales", "pulsar"]:
            self.ayradb_servers = [ {
                    "ip": config.get('server3', 'ip'),
                    "port": int(config.get('server3', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
                    "name": config.get('server3', 'name')
                }
            ]
        if scope == "fermi":
            self.table_name = "metadataFermi"
        if scope == "birales":
            self.table_name = "metadataBirales"
        if scope == "pulsar":
            self.table_name = "metadataPulsar"

        # Delete record from the SQL table
        res, error = adbc_1liner__delete_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key)

        # Check result of deleting the record
        if res == False:
            print(f'ERROR: deleting the record: {error}' )
        elif res == True:
            print('Successfully deleted record')

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

            if scope in ["fermi", "birales", "pulsar"]:
                self.ayradb_servers = [ {
                        "ip": config.get('server3', 'ip'),
                        "port": int(config.get('server3', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
                        "name": config.get('server3', 'name')
                    }
                ]
            if scope == "fermi":
                self.table_name = "metadataFermi"
            if scope == "birales":
                self.table_name = "metadataBirales"
            if scope == "pulsar":
                self.table_name = "metadataPulsar"

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
                query = f"SELECT {select} FROM ayradb.{self.table_name} WHERE {where_clause};"
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
                            time.sleep(10)
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
    async def manage_request(self, callType, functionName, args): #async
        params = {
            "channelid": "mychannel",
            "chaincodeid": "basic",
            "function": functionName,
            "args": args,
        }
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.blockchainUrl}/{callType}", headers=self.headers, params=params
                ) as res:
                    if res.status == 200:
                        text = await res.text()
                        return {"message": text, "status": 200}
                    return {"message": "Error", "status": res.status}
            except aiohttp.ClientConnectionError:
                return {"message": "Error contacting the server", "status": 503}
        # try:
        #     res = requests.get(
        #         f"{self.blockchainUrl}/{callType}", headers=self.headers, params=params
        #     )

        #     if res.status_code == 200:
        #         return {
        #             "message": res.text,
        #             "status": 200,
        #         }
        #     return {
        #         "message": "Error",
        #         "status": res.status_code,
        #     }
        # except requests.exceptions.ConnectionError:
        #     return {
        #         "message": "Error contacting the server",
        #         "status": 503,
        #     }

    async def set_blockchain(self, value: str):
        dict_value = json.loads(value)
        data_hash = dict_value["sha256"]
        fields = {k: v for k, v in dict_value.items() if k != 'sha256'}
        metadata_hash = adbc__generate_record_key_from_field(str(fields))
        DID = dict_value["LINK"]
        args_createDataset = [data_hash, metadata_hash, DID]

        return await self.manage_request("invoke", "CreateDataset", args_createDataset)

    async def _run_blockchain_tasks(self, results):
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.set_blockchain(value)
                for value in results
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for idx, res in enumerate(responses):
                if isinstance(res, Exception):
                    # Log, retry, or handle the exception
                    print(f"[Error] Blockchain task {idx} failed: {repr(res)}")
                else:
                    # Optionally log success
                    print(f"[OK] Blockchain task {idx} completed: {res}")

    # def set_blockchain(self, value: str):
    #     dict = json.loads(value)
    #     data_hash = dict["sha256"]

    #     self.fields = {keys: values for keys, values in dict.items() if keys != 'sha256'}

    #     metadata_hash = adbc__generate_record_key_from_field(str(self.fields))
    #     # LINK ex DID
    #     DID = dict["LINK"]

    #     args_createDataset = [
    #         data_hash,
    #         metadata_hash,
    #         DID
    #     ]
    #     response = self.manage_request(
    #         callType="invoke",
    #         functionName="CreateDataset",
    #         args=args_createDataset,
    #     #    headers=self.headers,
    #     )
    #     return response

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