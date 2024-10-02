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

# Includes for AyraDB connection
import random
import string
import sys
import time 

from adbc.core.adbc import adbc_1liner__write_record__wrapper
from adbc.core.adbc import adbc_1liner__delete_record__wrapper
from adbc.core.adbc import adbc_1liner__sql__wrapper
from adbc.core.adbc import adbc_1liner__dump_table_to_warehouse__wrapper
from adbc.core.adbc import adbc_1liner__dump_table_ild_metadata_to_warehouse
from adbc.core.adbc import adbc__generate_record_key_from_field

from datetime import datetime

# Old includes for postgres did-meta plugin
import json
import operator
from typing import TYPE_CHECKING

import psycopg2
import psycopg2.extras

from rucio.common import config, exception
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from sqlalchemy.sql.expression import true

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
        self.plugin_name = "RUCIO4LEO"

        # AyraDB cluster INAF coordinates 
        #ayradb_servers = [ {'ip': '95.217.130.33', 'port': 10021, 'name': 'ovqy400c' },
        #                    {'ip': '37.27.21.168', 'port': 10021, 'name': 'wv98hjxd'} ]
        
        # AyraDB cluster INFN coordinates
        self.ayradb_servers = [ {'ip': '65.109.166.225', 'port': 10021, 'name': 'bssm4u5y' }, 
                               {'ip': '95.216.170.67', 'port': 10021, 'name': 'g5joxu2z'} ] 

        # INFN cluster credentials
        self.credentials = {'username': 'infn1', 'password': 'Gelat0AlTamar1nd0'}

        self.table_name = 'metadata'

        # Fixed fields ONLY for testing!
        self.fields = {
            "IDL_L4_VERS": "0.1",
            "LINK": ""
        }

        # Field labels for the table dump in the internal warehouse of AyraDB (you can omit the fixed value labels)
        self.field_labels_string = 'IDL_L4_VERS,LINK'

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
                    try:
                        # Adjust the format string as needed for your datetime format
                       return datetime.strptime(decoded_string, '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        return decoded_string  # Return as string if it can't be parsed as datetime
            
                except UnicodeDecodeError:
                    return str(data)  # Return as a string representation if decoding fails
            else:
                return data  # Return as is if it's not a bytearray, list, or dict 

    def set_metadata(self, scope: "InternalScope", name: str, key: str, value: str, 
                     recursive: bool = False, *, session: "Optional[Session]" = None) -> None:
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
                dict["DID"] = f"{scope}:{name}"
                self.fields["LINK"] = dict["DID"]

                # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
                key = adbc__generate_record_key_from_field(self.fields['LINK'])
                print(key)

                # Write the record
                res, error = adbc_1liner__write_record__wrapper(self.ayradb_servers, 
                                                                self.credentials, self.table_name, 
                                                                    key, self.fields)
                
                # Dump table to internal warehouse
                res_dump_table, error_dump = adbc_1liner__dump_table_to_warehouse__wrapper(self.ayradb_servers, 
                                                                                           self.credentials, self.table_name, 
                                                                                           self.field_labels_string)
                
                # Check result of dumping table
                if res_dump_table == False:
                    print(f'ERROR: dumping table: {error_dump}')
                elif res_dump_table == True:
                    print('Successfully dumped the table!')

                # Check result of writing record
                if res == False:
                    print(f'ERROR: writing a record: {error}')
                elif res == True:
                    print('Successfully wrote the metadata!')
                
            except Exception as e:
                print(f"Error reading JSON file: {e}")
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
        # Constant SQL query to retrieve the metadata of a DID
        const_sql_query = "SELECT * FROM ayradb.metadata WHERE LINK = '{}:{}';".format(scope.internal, name)
        
        # Debug
        print(const_sql_query)

        res, error, records = adbc_1liner__sql__wrapper(
            self.ayradb_servers, self.credentials, 
            const_sql_query, warehouse_query=True
        )          

        # Debug
        print(records)
        print(type(records))
        print(records[0])
        print(type(records[0]))

        # Convert the Python dict from bytearrays to strings
        converted_dict = self.convert_bytearrays(records[0])

        # Check result of getting the metadata for a DID
        if res == False:
            print(f'ERROR: retrieving the metadata: {error}')
        elif res == True:
            return converted_dict

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
        
        # Debug
        print(key)

        res, error = adbc_1liner__delete_record__wrapper(self.ayradb_servers, self.credentials, self.table_name, key)

        # Check result of deleting the record
        if res == False:
            print(f'ERROR: deleting the record: {error}' )
        elif res == True:
            print('Successfully deleted record')

    def list_dids(self, scope, filters, did_type='all', ignore_case=False, limit=None, 
                  offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Optional[Session]" = None):

        # Backwards compatibility for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # Debug
        print(filters)
        print(type(filters))

        try:
            # instantiate fe and create SQL query
            fe = FilterEngine(filters, model_class=None, strict_coerce=False)
            # This query DOESN'T work...
            query_str = fe.create_sqla_query(
                additional_filters=[('scope', operator.eq, scope.internal), ('vo', operator.eq, scope.vo)]
            )
        except Exception as e:
            raise exception.DataIdentifierNotFound(e)
        
        # Probably we should return the list of dids that satisfy the filters...
        sql_query = "SELECT * FROM ayradb.metadata WHERE {} ".format(query_str)
        
        res, error, records = adbc_1liner__sql__wrapper(
            self.ayradb_servers, self.credentials, 
            sql_query, warehouse_query=True
        )           

        # Convert the records
        res_list = []
        i = 0
        for elem in records:
            converted_dict = self.convert_bytearrays(elem)
            res_list[i] = converted_dict
            i = i + 1

        # Check if getting the list of dids was successful
        if res == False:
            print(f'ERROR: error getting list of dids: {error}')
        elif res == True:
            return res_list

    def manages_key(self, key, *, session: "Optional[Session]" = None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this
        plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name