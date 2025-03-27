#!/usr/bin/env python3
 
from adbc.core.adbc import adbc__generate_record_key_from_field
from adbc.core.adbc import adbc_1liner__delete_record__wrapper
import os
import sys
import json
import time
import shutil
import argparse
import configparser

config = configparser.ConfigParser()
config.read('/tmp/metaDB_credentials_template.cfg')

# AyraDB cluster INFN coordinates
servers = [ {
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
credentials = { "username": config.get('credentials', 'username'), "password": config.get('credentials', 'password')}

table_name = 'metadata'
field_labels = ['*']

#Fallback methods
def customErase(scope, name):
    from rucio.client import Client
    import os
    os.environ['RUCIO_CONFIG'] = '/tmp/rucio_credentials.cfg'
    config2 = configparser.ConfigParser()
    config2.read('/tmp/rucio_credentials_template.cfg')
    username = config2.get('client', 'username')
    password = config2.get('client', 'password')
    account = config2.get('client', 'account')
    client = Client(
                rucio_host = "http://server-rucio-server",
                auth_host = "http://server-rucio-server",
                auth_type = "userpass",
                creds = {
                    "username": username,
                    "password": password,
                },
                account = account
            )
    try:
        # Set lifetime to expire in 5 seconds (value is in seconds).
        client.set_metadata(scope=scope, name=name, key='lifetime', value=5)
        print("Successfully erased the DID")
    except:
        os.environ['RUCIO_CONFIG'] = '/opt/rucio/etc/rucio.cfg'
        raise Exception(f"Failed to erase DID: {scope}:{name}")
    
    os.environ['RUCIO_CONFIG'] = '/opt/rucio/etc/rucio.cfg'            
    return 0

def customDeleteMetadata(scope, name):
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
    res, error = adbc_1liner__delete_record__wrapper(servers, credentials, table_name, key)

    # Check result of deleting the record
    if res == False:
        print(f'ERROR: deleting the record: {error}' )
    elif res == True:
        print('Successfully deleted record')
    
    return res, error

def multi_pipelined_set_metadata(args): # --dir
    from adbc.core.adbc_pipelined import multi_pipelined_write__wrapper
    
    values = []
    records = []
    keys = []
    
    for filename in os.listdir(args.dir):
        file_path = os.path.join(args.dir, filename)
        if os.path.isfile(file_path) and filename.endswith('.json'):
            # Open and read the file
            with open(file_path, 'r') as file:
                # Parse the JSON content into a Python dictionary
                try:
                    content = file.read()
                    values.append(content)
                    dict = json.loads(content)
                    fields = {keysss: valuesss for keysss, valuesss in dict.items() if keysss != 'sha256'}
                    records.append(fields)
                    # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
                    try:
                        key = adbc__generate_record_key_from_field(fields['LINK'])
                        keys.append(key)
                    except Exception as e:
                        print(f'Failed to generate key for AyraDB: {str(e)}')
                except Exception:
                    print(f"Error decoding JSON from file: {filename}. FALLBACK: Uploaded files have been erased!")
    # Management of retries
    max_attempts = 10 # set the maximum number of attempts, or 0 for unlimited attempts
    n_attempts = 0
    keep_trying = True
    while keep_trying:
        try:
            res, error = multi_pipelined_write__wrapper(table_name, servers, keys, records, credentials=credentials)
            if res == False:
                n_attempts += 1
                if max_attempts > 0 and n_attempts > max_attempts:
                    keep_trying = False
                    raise Exception(f"Failed to write the metadata records: {error}. FALLBACK: Uploaded files have been erased!")
                else:
                    time.sleep(2)
            else:
                keep_trying = False
                # Delete the tmp directory
                shutil.rmtree(args.dir)
                print(values)
        except Exception as e:
            print(f'Error writing metadata records: {str(e)}. FALLBACK!')  # Display in the server logs the raised error message
            # Fallback logic
            for record in records:
                did_scope = record["LINK"].split(":")[0]
                did_name = record["LINK"].split(":")[1]
                customErase(scope=did_scope, name=did_name)
                customDeleteMetadata(scope=did_scope, name=did_name)
            shutil.rmtree(args.dir)
            raise  # Re-raise the original exception

def multi_pipelined_get_metadata(args): # --dir
    from adbc.core.adbc_pipelined import multi_pipelined_read__wrapper

    keys = []

    for filename in os.listdir(args.dir):
        file_path = os.path.join(args.dir, filename)
        if os.path.isfile(file_path):
            # Open and read the file
            with open(file_path, 'r', encoding="utf-8") as f:
                try:
                    for line in f:
                        did = line.strip()
                        key = adbc__generate_record_key_from_field(did)
                        keys.append(key)
                except Exception as e:
                    print(f"ERROR during read of file with DIDs: {e}")
    # Management of retries
    max_attempts = 3 # set the maximum number of attempts, or 0 for unlimited attempts
    n_attempts = 0
    keep_trying = True
    while keep_trying:
        try:
            res, error, records = multi_pipelined_read__wrapper(table_name, field_labels, servers, keys,credentials=credentials)
            if res == False:
                n_attempts += 1
                if max_attempts > 0 and n_attempts > max_attempts:
                    keep_trying = False
                    raise Exception(f"Failed get-metadata: {error}.")
                else:
                    time.sleep(2)
            else:
                keep_trying = False
                # Delete the tmp directory
                shutil.rmtree(args.dir)
                output = []
                for record in records:
                    if "result" not in record:
                        output.append(record)
                true_output = []
                i = 0
                for r in output:
                    if i < len(output)/2:
                        true_output.append(r)
                        i += 1
                    elif i > len(output)/2:
                        break
                print(true_output)
        except Exception as e:
            print(f'Error getting metadata records: {e}.')  # Display in the server logs the raised error message
            shutil.rmtree(args.dir)
            raise  # Re-raise the original exception

def get_parser():
    """
    Returns the argparse parser.
    """
    oparser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]), add_help=True)
    subparsers = oparser.add_subparsers(dest="command")

    # Main arguments
    # oparser.add_argument('--version', action='version', version='%(prog)s ' + version.version_string())

    # Subparser multi set
    pars_upload = subparsers.add_parser("set", help="Set-metadata of one or multiple files in a multi pipelined fashion.")
    pars_upload.set_defaults(function=multi_pipelined_set_metadata)
    # Upload's args and flags
    pars_upload.add_argument("--dir", type=str, required=True, help="Path to the directory in which the metadata to set are stored")

    # Subparser multi get
    pars_upload = subparsers.add_parser("get", help="Set-metadata of one or multiple files in a multi pipelined fashion.")
    pars_upload.set_defaults(function=multi_pipelined_get_metadata)
    # Upload's args and flags
    pars_upload.add_argument("--dir", type=str, required=True, help="Path to the directory in which the DIDs of the metadata to get are stored")

    return oparser


if __name__ == "__main__":
    oparser = get_parser()
    arguments = sys.argv[1:]
    args = oparser.parse_args(arguments)
    result = args.function(args)
    # sys.exit(result)