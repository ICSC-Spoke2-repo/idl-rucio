#!/usr/bin/env python3

import sys
sys.path.append("/usr/local/lib/python3.9/site-packages/")

################# WARNING ##################
# FOR NOW I'M DISABLING THE HTTPS CONNCECTION WARNING, BUT THIS CAN HIDE SOME REAL HTTPS ISSUES!!!
import urllib3
import warnings

# Suppress only the InsecureRequestWarning from urllib3
warnings.filterwarnings('ignore', message='Unverified HTTPS request', category=urllib3.exceptions.InsecureRequestWarning)
############################################

#import requests
#import certifi
import argparse
import configparser
import json
import ast
import re
import os
import numpy as np

# Include to compute the sha-256 checksum of the data file
import hashlib

### Set Rucio virtual environment configuration ###
#os.environ['RUCIO_HOME']=os.path.expanduser('~/Rucio-v2/rucio')
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.uploadclient import UploadClient
from rucio.client.downloadclient import DownloadClient
#import rucio.rse.rsemanager as rsemgr
from rucio.client.ruleclient import RuleClient
from rucio.common import exception #import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    #AccessDenied, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    #InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    #ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)

#from rucio.common.utils import adler32, detect_client_location, execute, generate_uuid, md5, send_trace, GLOBALLY_SUPPORTED_CHECKSUMS

def compute_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

class IDL():
    def __init__(self):
        #self.scope = scope
        #self.rse = rse
        #self.working_folder = working_folder

        self.didc = DIDClient()
        self.uplc = UploadClient()
        self.dwnc = DownloadClient()
        #self.rulesClient = RuleClient()
        
        # Read account from the rucio.cfg in /opt/conda/etc/rucio.cfg. Edit it if your rucio config file is somewhere else
        config = configparser.ConfigParser()
        config.read('/opt/conda/etc/rucio.cfg')
        account = config.get('client', 'account')
        
        # Configuration
        self.account = account

        # account=account
        self.client = Client(account=account)

    def customUpload(self, scope, file, meta, rse):
        '''
        Custom upload: upload file + set-metadata from .json file

        :param file: file path of the data file
        :param meta: file path of the .json metadata file
        '''
        did_name = file.split('/')[-1] # Use the file name as the DID name
        did_scope = scope
        try:
            # Upload the file
            self.uplc.upload([{
                'path': file,
                'rse': rse,
                'did_scope': did_scope,
                'did_name': did_name,  
            }])

            # Parse the JSON file in a Python dict and add the "DID" and "sha-256" metadata
            with open(meta, 'r') as m:
                json_dict = json.load(m)
                json_dict['LINK'] = f'{did_scope}:{did_name}'
                json_dict['sha256'] = compute_sha256(file)
                json_string = json.dumps(json_dict)

            # Set the metadata for the uploaded file
            self.didc.set_metadata(scope=did_scope, name=did_name, key='JSON', value=json_string)
            
            #did_name = file.split('/')[-1]
            #for key, value in json_dict.items():
            #    did_name = file.split('/')[-1]
            #    self.didc.set_metadata(scope=scope, name=did_name, key=key, value=value)

        except Exception as e:
            print(f"Error: {e}")
    
    def customSetMeta(self, scope, file, meta):
        '''
        Custom set-metadata: set-metadata from .json file if you need to edit the metadata of a DID

        :param file: file path of the data file
        :param meta: file path of the .json metadata file
        '''
        did_name = file.split('/')[-1] # Use the file name as the DID name
        did_scope = scope
        try:
            # Parse the JSON file in a Python dict and add the "DID" and "sha-256" metadata
            with open(meta, 'r') as m:
                json_dict = json.load(m)
                json_dict['LINK'] = f'{did_scope}:{did_name}'
                json_dict['sha256'] = compute_sha256(file)
                json_string = json.dumps(json_dict)

            # Set the metadata for the file data
            self.didc.set_metadata(scope=did_scope, name=did_name, key='JSON', value=json_string)

        except Exception as e:
            print(f"Error: {e}")
    
    def customGetMeta(self, scope, file):
        '''
        Custom get-metadata: get-metadata of the specific DID for the custom plugin "IDL"

        :param file: file path of the data file
        :param meta: file path of the .json metadata file
        '''
        did_name = file.split('/')[-1] # Use the file name as the DID name
        did_scope = scope
        # Download of the file in /tmp/ without a subdir
        tmp_file = self.dwnc.download_dids(items=[{'did': f'{did_scope}:{did_name}', 'base_dir': '/tmp/', 'no_subdir': True}])
        hash_data = compute_sha256(tmp_file[0]['temp_file_path'][:-5])
        did_name = hash_data + ':' + did_name
        # After it is being used it is removed from /tmp/. You MUST have your donwloaded files in another directory!
        if os.path.exists(tmp_file[0]['temp_file_path'][:-5]):
            os.remove(tmp_file[0]['temp_file_path'][:-5])
        try:
            # Get the metadata for the specific DID
            dict = self.didc.get_metadata(scope=did_scope, name=did_name, plugin="IDL")
            # Print the resulting dict in the same format as the rucio get-metadata
            max_key_length = max(len(key) for key in dict.keys())
            for keys, values in dict.items():
                #if keys != 'LINK':
                    # Left-align the keys by as many characters as the longest key + 1
                print(f"{keys}:".ljust(max_key_length + 1) + f"  {values}")
                #else:
                    # Strip the "\n" at the end of LINK
                #    formatted_link = values[:-2]
                #    print(f"{keys}:".ljust(max_key_length + 1) + f"  {formatted_link}")
        except Exception as e:
            print(f"Error: {e}")
    
    def customListDids(self, scope, filters):
        #did_name = file.split('/')[-1] # Use the file name as the DID name
        did_scope = scope
        # Function to map operators to corresponding SQL-friendly keys
        def get_operator_key(field, operator):
            if operator != '=':
                operator_map = {
                    '>=': 'gte',
                    '<=': 'lte',
                    '>': 'gt',
                    '<': 'lt',
                    '!=': 'ne',
                }
                return f"{field}.{operator_map[operator]}"
            else:
                return f"{field}"

        # Function to parse filters
        def parse_filters(input_str):
            # Split by OR (to create separate dicts for OR conditions)
            or_conditions = input_str.split('OR')
            filters = []

            for or_cond in or_conditions:
                and_conditions = or_cond.split('AND')
                and_dict = {}
        
                for cond in and_conditions:
                    # Regex to capture key, operator, and value
                    match = re.match(r'(\w+)\s*(>=|<=|!=|>|<|=)\s*([^\s]+)', cond.strip())
            
                    if match:
                        field, operator, value = match.groups()
                        operator_key = get_operator_key(field, operator)
                        and_dict[operator_key] = value.strip()
        
                filters.append(and_dict)

            return filters
        try:
            filters = parse_filters(filters)
            for fil in filters:
                for key, value in fil.items():
                    if key.startswith("EPOCH") or key.startswith("CREATION_DATE"):
                        value = np.datetime64(f'{value}')
            i = 1
            res = list(self.didc.list_dids(scope=did_scope, filters=filters, did_type='all', long=False, recursive=False))
            max_list_len = len(str(abs(len(res))))
            for d in res:
                for result in list(d.values()):
                    result = result[:-1]
                    print(f"{i}:".ljust(max_list_len + 1) + f"  {result}")
                    i = i + 1
        except Exception as e:
            print(f"Error: {e}")
            

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="IDL client: upload (+ set-metadata), set-metadata, get-metadata with custom plugin") # This is the description of the binary if you read the help message {-h, --help}
    parser.add_argument('--method', choices=['upload', 'set', 'get', 'list'], help='Method to call', required = True)
    #parser.add_argument('--account', type=str, help='Account name')
    parser.add_argument('--scope', type=str, help='Scope')
    parser.add_argument('--rse', type=str, help='RSE expression')
    parser.add_argument('--file', type=str, help='File path of the data file')
    parser.add_argument('--meta', type=str, help='File path of the metadata .json file')
    parser.add_argument('--filters', type=str, help='Filters for the list-dids')

    # Parse arguments
    args = parser.parse_args()

    # Create an instance of IDL
    myClass = IDL()

    # Call the chosen method
    if args.method == 'upload':
        myClass.customUpload(args.scope, args.file, args.meta, args.rse)
    #elif args.method == 'set':
    #    myClass.customSetMeta(args.scope, args.file, args.meta)
    elif args.method == 'get':
        myClass.customGetMeta(args.scope, args.file)
    elif args.method == 'list':
        myClass.customListDids(args.scope, args.filters) #ast.literal_eval(args.filters))


if __name__ == "__main__":
    # Make a request to the service behind the Ingress
    #response = requests.get('https://rucio-server.131.154.98.24.myip.cloud.infn.it:443', verify=certifi.where()) #verify='/etc/pki/tls/certs/ca-bundle.crt'       
    
    main()
