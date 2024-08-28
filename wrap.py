import sys
sys.path.append("/usr/local/lib/python3.9/site-packages/")

import requests
import certifi
import argparse
import json

### Set Rucio virtual environment configuration ###
#os.environ['RUCIO_HOME']=os.path.expanduser('~/Rucio-v2/rucio')
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.uploadclient import UploadClient
from rucio.client.replicaclient import ReplicaClient
#import rucio.rse.rsemanager as rsemgr
from rucio.client.ruleclient import RuleClient
from rucio.common import exception #import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    #AccessDenied, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    #InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    #ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)

#from rucio.common.utils import adler32, detect_client_location, execute, generate_uuid, md5, send_trace, GLOBALLY_SUPPORTED_CHECKSUMS

class Rucio4Leo():
    def __init__(self, account):
        #self.scope = scope
        #self.rse = rse
        #self.working_folder = working_folder

        self.didc = DIDClient()
        self.uplc = UploadClient()
        self.repc = ReplicaClient()
        self.rulesClient = RuleClient()
        
        # Configuration
        self.account = account

        # account=account
        self.client = Client(account=self.account)

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

            # Parse the JSON file in a Python dict
            with open(meta, 'r') as m:
                json_dict = json.load(m)
                json_dict['DID'] = f'{did_scope}:{did_name}'
                json_string = json.dumps(json_dict)

            # Set the metadata for the uploaded file
            self.didc.set_metadata(scope=did_scope, name=did_name, key='JSON', value=json_string)
            
            #did_name = file.split('/')[-1]
            #for key, value in json_dict.items():
            #    did_name = file.split('/')[-1]
            #    self.didc.set_metadata(scope=scope, name=did_name, key=key, value=value)

        except Exception as e:
            print(f"Error: {e}")

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Choose a method to call.") # This is the description of the binary if you read the help message {-h, --help}
    parser.add_argument('--method', choices=['upload', 'download'], help='Method to call', required = True)
    parser.add_argument('--account', type=str, help='Account name')
    parser.add_argument('--scope', type=str, help='Scope')
    parser.add_argument('--rse', type=str, help='RSE expression')
    parser.add_argument('--file', type=str, help='File path of the data file')
    parser.add_argument('--meta', type=str, help='File path of the metadata .json file')

    # Parse arguments
    args = parser.parse_args()

    # Create an instance of MyClass
    myClass = Rucio4Leo(args.account)

    # Call the chosen method
    if args.method == 'upload':
        myClass.customUpload(args.scope, args.file, args.meta, args.rse)
    elif args.method == 'download':
        myClass.customDownload(args.message)

if __name__ == "__main__":
    # Make a request to the service behind the Ingress
    response = requests.get('https://rucio-server.131.154.98.24.myip.cloud.infn.it:443', verify=certifi.where()) #verify='/etc/pki/tls/certs/ca-bundle.crt'       
    
    main()
