#!/usr/bin/env python3

from rucio.client import Client
#from rucio.client.replicaclient import ReplicaClient
from adbc.core.adbc import adbc_1liner__sql__wrapper, adbc__generate_record_key_from_field, adbc_1liner__delete_record__wrapper
import os
import configparser
import psycopg2

config_db = configparser.ConfigParser()
config_db.read('/tmp/rucio_db_creds.cfg') # /etc/config/ after secret mount
DB_HOST = "rucio-db-postgresql.rucio-idl.svc.cluster.local"
DB_PORT = 5432
DB_NAME = config_db.get('database', 'db_name')
DB_USER = config_db.get('database', 'db_user')
DB_PASSWORD = config_db.get('database', 'db_password')

# Method to convert results of the DB queries into strings
def convert_bytearrays(data):
    if isinstance(data, dict):
        # Recursively process each key-value pair in the dictionary
        return {keys: convert_bytearrays(values) for keys, values in data.items()}
    elif isinstance(data, list):
        # Recursively process each element in the list
        return [convert_bytearrays(item) for item in data]
    elif isinstance(data, bytearray):
        try:
            # Attempt to decode the bytearray to a string
            decoded_string = data.decode('utf-8')  # Change 'utf-8' if needed
            return decoded_string  # Return as string if it can't be parsed as datetime
        
        except UnicodeDecodeError:
            return str(data)  # Return as a string representation if decoding fails
    else:
        return data  # Return as is if it's not a bytearray, list, or dict 

try:
    # Connect to PostgreSQL
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    cursor = conn.cursor()

    # Query the table and fetch three specific columns
    query = "SELECT scope, name, availability FROM test.dids WHERE did_type='F';"
    cursor.execute(query)

    # Fetch all results and store them in a list
    results = cursor.fetchall()  # List of tuples

    dids = set()
    map_state = {}
    for scope, name, state in results:
        did = f"{scope}:{name}"
        dids.add(did) 
        map_state[did] = state

    # dids = set(f"{scope}:{name}" for scope, name, _ in results)
    # map_state = {{f"{scope}:{name}": state for scope, name, state in results}}

    # Print the extracted columns
    print("Column DID:", dids)
    print("Map state:", map_state)

    # Cleanup
    cursor.close()
    conn.close()

except Exception as e:
    print("Error:", e)

config = configparser.ConfigParser()
config.read('/etc/config/AyraDB_cluster_credentials.cfg')

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

inaf_server = [ {
        "ip": config.get('server3', 'ip'),
        "port": int(config.get('server3', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
        "name": config.get('server3', 'name')
    }
]

# INFN cluster credentials
credentials = { "username": config.get('credentials', 'username'), "password": config.get('credentials', 'password')}

table_name = 'metadata'

try:
    query = f"SELECT LINK FROM ayradb.metadata;"
    res, error, records = adbc_1liner__sql__wrapper(servers, credentials, query, warehouse_query=True)
    if res == False:
        print(f"{error}")
    results = set()
    for dicts in records:
        converted_dict = convert_bytearrays(dicts)
        value = set(converted_dict.values())
        results.update(value)
except Exception as e:
    print("Error:", e)

for table_name in ["metadataFermi", "metadataBirales", "metadataPulsar"]:
    try:
        queries = f"SELECT LINK FROM ayradb.{table_name};"
        res, error, records = adbc_1liner__sql__wrapper(inaf_server, credentials, queries, warehouse_query=True)
        if res == False:
            print(f"{error}")
        results = set()
        for dicts in records:
            converted_dict = convert_bytearrays(dicts)
            value = set(converted_dict.values())
            results.update(value)
    except Exception as e:
        print("Error:", e)

print("#########################################################")
print(len(dids & results))
print(len(dids - results))
print(len(results - dids))

intersection = dids & results
delete_meta = {did for did in intersection if map_state[did] not in ['A', 'C', 'T']}
print(delete_meta)
for did in delete_meta:
    scope = did.split(':')[0]
    name = did.split(':')[1]
    # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
    key = adbc__generate_record_key_from_field(f"{scope}:{name}")
    if scope in ["fermi", "birales", "pulsar"]:
        servers = inaf_server
        table_name = f"metadata{scope}"
    # Delete record from the SQL table
    res, error = adbc_1liner__delete_record__wrapper(servers, credentials, table_name, key)
    # Check result of deleting the record
    if res == False:
        print(f'ERROR: deleting the record for {scope}:{name}: {error}' )

hanging_meta = results - dids
print(hanging_meta)
for did in hanging_meta:
    scope = did.split(':')[0]
    name = did.split(':')[1]
    # Key generated from a field which is unique for each record, the Rucio Data IDentifier (DID) in our case
    key = adbc__generate_record_key_from_field(f"{scope}:{name}")
    if scope in ["fermi", "birales", "pulsar"]:
        servers = inaf_server
        table_name = f"metadata{scope}"
    # Delete record from the SQL table
    res, error = adbc_1liner__delete_record__wrapper(servers, credentials, table_name, key)
    # Check result of deleting the record
    if res == False:
        print(f'ERROR: deleting the record for {scope}:{name}: {error}' )

os.environ['RUCIO_CONFIG'] = '/tmp/rucio_credentials.cfg' # /etc/config/ after secret mount
config_rucio = configparser.ConfigParser()
config_rucio.read('/tmp/rucio_credentials.cfg') # /etc/config/ after secret mount
username = config_rucio.get('client', 'username')
password = config_rucio.get('client', 'password')
account = config_rucio.get('client', 'account')

client = Client(
            rucio_host = "https://rucio-server.212.189.145.181.myip.cloud.infn.it:443",
            auth_host = "https://rucio-server.212.189.145.181.myip.cloud.infn.it:443",
            auth_type = "userpass",
            creds = {
                "username": username,
                "password": password,
            },
            account = account
        )

difference = dids - results
bad_replicas = {did for did in difference if map_state[did] in ['A', 'C', 'T']}
print(bad_replicas)
for did in bad_replicas:
    scope = did.split(':')[0]
    name = did.split(':')[1]
    #rpcl = ReplicaClient(Client)
    rse_list = [list(replica['states'].keys()) for replica in client.list_replicas(dids=[{'scope': scope, 'name': name}])]
    replica_state = [list(replica['states'].values()) for replica in client.list_replicas(dids=[{'scope': scope, 'name': name}])]
    if replica_state[0] != "AVAILABLE":
        continue
    for rse in rse_list[0]:
        # This works only on the state of the RSE! I need to find a way to update the "availability" on the internal metadata table...
        client.declare_bad_file_replicas(replicas=[{'scope': scope, 'name': name, 'rse': rse}], reason="File in storage with no metadata in external DB")
        #client.update_replicas_states(rse, files=[{'scope': scope, 'name': name, 'state': 'D'}])
        #client.set_metadata(scope=scope, name=name, key='availability', value='D')