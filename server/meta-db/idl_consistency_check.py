#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import psycopg2
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from rucio.client import Client
from adbc.core.adbc import (
    adbc_1liner__sql__wrapper,
    adbc__generate_record_key_from_field,
    adbc_1liner__delete_record__wrapper,
)

# --- Logger Setup ---
LOG_FORMAT = "[%(levelname)s] %(asctime)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger()

# --- Helpers ---

def convert_bytearrays(data):
    if isinstance(data, dict):
        return {k: convert_bytearrays(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_bytearrays(i) for i in data]
    elif isinstance(data, bytearray):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return str(data)
    else:
        return data

def parse_args():
    parser = argparse.ArgumentParser(description="Consistency check between Rucio DB and AyraDB")
    parser.add_argument(
        "--delete", action="store_true", help="Enable deletion of invalid records in AyraDB"
    )
    parser.add_argument(
        "--declare-bad", action="store_true", help="Enable declaring bad replicas on Rucio"
    )
    parser.add_argument(
        "--threads", type=int, default=4, help="Number of threads to use for pagination queries (default: 4)"
    )
    return parser.parse_args()

# --- Database & AyraDB queries with pagination ---

def fetch_all_dids_postgres(db_config, batch_size=1000000):
    """
    Fetch all DIDs from PostgreSQL in batches using id pagination.
    """
    logger.info("Fetching all DIDs from PostgreSQL with batch size %d", batch_size)
    dids = set()
    map_state = {}
    try:
        conn = psycopg2.connect(
            dbname=db_config["db_name"],
            user=db_config["db_user"],
            password=db_config["db_password"],
            host=db_config["db_host"],
            port=db_config["db_port"],
        )
        cursor = conn.cursor()
        last_created_at = None

        while True:
            if last_created_at:
                query = """
                SELECT scope, name, availability, created_at
                FROM test.dids
                WHERE did_type = 'F' AND created_at > %s
                ORDER BY created_at
                LIMIT %s;
                """
                cursor.execute(query, (last_created_at, batch_size))
            else:
                query = """
                SELECT scope, name, availability, created_at
                FROM test.dids
                WHERE did_type = 'F'
                ORDER BY created_at
                LIMIT %s;
                """
                cursor.execute(query, (batch_size,))
            
            rows = cursor.fetchall()
            if not rows:
                break

            for row in rows:
                scope, name, state, _ = row
                did = f"{scope}:{name}"
                dids.add(did)
                map_state[did] = state
            
            last_created_at = rows[-1][3]  # Update cursor
            logger.debug(f"Fetched batch up to DID created at: {last_created_at}")
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error("Error fetching DIDs from PostgreSQL: %s", e)
    logger.info("Fetched %d DIDs from PostgreSQL", len(dids))
    return dids, map_state

def fetch_links_paginated(server_list, credentials, table_name, batch_size=50000000000, threads=4):
    """
    Fetch all LINK records from AyraDB using pagination by ID with multithreading.
    """
    logger.info(f"Fetching LINK records from '{table_name}' with batch size {batch_size} and {threads} threads")
    results = set()
    queue = Queue()

    # Worker to fetch page
    def worker():
        while True:
            batch = queue.get()
            if batch is None:
                break
            start_id, end_id = batch
            query = (
                f"SELECT LINK FROM ayradb.{table_name} WHERE id >= {start_id} AND id < {end_id};"
            )
            try:
                res, error, records = adbc_1liner__sql__wrapper(server_list, credentials, query, warehouse_query=True)
                if not res:
                    logger.error(f"Error in query {query}: {error}")
                else:
                    for record in records:
                        converted = convert_bytearrays(record)
                        values = set(converted.values())
                        results.update(values)
            except Exception as e:
                logger.error(f"Exception during query {query}: {e}")
            queue.task_done()

    # First get max id to split ranges
    try:
        query_max = f"SELECT MAX(id) as max_id FROM ayradb.{table_name};"
        res, error, records = adbc_1liner__sql__wrapper(server_list, credentials, query_max, warehouse_query=True)
        if not res:
            logger.error(f"Error fetching max id from '{table_name}': {error}")
            return results
        records = convert_bytearrays(records)
        max_id = list(records[0].values())[0]
        logger.info(f"Max id in '{table_name}' is {max_id}")
    except Exception as e:
        logger.error(f"Exception fetching max id from '{table_name}': {e}")
        return results

    # Enqueue batches
    max_id = int(max_id)
    for start in range(0, max_id + 1, batch_size):
        queue.put((start, start + batch_size))

    # Start threads
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        threads_list.append(t)

    queue.join()

    # Stop workers
    for _ in range(threads):
        queue.put(None)
    for t in threads_list:
        t.join()

    logger.info(f"Fetched {len(results)} LINK records from '{table_name}'")
    return results

# --- Core consistency check functions ---

def identify_differences(dids, ayra_links, map_state):
    logger.info("Identifying differences between Rucio DB and AyraDB")
    intersection = dids & ayra_links
    hanging = ayra_links - dids
    missing = dids - ayra_links

    logger.info(f"Intersection count: {len(intersection)}") # Records present in both Rucio DB and AyraDB
    logger.info(f"Hanging records count: {len(hanging)}") # Records in AyraDB with no correspondence in Rucio DB. Offset = 1, due to the record "EMPTY_RESULT" in AyraDB
    logger.info(f"Missing records count: {len(missing)}") # Records in Rucio DB with no correspondence in AyraDB

    delete_meta = {did for did in intersection if map_state[did] not in ["A", "C", "T"]}
    logger.info(f"Records to delete: {len(delete_meta)}") # DIDs in intersection that are not in an "available" state (i.e. A, C, or T)

    bad_replicas = {did for did in missing if map_state.get(did) in ["A", "C", "T"]}
    logger.info(f"Records to declare bad replicas: {len(bad_replicas)}") # DIDs in Rucio DB that are not in AyraDB but are in an "available" state

    return intersection, hanging, missing, delete_meta, bad_replicas

def delete_records(delete_meta, tasi_server, inaf_server, tasi_table_name, credentials):
    logger.info("Starting deletion of bad records in AyraDB")
    for did in delete_meta:
        scope, name = did.split(":", 1)
        servers = tasi_server
        table_name = tasi_table_name
        if scope in ["fermi", "birales", "pulsar"]:
            servers = inaf_server
            table_name = f"metadata{scope.capitalize()}"
        key = adbc__generate_record_key_from_field(did)
        res, error = adbc_1liner__delete_record__wrapper(servers, credentials, table_name, key)
        logger.info(f"Deleting record {did} from table '{table_name}' with key {key}")
        if not res:
            logger.error(f"Failed to delete record {did}: {error}")

def delete_hanging_records(hanging, tasi_server, inaf_server, tasi_table_name, credentials):
    logger.info("Deleting hanging records in AyraDB")
    for did in hanging:
        if did == "EMPTY_RESULT":
            continue
        scope, name = did.split(":", 1)
        servers = tasi_server
        table_name = tasi_table_name
        if scope in ["fermi", "birales", "pulsar"]:
            servers = inaf_server
            table_name = f"metadata{scope.capitalize()}"
        key = adbc__generate_record_key_from_field(did)
        res, error = adbc_1liner__delete_record__wrapper(servers, credentials, table_name, key)
        logger.info(f"Deleting hanging record {did} from table '{table_name}' with key {key}")
        if not res:
            logger.error(f"Failed to delete hanging record {did}: {error}")

def declare_bad_replicas(client, bad_replicas):
    logger.info("Declaring bad replicas on Rucio")
    for did in bad_replicas:
        scope, name = did.split(":", 1)
        try:
            replicas = list(client.list_replicas(dids=[{"scope": scope, "name": name}]))
            if not replicas:
                logger.warning(f"No replicas found for {did}")
                continue
            rse_list = [list(replica["states"].keys()) for replica in replicas]
            replica_states = [list(replica["states"].values()) for replica in replicas]
            logger.debug(f"Checking {did} with RSEs {rse_list} and states {replica_states}")
            for replica_state in replica_states:
                if replica_state[0] != "AVAILABLE":
                    logger.info(f"Replica for {did} not available, skipping")
                    continue
            for rse in rse_list[0]:
                client.declare_bad_file_replicas(
                    replicas=[{"scope": scope, "name": name, "rse": rse}],
                    reason="File in storage with no metadata in external DB",
                )
                logger.info(f"Declared {did} as bad replica on RSE {rse}")
        except Exception as e:
            logger.error(f"Error processing {did}: {e}")

# --- Main consistency check runner ---

def run_consistency_check(do_delete=False, do_declare_bad=False, threads=4):
    # Load configs
    config_db = configparser.ConfigParser()
    config_db.read("/etc/config/rucio_db_creds.cfg")
    db_config = {
        "db_host": "rucio-db-postgresql.rucio-idl.svc.cluster.local",
        "db_port": 5432,
        "db_name": config_db.get("database", "db_name"),
        "db_user": config_db.get("database", "db_user"),
        "db_password": config_db.get("database", "db_password"),
    }

    config = configparser.ConfigParser()
    config.read("/etc/config/AyraDB_cluster_credentials.cfg")
    tasi_server = [
        {
            "ip": config.get("server1", "ip"),
            "port": int(config.get("server1", "port")),
            "name": config.get("server1", "name"),
        },
        {
            "ip": config.get("server2", "ip"),
            "port": int(config.get("server2", "port")),
            "name": config.get("server2", "name"),
        },
    ]
    inaf_server = [
        {
            "ip": config.get("server3", "ip"),
            "port": int(config.get("server3", "port")),
            "name": config.get("server3", "name"),
        }
    ]

    credentials = {
        "username": config.get("credentials", "username"),
        "password": config.get("credentials", "password"),
    }

    tasi_table_name = "metadata"

    # Fetch DIDs from Postgres
    dids, map_state = fetch_all_dids_postgres(db_config)

    # Fetch LINKS from AyraDB (pagination + multithread)
    ayra_results = fetch_links_paginated(tasi_server, credentials, tasi_table_name, threads=threads)
    for table_name in ["metadataFermi", "metadataBirales", "metadataPulsar"]:
        results_sub = fetch_links_paginated(inaf_server, credentials, table_name, threads=threads)
        ayra_results.update(results_sub)

    # Calculate differences
    intersection, hanging, missing, delete_meta, bad_replicas = identify_differences(dids, ayra_results, map_state)

    # Handle deletion if requested
    if do_delete:
        delete_records(delete_meta, tasi_server, inaf_server, tasi_table_name, credentials)
        delete_hanging_records(hanging, tasi_server, inaf_server, tasi_table_name, credentials)

    # Handle bad replicas declaration if requested
    if do_declare_bad:
        client = Client()
        declare_bad_replicas(client, bad_replicas)

    LOG_DIR = "/logs/idl"

    if not (do_delete or do_declare_bad):
        from datetime import datetime
        # Timestamp usato nei file di log
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs(LOG_DIR, exist_ok=True)

        def dump_dids_to_log(group_name: str, dids: set):
            if not dids:
                return
            filename = os.path.join(LOG_DIR, f"{group_name}_{timestamp}.log")
            with open(filename, 'w') as f:
                for did in sorted(dids):
                    f.write(did + '\n')
            logger.info(f"Dumped {len(dids)} DIDs to {filename}")
        
        dump_dids_to_log("hanging_meta", hanging)
        dump_dids_to_log("replicas_no_meta", missing)
        dump_dids_to_log("not_available_with_meta", delete_meta)
        dump_dids_to_log("bad_replicas", bad_replicas)


# --- Entry point ---

def main():
    args = parse_args()
    logger.info(f"Flags - delete: {args.delete}, declare_bad: {args.declare_bad}, threads: {args.threads}")
    run_consistency_check(do_delete=args.delete, do_declare_bad=args.declare_bad, threads=args.threads)

if __name__ == "__main__":
    main()