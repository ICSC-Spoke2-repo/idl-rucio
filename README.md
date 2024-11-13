# IDL-rucio
rucio wrapper for the IDL Innovation Grant

# Rucio-client IDL

Setup client:

* `docker pull lucapacioselli/rucio-client-test:test-v1.1.3`  
* `docker run --name=rucio-client-test -it -d lucapacioselli/rucio-client-test:test-v1.1.3`  
* `docker exec -it rucio-client-test /bin/bash`

Configure your rucio.cfg by running the cred.py script:

* `cred.py --user <USERNAME> --account <ACCOUNT>`

The script will request your password as follows:

* `Enter the password (hidden): <PASSWORD>`

Custom upload (upload data file in the rucio S3 RSE \+ set-metadata from the metadata .json file in the AyraDB database cluster):

* `IDL upload --scope user.prova --rse TEST_USERDISK --files <DATA_FILE> --metas <METADATA_JSON>`

Upload of more than one file from terminal (list of data file paths and metadata file paths, the order in which they are entered tells which metadata is assigned to which data file, e.g. \--files data1 data2 … \--metas meta1 meta2 … assigns meta1 to data1, meta2 to data2, …):

* `IDL upload --scope user.prova --rse TEST_USERDISK --files <DATA1> <DATA2> ... --metas <META_JSON1> <META_JSON2> ...`


Bulk upload from a .txt file (where each line has the path to a data file and its metadata file, divided by spaces):

* `IDL upload --bulk --scope user.prova --rse TEST_USERDISK --txt <TEXT_FILE>` 


Custom get-metadata from the AyraDB database cluster:

* `IDL get-metadata --scope user.prova --name <DID_NAME>`

Custom queries to the DB (\<SELECT\>: SELECTs for SQL queries, e.g. \--select 'PARTICIPANT\_1, EPOCH'. The LINK, which is the DID of the file, is always present in the selects and the wildcard \* is enabled/\<FILTERS\>: Operators must belong to the set of (\<=, \>=, \=, \!=, \>, \<) and the logical expressions AND and OR can be used):

* `IDL list-dids --scope user.prova --filters <FILTERS>`  
* `IDL sql --scope user.prova --select <SELECT> --filters <FILTERS>`

Account management:

* Retrieve info on the current user:  
  * `IDL whoami`  
* Show account usage  
  * `IDL list-account-usage <ACCOUNT>`  
* List the rules defined for a given account  
  * `IDL list-rules --account <ACCOUNT>`

Rucio Storage Elements (RSEs):

* List available RSEs (for testing you should use only the RSE "TEST\_USERDISK")  
  * `IDL list-rses`  
* Show RSE usage  
  * `IDL list-rse-usage TEST_USERDISK`  
* List datasets stored on a specific RSE  
  * `IDL list-datasets-rse TEST_USERDISK`

Scopes:

* List all scopes:  
  * `IDL list-scopes`  
* The test scope linked to the "prova" account is: “*user.prova*”

File management:

* Create a container (collection of containers and datasets):  
  * `IDL add-container user.prova:<container>`  
* Create a dataset (collection of files):  
  * `IDL add-dataset user.prova:<dataset>`  
* Download a file (or an entire dataset):  
  * `IDL download user.prova:<DATA_FILE>`  
* Add a file to an existing dataset:  
  * `IDL attach user.prova:<dataset> user.prova:<DATA_FILE>`  
* Get the datasets in a RSE:  
  * `IDL list-datasets-rse TEST_USERDISK`  
* Get the files in a dataset:  
  * `IDL list-files user.prova:<dataset>`  
* Get the list of DIDs satisfying a DID Expression (wildcard \<SCOPE\>:\*):  
  * `IDL list-dids <DID-Expression>`  
* Find where files are stored  
  * `IDL list-file-replicas user.prova:<DATA_FILE>`  
* Get file/dataset/container attributes  
  * `IDL stat user.prova:<DATA_FILE>`  
* Delete files/datasets/containers  
  * `IDL erase user.prova:<DATA_FILE>`  
  * `OUTPUT]:2023-03-10 08:26:54,645    INFO    CAUTION! erase operation is irreversible after 24 hours. To cancel this operation you can run the following command:`  
  * `IDL erase --undo user.prova:<DATA_FILE>`
