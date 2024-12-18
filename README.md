# IG-IDL project: Rucio Data Lake

- [Overview](#overview)
  - [Testbed](#testbed)
  - [Extending Rucio to support external metadata catalogs](#extending-rucio-to-support-external–metadata-catalogs)
- [Getting Started](#getting-started)
- [Installation](#installation)
  - [Rucio Server](#rucio-server)
  - [Local-path-provisioner TMP](#localpathprovisioner-TMP)
  - [S3 Storage](#S3-Storage)
- [License](#license)
- [Acknowledgements](#acknowledgements)

This document provides detailed instructions to reproduce the work carried out in the **Interoperable Data Lake (IDL)** project Work Package 1, focusing on the development of the Data Lake service. The guide outlines the complete process for setting up a distributed data management environment, including the automated deployment and configuration of the Rucio server on a Kubernetes cluster, IDL-tailored Rucio client, the development of the custom policy package and custom DID-metadata plugin to extend Rucio's functionality, and a JupyterHub instance on the same k8s cluster with a rucio-jupyterlab extension. Work in progress for the integration of the next-generation Rucio WebUI.

The work described in this document is specific to the IDL project; **however**, the procedures and methodologies outlined can be easily adapted and modified to suit other contexts and metadata catalog integrations.

_NOTE: The sections marked with "(tmp)" are to be intended as the work done for the first prototype developed on a bare-metal k8s cluster. After migrating the Data Lake service on ICSC resources the documentation will be updated and these sections will be deleted._

## Overview

“The Project aims at creating a **Data Lake service**, supporting a seamless access to space and ground-based observations and simulated data. The project addresses the design and commissioning of an interoperable, distributed data archive, relying on **state-of-the-art open technologies**, supporting both science and industry. The service will specifically address the challenges related to the big data scenario, in terms of both **data management, storage, access**, identification and of access to computing resources”

### Testbed

As part of the **Work Package 1 (WP1)** in the IDL project, this document describes the work done to develope an **end-to-end prototype for Data Management** (DM) in a distributed environment. 

### Extending Rucio to support external metadata catalogs

A key aspect of this work involves extending **Rucio**, an open-source data management software, to support external databases/metadata catalogs. This extension is made possible by Rucio's:

1. **Interoperability**: Facilitates integration with third-party metadata services to enrich data discovery and management.
2. **Proven Scalability**: Supports large-scale datasets with diverse metadata schemas.
3. **Flexibility and Extensibility**: With its extensible API and plugin-based design, Rucio can be customized to meet the specific requirements of the IDL project.

## Getting Started

## Installation

### Rucio Server

### Local-path-provisioner TMP

### S3 Storage

### S3 Storage Configuration

### Server Networking

### Containerized clients for testing

## IDL-dedicated components

### Custom policies

### Custom DID-metadata plugin

### Custom Rucio client

## JupyterHub instance

## IDL-dedicated Rucio client Guide

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
