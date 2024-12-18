# IG-IDL project: Rucio Data Lake

- [Overview](#overview)
  - [Testbed](#testbed)
  - [Extending Rucio to support external metadata catalogs](#extending-rucio-to-support-external-metadata-catalogs)
- [Getting Started](#getting-started)
- [Installation](#installation)
  - [Rucio Server](#rucio-server)
    - [Local-path-provisioner TMP](#local-path-provisioner-TMP)
    - [Server Installation TMP](#Server-Installation-TMP)
    - [Server Networking](#Server-Networking)
  - [S3 Storage Endpoint](#S3-Storage-Endpoint)
    - [RSE Configuration](#RSE-Configuration)
- [IDL-dedicated components](#IDL-dedicated-components)
  - [Custom policies](#Custom-policies)
  - [Custom DID-metadata plugin](#Custom-DID-metadata-plugin)
  - [Custom Rucio client](#Custom-Rucio-client)
- [JupyterHub instance](#JupyterHub-instance)
- [Containerized clients for testing](#Containerized-clients-for-testing)
- [IDL-dedicated Rucio client Guide](#IDL-dedicated-Rucio-client-Guide)

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

_**NOTE**: run once export KUBECONFIG=/etc/rancher/rke2/rke2.yaml in each new terminal window, otherwise add it in the .bashrc file. Also add `export PATH="/path/to/kubectl:$PATH"` to your .bashrc file in order to use kubectl directly._

Git clone repository (**TMP for the prototype**): 
- https://github.com/rucio/k8s-tutorial.git 

Install kubectl: 
- https://kubernetes.io/docs/tasks/tools/install-kubectl/

Install helm: 
- https://helm.sh/docs/intro/install/

Add Helm chart repositories:
* `helm repo add stable https://charts.helm.sh/stable`

* `helm repo add bitnami https://charts.bitnami.com/bitnami`

* `helm repo add rucio https://rucio.github.io/helm-charts`

## Installation

_**Editor's Note**: For the installation and setup of the first end-to-end prototype I have followed the tutorial suggested by the official Rucio documentation, but for the migration on ICSC resources I will set up the Rucio Server manually._

### Rucio Server

#### Local-path-provisioner TMP

Being on a bare-metal k8s cluster you need to install a dynamic provisioner, otherwise you'll need to manually claim persistent volumes. We installed the local-path-provisioner storageClass following: https://github.com/rancher/local-path-provisioner?tab=readme-ov-file#installation.

"In this setup, the directory /opt/local-path-provisioner will be used across all the nodes as the path for provisioning (a.k.a, store the persistent volume data). 

The provisioner will be installed in local-path-storage namespace by default.

* `kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.30/deploy/local-path-storage.yaml`

After installation, you should see something like the following:

```
$ kubectl -n local-path-storage get pod
NAME                                     READY     STATUS    RESTARTS   AGE
local-path-provisioner-d744ccf98-xfcbk   1/1       Running   0          7m
```

Check and follow the provisioner log using:

* `kubectl -n local-path-storage logs -f -l app=local-path-provisioner`

The storageClass should be the default in your cluster, you can check it with:

* `kubectl get sc`

If not please set it as default following: https://kubernetes.io/docs/tasks/administer-cluster/change-default-storage-class/#changing-the-default-storageclass.

#### Server Installation TMP

Follow the “Installation of Rucio + FTS + Storage” section up to the preparation of the client container from the tutorial: https://github.com/rucio/k8s-tutorial

Verify that the root client is working by jumping into it:

* `kubectl exec -it client -- /bin/bash`

and try using some basic rucio commands like:

* `rucio whoami`

#### Server Networking

### S3 Storage Endpoint

Follow the tutorial in [PLACEHOLDER]. Make sure that the traffic to the ports in the MinIO tutorial is allowed.

#### RSE Configuration

Create a RSE:

* `rucio-admin rse add TEST_USERDISK`

Add a protocol to the RSE:

* `rucio-admin rse add-protocol --hostname <YOUR_S3_HOSTNAME>  --domain-json ‘{“lan”: {“write”: 1, “read”: 1, “delete”: 1}, “wan”: {“write”: 1, “read”: 1, “delete”: 1, “third_party_copy_read”: 1, “third_party_copy_write”: 1}}’ --impl rucio.rse.protocols.gfal.NoRename --scheme https --prefix test --port 443 TEST_USERDISK`

Set a non-zero quota for the RSE:

* `rucio-admin account set-limits root TEST_USERDISK 10GB`

Set the following attributes:

```
rucio-admin rse set-attribute --rse TEST_USERDISK --key sign_url --value s3
rucio-admin rse set-attribute --rse TEST_USERDISK --key skip_upload_stat --value True
rucio-admin rse set-attribute --rse TEST_USERDISK --key verify_checksum --value False
rucio-admin rse set-attribute --rse TEST_USERDISK --key strict_copy --value True
rucio-admin rse set-attribute --rse TEST_USERDISK --key s3_url_style --value path
```

Create a rse-accounts.cfg (use your rse_id and s3 credentials below) file in /etc/:

```
cat >> etc/rse-accounts.cfg << EOL
{
	“YOUR_RSE_ID”: {
		“access_key”: “<YOUR_ACCESS_KEY>”,
		“secret_key”: “<YOUR_SECRET_KEY>”,
		“signature_version”: “s3v4”
		“region”: “us-west-2”
	}
}
EOL
```

Deploy the S3 configuration to the Rucio server by creating a server-rse-accounts secret from rse-accounts.cfg:

* `kubectl create secret generic server-rse-accounts --from-file /etc/rse-accounts.cfg`

Add the following values in your servers helm chart (values-server.yaml):

```
secretMounts:
   - secretName: rse-accounts
     mountPath: /opt/rucio/etc/rse-accounts.cfg
     subPath: rse-accounts.cfg
config:
   credentials:
     gcs: "/opt/rucio/etc/rse-accounts.cfg"
```

Restart the Rucio server by deleting the pod (kubectl get pods):

* `kubectl delete pod <YOUR_SERVER_POD>`

Give every Rucio account, including root, the following attribute to be able to sign URLs:

* `rucio-admin account add-attribute <ACCOUNT_NAME> --key sign-gcs --value true`

Create a test file:

* `dd if=/dev/urandom of=mydata bs=10M count=1`

To upload the file, an account must have a scope. Create a scope linked to your account:

* `rucio-admin scope add --account root --scope test`

Upload the file in the RSE in the test scope:

* `rucio upload --scope test --rse TEST_USERDISK mydata`

Verify that your file is in your MinIO instance (e.g. mc ls myminio/test/test/8e/d4):

* `mc ls myminio/test/path/to/uploaded/file`

Download the file:

* `rucio download test:mydata`


## IDL-dedicated components

### Custom policies

### Custom DID-metadata plugin

### Custom Rucio client

## JupyterHub instance

## Containerized clients for testing

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
