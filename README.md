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
  - [JHub Preliminaries](#jhub-preliminaries)
  - [JHub Installation](#jhub-installation)
  - [JHub Configuration](#jhub-configuration)
  - [JHub Rucio Extension](#jhub-rucio-extension)
- [Containerized clients for testing](#Containerized-clients-for-testing)
- [IDL-dedicated Rucio client Guide](#IDL-dedicated-Rucio-client-Guide)

This document provides detailed instructions to reproduce the work carried out in the **Interoperable Data Lake (IDL)** project Work Package 1, focusing on the development of the Data Lake service. The guide outlines the complete process for setting up a distributed data management environment, including the automated deployment and configuration of the Rucio server on a Kubernetes cluster, IDL-tailored Rucio client, the development of the custom policy package and custom DID-metadata plugin to extend Rucio's functionality, and a JupyterHub instance on the same k8s cluster with a rucio-jupyterlab extension. Work in progress for the integration of the next-generation Rucio WebUI.

The work described in this document is specific to the IDL project; **however**, the procedures and methodologies outlined can be easily adapted and modified to suit other contexts and metadata catalog integrations.

_NOTE: The sections marked with "TMP" are to be intended as the work done for the first prototype developed on a bare-metal k8s cluster. After migrating the Data Lake service on ICSC resources the documentation will be updated and these sections will be deleted._

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

_**NOTE**: run once `export KUBECONFIG=/path/to/kubeconfig/*.yaml` in each new terminal window, otherwise add it in the .bashrc file. Also add `export PATH="/path/to/kubectl:$PATH"` to your .bashrc file in order to use kubectl directly._

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

if not, set it as default following: https://kubernetes.io/docs/tasks/administer-cluster/change-default-storage-class/#changing-the-default-storageclass.

#### Server Installation TMP

(TMP) Follow the “Installation of Rucio + FTS + Storage” section up to the preparation of the client container from the tutorial: https://github.com/rucio/k8s-tutorial

Change the secrets and both the client's and DB's username and password.

Verify that the root client is working by running:

* `kubectl exec -it client -- /bin/bash`

and trying to use some basic rucio commands like:

* `rucio whoami`

#### Server Networking

Add the following values to the values-server.yaml:

```
ingress:
  enabled: true
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "false"
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    cert-manager.io/cluster-issuer: lets-issuer
  ingressClassName: nginx
  hosts:
    - <RUCIO_SERVER_ENDPOINT>
  - hosts:
    - <RUCIO_SERVER_ENDPOINT>
    secretName: tls-rucio-server
```

Restart the server:

* `helm upgrade server rucio/rucio-server -f /PATH/TO/VALUES/values-server.yaml`

Install the nginx-ingress Helm chart (as a DaemonSet):

* `helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace --set controller.kind= DaemonSet`

Open the chart:

* `kubectl edit daemonset ingress-nginx-controller -n ingress-nginx`

Add to the chart the following values (under spec: template: spec:):

```
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
  nodeSelectorTerms:
    - matchExpressions:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
tolerations:
  - effect: NoSchedule
    key: node-role.kubernetes.io/control-plane
    operator: Exists
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
    operator: Exists
  volumes:
  - name: webhook-cert
    secret:
      defaultMode: 420
      secretName: ingress-nginx-admission
```

(TMP) Follow the "Via the host network" section of the bare-metal considerations guide: https://kubernetes.github.io/ingress-nginx/deploy/baremetal/.

Install the default static configuration of the cert-manager:

* `kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.1/cert-manager.yaml`

Write the following ClusterIssuer resource (cert-issuer.yaml):

```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: lets-issuer
  namespace: cert-manager
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: <YOUR_EMAIL>
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt
    # Enable the HTTP-01 challenge provider
    solvers:
    - http01:
      ingress:
        class: nginx
```

Create the cert-issuer:

* `kubectl apply -f cert-issuer.yaml`

Follow the “Troubleshooting” guide to verify that the certificate-related resources are working fine: https://cert-manager.io/docs/troubleshooting/.

### S3 Storage Endpoint

- Follow the README in [MinIO-test](MinIO-test/). 

- Make sure that the traffic to the ports in the MinIO tutorial is allowed.

#### RSE Configuration

Create a Rucio Storage Element (RSE):

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

At this point, in order to allow users to upload/download files, one needs to change the general policies of the server.

Download/copy the generic.py permissions file (permissions.py) from: https://github.com/rucio/rucio/blob/ba102506d470c417fd2b136304e4fa4f7fc3a870/lib/rucio/core/permission/generic.py.

Replace the perm_get_signed_url function from permissions.py with this one:

```
def perm_get_signed_url(issuer, kwargs, *, session: "Optional[Session]" = None):
    """
    Checks if an account can request a signed
    URL.
    :param issuer: Account identifier which
    issues the command.
    :param session: The DB session to use
    :returns: True if account is allowed to
    call the API call, otherwise False
    """
    return _is_root(issuer) or has_account_attribute(account=issuer, key='sign-gcs', session=session)
```

Create the secret to automatically update the k8s cluster policies:

* `kubectl create secret generic server-permissions --from-file /PATH/TO/PERMISSIONS/FILE/permissions.py`

Add the following values to the values-server.yaml:

```
secretMounts:
  - secretName: permissions
    mountPath: /usr/local/lib/python3.9/site-packages/rucio/core/permission/permissions.py
    subPath: permissions.py
config:
  policy:
    permission: permissions
    schema: generic
    #package: policy_package
    lfn2pfn_algorithm_default: "hash"
    support: "https://github.com/rucio/rucio/issues/"
    support_rucio: "https://github.com/rucio/rucio/issues/"
```

Restart the server by deleting its pod.

### Custom DID-metadata plugin

### Custom Rucio client

## JupyterHub instance

### JHub Preliminaries

To install the Helm chart that deploys Jupyterhub version 4.1.5 you need Kubernetes version >= 1.23.0 and Helm >=3.5:

* `kubectl version`

* `helm version`

Initialize a chart configuration file (jupyter-config.yaml):

* `vi jupyter-config.yaml`

Add the following:

```
# This file can update the JupyterHub Helm chart's default configuration values.
#
# For reference see the configuration reference and default values, but make
# sure to refer to the Helm chart version of interest to you!
#
# Introduction to YAML:     https://www.youtube.com/watch?v=cdLNKUoMc6c
# Chart config reference:   https://zero-to-jupyterhub.readthedocs.io/en/stable/resources/reference.html
# Chart default values:     https://github.com/jupyterhub/zero-to-jupyterhub-k8s/blob/HEAD/jupyterhub/values.yaml
# Available chart versions: https://hub.jupyter.org/helm-chart/
```

### JHub Installation

Add Helm chart repository:

* `helm repo add jupyterhub https://hub.jupyter.org/helm-chart/`

Run:

* `helm repo update`

Install the chart configured by jupyter-config.yaml by running:

```
helm upgrade --cleanup-on-fail --install <your-helm-release-name> jupyterhub/jupyterhub --namespace <k8s-namespace> --create-namespace --version=<chart-version> --values jupyter-config.yaml
```

Wait for the hub and proxy pod to enter the Running state:

* `kubectl get pod -n jupyter`

Following what have been done in the [Server Networking](#server-networking) subsection of this documentation, create an Ingress resource (jupyter-ingress.yaml) for the jupyter services:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: jupyterhub-ingress
 namespace: jupyter
 annotations:
   nginx.ingress.kubernetes.io/ssl-passthrough: "false"
   nginx.ingress.kubernetes.io/ssl-redirect: "false"
   cert-manager.io/cluster-issuer: lets-issuer
spec:
 ingressClassName: nginx
 rules:
 - host: <JHUB_ENDPOINT>
   http:
     paths:
     - path: /
       pathType: Prefix
       backend:
         service:
           name: proxy-public
           port:
             number: 80
 tls:
 - hosts:
   - <JHUB_ENDPOINT>
   secretName: tls-jupyterhub
```

To verify that JupyterHub is working, enter https://<JHUB_ENDPOINT>:443 into a browser. At this point, JupyterHub is running with a default dummy authenticator so entering any username and password combination will let you enter the hub.

### JHub Configuration

The general method to modify the k8s deployment is to:

- Make a change in the jupyter-config.yaml

- Run a helm upgrade:

```
helm upgrade --cleanup-on-fail --install <your-helm-release-name> jupyterhub/jupyterhub --namespace <k8s-namespace> --create-namespace --version=<chart-version> --values jupyter-config.yaml
```

- Verify that the hub and proxy pods entered the Running state.

Default storage/volume provisioning is done by the k8s cluster’s local-path-provisioner (resets /home/jovyan at the pod's start-up)

Choose an existing docker image depending on what users need to do and modify the jupyter-config.yaml:

```
singleuser:
  image:
    #You should replace the "latest" tag with a fixed version from: https://hub.docker.com/r/jupyter/datascience-notebook/tags/
    #Inspect the Dockerfile at: https://github.com/jupyter/docker-stacks/tree/HEAD/datascience-notebook/Dockerfile
    name: jupyter/tensorflow-notebook
    tag: ubuntu-22.04
  #`cmd: null` allows the custom CMD of the Jupyter docker-stacks to be used
  #which performs further customization on startup.
  cmd: null
```

Use JupyterLab by default by adding the following to the jupyter-config.yaml:
singleuser:

```
# use jupyterlab as the default interface
defaultUrl: "/lab"
extraEnv:
  JUPYTERHUB_SINGLEUSER_APP: "jupyter_server.serverapp.ServerApp"
```

Customize the culling of inactive user servers:

```
singleuser:
  extraFiles:
    # jupyter_notebook_config reference: https://jupyter-notebook.readthedocs.io/en/stable/config.html
    jupyter_notebook_config.json:
      mountPath: /etc/jupyter/jupyter_notebook_config.json
      # data is a YAML structure here but will be rendered to JSON file as our
      # file extension is ".json".
      data:
        MappingKernelManager:
          # cull_idle_timeout: timeout (in seconds) after which an idle kernel is
          # considered ready to be culled
          cull_idle_timeout: 1200 # default: 0

          # cull_interval: the interval (in seconds) on which to check for idle
          # kernels exceeding the cull timeout value
          cull_interval: 120 # default: 300

          # cull_connected: whether to consider culling kernels which have one
          # or more connections
          cull_connected: true # default: false

          # cull_busy: whether to consider culling kernels which are currently
          # busy running some code
          cull_busy: false # default: false
```

Add admin users:

```
hub:
 config:
   Authenticator:
     admin_users:
       - test
   DummyAuthenticator:
     password: <YOUR-SHARED-PASSWORD>
   JupyterHub:
     authenticator_class: dummy
```

The setup (with some quality of life for the end-user) has been automated with a custom Docker image for the JHub's singleuser: https://hub.docker.com/repository/docker/lucapacioselli/jupyter4rucio/general.

To use it, edit the jupyter-config.yaml `singleuser.image.name` and `singleuser.image.tag` with `lucapacioselli/jupyter4rucio:v1.0.6`

Add to the jupyter-config.yaml, to execute the commands in the script at the startup of any singleuser pod:

```
singleuser
  lifecycleHooks:
    postStart:
      exec:
        command: ["/opt/conda/script_jhub.sh"]
```

At the start of your JLab instance, the terminal will print a warning message and the output of a `rucio whoami` to check if the rucio.cfg file has your credentials in it. The standard rucio.cfg file should be:

```
[client]
rucio_host = https://<RUCIO_SERVER_ENDPOINT>:443
auth_host = https://<RUCIO_SERVER_ENDPOINT>:443
ca_cert = /etc/ssl/certs/ca-certificates.crt
auth_type = userpass
username = <YOUR_USERNAME>
password = <YOUR_PASSWORD>
account = <YOUR_ACCOUNT_NAME>
client_cert =
client_key =
client_x509_proxy =
request_retries = 3

[policy]
permission = generic
schema = generic
lfn2pfn_algorithm_default = hash
support = https://github.com/rucio/rucio/issues/
support_rucio = https://github.com/rucio/rucio/issues/
```

You can edit it with the cred.py script to insert your account, username and password in the rucio.cfg file.

If you want to use the Python API Client in the jupyter notebook, run the following in the first cell:

```
import os
os.environ['RUCIO_HOME']="/path/to/’/etc/rucio.cfg’"
```

### JHub Rucio Extension

The Docker image also has the dependencies for the rucio-jupyterlab extension. 

- To make the extension work the first time, you or the administrator of the JHub must restart the singleuser pod!

- The rucio-jupyterlab extension is configured via two config files passed to every singleuser pod via configmaps and moved to the right .ipython and .jupyter. 

- The extension is in "download" mode. 

- The user must also insert the credentials in the Configuration section of the extension that appears on the left sidebar.

- After this, the user can search for every file in the rucio "filesystem" in the _Explore_ section and make it available to the current JLab session (this will create a sub-folder in the /home/jovyan/rucio/ directory). If the user wants to use a file made available from rucio in a notebook, he has to select a notebook tab and click the _Add to Notebook_ button to attach it to the current notebook (one can also choose a variable name for the file).

- The _Notebook_ section has the list of attached files to the current selected notebook tab. The user can detach a file from the notebook through the usual red cross. 

## Containerized clients for testing

Create a containerized client via Docker:

```
docker run -e RUCIO_CFG_CLIENT_RUCIO_HOST=https://<RUCIO_SERVER_ENDPOINT>:443 -e RUCIO_CFG_CLIENT_AUTH_HOST=https://<RUCIO_SERVER_ENDPOINT>:443 -e RUCIO_CFG_CLIENT_AUTH_TYPE=userpass -e RUCIO_CFG_CLIENT_USERNAME=<YOUR_USERNAME> -e RUCIO_CFG_CLIENT_PASSWORD=<YOUR_PASSWORD> -e RUCIO_CFG_CLIENT_ACCOUNT=<YOUR_ACCOUNT_NAME> --name=rucio-client -it -d rucio/rucio-clients
```

From the root account in your previous PC/VM, configure the accounts of the client containers by setting the quotas on the RSEs, create personal scopes, give the attribute to be able to sign URLs, etc…

Enter into the client container:

* `docker exec -it rucio-client /bin/bash`
     
and try using some basic rucio commands like:

* `rucio whoami`

* `rucio ping`


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
