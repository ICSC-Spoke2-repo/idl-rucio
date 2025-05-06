## Sensitive Data

Before using this setup, make sure to replace all placeholder values in the following files:

- `secrets/metaDB_credentials_template.cfg`: all fields with `<...>`
- `secrets/rucio_db_creds.cfg`: 
  - `<DB_PASSWORD>`
- `secrets/rse-accounts-template.cfg`:  
  - `<ACCESS_KEY>`  
  - `<SECRET_KEY>`  
  - `<RSE_ID>` (obtainable via `rucio-admin rse info <RSE>` after creating an S3-type `<RSE>`)
- `secrets/rucio_credentials_template.cfg`:  
  - `<ROOT_USERNAME>`  
  - `<ROOT_PASSWORD>`
- `manifests/daemons-rucio.yaml`:  
  - `<DB_PASSWORD>`  
  - `<HELM_RELEASE_NAME_DB_NAME>`
- `manifests/postgres.yaml`:  
  - `<DB_PASSWORD>`
- `manifests/rucio-init.yaml`:  
  - `<ROOT_USERNAME>`  
  - `<ROOT_PASSWORD>`  
  - `<DB_PASSWORD>`  
  - `<HELM_RELEASE_DB_NAME>`
- `manifests/rucio-server.yaml`:  
  - `<DB_PASSWORD>`  
  - `<HELM_RELEASE_DB_NAME>`  
  - `<SERVER_HOSTNAME>`