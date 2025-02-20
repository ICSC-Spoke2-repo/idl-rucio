# MinIO S3 setup

## Requirements

- Install docker: [https://docs.docker.com/engine/install/ubuntu/#install-from-a-package](https://docs.docker.com/engine/install/ubuntu/#install-from-a-package)

## Set up MinIO

_NOTE: Before executing the next command, please change directory to the git cloned repository location._

- Set up your MinIO:

  `docker compose up -d`

## Install MinIO Client (mc) in your working VM

- If you are using a linux amd distribution, run the following to download the minio client:

  `wget https://dl.min.io/client/mc/release/linux-amd64/mc`

- Otherwise follow: [https://min.io/docs/minio/linux/reference/minio-mc.html](https://min.io/docs/minio/linux/reference/minio-mc.html)

- Make the client executable and move it to your executable folder:

  `chmod +x mc`

  `sudo mv mc /usr/local/bin/mc`

- Check if the client is working and activate the autocompletion:

  `mc --version`

  `mc --autocompletion`

- Use the `mc alias set` command to add an S3-compatible service to the mc configuration:
  
  `mc alias set <ALIAS> https://<S3_HOSTNAME> <ACCESS_KEY> <SECRET_KEY>`

- Create a bucket:
  
  `mc mb <ALIAS>/<BUCKET_NAME>`