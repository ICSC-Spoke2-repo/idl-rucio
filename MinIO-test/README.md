# MinIO's S3 setup

## Requirements

- Install docker: [https://docs.docker.com/engine/install/ubuntu/#install-from-a-package](https://docs.docker.com/engine/install/ubuntu/#install-from-a-package)
- Install MinIO Client command line tool: [https://min.io/docs/minio/linux/reference/minio-mc.html](https://min.io/docs/minio/linux/reference/minio-mc.html)

## Install MinIO

_NOTE: Before executing the next command, please change directory to the git cloned repository location (This is needed by docker to see the docker-compose.yaml)._

- Set up your MinIO:

  `docker compose up -d`

- Use the `mc alias set` command to add an S3-compatible service to the mc configuration:
  
  `mc alias set myminio https://<YOUR_S3_HOSTNAME> <YOUR_ACCESS_KEY> <YOUR_SECRET_KEY>`

- Create a bucket:
  
  `mc mb myminio/test`
