# NFS Server with Docker on Dedicated Block Storage

---

## Prerequisites

- Linux machine with:
  - Docker and Docker Compose installed
  - A formatted and mounted block storage device of at least 20GB (e.g. `/data/nfs/k8s`)
- Root or sudo access

> This guide assumes your block storage is already **mounted at `/data/nfs/k8s`** and ready to use.

---

## Step 1: Set Permissions and Ownership

To make the storage accessible to NFS clients, set the following ownership and permissions:

```bash
sudo chown nobody:nobody /data/nfs/k8s
sudo chmod 777 /data/nfs/k8s
```

> Using chmod 777 makes the directory readable and writable by any user. This is acceptable for testing, development, or isolated networks. For production environments, consider using stricter permissions and user mapping.

## Step 2: NFS server setup

Start the NFS server using the [docker-compose.yaml](docker-compose.yaml):

```bash
docker compose up -d
```

Verify the container is running (optionally check the logs):

```bash
docker ps -a
docker logs <CONTAINER_ID>
```

Enter the container:

```bash
docker exec -it nfs bash
```

To allow only the RUCIO server replicas to mount the shared volume, open /etc/exports:

```bash
vi /etc/exports
```

and replace this line:

```bash
/data *(rw,fsid=0,async,no_subtree_check,no_auth_nlm,insecure,no_root_squash)
```

with:

```bash
/data <RUCIO_SERVER_IP>(async,wdelay,hide,no_subtree_check,insecure_locks,fsid=0,sec=sys,rw,insecure,no_root_squash,no_all_squash)
```

If your replicas have multiple IPs, you have to add all of them by separating them with spaces:

```bash
/data <RUCIO_SERVER_IP_1>(...) <RUCIO_SERVER_IP_2>(...) <RUCIO_SERVER_IP_3>(...)
```

After saving the file, reload the NFS export table:

```bash
exportfs -ra
```
