# Secure DB

## Running
```
docker-compose -p misc_secure_db -f docker-compose.yml build
docker-compose -p misc_secure_db -f docker-compose.yml up -d
```
## Directory description

* bin - precompiled checker files
* real - db & cloud key used by remote checker
* src - source of checker (download_third-party.sh to download dependencies)
* test - data for local testing