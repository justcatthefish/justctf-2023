#!/usr/bin/env bash

export MAX_CORES=50
export FLAG=justCTF{mong0db_blind_sSrf}

docker compose -p manager -f docker-compose.yml rm -f --stop
docker compose -p manager -f docker-compose.yml build
docker compose -p manager -f docker-compose.yml up -d
