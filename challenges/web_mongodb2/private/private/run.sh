#!/usr/bin/env bash

export MAX_CORES=50
export FLAG=justCTF{Re4lly_bliNd!}

docker compose -p manager -f docker-compose.yml rm -f --stop
docker compose -p manager -f docker-compose.yml build
docker compose -p manager -f docker-compose.yml up -d
