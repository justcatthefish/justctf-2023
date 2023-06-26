#!/bin/sh

cd private
docker compose -p re_rpg rm --force --stop
docker compose -p re_rpg build
docker compose -p re_rpg up
