#!/bin/bash
set -e

# set the container name otherwise it use the wsl munted directory name
export COMPOSE_PROJECT_NAME=docker-compose

# close docker container
docker compose down -v

cd scripts

# write groups
bash group-writer.sh

cd ..

# restart the docker container
docker compose up -d