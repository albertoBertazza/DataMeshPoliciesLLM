#!/bin/bash
set -e

# reset rego policy to original
./.venv/Scripts/python.exe reset_rego.py

# 1) extraction security group
#   1.1 write /docker-compose/etc/user-group/groups.txt useful to trino to pass group inside input object
#   1.2 write /LLM/Structure/security_groups.json useful to save the existing security group for generation
bash StructureExtraction/SecurityGroupExtraction/security_group_extraction.sh

# write a json file
bash StructureExtraction/UserCredentialsExtraction/user_credential_extraction.sh


# 2) launch docker compose
cd docker-compose
# set the container name otherwise it use the wsl munted directory name
export COMPOSE_PROJECT_NAME=docker-compose
# close docker container
docker compose down -v
# restart the docker container
docker compose up -d

cd ..

echo "⏳ Waiting for trino-init to finish..."

while true; do
    STATUS=$(docker inspect -f '{{.State.Status}}' trino-init)

    if [[ "$STATUS" == "exited" ]]; then
        EXIT_CODE=$(docker inspect -f '{{.State.ExitCode}}' trino-init)

        if [[ "$EXIT_CODE" == "0" ]]; then
            echo "✅ trino-init completed successfully"
            break
        else
            echo "❌ trino-init failed with exit code $EXIT_CODE"
            docker logs trino-init
            exit 1
        fi
    fi

    sleep 5
done



bash StructureExtraction/MinioStructureExtraction/data_mesh_extraction.sh --user trino --password trino123 --debug


# ./.venv/Scripts/python.exe orchestartor.py