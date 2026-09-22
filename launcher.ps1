$ErrorActionPreference = "Stop"

# Project root
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$Python = ".\.venv\Scripts\python.exe"

Write-Host "=== Reset Rego policy ==="
& $Python reset_rego.py

Write-Host "=== Extract security groups ==="
bash StructureExtraction/SecurityGroupExtraction/security_group_extraction.sh

Write-Host "=== Extract user credentials ==="
bash StructureExtraction/UserCredentialsExtraction/user_credential_extraction.sh

Write-Host "=== Start Docker Compose ==="

Set-Location docker-compose

$env:COMPOSE_PROJECT_NAME = "docker-compose"

docker compose down -v
docker compose up -d

Set-Location ..

Write-Host "Waiting for trino-init to finish..."

while ($true) {
    $status = docker inspect -f '{{.State.Status}}' trino-init

    if ($status -eq "exited") {
        $exitCode = docker inspect -f '{{.State.ExitCode}}' trino-init

        if ($exitCode -eq "0") {
            Write-Host "trino-init completed successfully"
            break
        }
        else {
            Write-Host "trino-init failed with exit code $exitCode"
            docker logs trino-init
            exit 1
        }
    }

    Start-Sleep -Seconds 5
}

Write-Host "=== Extract Data Mesh structure ==="

bash StructureExtraction/MinioStructureExtraction/data_mesh_extraction.sh `
    --user trino `
    --password trino123 `
    --debug

Write-Host "=== Launcher completed ==="

