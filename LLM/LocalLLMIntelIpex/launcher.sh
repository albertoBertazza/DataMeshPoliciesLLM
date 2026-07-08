#!/bin/bash

ROOT="$(wslpath -w "$(pwd)")"

# leave it it runs with ls 
ls

cmd.exe /c start powershell -NoExit -Command "cd '$ROOT\\llama-cpp-ipex-llm-2.3.0b20250424-win'; .\llama-server.exe -m .\models\Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf"

cmd.exe /c start powershell -NoExit -Command "cd '$ROOT'; .\.venv\Scripts\Activate.ps1; python RegoLocalRAGChat.py"