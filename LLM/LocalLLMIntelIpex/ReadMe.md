follow those instruction:
https://github.com/intel/ipex-llm/blob/main/docs/mddocs/Quickstart/llamacpp_portable_zip_gpu_quickstart.md

```bash
python.exe -m pip install --upgrade pip
pip install -U "huggingface_hub[cli]"
hf download bartowski/Qwen2.5.1-Coder-7B-Instruct-GGUF --include "Qwen2.5 1-Coder-7B-Instruct-Q4_K_M.gguf" --local-dir ./
cd llama-cpp-ipex-llm-2.3.0b20250424-win
mkdir "models"
cd ..
Move-Item "Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf" "models\"
```


```bash
cd llama-cpp-ipex-llm-2.3.0b20250424-win
.\llama-server.exe -m .\models\Qwen2.5.1-Coder-7B-Instruct-Q4_K_M.gguf
```

example of chatbot:

```bash
.\.venv\Scripts\Activate.ps1
python ChatBot.py
```