import subprocess
import time
import requests


def is_llm_running(url):
    """Return True if an LLM server is already responding."""
    try:
        r = requests.get(f"{url}/health", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


def wait_for_llm(url, timeout=120):
    print("Waiting for local LLM server...")
    start = time.time()

    while time.time() - start < timeout:
        if is_llm_running(url):
            print("LLM server ready")
            return True

        time.sleep(2)

    raise RuntimeError("LLM server did not start within timeout")


def activate_llm(llama_dir, islocal, url, model_name, port, other_params=""):
    if not islocal:
        return

    # Don't start a second server if one is already running.
    if is_llm_running(url):
        print(f"LLM server already running at {url}")
        return

    print("Starting local LLM server...")

    subprocess.Popen(
        [
            "powershell.exe",
            "-NoExit",
            "-Command",
            fr'''
cd "{llama_dir}"
.\llama-server.exe -m .\models\{model_name} --port {port} {other_params} --ctx-size 16384 --gpu-layers 999
'''
        ],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )

    wait_for_llm(url)