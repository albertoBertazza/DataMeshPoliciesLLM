import json
import subprocess
import os

REPORT = {"results": []}

TESTER_DIR_PATH = os.getcwd()

TESTS_DIR_PATH = os.path.join(TESTER_DIR_PATH, "tests")
TEST_PATH = os.path.join(TESTS_DIR_PATH, "tests.json")

OUTPUT_DIR_PATH = os.path.join(TESTER_DIR_PATH, "output")
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR_PATH, "tests_outputs.json")



def get_opa_logs():
    proc = subprocess.run(
        ["docker", "compose", "logs", "--no-color", "opa"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout.splitlines()

def launch_test():
    with open(TEST_PATH) as f:
        interactions = json.load(f)["output"]

    for interaction in interactions:

        logs_before = get_opa_logs()

        cmd = [
            "bash",
            "./run_query.sh",
            "--user", interaction["username"],
            "--password", interaction["password"],
            "--query", interaction["query"],
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        logs_after = get_opa_logs()
        new_logs = logs_after[len(logs_before):]

        success = proc.returncode == 0

        REPORT["results"].append({
            "input": {
                "username": interaction["username"],
                "password": interaction["password"],
                "query": interaction["query"],
                "expected_allowed": interaction["allowed"],
            },
            "output": {
                "actual_allowed": success,
                "return_code": proc.returncode,
                "trino_error": (proc.stderr + proc.stdout).strip(),
                "opa_logs": new_logs,
            },
        })

    os.makedirs(OUTPUT_DIR_PATH, exist_ok=True)

    with open(OUTPUT_FILE_PATH, "w") as f:
        json.dump(REPORT, f, indent=2)



if __name__ == "__main__":

    print("=" * 50)
    print(" Trino Test Interaction")
    print("=" * 50)
    launch_test()