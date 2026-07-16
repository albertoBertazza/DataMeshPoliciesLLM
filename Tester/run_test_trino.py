import json
import subprocess
import os
import datetime


REPORT = {"results": []}

DATA_MESH_DIR = os.getcwd()
TESTER_DIR_PATH = os.path.join(DATA_MESH_DIR, "Tester")

TESTS_DIR_PATH = os.path.join(TESTER_DIR_PATH, "tests")
TEST_PATH = os.path.join(TESTS_DIR_PATH, "tests.json")

OUTPUT_DIR_PATH = os.path.join(TESTER_DIR_PATH, "output")
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR_PATH, "tests_outputs.json")

LLM_DIR = os.path.join(DATA_MESH_DIR, "LLM")
LLM_PIPELINE_DIR = os.path.join(LLM_DIR, "LLMPipeline")
EVALUATION_DIR = os.path.join(LLM_PIPELINE_DIR, "Evaluation")
RESULTS_DIR = os.path.join(EVALUATION_DIR, "ResultInteraction")
TEST_OUTPUT_FILE_PATH = os.path.join(RESULTS_DIR, "test_results.json")

print("test", TEST_OUTPUT_FILE_PATH)



def get_opa_logs_since(since):
    proc = subprocess.run(
        [
            "docker",
            "logs",
            "--timestamps",
            "--since",
            since,
            "opa",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logs = proc.stderr if proc.stderr else proc.stdout

    return logs.splitlines()


def parse_opa_logs(logs, username):
    user_info = {}
    requests = []

    pending_requests = {}


    for line in logs:

        try:
            raw_json = line.split(" ", 1)[1]
            entry = json.loads(raw_json)

        except Exception:
            continue


        msg = entry.get("msg", "")
        req_id = entry.get("req_id")


        # ---------------------------------
        # Received Trino authorization request
        # ---------------------------------
        if msg == "Received request.":

            try:
                req_body = json.loads(
                    entry.get("req_body", "{}")
                )

                action = (
                    req_body
                    .get("input", {})
                    .get("action", {})
                    .get("operation")
                )

                identity = (
                    req_body
                    .get("input", {})
                    .get("context", {})
                    .get("identity", {})
                )

                request_user = identity.get(
                    "user"
                )

                if request_user == username:

                    pending_requests[req_id] = {
                        "action": action
                    }

            except Exception:
                pass



        # ---------------------------------
        # Extract user information
        # ---------------------------------
        if "HTTP RESPONSE:" in msg:

            try:

                response_raw = msg.split(
                    "HTTP RESPONSE:",
                    1
                )[1].strip()

                response = json.loads(
                    response_raw
                )

                body = response.get(
                    "body",
                    {}
                )

                if body.get("username") == username:
                    user_info = body

            except Exception:
                pass



        # ---------------------------------
        # Authorization response
        # ---------------------------------
        if msg == "Sent response.":

            try:

                if req_id in pending_requests:

                    response = json.loads(
                        entry.get(
                            "resp_body",
                            "{}"
                        )
                    )

                    pending_requests[req_id]["result"] = (
                        response.get("result")
                    )

                    requests.append(
                        pending_requests.pop(req_id)
                    )

            except Exception:
                pass


    return {
        "user_info": user_info,
        "requests": requests,
    }



def launch_test():

    with open(TEST_PATH) as f:
        interactions = json.load(f)["output"]


    for interaction in interactions:

        since = (
            datetime.datetime.now(datetime.UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )


        cmd = [
            "bash",
            "./Tester/run_query.sh",
            "--user",
            interaction["username"],
            "--password",
            interaction["password"],
            "--query",
            interaction["query"],
        ]


        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )


        opa_logs = get_opa_logs_since(
            since
        )


        opa_analysis = parse_opa_logs(
            opa_logs,
            interaction["username"]
        )


        REPORT["results"].append(
            {
                "input": {
                    "username": interaction["username"],
                    "password": interaction["password"],
                    "query": interaction["query"],
                    "expected_allowed": interaction["allowed"],
                },
                "output": {
                    "actual_allowed": proc.returncode == 0,
                    "return_code": proc.returncode,

                    "trino_error": (
                        proc.stderr.strip()
                        if proc.stderr.strip()
                        else None
                    ),

                    "trino_output": (
                        proc.stdout.strip()
                        if proc.stdout.strip()
                        else None
                    ),

                    "user_info": opa_analysis["user_info"],

                    "requests": opa_analysis["requests"],
                },
            }
        )


    os.makedirs(
        OUTPUT_DIR_PATH,
        exist_ok=True
    )


    with open(
        OUTPUT_FILE_PATH,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            REPORT,
            f,
            indent=4,
            ensure_ascii=False,
        )

    # write in evaluation folder
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(
        TEST_OUTPUT_FILE_PATH,
            "w",
            encoding="utf-8",
    ) as f:
        json.dump(
            REPORT,
            f,
            indent=4,
            ensure_ascii=False,
        )


if __name__ == "__main__":

    print("=" * 50)
    print(" Trino Test Interaction")
    print("=" * 50)

    launch_test()