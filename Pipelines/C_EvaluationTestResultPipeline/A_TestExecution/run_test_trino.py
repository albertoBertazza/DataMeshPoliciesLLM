import json
import subprocess
import os
import datetime

from Pipelines.costantPath import OUTPUT_TEST_EXECUTION_FILE, OUTPUT_TEST_EVALUATION_PATH, OUTPUT_TEST_GENERATION_FILE


# ---------------------------------------------------------------------------
# OPA LOGS
# ---------------------------------------------------------------------------

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

    logs = (
        proc.stderr
        if proc.stderr
        else proc.stdout
    )

    return logs.splitlines()



def parse_opa_logs(
    logs,
    username
):

    user_info = {}
    requests = []

    pending_requests = {}


    for line in logs:


        try:

            raw_json = line.split(
                " ",
                1
            )[1]

            entry = json.loads(
                raw_json
            )


        except Exception:

            continue



        msg = entry.get(
            "msg",
            ""
        )

        req_id = entry.get(
            "req_id"
        )



        # ---------------------------------
        # Trino request
        # ---------------------------------

        if msg == "Received request.":


            try:

                req_body = json.loads(
                    entry.get(
                        "req_body",
                        "{}"
                    )
                )


                input_data = req_body.get(
                    "input",
                    {}
                )


                action = input_data.get(
                    "action",
                    {}
                ).get(
                    "operation"
                )


                identity = input_data.get(
                    "context",
                    {}
                ).get(
                    "identity",
                    {}
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
        # User info
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


                if body.get(
                    "username"
                ) == username:

                    user_info = body


            except Exception:

                pass



        # ---------------------------------
        # OPA response
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


                    pending_requests[req_id][
                        "result"
                    ] = response.get(
                        "result"
                    )


                    requests.append(
                        pending_requests.pop(
                            req_id
                        )
                    )


            except Exception:

                pass



    return {
        "user_info": user_info,
        "requests": requests
    }



# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def launch_test(
    test_path=OUTPUT_TEST_GENERATION_FILE
):


    print("=" * 50)
    print("Trino Test Interaction")
    print("=" * 50)



    with open(
        test_path,
        "r",
        encoding="utf-8"
    ) as f:

        tests = json.load(f)

    if isinstance(tests, list):
        interactions = tests
    elif isinstance(tests, dict):
        interactions = tests.get("output", [])
    else:
        raise ValueError(f"Unexpected tests.json format: {type(tests)}")


    report = {
        "results": []
    }



    for interaction in interactions:


        print(
            "\nExecuting:",
            interaction["query"], "user: ", interaction["username"]
        )


        since = (
            datetime.datetime.now(
                datetime.UTC
            )
            .isoformat(
                timespec="milliseconds"
            )
            .replace(
                "+00:00",
                "Z"
            )
        )



        cmd = [

            "bash",

            "./Tester/run_query.sh",

            "--user",
            interaction["username"],

            "--password",
            interaction["password"],

            "--query",
            interaction["query"]

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



        report["results"].append(

            {

                "input": {

                    "username":
                        interaction["username"],

                    "password":
                        interaction["password"],

                    "query":
                        interaction["query"],

                    "expected_allowed":
                        interaction["allowed"]

                },


                "output": {

                    "actual_allowed":
                        proc.returncode == 0,


                    "return_code":
                        proc.returncode,


                    "trino_error":
                        proc.stderr.strip()
                        if proc.stderr.strip()
                        else None,


                    "trino_output":
                        proc.stdout.strip()
                        if proc.stdout.strip()
                        else None,


                    "user_info":
                        opa_analysis["user_info"],


                    "requests":
                        opa_analysis["requests"]

                }

            }

        )




    os.makedirs(
        OUTPUT_TEST_EVALUATION_PATH,
        exist_ok=True
    )



    with open(
        OUTPUT_TEST_EXECUTION_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False
        )



    print(
        "\nSaved:",
        OUTPUT_TEST_EXECUTION_FILE
    )


    return report



# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    launch_test()