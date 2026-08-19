import time

from trino.dbapi import connect


def execute_query(
    host,
    port,
    user,
    password,
    catalog,
    schema,
    sql
):

    connection = connect(
        host=host,
        port=port,
        user=user,
        catalog=catalog,
        schema=schema,
        http_scheme="http"
    )

    cursor = connection.cursor()

    start = time.perf_counter_ns()

    try:

        cursor.execute(sql)

        rows = cursor.fetchmany(5)

        success = True
        error = None

    except Exception as e:

        success = False
        error = str(e)
        rows = []

    elapsed = (
        time.perf_counter_ns()
        - start
    )

    return {
        "success": success,
        "error": error,
        "rows": len(rows),
        "latency_ns": elapsed
    }