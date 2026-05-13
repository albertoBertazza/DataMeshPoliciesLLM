# trino-hive-docker
trino + hive + minio with postgres in docker compose






# Trino-Hive-Postgres-Minio Exercise

This is a personal exercise for me to understand Trino and its architecture, especially with 
Hive Metastore/ Postgres/ Minio. The idea of the exercise is originated from 
https://trino.io/blog/2020/10/20/intro-to-hive-connector.html. The only difference is that I 
changed the DB of Hive Metastore from MariaDB to PostgresDB and tried to implement it 
with k8s with the help of https://github.com/alexcpn/presto_in_kubernetes.

## Architechure Diagram
![Exercise 1 (Trino Hive Postgres Minio on k8s)](https://user-images.githubusercontent.com/84711996/186559791-1b974247-dd1d-4ba1-bada-fe0759f5c8d4.jpeg)


## Run Locally with Docker-compose
The implementation with docker-compose is referred to https://github.com/bitsondatadev/trino-getting-started/tree/main/hive/trino-minio 
with the help of https://github.com/bitsondatadev/hive-metastore/pull/2/commits to build a Hive Metastore image to
support PostgresDB.

OPEN DOCKER DESKTOP AND RUN THE FOLLOWING COMMANDS IN YOUR TERMINAL:
Step 0 - Go to the docker-compose directory
```bash
cd docker-compose
```
Step 1 - Build a Hive Metastore image with the Dockerfile to support PostgresDB
```bash
docker build -t my-hive-metastore .
```
Step 2 - Implement with docker-compose
```bash
docker-compose up -d
```
Step 3 - Check if a Bucket in MinIO is created
- account: minio
- password: minio123

with name "warehouse", the minio-init in docker compose will do it automatically.

Step 4 - Into the runnung trino container
```bash
docker container exec -it docker-compose-trino-coordinator-1 trino
```
IF TRINO . IS REPLACED WITH N JUST USE POWERSHELL

```bash

trino> SHOW CATALOGS;
 Catalog
---------
 hive               ## contains the Hive Metastore connector
 iceberg            ## contains the Iceberg connector
 system
 tpcds
 tpch
(5 rows)

Query 20260507_194548_00019_dmrzi, FINISHED, 1 node
Splits: 19 total, 19 done (100.00%)
0.23 [0 rows, 178B] [0 rows/s, 777B/s]


trino> SHOW SCHEMAS FROM iceberg;
       Schema
--------------------
 default
 demographics
 hr                          ## we will use this as example
 information_schema
 mobility
 raw_demographics
 raw_hr
 raw_mobility
 system
(9 rows)

Query 20260507_194557_00020_dmrzi, FINISHED, 1 node
Splits: 19 total, 19 done (100.00%)
0.23 [9 rows, 464B] [38 rows/s, 1.94KiB/s]




trino> SHOW TABLES FROM iceberg.hr;       # verify the tables in hr schema
Table
-----------
employees                             # only one table in hr schema
(1 row)

Query 20260507_105700_00009_gmscr, FINISHED, 1 node
Splits: 19 total, 19 done (100.00%)
0.23 [1 rows, 133B] [4 rows/s, 591B/s]



trino> SELECT * FROM iceberg.hr.employees LIMIT 10;  ## check the data in employees table
 age | attrition |  businesstravel   | dailyrate |       department       | distancefromhome | education | employeecoun>
-----+-----------+-------------------+-----------+------------------------+------------------+-----------+------------->
  41 | Yes       | Travel_Rarely     |      1102 | Sales                  |                1 |         2 |          NUL>
  33 | No        | Travel_Frequently |      1392 | Research & Development |                3 |         4 |          NUL>
  27 | No        | Travel_Rarely     |       591 | Research & Development |                2 |         1 |          NUL>
  32 | No        | Travel_Frequently |      1005 | Research & Development |                2 |         2 |          NUL>
  59 | No        | Travel_Rarely     |      1324 | Research & Development |                3 |         3 |          NUL>
  49 | No        | Travel_Frequently |       279 | Research & Development |                8 |         1 |          NUL>
  37 | Yes       | Travel_Rarely     |      1373 | Research & Development |                2 |         2 |          NUL>
  30 | No        | Travel_Rarely     |      1358 | Research & Development |               24 |         1 |          NUL>
  38 | No        | Travel_Frequently |       216 | Research & Development |               23 |         3 |          NUL>
  36 | No        | Travel_Rarely     |      1299 | Research & Development |               27 |         3 |          NUL>
(10 rows)
(END)
```







### Execute Trino sql command with other username
```bash
docker exec -it docker-compose-trino-coordinator-1 trino --user alice
```
it will open a trino CLI with user alice, then you can run the same sql command to create schema and table. You can also check the trino dashboard to see the query history with different users.
```text
>trino
```
and paste:
```sql
SHOW SCHEMAS;
```
You will get the following result:
```text
 Query 20260507_075237_00004_wytmq failed: Access Denied: Cannot execute query
```


### CREATE DATASET with AI not compliant with GDPR
https://www.mockaroo.com/?utm_source=chatgpt.com
### (Optional: see the metadata store in Postgres)
Step 6 - Into the running postgres container
```bash 
docker exec -it "docker-compose_postgres_1" psql -U admin -d "hive_db"
```
Step 7 - Run SQL commands on postgresDB to see where the metadata is stored. 
```sql
SELECT
 "DB_ID",
 "DB_LOCATION_URI",
 "NAME", 
 "OWNER_NAME",
 "OWNER_TYPE",
 "CTLG_NAME"
FROM "DBS";
```

For more metadata detail, kindly check: 
https://github.com/bitsondatadev/trino-getting-started/tree/main/hive/trino-minio

Step 8 - Close down the running containers
```bash
docker-compose down
```


# OPA Policy for Trino

> ATTENTION
> 
> opa.example.com/v1/data/trino/ replace with opa:8181/v1/data/trino/authz/

name | description
--- | ---
opa.policy.uri | The required URI for the OPA endpoint, for example, https://opa.example.com/v1/data/trino/allow.
opa.policy.row-filters-uri | The optional URI for fetching row filters - if not set no row filtering is applied. For example, https://opa.example.com/v1/data/trino/rowFilters.
opa.policy.column-masking-uri | The optional URI for fetching column masks - if not set no masking is applied. For example, https://opa.example.com/v1/data/trino/columnMask.
opa.policy.batch-column-masking-uri | The optional URI for fetching columns masks in batches; must not be used with opa.policy.column-masking-uri. For example, http://opa.example.com/v1/data/trino/batchColumnMasks.
opa.policy.batched-uri | The optional URI for activating batch mode for certain authorization queries where batching is applicable, for example https://opa.example.com/v1/data/trino/batch. Batch mode is described Batch mode.
opa.log-requests | Configure if request details, including URI, headers and the entire body, are logged prior to sending them to OPA. Defaults to false.
opa.log-responses | Configure if OPA response details, including URI, status code, headers and the entire body, are logged. Defaults to false.
opa.allow-permission-management-operations | Configure if permission management operations are allowed. Find more details in Permission management. Defaults to false.
opa.http-client.* | Optional HTTP client configurations for the connection from Trino to OPA, for example opa.http-client.http-proxy for configuring the HTTP proxy. Find more details in HTTP client properties.
opa.context-file | Optional properties file, containing user defined properties (e.g. tenant namespace, tier or cluster) to be included in the OPA query context.


## opa.allow-permission-management-operations
Directly managed by Trino, without the need to call OPA, these operations include:
- GrantSchemaPrivilege
- DenySchemaPrivilege
- RevokeSchemaPrivilege
- GrantTablePrivilege
- DenyTablePrivilege
- RevokeTablePrivilege
- CreateRole
- DropRole
- GrantRoles
- RevokeRoles

if false or true, OPA is never called for these operations, and they are always allowed or denied respectively. If set to "opa", OPA is called for these operations, and the decision is based on the OPA response.

By default, it is set to false.

This avoids changes of permissions to be made without OPA's approval, which is important for security.
Additionally, users are always allowed to show information about roles (SHOW ROLES), regardless of this setting. The following operations are always allowed:
- ShowRoles
- ShowCurrentRoles
- ShowRoleGrants


## opa.policy.row-filters-uri
Row filtering allows Trino to remove some rows from the result before returning it to the caller, controlling what data different users can see.
### Example of OPA policy
etc/access-control.properties
```properties
access-control.name=opa

opa.policy.uri=http://opa:8181/v1/data/trino/authz/allow
opa.policy.row-filters-uri=http://opa:8181/v1/data/trino/authz/rowFilters
```

policy.rego 
```rego
package trino.authz
import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

is_admin if {
    input.context.identity.user == "trino"
}

#------------------------- ROW FILTER--------------------------
table_resource := input.action.resource.table
# we avoid to get rows with attrition='Yes' in iceberg.hr.employees table
rowFilters contains {"expression": "trim(attrition) <> 'Yes'"} if {
  not is_admin
  table_resource.catalogName == "iceberg"
  table_resource.schemaName == "hr"
  table_resource.tableName == "employees"
}
```

### Example query
```bash
 docker exec -it docker-compose-trino-coordinator-1 trino --user test_access
trino> SELECT * FROM iceberg.hr.employees LIMIT 10;
 age | attrition |  businesstravel   | dailyrate |       department       | distancefromhome | education | employeecoun>
-----+-----------+-------------------+-----------+------------------------+------------------+-----------+------------->
  49 | No        | Travel_Frequently |       279 | Research & Development |                8 |         1 |          NUL>
  33 | No        | Travel_Frequently |      1392 | Research & Development |                3 |         4 |          NUL>
  27 | No        | Travel_Rarely     |       591 | Research & Development |                2 |         1 |          NUL>
  32 | No        | Travel_Frequently |      1005 | Research & Development |                2 |         2 |          NUL>
  59 | No        | Travel_Rarely     |      1324 | Research & Development |                3 |         3 |          NUL>
  30 | No        | Travel_Rarely     |      1358 | Research & Development |               24 |         1 |          NUL>
  38 | No        | Travel_Frequently |       216 | Research & Development |               23 |         3 |          NUL>
  36 | No        | Travel_Rarely     |      1299 | Research & Development |               27 |         3 |          NUL>
  35 | No        | Travel_Rarely     |       809 | Research & Development |               16 |         3 |          NUL>
  29 | No        | Travel_Rarely     |       153 | Research & Development |               15 |         2 |          NUL>
(10 rows)
```
all rows have attrition different from 'Yes'.

## opa.policy.column-masking-uri

### What i want to filter
starting from:
```bash
docker exec -it docker-compose-trino-coordinator-1 trino
trino> SELECT * FROM iceberg.mobility.taxi_trips LIMIT 5;
 vendor_id |    tpep_pickup_datetime    |   tpep_dropoff_datetime    | passenger_count | trip_distance | ratecode_id | >
-----------+----------------------------+----------------------------+-----------------+---------------+-------------+->
      NULL | 2026-01-07 19:41:01.000000 | 2026-01-07 19:48:06.000000 |               1 |           1.2 |        NULL | >
      NULL | 2026-01-07 19:47:17.000000 | 2026-01-07 19:55:51.000000 |               1 |          1.68 |        NULL | >
      NULL | 2026-01-07 19:00:19.000000 | 2026-01-07 19:05:41.000000 |               2 |          0.83 |        NULL | >
      NULL | 2026-01-07 19:07:43.000000 | 2026-01-07 19:14:22.000000 |               3 |          0.78 |        NULL | >
      NULL | 2026-01-07 19:16:10.000000 | 2026-01-07 19:32:41.000000 |               1 |          2.35 |        NULL | >
(5 rows)
(END)
```
I want to set passenger_count to 0 for all rows and hide part of the timestamp: the hours and minute

### Example code
```properties
access-control.name=opa

opa.policy.uri=http://opa:8181/v1/data/trino/authz/allow
# Column filtering
opa.policy.column-masking-uri=http://opa:8181/v1/data/trino/authz/columnMask
```
```rego
package trino.authz
import future.keywords.in
import future.keywords.if
import future.keywords.contains

default allow := false

is_admin if {
    input.context.identity.user == "trino"
}

# --- MASK passenger_count ---
columnMask := {"expression": "0"} if {
    not is_admin
    input.action.resource.column.catalogName == "iceberg"
    input.action.resource.column.schemaName  == "mobility"
    input.action.resource.column.tableName   == "taxi_trips"
    input.action.resource.column.columnName  == "passenger_count"
}

# --- MASK datetime ---
columnMask := {"expression": "date_trunc('day', tpep_dropoff_datetime)"} if {
    not is_admin
    input.action.resource.column.catalogName == "iceberg"
    input.action.resource.column.schemaName  == "mobility"
    input.action.resource.column.tableName   == "taxi_trips"
    input.action.resource.column.columnName  == "tpep_dropoff_datetime"
}
```


### Example query
```bash
docker exec -it docker-compose-trino-coordinator-1 trino --user test_access
trino> SELECT * FROM iceberg.mobility.taxi_trips LIMIT 5;
vendor_id |    tpep_pickup_datetime    |   tpep_dropoff_datetime    | passenger_count | trip_distance | ratecode_id | store_and_fwd_flag | pu_location_id | >
-----------+----------------------------+----------------------------+-----------------+---------------+-------------+--------------------+----------------+->
NULL | 2026-01-31 15:34:56.000000 | 2026-01-31 00:00:00.000000 |               0 |           2.2 |        NULL | N                  |           NULL | >
NULL | 2026-01-31 15:57:27.000000 | 2026-01-31 00:00:00.000000 |               0 |           3.0 |        NULL | N                  |           NULL | >
NULL | 2026-01-31 15:47:30.000000 | 2026-01-31 00:00:00.000000 |               0 |          0.65 |        NULL | N                  |           NULL | >
NULL | 2026-01-31 15:20:47.000000 | 2026-01-31 00:00:00.000000 |               0 |           1.0 |        NULL | N                  |           NULL | >
NULL | 2026-01-31 15:24:14.000000 | 2026-01-31 00:00:00.000000 |               0 |          1.12 |        NULL | N                  |           NULL | >
(5 rows)
```
passenger_count is always 0 and tpep_dropoff_datetime hours, minute and seconds are always 00.



