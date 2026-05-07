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
