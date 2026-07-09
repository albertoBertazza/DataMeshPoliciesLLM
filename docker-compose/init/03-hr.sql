-- ======================
-- HR DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_hr
    WITH (
    location = 's3://warehouse/datasets/hr/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_hr.people_raw (
                                                      "Index"         VARCHAR,
                                                      "User Id"       VARCHAR,
                                                      "First Name"    VARCHAR,
                                                      "Last Name"     VARCHAR,
                                                      "Sex"           VARCHAR,
                                                      "Email"         VARCHAR,
                                                      "Phone"         VARCHAR,
                                                      "Date of birth" VARCHAR,
                                                      "Job Title"     VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/hr/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create Iceberg table
CREATE TABLE IF NOT EXISTS iceberg.hr.people (
                                                 employee_index INTEGER,
                                                 user_id        VARCHAR,
                                                 first_name     VARCHAR,
                                                 last_name      VARCHAR,
                                                 sex            VARCHAR,
                                                 email          VARCHAR,
                                                 phone          VARCHAR,
                                                 date_of_birth  DATE,
                                                 job_title      VARCHAR
)
    WITH (
        location = 's3://warehouse/iceberg/hr/people/'
        );

-- Step 3: Load data into Iceberg
INSERT INTO iceberg.hr.people
SELECT
    TRY_CAST("Index" AS INTEGER),
    "User Id",
    "First Name",
    "Last Name",
    "Sex",
    "Email",
    "Phone",
    TRY_CAST("Date of birth" AS DATE),
    "Job Title"
FROM hive.raw_hr.people_raw;