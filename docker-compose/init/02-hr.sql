-- ======================
-- HR DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_hr
    WITH (location = 's3://warehouse/datasets/IBMHRAnalyticsEmployeeAttritionDataset/');

CREATE TABLE IF NOT EXISTS hive.raw_hr.employees_raw (
                                                         Age                     VARCHAR,
                                                         Attrition               VARCHAR,
                                                         BusinessTravel          VARCHAR,
                                                         DailyRate               VARCHAR,
                                                         Department              VARCHAR,
                                                         DistanceFromHome        VARCHAR,
                                                         Education               VARCHAR,
                                                         EmployeeCount           VARCHAR,
                                                         EmployeeNumber          VARCHAR,
                                                         EnvironmentSatisfaction VARCHAR,
                                                         Gender                  VARCHAR,
                                                         HourlyRate              VARCHAR,
                                                         JobRole                 VARCHAR,
                                                         MonthlyIncome           VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/IBMHRAnalyticsEmployeeAttritionDataset/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create empty Iceberg table at a clean location
CREATE TABLE IF NOT EXISTS iceberg.hr.employees (
                                                    Age                     INTEGER,
                                                    Attrition               VARCHAR,
                                                    BusinessTravel          VARCHAR,
                                                    DailyRate               INTEGER,
                                                    Department              VARCHAR,
                                                    DistanceFromHome        INTEGER,
                                                    Education               INTEGER,
                                                    EmployeeCount           INTEGER,
                                                    EmployeeNumber          INTEGER,
                                                    EnvironmentSatisfaction INTEGER,
                                                    Gender                  VARCHAR,
                                                    HourlyRate              INTEGER,
                                                    JobRole                 VARCHAR,
                                                    MonthlyIncome           INTEGER
)
    WITH (
        location = 's3://warehouse/iceberg/hr/employees/'
        );

-- Step 3: Load data with type casting
INSERT INTO iceberg.hr.employees
SELECT
    TRY_CAST(Age AS INTEGER),
    Attrition,
    BusinessTravel,
    TRY_CAST(DailyRate AS INTEGER),
    Department,
    TRY_CAST(DistanceFromHome AS INTEGER),
    TRY_CAST(Education AS INTEGER),
    TRY_CAST(EmployeeCount AS INTEGER),
    TRY_CAST(EmployeeNumber AS INTEGER),
    TRY_CAST(EnvironmentSatisfaction AS INTEGER),
    Gender,
    TRY_CAST(HourlyRate AS INTEGER),
    JobRole,
    TRY_CAST(MonthlyIncome AS INTEGER)
FROM hive.raw_hr.employees_raw;