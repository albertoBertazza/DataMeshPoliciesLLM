-- ======================
-- DEMOGRAPHICS DOMAIN
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_demographics
    WITH (location = 's3://warehouse/datasets/UCIAdultIncomeDataset/');

CREATE TABLE IF NOT EXISTS hive.raw_demographics.population_raw (
                                                                    age            VARCHAR,
                                                                    workclass      VARCHAR,
                                                                    fnlwgt         VARCHAR,
                                                                    education      VARCHAR,
                                                                    education_num  VARCHAR,
                                                                    marital_status VARCHAR,
                                                                    occupation     VARCHAR,
                                                                    relationship   VARCHAR,
                                                                    race           VARCHAR,
                                                                    sex            VARCHAR,
                                                                    capital_gain   VARCHAR,
                                                                    capital_loss   VARCHAR,
                                                                    hours_per_week VARCHAR,
                                                                    native_country VARCHAR,
                                                                    income         VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/UCIAdultIncomeDataset/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create empty Iceberg table
CREATE TABLE IF NOT EXISTS iceberg.demographics.population (
                                                               age            INTEGER,
                                                               workclass      VARCHAR,
                                                               fnlwgt         BIGINT,
                                                               education      VARCHAR,
                                                               education_num  INTEGER,
                                                               marital_status VARCHAR,
                                                               occupation     VARCHAR,
                                                               relationship   VARCHAR,
                                                               race           VARCHAR,
                                                               sex            VARCHAR,
                                                               capital_gain   BIGINT,
                                                               capital_loss   BIGINT,
                                                               hours_per_week INTEGER,
                                                               native_country VARCHAR,
                                                               income         VARCHAR
)
    WITH (
        location = 's3://warehouse/iceberg/demographics/population/'
        );

-- Step 3: Load data with type casting
INSERT INTO iceberg.demographics.population
SELECT
    TRY_CAST(age AS INTEGER),
    TRIM(workclass),
    TRY_CAST(fnlwgt AS BIGINT),
    TRIM(education),
    TRY_CAST(education_num AS INTEGER),
    TRIM(marital_status),
    TRIM(occupation),
    TRIM(relationship),
    TRIM(race),
    TRIM(sex),
    TRY_CAST(capital_gain AS BIGINT),
    TRY_CAST(capital_loss AS BIGINT),
    TRY_CAST(hours_per_week AS INTEGER),
    TRIM(native_country),
    TRIM(income)
FROM hive.raw_demographics.population_raw;