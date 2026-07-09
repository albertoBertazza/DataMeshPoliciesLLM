-- ======================
-- FINANCE DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_finance
    WITH (
    location = 's3://warehouse/datasets/finance/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_finance.employee_finance_raw (
                                                                     employee_id VARCHAR,
                                                                     department VARCHAR,
                                                                     annual_salary VARCHAR,
                                                                     bonus VARCHAR,
                                                                     benefits VARCHAR,
                                                                     total_cost VARCHAR,
                                                                     annual_revenue_generated VARCHAR,
                                                                     profit_contribution VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/finance/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create Iceberg table
CREATE SCHEMA IF NOT EXISTS iceberg.finance;

CREATE TABLE IF NOT EXISTS iceberg.finance.employee_finance (
                                                                employee_id VARCHAR,
                                                                department VARCHAR,
                                                                annual_salary INTEGER,
                                                                bonus INTEGER,
                                                                benefits INTEGER,
                                                                total_cost INTEGER,
                                                                annual_revenue_generated INTEGER,
                                                                profit_contribution INTEGER
)
    WITH (
        location = 's3://warehouse/iceberg/finance/employee_finance/'
        );

-- Step 3: Load data into Iceberg
INSERT INTO iceberg.finance.employee_finance
SELECT
    employee_id,
    department,
    TRY_CAST(annual_salary AS INTEGER),
    TRY_CAST(bonus AS INTEGER),
    TRY_CAST(benefits AS INTEGER),
    TRY_CAST(total_cost AS INTEGER),
    TRY_CAST(annual_revenue_generated AS INTEGER),
    TRY_CAST(profit_contribution AS INTEGER)
FROM hive.raw_finance.employee_finance_raw;