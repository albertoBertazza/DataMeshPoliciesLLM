-- ======================
-- SUPPORT DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_support
    WITH (
    location = 's3://warehouse/datasets/support/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_support.support_tickets_raw (
                                                                    "Index" VARCHAR,
                                                                    "Ticket ID" VARCHAR,
                                                                    "Customer Plan" VARCHAR,
                                                                    "Ticket Subject" VARCHAR,
                                                                    "Ticket Text" VARCHAR,
                                                                    "Priority Hint" VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/support/',
        format = 'CSV',
        skip_header_line_count = 1
        );


-- Step 2: Create Iceberg table
CREATE SCHEMA IF NOT EXISTS iceberg.support;

CREATE TABLE IF NOT EXISTS iceberg.support.support_tickets (
                                                               ticket_index INTEGER,
                                                               ticket_id VARCHAR,
                                                               customer_plan VARCHAR,
                                                               ticket_subject VARCHAR,
                                                               ticket_text VARCHAR,
                                                               priority_hint VARCHAR
)
    WITH (
        location = 's3://warehouse/iceberg/support/support_tickets/'
        );


-- Step 3: Load data into Iceberg
INSERT INTO iceberg.support.support_tickets
SELECT
    TRY_CAST("Index" AS INTEGER),
    "Ticket ID",
    "Customer Plan",
    "Ticket Subject",
    "Ticket Text",
    "Priority Hint"
FROM hive.raw_support.support_tickets_raw;