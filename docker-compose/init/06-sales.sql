-- ======================
-- SALES DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_sales
    WITH (
    location = 's3://warehouse/datasets/sales/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_sales.offers_raw (
                                                         "Index" VARCHAR,
                                                         "EAN" VARCHAR,
                                                         "Stock" VARCHAR,
                                                         "Price" VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/sales/',
        format = 'CSV',
        skip_header_line_count = 1
        );


-- Step 2: Create Iceberg table
CREATE SCHEMA IF NOT EXISTS iceberg.sales;

CREATE TABLE IF NOT EXISTS iceberg.sales.offers (
                                                    offer_index INTEGER,
                                                    ean VARCHAR,
                                                    stock INTEGER,
                                                    price DOUBLE
)
    WITH (
        location = 's3://warehouse/iceberg/sales/offers/'
        );


-- Step 3: Load data into Iceberg
INSERT INTO iceberg.sales.offers
SELECT
    TRY_CAST("Index" AS INTEGER),
    "EAN",
    TRY_CAST("Stock" AS INTEGER),
    TRY_CAST("Price" AS DOUBLE)
FROM hive.raw_sales.offers_raw;