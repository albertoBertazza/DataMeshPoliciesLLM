-- ======================
-- PROCUREMENT DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_procurement
    WITH (
    location = 's3://warehouse/datasets/procurement/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_procurement.product_catalog_raw (
                                                                        "Index" VARCHAR,
                                                                        "Product ID" VARCHAR,
                                                                        "Product Title" VARCHAR,
                                                                        "Raw Description" VARCHAR,
                                                                        "Brand" VARCHAR,
                                                                        "Category" VARCHAR,
                                                                        "Target Language" VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/procurement/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create Iceberg table
CREATE SCHEMA IF NOT EXISTS iceberg.procurement;

CREATE TABLE IF NOT EXISTS iceberg.procurement.product_catalog (
                                                                   product_index INTEGER,
                                                                   product_id VARCHAR,
                                                                   product_title VARCHAR,
                                                                   raw_description VARCHAR,
                                                                   brand VARCHAR,
                                                                   category VARCHAR,
                                                                   target_language VARCHAR
)
    WITH (
        location = 's3://warehouse/iceberg/procurement/product_catalog/'
        );

-- Step 3: Load data into Iceberg
INSERT INTO iceberg.procurement.product_catalog
SELECT
    TRY_CAST("Index" AS INTEGER),
    "Product ID",
    "Product Title",
    "Raw Description",
    "Brand",
    "Category",
    "Target Language"
FROM hive.raw_procurement.product_catalog_raw;