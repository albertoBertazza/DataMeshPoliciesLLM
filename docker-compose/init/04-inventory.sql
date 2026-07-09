-- ======================
-- INVENTORY DOMAIN (ICEBERG)
-- ======================

-- Step 1: Register raw CSV as Hive external table
CREATE SCHEMA IF NOT EXISTS hive.raw_inventory
    WITH (
    location = 's3://warehouse/datasets/inventory/'
    );

CREATE TABLE IF NOT EXISTS hive.raw_inventory.products_raw (
                                                               "Index" VARCHAR,
                                                               "Name" VARCHAR,
                                                               "Description" VARCHAR,
                                                               "Brand" VARCHAR,
                                                               "Category" VARCHAR,
                                                               "Price" VARCHAR,
                                                               "Currency" VARCHAR,
                                                               "Stock" VARCHAR,
                                                               "EAN" VARCHAR,
                                                               "Color" VARCHAR,
                                                               "Size" VARCHAR,
                                                               "Availability" VARCHAR,
                                                               "Internal ID" VARCHAR
)
    WITH (
        external_location = 's3://warehouse/datasets/inventory/',
        format = 'CSV',
        skip_header_line_count = 1
        );

-- Step 2: Create Iceberg table
CREATE SCHEMA IF NOT EXISTS iceberg.inventory;

CREATE TABLE IF NOT EXISTS iceberg.inventory.products (
                                                          product_index INTEGER,
                                                          name VARCHAR,
                                                          description VARCHAR,
                                                          brand VARCHAR,
                                                          category VARCHAR,
                                                          price DOUBLE,
                                                          currency VARCHAR,
                                                          stock INTEGER,
                                                          ean VARCHAR,
                                                          color VARCHAR,
                                                          size VARCHAR,
                                                          availability VARCHAR,
                                                          internal_id INTEGER
)
    WITH (
        location = 's3://warehouse/iceberg/inventory/products/'
        );

-- Step 3: Load data into Iceberg
INSERT INTO iceberg.inventory.products
SELECT
    TRY_CAST("Index" AS INTEGER),
    "Name",
    "Description",
    "Brand",
    "Category",
    TRY_CAST("Price" AS DOUBLE),
    "Currency",
    TRY_CAST("Stock" AS INTEGER),
    "EAN",
    "Color",
    "Size",
    "Availability",
    TRY_CAST("Internal ID" AS INTEGER)
FROM hive.raw_inventory.products_raw;