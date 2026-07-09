CREATE SCHEMA IF NOT EXISTS iceberg.finance
    WITH (location = 's3://warehouse/datasets/finance/');

CREATE SCHEMA IF NOT EXISTS iceberg.hr
    WITH (location = 's3://warehouse/datasets/hr/');

CREATE SCHEMA IF NOT EXISTS iceberg.inventory
    WITH (location = 's3://warehouse/datasets/inventory/');

CREATE SCHEMA IF NOT EXISTS iceberg.procurement
    WITH (location = 's3://warehouse/datasets/procurement/');

CREATE SCHEMA IF NOT EXISTS iceberg.sales
    WITH (location = 's3://warehouse/datasets/sales/');

CREATE SCHEMA IF NOT EXISTS iceberg.support
    WITH (location = 's3://warehouse/datasets/support/');

CREATE SCHEMA IF NOT EXISTS iceberg.inventory
    WITH (location = 's3://warehouse/datasets/inventory/');
