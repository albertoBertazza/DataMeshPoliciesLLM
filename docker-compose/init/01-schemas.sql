CREATE SCHEMA IF NOT EXISTS iceberg.hr
    WITH (location = 's3://warehouse/datasets/IBMHRAnalyticsEmployeeAttritionDataset/');

CREATE SCHEMA IF NOT EXISTS iceberg.mobility
    WITH (location = 's3://warehouse/datasets/NYCTLCTripRecordDataset/');

CREATE SCHEMA IF NOT EXISTS iceberg.demographics
    WITH (location = 's3://warehouse/datasets/UCIAdultIncomeDataset/');