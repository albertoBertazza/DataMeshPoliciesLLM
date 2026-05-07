CREATE SCHEMA IF NOT EXISTS hive.raw_mobility
    WITH (location = 's3://warehouse/datasets/NYCTLCTripRecordDataset/');


CREATE TABLE IF NOT EXISTS hive.raw_mobility.taxi_trips_raw (
                                                                vendor_id INTEGER,
                                                                tpep_pickup_datetime TIMESTAMP,
                                                                tpep_dropoff_datetime TIMESTAMP,
                                                                passenger_count INTEGER,
                                                                trip_distance DOUBLE,
                                                                ratecode_id INTEGER,
                                                                store_and_fwd_flag VARCHAR,
                                                                pu_location_id INTEGER,
                                                                do_location_id INTEGER,
                                                                payment_type INTEGER,
                                                                fare_amount DOUBLE,
                                                                extra DOUBLE,
                                                                mta_tax DOUBLE,
                                                                tip_amount DOUBLE,
                                                                tolls_amount DOUBLE,
                                                                total_amount DOUBLE
)
    WITH (
        external_location = 's3://warehouse/datasets/NYCTLCTripRecordDataset/',
        format = 'PARQUET'
        );

CREATE TABLE IF NOT EXISTS iceberg.mobility.taxi_trips (
                                                           vendor_id INTEGER,
                                                           tpep_pickup_datetime TIMESTAMP,
                                                           tpep_dropoff_datetime TIMESTAMP,
                                                           passenger_count INTEGER,
                                                           trip_distance DOUBLE,
                                                           ratecode_id INTEGER,
                                                           store_and_fwd_flag VARCHAR,
                                                           pu_location_id INTEGER,
                                                           do_location_id INTEGER,
                                                           payment_type INTEGER,
                                                           fare_amount DOUBLE,
                                                           extra DOUBLE,
                                                           mta_tax DOUBLE,
                                                           tip_amount DOUBLE,
                                                           tolls_amount DOUBLE,
                                                           total_amount DOUBLE
)
    WITH (
        location = 's3://warehouse/iceberg/mobility/taxi_trips/'
        );

INSERT INTO iceberg.mobility.taxi_trips
SELECT
    TRY_CAST(vendor_id AS INTEGER),
    TRY_CAST(tpep_pickup_datetime AS TIMESTAMP),
    TRY_CAST(tpep_dropoff_datetime AS TIMESTAMP),
    TRY_CAST(passenger_count AS INTEGER),
    TRY_CAST(trip_distance AS DOUBLE),
    TRY_CAST(ratecode_id AS INTEGER),
    store_and_fwd_flag,
    TRY_CAST(pu_location_id AS INTEGER),
    TRY_CAST(do_location_id AS INTEGER),
    TRY_CAST(payment_type AS INTEGER),
    TRY_CAST(fare_amount AS DOUBLE),
    TRY_CAST(extra AS DOUBLE),
    TRY_CAST(mta_tax AS DOUBLE),
    TRY_CAST(tip_amount AS DOUBLE),
    TRY_CAST(tolls_amount AS DOUBLE),
    TRY_CAST(total_amount AS DOUBLE)
FROM hive.raw_mobility.taxi_trips_raw;