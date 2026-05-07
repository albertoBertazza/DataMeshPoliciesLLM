-- ======================
-- NYC TAXI (PARQUET)
-- ======================

CREATE TABLE hive.mobility.taxi_trips (
                                          vendor_id VARCHAR,
                                          tpep_pickup_datetime VARCHAR,
                                          tpep_dropoff_datetime VARCHAR,
                                          passenger_count VARCHAR,
                                          trip_distance VARCHAR,
                                          ratecode_id VARCHAR,
                                          store_and_fwd_flag VARCHAR,
                                          pu_location_id VARCHAR,
                                          do_location_id VARCHAR,
                                          payment_type VARCHAR,
                                          fare_amount VARCHAR,
                                          extra VARCHAR,
                                          mta_tax VARCHAR,
                                          tip_amount VARCHAR,
                                          tolls_amount VARCHAR,
                                          total_amount VARCHAR
)
    WITH (
        format = 'PARQUET',
        external_location = 's3a://warehouse/datasets/NYCTLCTripRecordDataset/'
        );

