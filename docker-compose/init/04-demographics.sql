


-- ======================
-- ADULT INCOME
-- ======================

CREATE TABLE IF NOT EXISTS hive.demographics.adult_income (
                                                              age VARCHAR,
                                                              workclass VARCHAR,
                                                              fnlwgt VARCHAR,
                                                              education VARCHAR,
                                                              education_num VARCHAR,
                                                              marital_status VARCHAR,
                                                              occupation VARCHAR,
                                                              relationship VARCHAR,
                                                              race VARCHAR,
                                                              sex VARCHAR,
                                                              capital_gain VARCHAR,
                                                              capital_loss VARCHAR,
                                                              hours_per_week VARCHAR,
                                                              native_country VARCHAR,
                                                              income VARCHAR
)
    WITH (
        format = 'CSV',
        external_location = 's3a://warehouse/datasets/UCIAdultIncomeDataset/'
        -- note: adult.data has no header, so NO skip_header_line_count
        );