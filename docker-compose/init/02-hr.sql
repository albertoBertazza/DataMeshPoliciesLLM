-- ======================
-- HR DATASET
-- ======================

CREATE TABLE hive.hr.employees (
                                   Age VARCHAR,
                                   Attrition VARCHAR,
                                   BusinessTravel VARCHAR,
                                   DailyRate VARCHAR,
                                   Department VARCHAR,
                                   DistanceFromHome VARCHAR,
                                   Education VARCHAR,
                                   EmployeeCount VARCHAR,
                                   EmployeeNumber VARCHAR,
                                   EnvironmentSatisfaction VARCHAR,
                                   Gender VARCHAR,
                                   HourlyRate VARCHAR,
                                   JobRole VARCHAR,
                                   MonthlyIncome VARCHAR
)
    WITH (
        format = 'CSV',
        skip_header_line_count = 1,
        external_location = 's3a://warehouse/datasets/IBMHRAnalyticsEmployeeAttritionDataset/'
        );
