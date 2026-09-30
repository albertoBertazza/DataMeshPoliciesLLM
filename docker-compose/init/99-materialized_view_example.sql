CREATE OR REPLACE VIEW iceberg.inventory.available_products AS
SELECT
    product_index,
    name,
    brand,
    category,
    price,
    currency,
    stock,
    color,
    size
FROM iceberg.inventory.products
WHERE stock > 0
  AND LOWER(availability) = 'in stock';


CREATE OR REPLACE MATERIALIZED VIEW iceberg.inventory.inventory_summary AS
SELECT
    category,
    brand,
    COUNT(*) AS product_count,
    SUM(stock) AS total_stock,
    AVG(price) AS average_price,
    MIN(price) AS minimum_price,
    MAX(price) AS maximum_price
FROM iceberg.inventory.products
WHERE stock > 0
GROUP BY
    category,
    brand;