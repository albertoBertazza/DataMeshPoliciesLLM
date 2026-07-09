# ERP
Financial managers rely entirely on ERP (Enterprise Resource Planning) systems or dedicated accounting databases to run the business

# HRIS
HR teams typically rely on an HRIS (Human Resource Information System) or HCM (Human Capital Management) platform.

# hidden to hr and finance:
When records are "hidden" from HR or Finance, it is usually done via Role-Based Access Controls (RBAC) to protect privacy, 
prevent conflicts of interest, or comply with strict labor laws.The most common types of hidden databases or records include:
Executive Compensation & Equity Databases: Sensitive salary data for C-suite executives, bonuses, or equity/stock options are often hidden from general HR staff and Finance.
Medical & Mental Health Databases: FMLA documents, specific health diagnoses, and accommodation logs are legally restricted from general access.
Legal & Disciplinary Databases: Internal investigations, grievance details, and ongoing litigation records involving employees are typically restricted to the legal department or senior HR.
Dynamic Data Masking: General financial reports or payroll ledgers can be configured to hide names, Social Security numbers/tax IDs, or specific bank routing information from finance users to prevent identity theft or bias.

# NO OPERATOR
we are in a data mesh data is already created, and now it is loaded by etl_job to the data mesh.
Here exist only those security groups.

| Domain           | Example Database / Data Product       | Typical Owner        |
| ---------------- | ------------------------------------- | -------------------- |
| Human Resources  | **HRIC**, Workday HR, Employees       | HR Manager           |
| Finance          | **ERP**, General Ledger, Transactions | Finance Manager      |
| Sales            | CRM, Orders, Opportunities            | Sales Manager        |
| Marketing        | Campaigns, Leads, Customer Engagement | Marketing Manager    |
| Customer Support | Tickets, Cases, SLAs                  | Support Manager      |
| Supply Chain     | Inventory, Warehouses, Shipments      | Supply Chain Manager |
| Manufacturing    | Production, Machines, Quality Control | Operations Manager   |
| Procurement      | Suppliers, Purchase Orders            | Procurement Manager  |
| Logistics        | Deliveries, Routes, Fleet             | Logistics Manager    |
| Legal            | Contracts, Compliance                 | Legal Manager        |
| IT               | Assets, Users, Access Logs            | IT Administrator     |
| Security         | Audit Logs, Identity, Events          | Security Officer     |
| Product          | Product Catalog, Features             | Product Manager      |
| E-commerce       | Customers, Orders, Payments           | E-commerce Manager   |
