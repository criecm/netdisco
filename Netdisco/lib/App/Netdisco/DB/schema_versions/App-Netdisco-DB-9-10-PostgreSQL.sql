-- Convert schema '/home/oliver/git/netdisco-frontend-sandpit/Netdisco/bin/../lib/App/Netdisco/DB/schema_versions/App-Netdisco-DB-3-PostgreSQL.sql' to '/home/oliver/git/netdisco-frontend-sandpit/Netdisco/bin/../lib/App/Netdisco/DB/schema_versions/App-Netdisco-DB-4-PostgreSQL.sql':;

BEGIN;

ALTER TABLE node_wireless DROP CONSTRAINT node_wireless_pkey;

COMMIT;

