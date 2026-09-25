#!/bin/bash
# Structural credential separation (ADR-0019 §19b). Runs once on first
# PostgreSQL start via docker-entrypoint-initdb.d. Role passwords come from
# the environment (set in .env by the operator; never defaults in production).
set -euo pipefail

: "${VARLATCH_MIGRATE_PASSWORD:?set VARLATCH_MIGRATE_PASSWORD in .env}"
: "${VARLATCH_RUNTIME_PASSWORD:?set VARLATCH_RUNTIME_PASSWORD in .env}"
: "${CONVEX_DB_PASSWORD:?set CONVEX_DB_PASSWORD in .env}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
  CREATE ROLE varlatchd_migrate LOGIN PASSWORD '${VARLATCH_MIGRATE_PASSWORD}';
  CREATE ROLE varlatchd_runtime LOGIN PASSWORD '${VARLATCH_RUNTIME_PASSWORD}';
  CREATE DATABASE varlatch OWNER varlatchd_migrate;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname varlatch <<-SQL
  GRANT CONNECT ON DATABASE varlatch TO varlatchd_runtime;
  -- Table-level grants (including the audit append-only restriction) are
  -- applied by varlatchd migration 0003 under the migrate role.
SQL

# Convex Application Plane: own role + database, zero access to varlatch
# (ADR-0019 §4). Convex requires the database named after the instance.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
  CREATE ROLE convex LOGIN PASSWORD '${CONVEX_DB_PASSWORD}';
  CREATE DATABASE convex_self_hosted OWNER convex;
SQL
