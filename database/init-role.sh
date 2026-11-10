#!/bin/bash
set -euo pipefail
password=$(cat /run/secrets/app_db_password)
psql --username postgres --dbname audit --set=ON_ERROR_STOP=1 --set="pwd=$password" <<'SQL'
CREATE ROLE audit LOGIN PASSWORD :'pwd';
GRANT CONNECT ON DATABASE audit TO audit;
GRANT USAGE ON SCHEMA public TO audit;
GRANT SELECT, INSERT ON operations TO audit;
GRANT UPDATE(status, finished_at) ON operations TO audit;
SQL
