#!/bin/bash
set -euo pipefail
password=$(cat /run/secrets/identity_db_password)
psql --username postgres --dbname keycloak --set=ON_ERROR_STOP=1 --set="pwd=$password" <<'SQL'
CREATE ROLE keycloak LOGIN PASSWORD :'pwd';
ALTER DATABASE keycloak OWNER TO keycloak;
GRANT USAGE, CREATE ON SCHEMA public TO keycloak;
SQL
