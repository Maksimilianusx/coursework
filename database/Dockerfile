FROM postgres:17.11-bookworm
COPY init.sql /docker-entrypoint-initdb.d/001-init.sql
COPY --chmod=755 init-role.sh /docker-entrypoint-initdb.d/002-role.sh
