#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for name in app_db_password app_db_admin_password identity_db_password identity_db_admin_password manager_client_secret bootstrap_admin_password demo_password; do
  if ! docker secret inspect "course_$name" >/dev/null 2>&1; then
    docker secret create "course_$name" "secrets/$name.txt"
  fi
done
for name in cert key; do
  if ! docker secret inspect "course_tls_$name" >/dev/null 2>&1; then
    file="secrets/tls.$name"
    [ "$name" = cert ] && file=secrets/tls.crt
    docker secret create "course_tls_$name" "$file"
  fi
done
