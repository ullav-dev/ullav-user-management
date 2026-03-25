#!/bin/sh
set -e

DB_PASS=$(cat /run/secrets/db_password)
export PGPASSWORD="$DB_PASS"
export PGHOST=db
export PGUSER="$DATABASE_USER"
export PGDATABASE="$DATABASE_NAME"

echo "==> Ensuring schema_migrations table exists"
psql -c "
  CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
"

for file in $(ls /migrations/*.sql | sort); do
  name=$(basename "$file")

  already_applied=$(psql -tAc "SELECT COUNT(*) FROM schema_migrations WHERE filename = '$name'")

  if [ "$already_applied" -eq "1" ]; then
    echo "==> Skipping $name (already applied)"
  else
    echo "==> Applying $name"
    psql -f "$file"
    psql -c "INSERT INTO schema_migrations (filename) VALUES ('$name')"
    echo "==> Applied $name"
  fi
done

echo "==> Migrations complete"
