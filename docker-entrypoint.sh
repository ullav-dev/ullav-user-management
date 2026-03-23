#!/bin/sh
set -e

# DATABASE_URL does not support the _FILE convention in the app, so we
# construct it here by reading the db_password Docker secret directly.
DB_PASS=$(cat /run/secrets/db_password)
export DATABASE_URL="postgresql://${DATABASE_USER}:${DB_PASS}@db:5432/${DATABASE_NAME}"

exec ./user_management
