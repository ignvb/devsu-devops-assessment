#!/bin/sh

set -e

DB_PATH="$APP_HOME/db.sqlite3"

if [ ! -f "$DB_PATH" ]; then
    echo "Database not found!"
    echo "Making migrations"
    python manage.py makemigrations
    python manage.py migrate
else
    echo "Database found"
fi

exec python manage.py runserver 0.0.0.0:8000 --noreload
