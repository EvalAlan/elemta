"""Create a restricted mailbox database owner during new lab-cluster bootstrap."""
import os
import sys
import psycopg
from psycopg import sql

with psycopg.connect(sys.argv[1], autocommit=True) as conn:
    conn.execute(sql.SQL('CREATE ROLE mailbox_dev LOGIN PASSWORD {}').format(
        sql.Literal(os.environ['MAILBOX_DB_PASSWORD'])))
    conn.execute('GRANT pg_monitor TO mailbox_dev')
    conn.execute('CREATE DATABASE mailbox_dev OWNER mailbox_dev')
