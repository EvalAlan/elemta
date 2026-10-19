FROM postgres:17-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv curl && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/patroni && \
    /opt/patroni/bin/pip install --no-cache-dir 'patroni[etcd3,psycopg3]==4.1.5' 'psycopg[binary]>=3.2,<4'
COPY patroni.yml /etc/patroni.yml
COPY bootstrap.py /opt/bootstrap.py
RUN mkdir -p /var/lib/postgresql/data && chown postgres:postgres /var/lib/postgresql/data
USER postgres
ENTRYPOINT ["/opt/patroni/bin/patroni", "/etc/patroni.yml"]
