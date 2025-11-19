#!/bin/bash
# FoundationDB Entrypoint Script for Integration Tests
# This script starts a single-node FDB cluster for testing

set -e

# Get container IP
CONTAINER_IP=$(hostname -i)
FDB_PORT=4500

echo "Starting FDB server on ${CONTAINER_IP}:${FDB_PORT}"

# Create cluster file
echo "docker:docker@${CONTAINER_IP}:${FDB_PORT}" > /var/fdb/fdb.cluster

# Start fdbserver directly (no need for fdbmonitor in Docker)
/usr/sbin/fdbserver \
    --cluster-file=/var/fdb/fdb.cluster \
    --datadir=/var/fdb/data \
    --logdir=/var/fdb/logs \
    --public-address=${CONTAINER_IP}:${FDB_PORT} \
    --listen-address=0.0.0.0:${FDB_PORT}
