#!/bin/bash
# Docker Container Hardening Check #734
echo "Auditing container daemon parameters..."
grep -i "icc" /etc/docker/daemon.json 2>/dev/null || true
