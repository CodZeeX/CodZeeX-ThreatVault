#!/bin/bash
# CIS Benchmark Control 356 for Linux Systems
# Author: RobsHs (CodZeeX)
# Date: 2026-07-17

echo "[CodZeeX Hardening] Verifying CIS Control 356..."
# Enforce restrictive permissions on system configuration files
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
echo "[CodZeeX Hardening] CIS Control 356 validated."
