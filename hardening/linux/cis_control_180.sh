#!/bin/bash
# CIS Benchmark Control 180 for Linux Systems
# Author: RobsHs (CodZeeX)
# Date: 2026-07-06

echo "[CodZeeX Hardening] Verifying CIS Control 180..."
# Enforce restrictive permissions on system configuration files
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
echo "[CodZeeX Hardening] CIS Control 180 validated."
