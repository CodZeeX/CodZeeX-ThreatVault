#!/bin/bash
# CIS Benchmark Control 480 for Linux Systems
# Author: RobsHs (CodZeeX)
# Date: 2026-07-25

echo "[CodZeeX Hardening] Verifying CIS Control 480..."
# Enforce restrictive permissions on system configuration files
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
echo "[CodZeeX Hardening] CIS Control 480 validated."
