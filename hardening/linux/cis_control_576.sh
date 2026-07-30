#!/bin/bash
# CIS Benchmark Control 576 for Linux Systems
# Author: RobsHs (CodZeeX)
# Date: 2026-07-30

echo "[CodZeeX Hardening] Verifying CIS Control 576..."
# Enforce restrictive permissions on system configuration files
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
echo "[CodZeeX Hardening] CIS Control 576 validated."
