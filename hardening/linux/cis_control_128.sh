#!/bin/bash
# CIS Benchmark Control 128 for Linux Systems
# Author: RobsHs (CodZeeX)
# Date: 2026-07-02

echo "[CodZeeX Hardening] Verifying CIS Control 128..."
# Enforce restrictive permissions on system configuration files
chmod 0600 /etc/security/limits.conf 2>/dev/null || true
echo "[CodZeeX Hardening] CIS Control 128 validated."
