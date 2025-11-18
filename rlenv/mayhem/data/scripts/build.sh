#!/bin/bash
set -euo pipefail

# RLENV Build Script
# This script rebuilds the application from source located at /rlenv/source/libelfmaster/
#
# Original image: ghcr.io/mayhemheroes/libelfmaster:master
# Git revision: 9d3c01263d75ee1ac2965f49adca8ebfc40ee20d

# ============================================================================
# REQUIRED: Change to Source Directory
# ============================================================================
cd /rlenv/source/libelfmaster/

# ============================================================================
# Clean Previous Build
# ============================================================================
# Clean build artifacts to ensure fresh rebuild
make clean 2>/dev/null || true
rm -f /stripx 2>/dev/null || true
rm -rf /install 2>/dev/null || true

# ============================================================================
# Build Commands (NO NETWORK, NO PACKAGE INSTALLATION)
# ============================================================================
# Configure the build
./configure --prefix=/install

# Build the library
make -j8

# Install the library
make install

# Build the stripx fuzzing target
cd utils
gcc stripx.c -o stripx

# ============================================================================
# Copy Artifacts (use 'cat >' for busybox compatibility)
# ============================================================================
# Copy stripx to the expected location
cat stripx > /stripx

# ============================================================================
# Set Permissions
# ============================================================================
chmod 777 /stripx 2>/dev/null || true

# 777 allows validation script (running as UID 1000) to overwrite during rebuild
# 2>/dev/null || true prevents errors if chmod not available

# ============================================================================
# REQUIRED: Verify Build Succeeded
# ============================================================================
if [ ! -f /stripx ]; then
    echo "Error: Build artifact not found at /stripx"
    exit 1
fi

# Verify executable bit
if [ ! -x /stripx ]; then
    echo "Warning: Build artifact is not executable"
fi

# Verify file size
SIZE=$(stat -c%s /stripx 2>/dev/null || stat -f%z /stripx 2>/dev/null || echo 0)
if [ "$SIZE" -lt 100 ]; then
    echo "Warning: Build artifact is suspiciously small ($SIZE bytes)"
fi

echo "Build completed successfully: /stripx ($SIZE bytes)"
