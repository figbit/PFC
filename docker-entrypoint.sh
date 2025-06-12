#!/bin/bash
set -e

# Create directories if they don't exist (as appuser)
mkdir -p /app/uploads /app/downloads

# Try to set permissions (will work if running as root or if already correct)
chmod -f 777 /app/uploads /app/downloads 2>/dev/null || true

# Execute the main command
exec "$@" 