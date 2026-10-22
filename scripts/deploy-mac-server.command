#!/bin/bash
set -euo pipefail
exec /bin/bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/setup-mac-server.sh" "$@"
