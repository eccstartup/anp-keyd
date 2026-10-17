#!/bin/bash
# Human-run complete-framework acceptance. Temporary identities/state only.
set -euo pipefail
if [ "${1:-}" = --help ] || [ "$#" -lt 6 ] || [ "$#" -gt 7 ]; then
  echo 'Usage: sudo bash check-agent.sh CANDIDATE_PATH SHA256 HELPER_PATH SHA256 CLAUDE_STANDALONE_PATH SHA256 [--interactive-ui]'
  echo 'Default reuses the recorded native UI acceptance; --interactive-ui explicitly repeats the three windows.'
  echo 'Claude uses a loopback API fixture, no real model credentials or inference. Existing installation is unchanged.'
  if [ "${1:-}" = --help ]; then exit 0; else exit 2; fi
fi
if [ "$(uname -s)" != Darwin ] || [ "$(id -u)" != 0 ]; then
  echo 'Requires macOS root in the human terminal; enter any sudo password locally.' >&2
  exit 1
fi
ui=()
if [ "$#" = 7 ]; then
  if [ "$7" != --interactive-ui ]; then echo 'Unknown seventh argument' >&2; exit 2; fi
  ui=(--interactive-ui)
fi
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
/usr/bin/python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import hashlib
from pathlib import Path
import re
import stat
import sys
for name, digest in zip(sys.argv[1::2], sys.argv[2::2]):
    path = Path(name)
    if not path.is_absolute() or not stat.S_ISREG(path.lstat().st_mode):
        sys.exit('expected absolute regular executable, not symlink: ' + name)
    if not re.fullmatch('[0-9a-f]{64}', digest):
        sys.exit('expected reviewed lowercase SHA-256')
    with path.open('rb') as source:
        data = source.read(256 * 1024 * 1024 + 1)
    if len(data) > 256 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        sys.exit('digest/size mismatch: ' + name)
print('PASS all reviewed executable digests checked', flush=True)
PY
/usr/bin/python3 "$script_dir/test-install.py"
/usr/bin/python3 "$script_dir/test-runtime.py" \
  --candidate-binary "$1" --candidate-sha256 "$2" \
  --signing-helper "$3" --helper-sha256 "$4" \
  --migrate-fixture --claude-binary "$5" --claude-sha256 "$6" "${ui[@]}"
echo 'PASS isolated framework acceptance. Daily state unchanged; live model, real-identity migration and U3 hardware/release gates remain separate.'
