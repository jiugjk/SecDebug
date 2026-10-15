#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: sh $0 /path/to/host KernelPatch|KPatch-Next [--check|--apply|--verify]" >&2
  exit 2
fi
case "${3:---check}" in
  --check) ACTION=check;;
  --apply) ACTION=apply;;
  --verify) ACTION=verify;;
  *) echo "Unknown action" >&2; exit 2;;
esac
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$HERE/../scripts/host_contract.py" --host "$1" --fork "$2" --action "$ACTION"
