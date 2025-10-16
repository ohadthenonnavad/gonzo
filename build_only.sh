#!/bin/bash
set -euo pipefail

# Usage: ./build_and_deploy.sh /path/to/kernel/build 
# Example: ./build_and_deploy.sh /lib/modules/$(uname -r)/build

if [[ ${#} -ne 1 ]]; then
	echo "Usage: $0 <KDIR> " >&2
	exit 1
fi

KDIR="${1}"

if [[ ! -d "${KDIR}" ]]; then
	echo "KDIR not found: ${KDIR}" >&2
	exit 1
fi


echo "[*] Building kernel module with KDIR=${KDIR} (debug info enabled)"
make clean >/dev/null
make KDIR="${KDIR}"

echo "[*] Building userspace control tool"
pushd user >/dev/null
make clean >/dev/null || true
make
popd >/dev/null
