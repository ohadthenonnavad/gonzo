#!/bin/bash
set -euo pipefail

# Usage: ./extract_logs.sh /path/to/boot.img

if [[ ${#} -ne 1 ]]; then
	echo "Usage: $0 <BOOT_IMAGE.img>" >&2
	exit 1
fi

BOOT_IMAGE="${1}"
DEST_DIR="parsers/input"

if [[ ! -f "${BOOT_IMAGE}" ]]; then
	echo "BOOT_IMAGE not found: ${BOOT_IMAGE}" >&2
	exit 1
fi

if [[ ! -d "${DEST_DIR}" ]]; then
	echo "Destination directory not found: ${DEST_DIR}" >&2
	exit 1
fi

echo "[*] Ensuring script is running as root for mount/losetup"
if [[ "${EUID}" -ne 0 ]]; then
	exec sudo --preserve-env=BOOT_IMAGE "$0" "$BOOT_IMAGE"
fi

echo "[*] Mounting loopback image: ${BOOT_IMAGE}"
TMPDIR="$(mktemp -d)"
LOOPDEV=""

cleanup() {
	set +e
	if mountpoint -q "${TMPDIR}"; then
		umount "${TMPDIR}" || true
	fi
	[[ -n "${LOOPDEV}" ]] && losetup -d "${LOOPDEV}" 2>/dev/null || true
	rmdir "${TMPDIR}" 2>/dev/null || true
}
trap cleanup EXIT

# Setup loop device
if ! modprobe loop 2>/dev/null; then :; fi
set +e
LOOPDEV=$(losetup --show -f "${BOOT_IMAGE}" 2>/dev/null)
rc=$?
set -e
if [[ $rc -ne 0 || -z "${LOOPDEV}" ]]; then
	echo "losetup failed to find an unused loop device." >&2
	exit 1
fi

# Try to mount; support images with a single partition or a filesystem directly
if ! mount "${LOOPDEV}" "${TMPDIR}" 2>/dev/null; then
	if losetup -d "${LOOPDEV}" 2>/dev/null; then :; fi
	LOOPDEV=$(losetup --show -f -P "${BOOT_IMAGE}")
	PARTDEV="${LOOPDEV}p1"
	if [[ ! -b "${PARTDEV}" ]]; then
		PARTDEV="${LOOPDEV}p1"
	fi
	if ! mount "${PARTDEV}" "${TMPDIR}"; then
		echo "Failed to mount image (tried raw and first partition)" >&2
		exit 1
	fi
fi

echo "[*] Copying dekermit files from image rootfs to ${DEST_DIR}"
cp -v "${TMPDIR}/dekermit."* "${DEST_DIR}/"

sync
echo "[*] Unmounting image"
umount "${TMPDIR}"
losetup -d "${LOOPDEV}" || true
rmdir "${TMPDIR}" || true
trap - EXIT

echo "[+] Done. Logs extracted to ${DEST_DIR}"
