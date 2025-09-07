#!/bin/bash
set -euo pipefail

# Usage: ./build_and_deploy.sh /path/to/kernel/build /path/to/boot.img
# Example: ./build_and_deploy.sh /lib/modules/$(uname -r)/build /path/to/image.img

if [[ ${#} -ne 2 ]]; then
	echo "Usage: $0 <KDIR> <BOOT_IMAGE.img>" >&2
	exit 1
fi

KDIR="${1}"
BOOT_IMAGE="${2}"

if [[ ! -d "${KDIR}" ]]; then
	echo "KDIR not found: ${KDIR}" >&2
	exit 1
fi

if [[ ! -f "${BOOT_IMAGE}" ]]; then
	echo "BOOT_IMAGE not found: ${BOOT_IMAGE}" >&2
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

KO="gonzo.ko"
CTL="user/gonzo_ctl"

if [[ ! -f "${KO}" ]]; then
	echo "Build failed: ${KO} not found" >&2
	exit 1
fi

if [[ ! -f "${CTL}" ]]; then
	echo "Build failed: ${CTL} not found" >&2
	exit 1
fi

echo "[*] Ensuring script is running as root for mount/losetup"
if [[ "${EUID}" -ne 0 ]]; then
	exec sudo --preserve-env=KDIR,BOOT_IMAGE "$0" "$KDIR" "$BOOT_IMAGE"
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
	echo "losetup failed to find an unused loop device. You may need to free one (e.g., 'losetup -a' to list, 'losetup -d /dev/loopN' to detach)." >&2
	exit 1
fi

# Try to mount; support images with a single partition or a filesystem directly
if ! mount "${LOOPDEV}" "${TMPDIR}" 2>/dev/null; then
	# Attempt partition mapping via kpartx or losetup -P
	if losetup -d "${LOOPDEV}" 2>/dev/null; then :; fi
	LOOPDEV=$(losetup --show -f -P "${BOOT_IMAGE}")
	PARTDEV="${LOOPDEV}p1"
	if [[ ! -b "${PARTDEV}" ]]; then
		# Fallback for systems naming as loop0p1 vs loop0p1 presence
		PARTDEV="${LOOPDEV}p1"
	fi
	if ! mount "${PARTDEV}" "${TMPDIR}"; then
		echo "Failed to mount image (tried raw and first partition)" >&2
		exit 1
	fi
fi

echo "[*] Copying artifacts to image rootfs (/ )"
install -D -m 0644 "${KO}" "${TMPDIR}/gonzo.ko"
install -D -m 0755 "${CTL}" "${TMPDIR}/gonzo_ctl"

sync
echo "[*] Unmounting image"
umount "${TMPDIR}"
losetup -d "${LOOPDEV}" || true
rmdir "${TMPDIR}" || true
trap - EXIT

echo "[+] Done. Deployed to ${BOOT_IMAGE}"


