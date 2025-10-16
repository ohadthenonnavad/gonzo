#!/bin/bash
set -euo pipefail

# Usage: ./run_qemu.sh /path/to/kernel/build /path/to/image.img
# Boots x86_64 with kernel from KDIR and the image as /dev/sda (AHCI),
# passing: console=ttyS0 root=/dev/sda1 init=/sbin/init rw

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

# Locate bzImage
BZIMAGE="${KDIR}/arch/x86/boot/bzImage"
if [[ ! -f "${BZIMAGE}" ]]; then
	# common out-of-tree build target
	candidates=(
		"${KDIR}/bzImage"
	)
	for c in "${candidates[@]}"; do
		if [[ -f "${c}" ]]; then BZIMAGE="${c}"; break; fi
		done
fi

if [[ ! -f "${BZIMAGE}" ]]; then
	echo "Could not find bzImage under ${KDIR}. Build your kernel or adjust path." >&2
	exit 1
fi

QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}

# Prefer KVM if available
# Port forwarding for debug (host:7777 -> guest:7777)
NET_FLAGS=(
    -netdev user,id=net0,hostfwd=tcp::7777-:7777
    -device e1000,netdev=net0
)

KVM_FLAGS=()
if [[ -w /dev/kvm ]]; then
    KVM_FLAGS=( -enable-kvm -cpu host )
else
    KVM_FLAGS=( -cpu qemu64 )
fi

APPEND="console=ttyS0 root=/dev/sda1 init=/sbin/init rw acpi=on"

exec "${QEMU_BIN}" \
	"${KVM_FLAGS[@]}" \
	"${NET_FLAGS[@]}" \
	-m 2048 \
	-smp 2 \
	-nographic \
	-machine q35 \
	-kernel "${BZIMAGE}" \
	-append "${APPEND}" \
	-net none \
	-device ich9-ahci,id=ahci \
	-drive id=disk,file="${BOOT_IMAGE}",if=none,format=raw,cache=none,discard=unmap \
	-device ide-hd,drive=disk,bus=ahci.0 \
	-serial mon:stdio
  	-device usb-ehci,id=ehci \
	-device usb-storage,bus=ehci.0,drive=usbstick \
  	-drive id=usbstick,file=usb_drive.img,format=raw,if=none


