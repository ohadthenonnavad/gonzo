## gonzo: ACPI/PCI snapshot kernel module and userspace controller

### Overview
- Kernel module `gonzo.ko` builds two in-kernel buffers on demand (via ioctl):
  - ACPI blob: concatenation of ACPI tables (XSDT/RSDT + all referenced tables). If FADT (FACP) is present, it also appends the legacy 32-bit `FirmwareCtrl` and `Dsdt` pointed tables.
    - Prefers ACPICA (`acpi_get_table`). Falls back to manual RSDP discovery (EBDA/0xE0000–0xFFFFF) if needed.
  - PCI blob: enumerates buses 0x00–0x04, dev 0–31, func 0–7; for each present BDF (vendor != 0xFFFF) appends an 8-byte header `[bus,dev,fun,0][cfg_size_le32]` followed by the config space (4096 bytes via MMCONFIG when available; otherwise 256 bytes via CF8/CFC).
- Userspace tool `user/gonzo_ctl` opens `/dev/gonzo` and issues the build ioctl. No data is copied to userspace for now.

### Requirements
- Linux kernel headers for the target kernel: `/lib/modules/$(uname -r)/build` must exist.
- Compiler compatible with the target kernel build:
  - If the kernel adds flags like `-ftrivial-auto-var-init=zero`, use the same GCC version (e.g., `gcc-12`).
  - Alternatively, Clang/LLVM: `make LLVM=1`.
- For static userspace build: a static libc (glibc static or musl). You can do `make user CC=musl-gcc` if glibc static is unavailable.
- QEMU to run full system emulation (optional): `qemu-system-x86_64` (KVM optional).

### Build (against host kernel)
```bash
make clean && make              # builds gonzo.ko with debug info
make user                       # builds user/gonzo_ctl (static)

# choose compiler explicitly if needed
make CC=gcc-12
make user CC=gcc-11             # userspace may use a different compiler
```

### Quick test on host
```bash
sudo insmod gonzo.ko
ls -l /dev/gonzo
sudo ./user/gonzo_ctl          # triggers ACPI + PCI buffer builds
dmesg | tail -n 200
sudo rmmod gonzo
```

### Build and deploy to a disk image
```bash
./build_and_deploy.sh /lib/modules/$(uname -r)/build /path/to/image.img
```
What it does:
- Builds the module and userspace tool
- Mounts the image via loop and copies artifacts to image root:
  - `/gonzo.ko`
  - `/gonzo_ctl`

### Run in QEMU
```bash
./run_qemu.sh /path/to/kernel/build /path/to/image.img
```
Notes:
- Boots with: `console=ttyS0 root=/dev/sda1 init=/sbin/init rw acpi=on`
- Uses `-machine q35` and AHCI so the disk is `/dev/sda`
- Uses KVM if available; otherwise TCG. Console is on `ttyS0` (`-nographic`).

### Device and ioctl
- Device node: `/dev/gonzo` (created at module init)
- Ioctl: `GONZO_IOCTL_BUILD` — builds both ACPI and PCI blobs in kernel memory

### Repository layout
- `gonzo.c`: kernel module implementation
- `user/gonzo_ctl.c`: minimal userspace controller
- `Makefile`: kernel module build
- `user/Makefile`: userspace build (static)
- `build_and_deploy.sh`: build and copy artifacts into a disk image
- `run_qemu.sh`: run the image in QEMU with the provided kernel

### Notes
- Concurrency: single-request-at-a-time assumed; buffers are rebuilt on demand.
- Bus scan limited to 0x00–0x04 by design.
- Future work: add ioctls to expose sizes and copy buffers to userspace.


