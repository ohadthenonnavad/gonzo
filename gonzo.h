#ifndef GONZO_H
#define GONZO_H

#include <linux/types.h>

#define DRV_NAME "gonzo"

/* IOCTLs */
#define GONZO_IOCTL_BUILD _IO('G', 0x01)
/* Time profiling ioctl (kernel-only hex dump output) */
#define IOCTL_HV_TIMED_PROF _IO('G', 0x02)

/* Hypervisor timing entrypoint */
void hv_init(unsigned long iterations);

/* Per-device header for PCI blobs */
struct gonzo_pci_hdr {
	uint8_t bus;
	uint8_t dev;
	uint8_t fun;
	uint8_t reserved; /* pad to 8 bytes */
	__le32 cfg_size;   /* 256 or 4096, little-endian */
} __packed;

/* Exposed buffers (in-kernel only) */
extern uint8_t *acpi_blob;
extern size_t acpi_blob_len;

extern uint8_t *pci_blob;
extern size_t pci_blob_len;

/* Build entrypoints */
int acpi_build_blob(void);
int pci_build_blob(void);

/* Optional helper exported */
uint32_t ReadPCICfg(uint8_t bus, uint8_t dev, uint8_t fun, uint8_t of, uint8_t len);

#endif /* GONZO_H */

