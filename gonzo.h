#ifndef GONZO_H
#define GONZO_H

#include <linux/types.h>

#define DRV_NAME "gonzo"

/* Debug macro */
#ifndef DBG
#define DBG(fmt, ...) printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#endif

/* IOCTLs */
#define IOCTL_ACPI_DUMP _IO('G', 0x01)
#define IOCTL_PCI_DUMP _IO('G', 0x06)
/* Time profiling ioctl (kernel-only hex dump output) */
#define IOCTL_HV_TIMED_PROF _IO('G', 0x02)
/* Timer configuration dump ioctl */
#define IOCTL_TIMERS_DUMP _IO('G', 0x03)
/* USB dump ioctl */
#define IOCTL_USB_DUMP _IO('G', 0x04)
/* MSR dump ioctl */
#define IOCTL_MSR_DUMP _IO('G', 0x05)

/* Hypervisor timing entrypoint */
void hv_init(unsigned long iterations);

/* Timer dump entrypoint */
int timers_dump_all(void);

/* USB dump entrypoint and buffers */
int usb_build_blob(void);
extern uint8_t *usb_blob;
extern size_t usb_blob_len;

/* Timers single aggregate blob */
extern uint8_t *timers_blob;
extern size_t timers_blob_len;

/* File dump helper */
int gonzo_dump_to_file(const char *path, const uint8_t *buf, size_t len);

/* MSR dump */
int msr_dump_blob(void);

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
void *append_blob(uint8_t **, size_t *, const void *, size_t);
#endif /* GONZO_H */

