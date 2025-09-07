// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/pci_regs.h>
#include <linux/string.h>

#define DRV_NAME "gonzo"

/*
 * Overview
 * --------
 * gonzo builds two in-kernel buffers on demand via an ioctl:
 *  - ACPI blob: concatenation of ACPI tables (XSDT/RSDT and all referenced
 *    tables), including full headers and bodies. If the official ACPICA API
 *    is unavailable, we fall back to a manual RSDP scan of EBDA/BIOS areas,
 *    then parse XSDT/RSDT directly via ioremap. When encountering FADT, we
 *    also append the tables referenced by its legacy 32-bit FirmwareCtrl and
 *    DSDT fields.
 *  - PCI blob: for each discovered function (vendor != 0xFFFF) on buses
 *    0x00–0x04, we append an 8-byte per-device header followed by the config
 *    space (4KB via MMCONFIG when available, else 256B via CF8/CFC).
 *
 * Userland currently just triggers the build. No data is copied to user.
 */

#define GONZO_IOCTL_BUILD _IO('G', 0x01)

/**
 * struct gonzo_pci_hdr - Per-device header for PCI blobs
 * @bus: PCI bus number (0-255)
 * @dev: PCI device number (0-31)
 * @fun: PCI function number (0-7)
 * @reserved: Pad to maintain an 8-byte header (always 0)
 * @cfg_size: Little-endian size of the following config space (256 or 4096)
 */
struct gonzo_pci_hdr {
	uint8_t bus;
	uint8_t dev;
	uint8_t fun;
	uint8_t reserved; // to make total header 8 bytes
	__le32 cfg_size;
} __packed;

/* Character device plumbing */
static dev_t gonzo_devno;
static struct cdev gonzo_cdev;
static struct class *gonzo_class;

/* In-kernel buffers built on demand */
static uint8_t *acpi_blob;
static size_t acpi_blob_len;

static uint8_t *pci_blob;
static size_t pci_blob_len;

/* MMCONFIG state (single region that covers bus 0-4 if present) */
static void __iomem *mmcfg_base;
static u16 mmcfg_seg;
static u8 mmcfg_bus_start;
static u8 mmcfg_bus_end;

/**
 * append_blob - Extend a growing byte buffer with more data
 * @blob: pointer to heap buffer pointer
 * @len: pointer to current buffer length
 * @data: source bytes to append
 * @add: number of bytes to append
 *
 * Returns: pointer to start of the newly appended region on success, NULL on OOM.
 */
static void *append_blob(uint8_t **blob, size_t *len, const void *data, size_t add)
{
	void *dst;
	uint8_t *newbuf;
	newbuf = krealloc(*blob, *len + add, GFP_KERNEL);
	if (!newbuf)
		return NULL;
	dst = newbuf + *len;
	memcpy(dst, data, add);
	*blob = newbuf;
	*len += add;
	return dst;
}

// ---------- Helpers ----------

/**
 * gonzo_rsdp_checksum_ok - Validate ACPI RSDP checksum over len bytes
 */
static bool gonzo_rsdp_checksum_ok(const u8 *p, size_t len)
{
	u8 sum = 0;
	size_t i;
	for (i = 0; i < len; i++)
		sum = (u8)(sum + p[i]);
	return sum == 0;
}

static void gonzo_hexdump(const u8 *buf, size_t len, const char *tag)
{
	size_t i;
	for (i = 0; i < len; i += 16) {
		char line[16 * 3 + 1];
		int pos = 0;
		size_t j;
		for (j = 0; j < 16 && (i + j) < len; j++)
			pos += scnprintf(line + pos, sizeof(line) - pos, "%02x ", buf[i + j]);
		pr_info(DRV_NAME ": %s %08zx: %s\n", tag, i, line);
	}
}

/**
 * gonzo_append_table_phys - Map and append an ACPI table by physical address
 * @pa: physical address of table header
 * @why: log tag for context (e.g., "FADT.Dsdt")
 *
 * Maps the header to read the length, then maps the full table and appends it.
 */
static int gonzo_append_table_phys(phys_addr_t pa, const char *why)
{
	void __iomem *hdr_io;
	u32 len;
	void __iomem *tbl_io;
	if (!pa)
		return -EINVAL;
	hdr_io = acpi_os_map_iomem(pa, sizeof(struct acpi_table_header));
	if (!hdr_io)
		return -ENODEV;
	len = le32_to_cpu(((struct acpi_table_header __force *)hdr_io)->length);
	acpi_os_unmap_iomem(hdr_io, sizeof(struct acpi_table_header));
	tbl_io = acpi_os_map_iomem(pa, len);
	if (!tbl_io)
		return -ENODEV;
	append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)tbl_io, len);
	pr_info(DRV_NAME ": ACPI: appended table via %s pa=%pa len=%u\n", why, &pa, len);
	acpi_os_unmap_iomem(tbl_io, len);
	return 0;
}

/**
 * gonzo_collect_from_sdt - Walk XSDT/RSDT entries and append each table
 * @base: mapped SDT (XSDT or RSDT)
 * @is_xsdt: true for XSDT (64-bit entries), false for RSDT (32-bit entries)
 *
 * Also detects FADT (FACP) and appends FirmwareCtrl/DSDT legacy 32-bit targets.
 */
static void gonzo_collect_from_sdt(void __iomem *base, bool is_xsdt)
{
	struct acpi_table_header __iomem *hdr = base;
	u32 total_len = le32_to_cpu(hdr->length);
	int entry_size = is_xsdt ? sizeof(u64) : sizeof(u32);
	int cnt = (total_len - sizeof(struct acpi_table_header)) / entry_size;
	int i;
	pr_info(DRV_NAME ": ACPI: (manual) %s entries=%d\n", is_xsdt ? "XSDT" : "RSDT", cnt);
	for (i = 0; i < cnt; i++) {
		phys_addr_t tpa;
		if (is_xsdt) {
			u64 tpa64;
			memcpy_fromio(&tpa64, (u8 __iomem *)base + sizeof(struct acpi_table_header) + i * sizeof(u64), sizeof(u64));
			tpa = (phys_addr_t)tpa64;
		} else {
			u32 tpa32;
			memcpy_fromio(&tpa32, (u8 __iomem *)base + sizeof(struct acpi_table_header) + i * sizeof(u32), sizeof(u32));
			tpa = (phys_addr_t)tpa32;
		}
		{
			void __iomem *th = acpi_os_map_iomem(tpa, sizeof(struct acpi_table_header));
			u32 tlen;
			char sig4[5];
			if (!th)
				continue;
			memcpy_fromio(sig4, th, 4);
			sig4[4] = '\0';
			tlen = le32_to_cpu(((struct acpi_table_header __force *)th)->length);
			acpi_os_unmap_iomem(th, sizeof(struct acpi_table_header));
			th = acpi_os_map_iomem(tpa, tlen);
			if (!th)
				continue;
			pr_info(DRV_NAME ": ACPI: (manual) %s entry %d pa=%pa sig=%s len=%u\n",
				is_xsdt ? "XSDT" : "RSDT", i, &tpa, sig4, tlen);
			append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)th, tlen);
			/* If this is FADT (FACP), also append FirmwareCtrl and DSDT tables by legacy 32-bit fields */
			if (sig4[0] == 'F' && sig4[1] == 'A' && sig4[2] == 'C' && sig4[3] == 'P') {
				u32 fwctrl = 0, dsdt = 0;
				/* Offsets 36 and 40 (ACPI 1.0) right after header */
				memcpy_fromio(&fwctrl, (u8 __iomem *)th + sizeof(struct acpi_table_header) + 0x00, sizeof(u32));
				memcpy_fromio(&dsdt, (u8 __iomem *)th + sizeof(struct acpi_table_header) + 0x04, sizeof(u32));
				if (fwctrl)
					gonzo_append_table_phys((phys_addr_t)fwctrl, "FADT.FirmwareCtrl");
				if (dsdt)
					gonzo_append_table_phys((phys_addr_t)dsdt, "FADT.Dsdt");
			}
			acpi_os_unmap_iomem(th, tlen);
		}
	}
}

// ---------- ACPI dump ----------

/**
 * gonzo_build_acpi_blob_manual - Manual ACPI discovery when ACPICA lookup fails
 *
 * Scans EBDA then BIOS area for RSDP, validates checksums, and walks XSDT/RSDT.
 */
static int gonzo_build_acpi_blob_manual(void)
{
	/* Fallback: scan RSDP in EBDA and BIOS areas, then walk XSDT/RSDT */
	struct rsdp_v1 {
		char signature[8];
		u8 checksum;
		char oemid[6];
		u8 revision;
		u32 rsdt_physical_address;
	} __packed;
	struct rsdp_v2 {
		struct rsdp_v1 v1;
		u32 length;
		u64 xsdt_physical_address;
		u8 extended_checksum;
		u8 reserved[3];
	} __packed;

	void __iomem *bda = ioremap(0x400, 1024);
	u16 ebda_seg = 0;
	void __iomem *scan = NULL;
	phys_addr_t scan_pa = 0;
	const char sig[8] = { 'R','S','D',' ','P','T','R',' ' };
	struct rsdp_v2 rsdp;
	bool found = false;

	if (bda) {
		/* EBDA segment at 0x40E (paragraphs) */
		ebda_seg = readw(bda + 0x40E);
		iounmap(bda);
	}
	if (ebda_seg) {
		scan_pa = ((phys_addr_t)ebda_seg) << 4;
		scan = ioremap(scan_pa, 1024);
		if (scan) {
			size_t off;
			for (off = 0; off < 1024; off += 16) {
				void __iomem *p = scan + off;
				char sig_io[8];
				memcpy_fromio(sig_io, p, 8);
				if (memcmp(sig_io, sig, 8) == 0) {
					memcpy_fromio(&rsdp, p, sizeof(rsdp));
					if (gonzo_rsdp_checksum_ok((u8 *)&rsdp, 20) &&
					    (rsdp.v1.revision == 0 || gonzo_rsdp_checksum_ok((u8 *)&rsdp, rsdp.length))) {
						found = true;
						pr_info(DRV_NAME ": ACPI: RSDP found via EBDA at %pa (offset %#zx)\n", &scan_pa, off);
						break;
					}
				}
			}
			iounmap(scan);
			scan = NULL;
		}
	}
	if (!found) {
		/* Scan BIOS area 0xE0000-0xFFFFF */
		scan_pa = 0xE0000;
		scan = ioremap(scan_pa, 0x20000);
		if (scan) {
			size_t off;
			for (off = 0; off < 0x20000; off += 16) {
				void __iomem *p = scan + off;
				char sig_io2[8];
				memcpy_fromio(sig_io2, p, 8);
				if (memcmp(sig_io2, sig, 8) == 0) {
					memcpy_fromio(&rsdp, p, sizeof(rsdp));
					if (gonzo_rsdp_checksum_ok((u8 *)&rsdp, 20) &&
					    (rsdp.v1.revision == 0 || gonzo_rsdp_checksum_ok((u8 *)&rsdp, rsdp.length))) {
						found = true;
						pr_info(DRV_NAME ": ACPI: RSDP found via BIOS area at %pa (offset %#zx)\n", &scan_pa, off);
						break;
					}
				}
			}
			iounmap(scan);
			scan = NULL;
		}
	}

	if (!found) {
		pr_info(DRV_NAME ": ACPI: manual RSDP scan failed\n");
		return -ENODEV;
	}

	pr_info(DRV_NAME ": ACPI: RSDP found rev=%u rsdt=%#x xsdt=%#llx len=%u\n",
		rsdp.v1.revision,
		rsdp.v1.rsdt_physical_address,
		(unsigned long long)rsdp.xsdt_physical_address,
		rsdp.length);

	if (rsdp.v1.revision >= 2 && rsdp.xsdt_physical_address) {
		phys_addr_t pa = (phys_addr_t)rsdp.xsdt_physical_address;
		struct acpi_table_header __iomem *xh;
		u32 len;
		void __iomem *base = acpi_os_map_iomem(pa, sizeof(struct acpi_table_header));
		if (!base)
			return -ENODEV;
		xh = base;
		len = le32_to_cpu(xh->length);
		acpi_os_unmap_iomem(base, sizeof(struct acpi_table_header));
		base = acpi_os_map_iomem(pa, len);
		if (!base)
			return -ENODEV;
		append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)base, len);
		gonzo_collect_from_sdt(base, true);
		acpi_os_unmap_iomem(base, len);
		pr_info(DRV_NAME ": ACPI: (manual) total blob len after XSDT=%zu\n", acpi_blob_len);
		return 0;
	}

	/* ACPI 1.0: use RSDT */
	{
		phys_addr_t pa = (phys_addr_t)rsdp.v1.rsdt_physical_address;
		struct acpi_table_header __iomem *rh;
		u32 len;
		void __iomem *base = acpi_os_map_iomem(pa, sizeof(struct acpi_table_header));
		if (!base)
			return -ENODEV;
		rh = base;
		len = le32_to_cpu(rh->length);
		acpi_os_unmap_iomem(base, sizeof(struct acpi_table_header));
		base = acpi_os_map_iomem(pa, len);
		if (!base)
			return -ENODEV;
		append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)base, len);
		gonzo_collect_from_sdt(base, false);
		acpi_os_unmap_iomem(base, len);
		pr_info(DRV_NAME ": ACPI: (manual) total blob len after RSDT=%zu\n", acpi_blob_len);
		return 0;
	}
}

/**
 * gonzo_build_acpi_blob - Preferred ACPI dump using ACPICA APIs
 *
 * Uses acpi_get_table(XSDT/RSDT) to enumerate and copy full tables.
 * Falls back to manual discovery if ACPICA returns AE_NOT_FOUND.
 */
static int gonzo_build_acpi_blob(void)
{
	struct acpi_table_header *xsdt = NULL;
	acpi_status status;
	int i;
	uint64_t *entries;
	int num_entries;

	// reset previous
	kfree(acpi_blob);
	acpi_blob = NULL;
	acpi_blob_len = 0;

	pr_info(DRV_NAME ": ACPI: start build\n");

	status = acpi_get_table(ACPI_SIG_XSDT, 0, &xsdt);
	pr_info(DRV_NAME ": ACPI: get XSDT status=%d ptr=%p\n", (int)status, xsdt);
	// Try using XSDT table 
	if (ACPI_FAILURE(status) || !xsdt) {
		struct acpi_table_header *rsdt = NULL;
		status = acpi_get_table(ACPI_SIG_RSDT, 0, &rsdt);
		pr_info(DRV_NAME ": ACPI: get RSDT status=%d ptr=%p\n", (int)status, rsdt);
		if (ACPI_FAILURE(status) || !rsdt)
			return gonzo_build_acpi_blob_manual();
		// Include RSDT itself
		append_blob(&acpi_blob, &acpi_blob_len, rsdt, le32_to_cpu(rsdt->length));
		// RSDT entries are 32-bit
		num_entries = (le32_to_cpu(rsdt->length) - sizeof(*rsdt)) / sizeof(u32);
		pr_info(DRV_NAME ": ACPI: RSDT len=%u entries=%d\n", le32_to_cpu(rsdt->length), num_entries);
		for (i = 0; i < num_entries; i++) {
			phys_addr_t pa = ((u32 __force *)((u8 *)rsdt + sizeof(*rsdt)))[i];
			struct acpi_table_header __iomem *hdr;
			u32 len;
			void __iomem *base = acpi_os_map_iomem(pa, sizeof(struct acpi_table_header));
			if (!base)
				continue;
			hdr = base;
			len = le32_to_cpu(hdr->length);
			{
				char sig[5];
				memcpy(sig, hdr->signature, 4);
				sig[4] = '\0';
				pr_info(DRV_NAME ": ACPI: RSDT entry %d pa=%pa sig=%s len=%u\n", i, &pa, sig, len);
			}
			acpi_os_unmap_iomem(base, sizeof(struct acpi_table_header));
			base = acpi_os_map_iomem(pa, len);
			if (!base)
				continue;
			append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)base, len);
			acpi_os_unmap_iomem(base, len);
		}
		pr_info(DRV_NAME ": ACPI: total blob len after RSDT=%zu\n", acpi_blob_len);
		acpi_put_table(rsdt);
		return 0;
	}

	// Include XSDT itself
	append_blob(&acpi_blob, &acpi_blob_len, xsdt, le32_to_cpu(xsdt->length));

	entries = (uint64_t *)((u8 *)xsdt + sizeof(*xsdt));
	num_entries = (le32_to_cpu(xsdt->length) - sizeof(*xsdt)) / sizeof(u64);
	pr_info(DRV_NAME ": ACPI: XSDT len=%u entries=%d\n", le32_to_cpu(xsdt->length), num_entries);
	for (i = 0; i < num_entries; i++) {
		phys_addr_t pa = (phys_addr_t)le64_to_cpu(entries[i]);
		struct acpi_table_header __iomem *hdr;
		u32 len;
		void __iomem *base = acpi_os_map_iomem(pa, sizeof(struct acpi_table_header));
		if (!base)
			continue;
		hdr = base;
		len = le32_to_cpu(hdr->length);
		{
			char sig[5];
			memcpy(sig, hdr->signature, 4);
			sig[4] = '\0';
			pr_info(DRV_NAME ": ACPI: XSDT entry %d pa=%pa sig=%s len=%u\n", i, &pa, sig, len);
		}
		acpi_os_unmap_iomem(base, sizeof(struct acpi_table_header));
		base = acpi_os_map_iomem(pa, len);
		if (!base)
			continue;
		append_blob(&acpi_blob, &acpi_blob_len, (const void __force *)base, len);
		acpi_os_unmap_iomem(base, len);
	}
	pr_info(DRV_NAME ": ACPI: total blob len after XSDT=%zu\n", acpi_blob_len);
	acpi_put_table(xsdt);
	return 0;
}

// ---------- PCI config access ----------

/**
 * cf8_addr - Compute CF8 address for PCI config mechanism #1
 */
static inline u32 cf8_addr(u8 bus, u8 dev, u8 fun, u16 off)
{
	return (u32)(0x80000000U | ((u32)bus << 16) | ((u32)dev << 11) | ((u32)fun << 8) | (off & ~0x3));
}

/**
 * pci_cfg_read_dword_cf8 - Read 32-bit from PCI config space via CF8/CFC
 */
static u32 pci_cfg_read_dword_cf8(u8 bus, u8 dev, u8 fun, u16 off)
{
	outl(cf8_addr(bus, dev, fun, off), 0xCF8);
	return inl(0xCFC);
}

/**
 * mmcfg_covers_bus - Whether MMCONFIG region is set and covers given bus
 */
static bool mmcfg_covers_bus(u8 bus)
{
	return mmcfg_base && bus >= mmcfg_bus_start && bus <= mmcfg_bus_end;
}

/**
 * pci_cfg_read_dword_mmcfg - Read 32-bit from PCI config via MMCONFIG
 */
static u32 pci_cfg_read_dword_mmcfg(u8 bus, u8 dev, u8 fun, u16 off)
{
	void __iomem *addr;
	addr = mmcfg_base
		+ (((u32)bus - mmcfg_bus_start) << 20)
		+ ((u32)dev << 15)
		+ ((u32)fun << 12)
		+ (off & ~0x3);
	return readl(addr);
}

/**
 * ReadPCICfg - Public helper to read up to 4 bytes from PCI config space
 * @bus, @dev, @fun: BDF
 * @of: byte offset into config space (unaligned ok)
 * @len: 1, 2, or 4 bytes to return in the low bits of the return value
 */
uint32_t ReadPCICfg(uint8_t bus, uint8_t dev, uint8_t fun, uint8_t of, uint8_t len)
{
	// Reads up to 4 bytes aligned to dword boundary using preferred mech
	u16 off = (u16)of;
	u32 val;
	if (mmcfg_covers_bus(bus))
		val = pci_cfg_read_dword_mmcfg(bus, dev, fun, off);
	else
		val = pci_cfg_read_dword_cf8(bus, dev, fun, off);
	// Align/shift to return the requested len at offset within dword
	{
		u8 shift = (off & 3) * 8;
		u32 shifted = val >> shift;
		if (len == 1)
			return shifted & 0xFF;
		if (len == 2)
			return shifted & 0xFFFF;
		return shifted; // len >= 4
	}
}
EXPORT_SYMBOL(ReadPCICfg);

/**
 * gonzo_init_mmcfg_from_acpi - Initialize MMCONFIG mapping from MCFG table
 *
 * Searches the ACPI MCFG table for a segment covering bus[0..4] and maps it.
 */
static int gonzo_init_mmcfg_from_acpi(void)
{
	struct acpi_table_mcfg *mcfg;
	acpi_status status;
	status = acpi_get_table(ACPI_SIG_MCFG, 0, (struct acpi_table_header **)&mcfg);
	if (ACPI_FAILURE(status) || !mcfg)
		return -ENODEV;
	{
		size_t bytes = le32_to_cpu(mcfg->header.length);
		size_t n = (bytes - sizeof(*mcfg)) / sizeof(struct acpi_mcfg_allocation);
		struct acpi_mcfg_allocation *alloc = (void *)((u8 *)mcfg + sizeof(*mcfg));
		int i;
		for (i = 0; i < n; i++) {
			u64 base = le64_to_cpu(alloc[i].address);
			u16 seg = le16_to_cpu(alloc[i].pci_segment);
			u8 sb = alloc[i].start_bus_number;
			u8 eb = alloc[i].end_bus_number;
			if (seg == 0 && sb <= 4) {
				phys_addr_t map_base = (phys_addr_t)base + ((u64)0 << 20);
				void __iomem *mm = ioremap(map_base, (eb - sb + 1) * (1ULL << 20));
				if (mm) {
					mmcfg_base = mm;
					mmcfg_seg = seg;
					mmcfg_bus_start = sb;
					mmcfg_bus_end = eb;
					break;
				}
			}
		}
	}
	acpi_put_table(&mcfg->header);
	return mmcfg_base ? 0 : -ENODEV;
}

/**
 * gonzo_build_pci_blob - Build concatenated PCI headers+config spaces
 */
static int gonzo_build_pci_blob(void)
{
	int bus, dev, fun;
	int ret;
	// reset previous
	kfree(pci_blob);
	pci_blob = NULL;
	pci_blob_len = 0;

	// Setup MMCONFIG if available
	mmcfg_base = NULL;
	ret = gonzo_init_mmcfg_from_acpi();
	(void)ret;

	for (bus = 0; bus <= 0x4; bus++) {
		for (dev = 0; dev < 32; dev++) {
			for (fun = 0; fun < 8; fun++) {
				u16 vendor;
				u32 v;
				v = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x00, 2);
				vendor = (u16)(v & 0xFFFF);
				if (vendor == 0xFFFF)
					continue;

				// Determine config size
				bool use_mmcfg = mmcfg_covers_bus((u8)bus);
				u32 cfg_size = use_mmcfg ? 4096u : 256u;

				// Header
				struct gonzo_pci_hdr hdr;
				hdr.bus = (u8)bus;
				hdr.dev = (u8)dev;
				hdr.fun = (u8)fun;
				hdr.reserved = 0;
				hdr.cfg_size = cpu_to_le32(cfg_size);
				if (!append_blob(&pci_blob, &pci_blob_len, &hdr, sizeof(hdr)))
					return -ENOMEM;

				// Append config space
				u16 off;
				for (off = 0; off < cfg_size; off += 4) {
					u32 d;
					if (use_mmcfg)
						d = pci_cfg_read_dword_mmcfg((u8)bus, (u8)dev, (u8)fun, off);
					else
						d = pci_cfg_read_dword_cf8((u8)bus, (u8)dev, (u8)fun, off);
					if (!append_blob(&pci_blob, &pci_blob_len, &d, sizeof(d)))
						return -ENOMEM;
				}
			}
		}
	}
	return 0;
}

// ---------- Char device and ioctl ----------

/**
 * gonzo_unlocked_ioctl - Single entry point to build both ACPI and PCI blobs
 * @cmd: GONZO_IOCTL_BUILD triggers the builds
 *
 * Attempts ACPI and PCI independently; returns success if at least one worked.
 */
static long gonzo_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	switch (cmd) {
	case GONZO_IOCTL_BUILD: {
		int acpi_ret = gonzo_build_acpi_blob();
		if (acpi_ret)
			pr_warn(DRV_NAME ": ACPI build failed: %d\n", acpi_ret);
		else
			pr_info(DRV_NAME ": ACPI build ok, len=%zu\n", acpi_blob_len);

		int pci_ret = gonzo_build_pci_blob();
		if (pci_ret)
			pr_warn(DRV_NAME ": PCI build failed: %d\n", pci_ret);
		else
			pr_info(DRV_NAME ": PCI build ok, len=%zu\n", pci_blob_len);

		if (acpi_ret && pci_ret)
			return acpi_ret; // both failed -> report one
		return 0; // at least one succeeded
	}
	default:
		return -ENOTTY;
	}
}

static int gonzo_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int gonzo_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations gonzo_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = gonzo_unlocked_ioctl,
	.open = gonzo_open,
	.release = gonzo_release,
};

/**
 * gonzo_init - Module init: registers chardev and device node
 */
static int __init gonzo_init(void)
{
	int err;

	err = alloc_chrdev_region(&gonzo_devno, 0, 1, DRV_NAME);
	if (err)
		return err;

	cdev_init(&gonzo_cdev, &gonzo_fops);
	gonzo_cdev.owner = THIS_MODULE;
	err = cdev_add(&gonzo_cdev, gonzo_devno, 1);
	if (err)
		goto err_unregister;

	gonzo_class = class_create(THIS_MODULE, DRV_NAME);
	if (IS_ERR(gonzo_class)) {
		err = PTR_ERR(gonzo_class);
		goto err_cdev;
	}
	if (!device_create(gonzo_class, NULL, gonzo_devno, NULL, DRV_NAME)) {
		err = -ENODEV;
		goto err_class;
	}

	pr_info(DRV_NAME ": loaded\n");
	return 0;

err_class:
	class_destroy(gonzo_class);
err_cdev:
	cdev_del(&gonzo_cdev);
err_unregister:
	unregister_chrdev_region(gonzo_devno, 1);
	return err;
}

/**
 * gonzo_exit - Module exit: unmap/free buffers and unregister device
 */
static void __exit gonzo_exit(void)
{
	if (mmcfg_base)
		iounmap(mmcfg_base);
	kfree(acpi_blob);
	kfree(pci_blob);
	device_destroy(gonzo_class, gonzo_devno);
	class_destroy(gonzo_class);
	cdev_del(&gonzo_cdev);
	unregister_chrdev_region(gonzo_devno, 1);
	pr_info(DRV_NAME ": unloaded\n");
}

module_init(gonzo_init);
module_exit(gonzo_exit);

MODULE_AUTHOR("gonzo");
MODULE_DESCRIPTION("Gonzo ACPI/PCI snapshot builder");
MODULE_LICENSE("GPL");

