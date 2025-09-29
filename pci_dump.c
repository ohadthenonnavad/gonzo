// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/version.h>
#ifdef CONFIG_ACPI
#include <linux/acpi.h>
#include <acpi/actbl1.h>
#endif
#include <linux/pci_regs.h>
#include "gonzo.h"

#define DBG(fmt, ...) printk(KERN_DEBUG "gonzo: " fmt, ##__VA_ARGS__)



static void __iomem *mmcfg_base;
static u8 mmcfg_bus_start;
static u8 mmcfg_bus_end;

/**
 * cf8_addr - Compute CF8 address for PCI config mechanism #1
 */
static inline u32 cf8_addr(u8 bus, u8 dev, u8 fun, u16 off)
{
    return (u32)(0x80000000U | ((u32)bus << 16) | ((u32)dev << 11) | ((u32)fun << 8) | (off & ~0x3));
}

/**
 * pci_cfg_read_dword_cf8 - Read 32-bit from PCI config via CF8/CFC
 */
static u32 pci_cfg_read_dword_cf8(u8 bus, u8 dev, u8 fun, u16 off)
{
    outl(cf8_addr(bus, dev, fun, off), 0xCF8);
    return inl(0xCFC);
}

/**
 * mmcfg_covers_bus - Whether MMCONFIG region covers this bus
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
 * ReadPCICfg - Read up to 4 bytes from PCI config space
 * @bus: bus number (0..255)
 * @dev: device number (0..31)
 * @fun: function number (0..7)
 * @of: byte offset within config space (unaligned ok)
 * @len: 1, 2, or 4 bytes; result returned right-aligned in u32
 *
 * Return: u32 value containing the requested bytes.
 */
uint32_t ReadPCICfg(uint8_t bus, uint8_t dev, uint8_t fun, uint8_t of, uint8_t len)
{
    u16 off = (u16)of;
    u32 val;
    if (mmcfg_covers_bus(bus))
        val = pci_cfg_read_dword_mmcfg(bus, dev, fun, off);
    else
        val = pci_cfg_read_dword_cf8(bus, dev, fun, off);
    {
        u8 shift = (off & 3) * 8;
        u32 shifted = val >> shift;
        if (len == 1)
            return shifted & 0xFF;
        if (len == 2)
            return shifted & 0xFFFF;
        return shifted;
    }
}
EXPORT_SYMBOL(ReadPCICfg);

/**
 * gonzo_init_mmcfg_from_acpi - Initialize MMCONFIG mapping from ACPI MCFG
 *
 * Return: 0 if mapped, -ENODEV otherwise (caller will fall back to CF8/CFC).
 */
#ifdef CONFIG_ACPI
static int init_mmcfg_from_acpi(void)
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
            if (seg == 0) {
                phys_addr_t map_base = (phys_addr_t)base + ((u64)0 << 20);
                void __iomem *mm = ioremap(map_base, (eb - sb + 1) * (1ULL << 20));
                if (mm) {
                    mmcfg_base = mm;
                    mmcfg_bus_start = sb;
                    mmcfg_bus_end = eb;
                    break;
                }
            }
        }
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    acpi_put_table(&mcfg->header);
#else
    /* On older kernels 3.x, acpi_put_table may not exist; nothing to do */
#endif
    return mmcfg_base ? 0 : -ENODEV;
}
#else
static int init_mmcfg_from_acpi(void)
{
    /* ACPI not available at build time; force CF8/CFC compatibility path */
    return -ENODEV;
}
#endif

/**
 * gonzo_build_pci_blob - Build concatenated PCI headers + config spaces
 *
 * Return: 0 on success, negative errno on allocation or mapping failure.
 */
int pci_build_blob(void)
{
    int bus, dev, fun;
    int ret;
    u8 bus_start = 0, bus_end = 4;  // Default fallback range
    
    // Free any previous PCI blob to avoid memory leak before building a new one
    kfree(pci_blob);
    pci_blob = NULL;
    pci_blob_len = 0;

    mmcfg_base = NULL;
    ret = init_mmcfg_from_acpi();
    if (ret == 0) {
        // Use MMCONFIG range if available
        bus_start = mmcfg_bus_start;
        bus_end = mmcfg_bus_end;
        DBG("Using MMCONFIG range: buses %d-%d\n", bus_start, bus_end);
    } else {
        // If MMCONFIG fails, scan a reasonable range with CF8/CFC
        bus_start = 0;
        bus_end = 31;  // Scan buses 0-31 with CF8/CFC
        DBG("MMCONFIG failed, using CF8/CFC for buses %d-%d\n", bus_start, bus_end);
    }

    for (bus = bus_start; bus <= bus_end; bus++) {
        for (dev = 0; dev < 32; dev++) {
            for (fun = 0; fun < 8; fun++) {
                u16 vendor;
                u32 v = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x00, 2);
                vendor = (u16)(v & 0xFFFF);
                if (vendor == 0xFFFF)
                    continue;
                    
                u32 dev_id = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x02, 2);
                u32 class_code = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x0A, 3);
                DBG("Found PCI device %02x:%02x.%d: VendorID=%04x, DeviceID=%04x, Class=%06x\n", 
                    bus, dev, fun, vendor, dev_id, class_code);

                {
                    bool use_mmcfg = mmcfg_covers_bus((u8)bus);
                    u32 cfg_size = 256u; // Default to 256 bytes (PCI)
                    
                    // Check if device supports PCIe (which has 4K config space)
                    u32 status = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x04, 2);
                    if (status & (1 << 4)) { // Check if Capabilities List bit is set
                        u8 cap_ptr = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, 0x34, 1);
                        
                        // Walk the capabilities list looking for PCIe capability
                        while (cap_ptr != 0 && cap_ptr != 0xFF) {
                            u32 cap = ReadPCICfg((u8)bus, (u8)dev, (u8)fun, cap_ptr, 4);
                            if ((cap & 0xFF) == 0x10) { // PCIe capability ID
                                cfg_size = 4096u;
                                break;
                            }
                            cap_ptr = (cap >> 8) & 0xFC; // Next capability pointer
                        }
                    }
                    
                    // If using MMCONFIG, we can use the full 4K if the device supports it
                    if (use_mmcfg && cfg_size == 4096u) {
                        cfg_size = 4096u;
                        DBG("  Using 4K config space (MMCFG + PCIe)\n");
                    } else {
                        cfg_size = 256u; // Fall back to 256 bytes for non-PCIe devices
                        DBG("  Using 256B config space (CF8/CFC or non-PCIe)\n");
                    }
                    
                    struct gonzo_pci_hdr hdr;
                    hdr.bus = (u8)bus;
                    hdr.dev = (u8)dev;
                    hdr.fun = (u8)fun;
                    hdr.reserved = 0;
                    hdr.cfg_size = cpu_to_le32(cfg_size);
                    if (!append_blob(&pci_blob, &pci_blob_len, &hdr, sizeof(hdr)))
                        return -ENOMEM;
                    {
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
        }
    }
	if (pci_blob_len > 0) {
		int ret = gonzo_dump_to_file("dekermit.pci", pci_blob, pci_blob_len);
		if (ret)
			DBG("failed to dump pci blob: %d\n", ret);
	}
    return 0;
}

MODULE_DESCRIPTION("Gonzo PCI builder");
MODULE_LICENSE("GPL");


