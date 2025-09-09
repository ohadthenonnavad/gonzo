// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/string.h>
#include "gonzo.h"

/**
 * append_blob - Grow a heap buffer and append bytes
 * @blob: pointer to buffer pointer
 * @len: pointer to current length
 * @data: source bytes to append
 * @add: number of bytes to add
 *
 * Return: pointer to the start of appended region on success, NULL on OOM.
 */
static void *append_blob(uint8_t **blob, size_t *len, const void *data, size_t add)
{
    void *dst;
    uint8_t *newbuf = krealloc(*blob, *len + add, GFP_KERNEL);
    if (!newbuf)
        return NULL;
    dst = newbuf + *len;
    memcpy(dst, data, add);
    *blob = newbuf;
    *len += add;
    return dst;
}

/**
 * gonzo_rsdp_checksum_ok - Validate ACPI RSDP checksum over len bytes
 */
static bool rsdp_checksum_ok(const u8 *p, size_t len)
{
    u8 sum = 0;
    size_t i;
    for (i = 0; i < len; i++)
        sum = (u8)(sum + p[i]);
    return sum == 0;
}

/**
 * gonzo_append_table_phys - Map and append an ACPI table by physical address
 * @pa: physical address of table header
 * @why: log context (e.g. "FADT.Dsdt")
 *
 * Return: 0 on success or negative errno.
 */
static int append_table_phys(phys_addr_t pa, const char *why)
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
 * gonzo_collect_from_sdt - Walk XSDT/RSDT entries and append their tables
 * @base: mapped XSDT or RSDT base
 * @is_xsdt: true for XSDT (64-bit entries) false for RSDT (32-bit)
 */
static void collect_from_sdt(void __iomem *base, bool is_xsdt)
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
            if (sig4[0] == 'F' && sig4[1] == 'A' && sig4[2] == 'C' && sig4[3] == 'P') {
                u32 fwctrl = 0, dsdt = 0;
                memcpy_fromio(&fwctrl, (u8 __iomem *)th + sizeof(struct acpi_table_header) + 0x00, sizeof(u32));
                memcpy_fromio(&dsdt, (u8 __iomem *)th + sizeof(struct acpi_table_header) + 0x04, sizeof(u32));
                if (fwctrl)
                    append_table_phys((phys_addr_t)fwctrl, "FADT.FirmwareCtrl");
                if (dsdt)
                    append_table_phys((phys_addr_t)dsdt, "FADT.Dsdt");
            }
            acpi_os_unmap_iomem(th, tlen);
        }
    }
}

/**
 * gonzo_build_acpi_blob_manual - Manual ACPI discovery
 *
 * Scans EBDA then BIOS region for RSDP, validates, then parses XSDT/RSDT.
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int acpi_build_manual(void)
{
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
                    if (rsdp_checksum_ok((u8 *)&rsdp, 20) &&
                        (rsdp.v1.revision == 0 || rsdp_checksum_ok((u8 *)&rsdp, rsdp.length))) {
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
                    if (rsdp_checksum_ok((u8 *)&rsdp, 20) &&
                        (rsdp.v1.revision == 0 || rsdp_checksum_ok((u8 *)&rsdp, rsdp.length))) {
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
        collect_from_sdt(base, true);
        acpi_os_unmap_iomem(base, len);
        pr_info(DRV_NAME ": ACPI: (manual) total blob len after XSDT=%zu\n", acpi_blob_len);
        return 0;
    }

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
        collect_from_sdt(base, false);
        acpi_os_unmap_iomem(base, len);
        pr_info(DRV_NAME ": ACPI: (manual) total blob len after RSDT=%zu\n", acpi_blob_len);
        return 0;
    }
}

/**
 * gonzo_build_acpi_blob - Preferred ACPI build using ACPICA (fallback manual)
 *
 * Return: 0 on success, negative errno otherwise.
 */
static int acpi_build_acpica(void)
{
    struct acpi_table_header *xsdt = NULL;
    acpi_status status;
    int i;
    uint64_t *entries;
    int num_entries;

    kfree(acpi_blob);
    acpi_blob = NULL;
    acpi_blob_len = 0;

    pr_info(DRV_NAME ": ACPI: start build via ACPICA\n");

    status = acpi_get_table(ACPI_SIG_XSDT, 0, &xsdt);
    pr_info(DRV_NAME ": ACPI: get XSDT status=%d ptr=%p\n", (int)status, xsdt);
    if (ACPI_FAILURE(status) || !xsdt) {
        struct acpi_table_header *rsdt = NULL;
        status = acpi_get_table(ACPI_SIG_RSDT, 0, &rsdt);
        pr_info(DRV_NAME ": ACPI: get RSDT status=%d ptr=%p\n", (int)status, rsdt);
        if (ACPI_FAILURE(status) || !rsdt)
            return acpi_build_manual();
        append_blob(&acpi_blob, &acpi_blob_len, rsdt, le32_to_cpu(rsdt->length));
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

int acpi_build_blob(void)
{
    /* Decide ACPICA vs manual and call accordingly */
    int ret;
    /* Try ACPICA first; if it falls back to manual internally, fine. */
    ret = acpi_build_acpica();
    return ret;
}

MODULE_DESCRIPTION("Gonzo ACPI builder");
MODULE_LICENSE("GPL");


