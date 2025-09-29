// SPDX-License-Identifier: GPL-2.0
/**
 * timers.c - Timer configuration space dumper
 *
 * This module dumps configuration spaces for various system timers:
 * - HPET: Hardware Performance Event Timer configuration space
 * - APIC: Advanced Programmable Interrupt Controller with TSC-Deadline support
 * - ACPI Timer: X_PMTimerBlock (MMIO/IO) or PMTimerBlock (IO only)
 * - IOAPIC: I/O Advanced Programmable Interrupt Controller timer tables
 *
 * Each timer type outputs a header followed by the raw configuration data.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/acpi.h>
#include <linux/pci.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/hpet.h>
#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <linux/version.h>
#include "gonzo.h"


/* Timer type enumeration */
enum timer_type {
    TIMER_HPET = 1,
    TIMER_APIC = 2,
    TIMER_ACPI = 3,
    TIMER_IOAPIC = 4,
};

/* Common timer header structure */
struct timer_header {
    uint8_t timer_enum;    /* timer type (see enum timer_type) */
    uint8_t reserved[3];   /* padding to 4-byte boundary */
    __le32 data_size;      /* size of following data in bytes */
} __packed;

/* HPET memory space - dump entire mapped region */
#define HPET_MEM_SIZE 0x1000  /* 4KB HPET memory space */

/* APIC memory space - dump entire mapped region */
#define APIC_MEM_SIZE 0x1000  /* 4KB APIC memory space */

/* ACPI timer data */
struct acpi_timer_data {
    __le32 counter_value;  /* 32-bit counter value */
    __le32 reserved;       /* Padding to 8 bytes */
} __packed;

/* IOAPIC timer configuration */
struct ioapic_timer_config {
    __le32 ioapic_id;      /* IOAPIC ID */
    __le32 ioapic_version; /* IOAPIC version */
    __le32 redir_table[64]; /* Redirection table entries */
} __packed;

/* Global timer buffers */
static uint8_t *hpet_buffer;
static size_t hpet_buffer_len;
static uint8_t *apic_buffer;
static size_t apic_buffer_len;
static uint8_t *acpi_timer_buffer;
static size_t acpi_timer_buffer_len;
static uint8_t *ioapic_buffer;
static size_t ioapic_buffer_len;

/* Aggregate timers blob */
uint8_t *timers_blob;
size_t timers_blob_len;

/**
 * append_timer_data - Append timer data to buffer with header
 * @buffer: pointer to buffer pointer
 * @len: pointer to current length
 * @timer_type: timer type enum
 * @data: data to append
 * @data_size: size of data
 *
 * Return: 0 on success, -ENOMEM on allocation failure
 */
static int append_timer_data(uint8_t **buffer, size_t *len, enum timer_type timer_type,
                            const void *data, size_t data_size)
{
    struct timer_header hdr;
    uint8_t *newbuf;
    
    hdr.timer_enum = timer_type;
    hdr.reserved[0] = hdr.reserved[1] = hdr.reserved[2] = 0;
    hdr.data_size = cpu_to_le32(data_size);
    
    newbuf = krealloc(*buffer, *len + sizeof(hdr) + data_size, GFP_KERNEL);
    if (!newbuf)
        return -ENOMEM;
    
    memcpy(newbuf + *len, &hdr, sizeof(hdr));
    memcpy(newbuf + *len + sizeof(hdr), data, data_size);
    
    *buffer = newbuf;
    *len += sizeof(hdr) + data_size;
    return 0;
}

/**
 * dump_hpet_config - Dump HPET configuration space
 *
 * Maps HPET MMIO region and copies configuration registers.
 * Checks for HPET support via ACPI and CPU features.
 *
 * Return: 0 on success, negative errno on failure
 */
static int dump_hpet_config(void)
{
    void __iomem *hpet_base;
    phys_addr_t hpet_phys;
    u8 *hpet_mem_data;
    int ret = 0;
    struct acpi_table_hpet *hpet_table;
    acpi_status status;
    
    /* Allocate new buffer for entire HPET memory space */
    hpet_buffer = kmalloc(sizeof(struct timer_header) + HPET_MEM_SIZE, GFP_KERNEL);
    if (!hpet_buffer) {
        DBG("Failed to allocate HPET buffer\n");
        return -ENOMEM;
    }
    hpet_buffer_len = 0;
    
    /* Check if HPET is supported - use kernel version compatible approach */
#if defined(CONFIG_ACPI) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
    /* Newer kernels: try FADT first, fallback to table */
    if (acpi_gbl_FADT.hpet_block && acpi_gbl_FADT.hpet_block.address) {
        hpet_phys = acpi_gbl_FADT.hpet_block.address;
        DBG("Using HPET from FADT (newer kernel)\n");
    } else {        
        
        status = acpi_get_table(ACPI_SIG_HPET, 0, (struct acpi_table_header **)&hpet_table);
        if (ACPI_FAILURE(status) || !hpet_table) {
            DBG("HPET not found in FADT or ACPI table\n");
            kfree(hpet_buffer);
            hpet_buffer = NULL;
            return -ENODEV;
        }
        hpet_phys = hpet_table->address.address;
        acpi_put_table(&hpet_table->header);
        DBG("Using HPET from ACPI table (newer kernel)\n");
    }
#else /* older kernels or ACPI disabled */
    /* Older kernels: use ACPI table approach */
    
    status = acpi_get_table(ACPI_SIG_HPET, 0, (struct acpi_table_header **)&hpet_table);
    if (ACPI_FAILURE(status) || !hpet_table) {
        /* As a last resort, try the common default HPET base 0xFED00000 */
        hpet_phys = (phys_addr_t)0xFED00000ULL;
        DBG("HPET ACPI table not found; trying default base 0xFED00000\n");
        goto try_map_hpet;
    }
    hpet_phys = hpet_table->address.address;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    acpi_put_table(&hpet_table->header);
    #endif
    DBG("Using HPET from ACPI table (older kernel)\n");
#endif
    
    if (!hpet_phys) {
        DBG("HPET base address not found\n");
        kfree(hpet_buffer);
        hpet_buffer = NULL;
        return -ENODEV;
    }
    
    DBG("HPET supported, base address: 0x%llx\n", (unsigned long long)hpet_phys);
    
try_map_hpet:
    /* Map entire HPET MMIO region */
    hpet_base = ioremap(hpet_phys, HPET_MEM_SIZE);
    if (!hpet_base) {
        DBG("Failed to map HPET MMIO region\n");
        kfree(hpet_buffer);
        hpet_buffer = NULL;
        return -ENOMEM;
    }
    
    /* Read entire HPET memory space */
    hpet_mem_data = kmalloc(HPET_MEM_SIZE, GFP_KERNEL);
    if (!hpet_mem_data) {
        DBG("Failed to allocate HPET memory data buffer\n");
        iounmap(hpet_base);
        kfree(hpet_buffer);
        hpet_buffer = NULL;
        return -ENOMEM;
    }
    
    memcpy_fromio(hpet_mem_data, hpet_base, HPET_MEM_SIZE);
    /* Heuristic: ensure capabilities register (first qword) looks nonzero */
    if (*(u64 *)hpet_mem_data == 0) {
        DBG("HPET at 0x%llx appears invalid (capabilities=0)\n", (unsigned long long)hpet_phys);
        iounmap(hpet_base);
        kfree(hpet_mem_data);
        kfree(hpet_buffer);
        hpet_buffer = NULL;
        return -ENODEV;
    }
    
    /* Append entire memory space to buffer */
    ret = append_timer_data(&hpet_buffer, &hpet_buffer_len, TIMER_HPET,
                           hpet_mem_data, HPET_MEM_SIZE);
    
    iounmap(hpet_base);
    kfree(hpet_mem_data);
    
    if (ret) {
        kfree(hpet_buffer);
        hpet_buffer = NULL;
    }
    
    return ret;
}

/**
 * dump_apic_config - Dump APIC timer configuration
 *
 * Reads local APIC timer configuration including TSC-Deadline support.
 * Checks for APIC and TSC-Deadline timer support.
 *
 * Return: 0 on success, negative errno on failure
 */
static int dump_apic_config(void)
{
    void __iomem *apic_base;
    u8 *apic_mem_data;
    int ret = 0;
    
    /* Allocate new buffer for entire APIC memory space */
    apic_buffer = kmalloc(sizeof(struct timer_header) + APIC_MEM_SIZE, GFP_KERNEL);
    if (!apic_buffer) {
        DBG("Failed to allocate APIC buffer\n");
        return -ENOMEM;
    }
    apic_buffer_len = 0;
    
    /* Check if APIC is available */
    if (!boot_cpu_has(X86_FEATURE_APIC)) {
        DBG("APIC not available on this CPU\n");
        kfree(apic_buffer);
        apic_buffer = NULL;
        return -ENODEV;
    }
    
    /* For older kernels, we'll assume APIC is initialized if the feature is present */
    DBG("APIC feature detected, proceeding with memory dump\n");
    
    /* Determine APIC base via MSR IA32_APIC_BASE (0x1B) */
    {
        u32 lo, hi;
        phys_addr_t apic_phys;
        rdmsr(MSR_IA32_APICBASE, lo, hi);
        apic_phys = ((u64)hi << 32) | (lo & 0xFFFFF000U);
        if (!apic_phys)
            apic_phys = 0xFEE00000ULL; /* fallback */
        DBG("APIC base via MSR: 0x%llx\n", (unsigned long long)apic_phys);
        /* Map APIC memory space using detected base */
        apic_base = ioremap(apic_phys, APIC_MEM_SIZE);
    }
    if (!apic_base) {
        DBG("Failed to map APIC memory region\n");
        kfree(apic_buffer);
        apic_buffer = NULL;
        return -ENOMEM;
    }
    
    /* Read entire APIC memory space */
    apic_mem_data = kmalloc(APIC_MEM_SIZE, GFP_KERNEL);
    if (!apic_mem_data) {
        DBG("Failed to allocate APIC memory data buffer\n");
        iounmap(apic_base);
        kfree(apic_buffer);
        apic_buffer = NULL;
        return -ENOMEM;
    }
    
    memcpy_fromio(apic_mem_data, apic_base, APIC_MEM_SIZE);
    
    /* Append entire memory space to buffer */
    ret = append_timer_data(&apic_buffer, &apic_buffer_len, TIMER_APIC,
                           apic_mem_data, APIC_MEM_SIZE);
    
    iounmap(apic_base);
    kfree(apic_mem_data);
    
    if (ret) {
        kfree(apic_buffer);
        apic_buffer = NULL;
    }
    
    return ret;
}

/**
 * dump_acpi_timer - Dump ACPI timer counter value
 *
 * Handles both X_PMTimerBlock (MMIO/IO) and PMTimerBlock (IO only).
 * Checks for ACPI timer support and availability.
 *
 * Return: 0 on success, negative errno on failure
 */
static int dump_acpi_timer(void)
{
    struct acpi_timer_data timer_data;
    void __iomem *mmio_base = NULL;
    u32 counter_value = 0;
    int ret = 0;
    
    /* Allocate new buffer */
    acpi_timer_buffer = kmalloc(sizeof(struct timer_header) + sizeof(timer_data), GFP_KERNEL);
    if (!acpi_timer_buffer) {
        DBG("Failed to allocate ACPI timer buffer\n");
        return -ENOMEM;
    }
    acpi_timer_buffer_len = 0;
    
    /* Check if ACPI is available */
    if (acpi_disabled) {
        DBG("ACPI is disabled\n");
        kfree(acpi_timer_buffer);
        acpi_timer_buffer = NULL;
        return -ENODEV;
    }
    
    /* Check X_PMTimerBlock first */
    if (acpi_gbl_FADT.xpm_timer_block.address) {
        u64 addr = acpi_gbl_FADT.xpm_timer_block.address;
        u8 space_id = acpi_gbl_FADT.xpm_timer_block.space_id;
        
        DBG("Using X_PMTimerBlock, address: 0x%llx, space: %d\n", 
            (unsigned long long)addr, space_id);
        
        if (space_id == ACPI_ADR_SPACE_SYSTEM_MEMORY) {
            /* MMIO space */
            mmio_base = ioremap(addr, 4);
            if (mmio_base) {
                counter_value = readl(mmio_base);
                iounmap(mmio_base);
                DBG("ACPI timer (MMIO) counter: 0x%x\n", counter_value);
            } else {
                DBG("Failed to map ACPI timer MMIO\n");
                ret = -ENOMEM;
            }
        } else if (space_id == ACPI_ADR_SPACE_SYSTEM_IO) {
            /* IO space */
            counter_value = inl(addr);
            DBG("ACPI timer (IO) counter: 0x%x\n", counter_value);
        } else {
            DBG("Unsupported ACPI timer address space: %d\n", space_id);
            ret = -ENODEV;
        }
    } else if (acpi_gbl_FADT.pm_timer_length) {
        /* PMTimerBlock - IO space only */
        DBG("Using PMTimerBlock, address: 0x%x\n", 
            acpi_gbl_FADT.pm_timer_block);
        counter_value = inl(acpi_gbl_FADT.pm_timer_block);
        DBG("ACPI timer (PMTimer) counter: 0x%x\n", counter_value);
    } else {
        DBG("No ACPI timer found (neither X_PMTimerBlock nor PMTimerBlock)\n");
        ret = -ENODEV;
    }
    
    if (ret) {
        kfree(acpi_timer_buffer);
        acpi_timer_buffer = NULL;
        return ret;
    }
    
    timer_data.counter_value = cpu_to_le32(counter_value);
    timer_data.reserved = 0;
    
    /* Append to buffer */
    ret = append_timer_data(&acpi_timer_buffer, &acpi_timer_buffer_len, TIMER_ACPI,
                           &timer_data, sizeof(timer_data));
    
    if (ret) {
        kfree(acpi_timer_buffer);
        acpi_timer_buffer = NULL;
    }
    
    return ret;
}

/**
 * dump_ioapic_config - Dump IOAPIC configuration
 *
 * Follows OSDev wiki guidelines to find and dump IOAPIC tables.
 * Checks for IOAPIC support and availability.
 *
 * Return: 0 on success, negative errno on failure
 */
static int dump_ioapic_config(void)
{
    struct ioapic_timer_config ioapic_data;
    void __iomem *ioapic_base;
    u32 ioapic_id, ioapic_version;
    int i, ret = 0;
    
    /* Allocate new buffer */
    ioapic_buffer = kmalloc(sizeof(struct timer_header) + sizeof(ioapic_data), GFP_KERNEL);
    if (!ioapic_buffer) {
        DBG("Failed to allocate IOAPIC buffer\n");
        return -ENOMEM;
    }
    ioapic_buffer_len = 0;
    
    /* Check if IOAPIC is supported - use alternative detection for older kernels */
    /* For now, we'll try to access the default IOAPIC base and see if it works */
    DBG("Attempting IOAPIC detection\n");
    
    /* Check if ACPI MADT is available for IOAPIC discovery */
    if (acpi_disabled) {
        DBG("ACPI disabled, cannot discover IOAPIC configuration\n");
        kfree(ioapic_buffer);
        ioapic_buffer = NULL;
        return -ENODEV;
    }
    
    DBG("Attempting to access IOAPIC configuration\n");
    
    /* For now, use the first IOAPIC found in MADT */
    /* This is a simplified implementation - full implementation would
     * parse MADT to find all IOAPICs and their base addresses */
    
    /* Use default IOAPIC base if available */
    ioapic_base = ioremap(0xFEC00000, 0x1000); /* Default IOAPIC base */
    if (!ioapic_base) {
        DBG("Failed to map IOAPIC base\n");
        kfree(ioapic_buffer);
        ioapic_buffer = NULL;
        return -ENOMEM;
    }
    
    /* Read IOAPIC ID and version */
    ioapic_id = readl(ioapic_base + 0x00);
    ioapic_version = readl(ioapic_base + 0x01);
    
    ioapic_data.ioapic_id = cpu_to_le32(ioapic_id);
    ioapic_data.ioapic_version = cpu_to_le32(ioapic_version);
    
    /* Read redirection table entries (simplified - read first 64 entries) */
    for (i = 0; i < 64; i++) {
        u32 reg = 0x10 + (i * 2);
        u32 low = readl(ioapic_base + reg);
        u32 high = readl(ioapic_base + reg + 4);
        /* Store as 64-bit value split into two 32-bit parts */
        ioapic_data.redir_table[i] = cpu_to_le32(low);
        if (i < 32) /* Only store high parts for first 32 entries to avoid overflow */
            ioapic_data.redir_table[i + 32] = cpu_to_le32(high);
    }
    
    /* Append to buffer */
    ret = append_timer_data(&ioapic_buffer, &ioapic_buffer_len, TIMER_IOAPIC,
                           &ioapic_data, sizeof(ioapic_data));
    
    iounmap(ioapic_base);
    
    if (ret) {
        kfree(ioapic_buffer);
        ioapic_buffer = NULL;
    }
    
    return ret;
}

/**
 * timers_dump_all - Dump all timer configurations
 *
 * Calls individual timer dump functions and reports results.
 *
 * Return: 0 on success, negative errno if all dumps fail
 */
int timers_dump_all(void)
{
    int hpet_ret, apic_ret, acpi_ret, ioapic_ret;
    int success_count = 0;
    
    DBG("Starting timer configuration dump\n");
    DBG("Entering timers_dump_all function\n");
    
    hpet_ret = dump_hpet_config();
    if (hpet_ret) {
        DBG("HPET dump failed: %d\n", hpet_ret);
    } else {
        DBG("HPET dump ok, len=%zu\n", hpet_buffer_len);
        success_count++;
    }
    
    apic_ret = dump_apic_config();
    if (apic_ret) {
        DBG("APIC dump failed: %d\n", apic_ret);
    } else {
        DBG("APIC dump ok, len=%zu\n", apic_buffer_len);
        success_count++;
    }
    
    acpi_ret = dump_acpi_timer();
    if (acpi_ret) {
        DBG("ACPI timer dump failed: %d\n", acpi_ret);
    } else {
        DBG("ACPI timer dump ok, len=%zu\n", acpi_timer_buffer_len);
        success_count++;
    }
    
    ioapic_ret = dump_ioapic_config();
    if (ioapic_ret) {
        DBG("IOAPIC dump failed: %d\n", ioapic_ret);
    } else {
        DBG("IOAPIC dump ok, len=%zu\n", ioapic_buffer_len);
        success_count++;
    }
    
    if (success_count == 0)
        return -ENODEV;

    /* Aggregate: concatenate all available timer segments into one blob */
    kfree(timers_blob);
    timers_blob = NULL;
    timers_blob_len = 0;
    if (hpet_buffer && hpet_buffer_len)
        append_blob(&timers_blob, &timers_blob_len, hpet_buffer, hpet_buffer_len);
    if (apic_buffer && apic_buffer_len)
        append_blob(&timers_blob, &timers_blob_len, apic_buffer, apic_buffer_len);
    if (acpi_timer_buffer && acpi_timer_buffer_len)
        append_blob(&timers_blob, &timers_blob_len, acpi_timer_buffer, acpi_timer_buffer_len);
    if (ioapic_buffer && ioapic_buffer_len)
        append_blob(&timers_blob, &timers_blob_len, ioapic_buffer, ioapic_buffer_len);

    /* Dump to file in current working dir */
    gonzo_dump_to_file("dekermit.timers", timers_blob, timers_blob_len);
    return 0;
}


MODULE_DESCRIPTION("Gonzo timer configuration dumper");
MODULE_LICENSE("GPL");
