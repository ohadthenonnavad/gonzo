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
#include <linux/init.h>
#include <linux/printk.h>
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
    __le32 type;           /* timer type (see enum timer_type) */
    __le32 data_size;      /* size of following data in bytes */
} __packed;

/* HPET memory space - dump entire mapped region */
#define HPET_MEM_SIZE 0x1000  /* 4KB HPET memory space */

/* APIC memory space - dump entire mapped region */
#define APIC_MEM_SIZE 0x1000  /* 4KB APIC memory space */

/* ACPI timer data */
struct acpi_timer_data {
    __le32 counter_value;  /* 32-bit counter value */
} __packed;

/* IOAPIC Interrupt Source Override */
struct ioapic_irq_override {
    __u8 bus;               /* Bus number */
    __u8 source_irq;        /* Source IRQ */
    __u32 global_irq;       /* Global system interrupt */
    __u16 inti_flags;       /* MPS INTI flags */
} __packed;

/* IOAPIC NMI Source */
struct ioapic_nmi_source {
    __u32 global_irq;       /* Global system interrupt */
    __u16 inti_flags;       /* MPS INTI flags */
} __packed;

/* IOAPIC entry type counts */
struct ioapic_entry_counts {
    __le32 num_ioapic;      /* Number of IOAPIC entries */
    __le32 num_irq_override; /* Number of IRQ override entries */
    __le32 num_nmi_source;   /* Number of NMI source entries */
} __packed;

/* IOAPIC timer configuration */
struct ioapic_timer_config {
    /* Header with entry type counts */
    __le32 magic;           /* Magic number IOAPIC */
    __le32 version;         /* Structure version */
    __le32 header_size;     /* Size of this header */
    __le32 num_ioapic;      /* Number of IOAPIC entries */
    __le32 num_irq_override; /* Number of IRQ override entries */
    __le32 num_nmi_source;   /* Number of NMI source entries */
    
    /* IOAPIC-specific data */
    __le32 ioapic_id;       /* IOAPIC ID */
    __le32 ioapic_version;  /* IOAPIC version */
    __le32 gsi_base;        /* Global System Interrupt base */
    __le32 redir_table[64];  /* Redirection table entries (64 entries * 32 bits each) */
    
    /* Followed by:
     * - Array of ioapic_irq_override (num_irq_override entries)
     * - Array of ioapic_nmi_source (num_nmi_source entries)
     */
} __packed;

/* IOAPIC magic number and version */
#define IOAPIC_MAGIC 0x4F41504F  /* 'OAPO' in ASCII */
#define IOAPIC_VERSION 1

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
    
    /* Initialize header */
    hdr.type = cpu_to_le32(timer_type);
    hdr.data_size = cpu_to_le32(data_size);
    
    /* Allocate or reallocate buffer */
    newbuf = krealloc(*buffer, *len + sizeof(hdr) + data_size, GFP_KERNEL);
    if (!newbuf) {
        DBG("Failed to reallocate timer data buffer\n");
        return -ENOMEM;
    }
    
    *buffer = newbuf;
    
    /* Copy header */
    memcpy(*buffer + *len, &hdr, sizeof(hdr));
    *len += sizeof(hdr);
    
    /* Copy data */
    if (data && data_size > 0) {
        memcpy(*buffer + *len, data, data_size);
        *len += data_size;
    }
    
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
    struct acpi_table_header *madt;
    struct acpi_subtable_header *entry;
    struct ioapic_timer_config *ioapic_data = NULL;
    struct ioapic_irq_override *override_ptr = NULL;
    struct ioapic_nmi_source *nmi_ptr = NULL;
    void *madt_end;
    u32 num_ioapic = 0, num_irq_override = 0, num_nmi_source = 0;
    size_t header_size, buffer_size, data_size;
    u8 *buffer_ptr = NULL;
    acpi_status status;
    int i, num_ioapics = 0;

    /* Get MADT table */
    status = acpi_get_table(ACPI_SIG_MADT, 0, &madt);
    if (ACPI_FAILURE(status)) {
        DBG("Failed to get MADT table\n");
        return -ENODEV;
    }

    DBG("MADT found at %p, length: %u\n", madt, madt->length);
    /* Print first 256 bytes or full table, whichever is smaller */
    {
        size_t dump_len = madt->length > 256 ? 256 : madt->length;
        print_hex_dump(KERN_DEBUG, "MADT: ", DUMP_PREFIX_OFFSET, 16, 1, madt, dump_len, true);
    }
    madt_end = (void *)madt + madt->length;

    /* First pass: count different entry types */
    entry = (struct acpi_subtable_header *)((char *)madt + 0x2c);
    while ((void *)entry < madt_end) {
        if (entry->length == 0) {
            DBG("Invalid zero-length MADT entry, stopping parse\n");
            break;
        }

        switch (entry->type) {
            case ACPI_MADT_TYPE_IO_APIC:
                num_ioapic++;
                DBG("Found IOAPIC entry, count: %u\n", num_ioapic);
                break;
                
            case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE:
                num_irq_override++;
                DBG("Found IRQ override entry, count: %u\n", num_irq_override);
                break;
                
            case ACPI_MADT_TYPE_NMI_SOURCE:
                num_nmi_source++;
                DBG("Found NMI source entry, count: %u\n", num_nmi_source);
                break;
                
            default:
                DBG("Skipping MADT entry type: 0x%02x\n", entry->type);
                break;
        }
        
        entry = (struct acpi_subtable_header *)((char *)entry + entry->length);
       
        if (entry->length == 0) {
            DBG("Invalid zero-length MADT entry, stopping parse\n");
            break;
        }
        
        entry = (struct acpi_subtable_header *)((char *)entry + entry->length );
        
    }
    
    DBG("IOAPIC Entry Counts: IOAPIC=%u, IRQ Override=%u, NMI Source=%u\n",
        num_ioapic, num_irq_override, num_nmi_source);
    
    /* Calculate sizes */
    header_size = sizeof(struct ioapic_timer_config);
    data_size = header_size + 
               (num_irq_override * sizeof(struct ioapic_irq_override)) +
               (num_nmi_source * sizeof(struct ioapic_nmi_source));
    
    /* Allocate buffer for timer header + IOAPIC data */
    buffer_size = sizeof(struct timer_header) + data_size;
    ioapic_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!ioapic_buffer) {
        DBG("Failed to allocate IOAPIC buffer\n");
        acpi_put_table(madt);
        return -ENOMEM;
    }
    
    /* Initialize buffer */
    buffer_ptr = ioapic_buffer + sizeof(struct timer_header);
    memset(buffer_ptr, 0, data_size);
    
    /* Set up IOAPIC header */

    DBG("Setting up IOAPIC header");
    ioapic_data = (struct ioapic_timer_config *)buffer_ptr;
    ioapic_data->magic = cpu_to_le32(IOAPIC_MAGIC);
    ioapic_data->version = cpu_to_le32(IOAPIC_VERSION);
    ioapic_data->header_size = cpu_to_le32(header_size);
    ioapic_data->num_ioapic = cpu_to_le32(num_ioapic);
    ioapic_data->num_irq_override = cpu_to_le32(num_irq_override);
    ioapic_data->num_nmi_source = cpu_to_le32(num_nmi_source);
    
    /* Pointers to variable data sections */
    override_ptr = (struct ioapic_irq_override *)((u8 *)ioapic_data + header_size);
    nmi_ptr = (struct ioapic_nmi_source *)((u8 *)override_ptr + 
                                         (num_irq_override * sizeof(struct ioapic_irq_override)));
    
    /* Second pass: process all entries */
    entry = (struct acpi_subtable_header *)((char *)madt + 0x2c);
    while ((void *)entry < madt_end) {
        if (entry->length == 0) {
            break;
        }
            
        switch (entry->type) {
            case ACPI_MADT_TYPE_IO_APIC: {
                struct acpi_madt_io_apic *ioapic = (struct acpi_madt_io_apic *)((char *)entry);
                void __iomem *ioapic_base;
                int i;
                
                DBG("IOAPIC: ID=%u, Addr=0x%llx, GSI Base=%u\n",
                    ioapic->id, (unsigned long long)ioapic->address, ioapic->global_irq_base);
               
                /* Process all IOAPICs */
                ioapic_base = ioremap(ioapic->address, 0x1000);
                if (ioapic_base) {
                    /* Only process the first IOAPIC for now (simplification) */
                    if (num_ioapics++ == 0) {
                        ioapic_data->ioapic_id = cpu_to_le32(ioapic->id);
                        ioapic_data->gsi_base = cpu_to_le32(ioapic->global_irq_base);
                        ioapic_data->ioapic_version = cpu_to_le32(readl(ioapic_base + 0x01) & 0xFF);

                        /* Read redirection table */
                        for (i = 0; i < 64; i++) {
                            u32 reg_high = 0x10 + 2 * i + 1;
                            u32 low = readl(ioapic_base + 0x10 + 2 * i);
                            u32 high = readl(ioapic_base + reg_high);
                            ioapic_data->redir_table[i] = cpu_to_le32(low | (high << 16));
                        }
                    }
                    iounmap(ioapic_base);
                }
                break;
            }
            
            case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE: {
                struct acpi_madt_interrupt_override *madt_override = 
                    (struct acpi_madt_interrupt_override *)entry;
                if (override_ptr < (struct ioapic_irq_override *)nmi_ptr) {
                    override_ptr->bus = madt_override->bus;
                    override_ptr->source_irq = madt_override->source_irq;
                    override_ptr->global_irq = cpu_to_le32(madt_override->global_irq);
                    override_ptr->inti_flags = cpu_to_le16(madt_override->inti_flags);
                    DBG("override_ptr fields are %lu %lu %lu %lu", override_ptr->bus, override_ptr->source_irq, override_ptr->global_irq, override_ptr->inti_flags);
                    override_ptr++;
                }
                break;
            }
            
            case ACPI_MADT_TYPE_NMI_SOURCE: {
                struct acpi_madt_nmi_source *madt_nmi = 
                    (struct acpi_madt_nmi_source *)entry;
                if (nmi_ptr < (struct ioapic_nmi_source *)((u8 *)buffer_ptr + buffer_size)) {
                    nmi_ptr->global_irq = cpu_to_le32(madt_nmi->global_irq);
                    nmi_ptr->inti_flags = cpu_to_le16(madt_nmi->inti_flags);
                    nmi_ptr++;
                }
                break;
            }
        
            default: {
                break;
            }

        }

        entry = (struct acpi_subtable_header *)((char *)entry + entry->length);
       
    }

    /* Verify we have enough space for the data we wrote */
    size_t actual_data_size = (u8 *)nmi_ptr + (num_nmi_source * sizeof(struct ioapic_nmi_source)) - (u8 *)ioapic_data;
    if (actual_data_size > data_size) {
        DBG("Warning: Data size mismatch: expected %zu, actual %zu\n", 
            data_size, actual_data_size);
    }
    
    /* Set up the timer header */
    {
        struct timer_header *header = (struct timer_header *)ioapic_buffer;
        header->type = cpu_to_le32(TIMER_IOAPIC);
        header->data_size = cpu_to_le32(data_size);

        DBG("Setting up timer header for IOAPIC, data size: %zu\n", header->data_size);
        DBG("Setting up timer header for IOAPIC, header_type: %d\n", header->type);

        ioapic_buffer_len = sizeof(struct timer_header) + data_size;
    }
    
    acpi_put_table(madt);
   
    return 0;
}

/**
 * timers_dump_all - Dump all timer configurations
 *
 * Calls individual timer dump functions and reports results.
 *
 * Return: 0 on success, negative errno if all dumps fail
 */
/* Header structure for timers dump */
struct timers_dump_header {
    __le32 magic;           /* 'TIMR' in ASCII */
    __le32 version;         /* Format version */
    __le32 hpet_count;      /* Number of HPET timers */
    __le32 apic_count;      /* Number of APIC timers */
    __le32 acpi_count;      /* Number of ACPI timers */
    __le32 ioapic_count;    /* Number of IOAPIC timers */
    __le32 reserved[2];     /* For future use */
} __packed;

int timers_dump_all(void)
{
    int hpet_ret = 0, apic_ret = 0, acpi_ret = 0, ioapic_ret = 0;
    size_t success_count = 0;
    struct timers_dump_header header = {
        .magic = cpu_to_le32(0x524D4954), /* 'TIMR' in little-endian */
        .version = cpu_to_le32(1),
    };
    
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

    /*Finshed, done*/

    /* Prepend header to the blob */
    {
        size_t total_size = sizeof(header) + timers_blob_len;
        void *final_blob = kmalloc(total_size, GFP_KERNEL);
        
        if (!final_blob) {
            DBG("Failed to allocate memory for final timers blob\n");
            kfree(timers_blob);
            return -ENOMEM;
        }
        
        /* Update counts in header */
        header.hpet_count = cpu_to_le32(hpet_buffer && hpet_buffer_len ? 1 : 0);
        header.apic_count = cpu_to_le32(apic_buffer && apic_buffer_len ? 1 : 0);
        header.acpi_count = cpu_to_le32(acpi_timer_buffer && acpi_timer_buffer_len ? 1 : 0);
        header.ioapic_count = cpu_to_le32(ioapic_buffer && ioapic_buffer_len ? 1 : 0);
        
        /* Copy header and data */
        memcpy(final_blob, &header, sizeof(header));
        if (timers_blob_len > 0) {
            memcpy((char *)final_blob + sizeof(header), timers_blob, timers_blob_len);
        }
        
        /* Dump to file in current working dir */
        gonzo_dump_to_file("dekermit.timers", final_blob, total_size);
        kfree(final_blob);
    }
    
    kfree(timers_blob);
    return 0;
}


MODULE_DESCRIPTION("Gonzo timer configuration dumper");
MODULE_LICENSE("GPL");
