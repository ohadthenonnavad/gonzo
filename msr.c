// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/msr.h> 
#include "gonzo.h"

struct msr_entry {
    u32 num;
    char name[32];
    u64 val;
    u8 success;
} __packed;

static uint8_t *msr_blob;
static size_t msr_blob_len;

static void append_msr(u32 num, const char *name) {
    struct msr_entry entry;
    entry.num = num;
    strncpy(entry.name, name, sizeof(entry.name) - 1);
    entry.name[sizeof(entry.name) - 1] = '\0';
    if (rdmsrl_safe(num, &entry.val) != 0) {
        entry.val = 0x0;
        entry.success = 0;
    } else {
        entry.success = 1;
    }
    append_blob(&msr_blob, &msr_blob_len, &entry, sizeof(entry));
}

int msr_dump_blob(void) {
    kfree(msr_blob);
    msr_blob = NULL;
    msr_blob_len = 0;

    append_msr(0x34, "SMI_COUNT");

    if (boot_cpu_has(X86_FEATURE_VMX)) {
        append_msr(0x480, "IA32_VMX_BASIC");
        append_msr(0x481, "IA32_VMX_PINBASED_CTLS");
        append_msr(0x482, "IA32_VMX_PROCBASED_CTLS");
        append_msr(0x483, "IA32_VMX_EXIT_CTLS");
        append_msr(0x484, "IA32_VMX_ENTRY_CTLS");
    }

    if (msr_blob_len > 0) {
        int ret = gonzo_dump_to_file("dekermit.msr", msr_blob, msr_blob_len);
        if (ret) {
            DBG("failed to dump msr blob: %d\n", ret);
        }
    }

    DBG("MSR dump complete, len=%zu\n", msr_blob_len);
    return 0;
}

MODULE_DESCRIPTION("Gonzo MSR dumper");
MODULE_LICENSE("GPL");
