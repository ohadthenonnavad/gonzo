// SPDX-License-Identifier: GPL-2.0
/**
 * hypervisor.c - Timing-based hypervisor heuristics and profiling
 *
 * This file implements IOCTL_HV_TIMED_PROF functionality used by the
 * core driver to profile selected instructions and emit a packed report
 * as a kernel hex dump. The primary goal is to contrast the average
 * latency of CPUID against a comparatively cheap arithmetic instruction
 * (FYL2XP1), and optionally RDMSR(IA32_TSC), using RDTSCP-based cycle
 * measurements with serialization fences for stability.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include "gonzo.h"

/*
 * Packed 12-byte per-instruction record, little-endian as required.
 */
struct hv_prof_rec {
    uint8_t instr_enum;   /* instruction id (see hv_instr_id) */
    uint8_t alignment;    /* reserved/alignment byte (always 0) */
    __le16 run_count;     /* number of measurements (<= 65535) */
    __le32 avg_cycles;    /* average cycles via RDTSCP */
    __le32 max_cycles;    /* maximum cycles observed */
} __packed;

/* Instruction identifiers for report */
enum hv_instr_id {
    HV_INSTR_CPUID = 1,
    HV_INSTR_FYL2XP1 = 2,
    HV_INSTR_RDMSR_TSC = 3,
};

/* Feature flags determined once per ioctl call */
static bool g_has_rdtsc;
static bool g_has_rdtscp;

/**
 * cpuid_query - Run CPUID with an input leaf and subleaf
 */
static inline void cpuid_query(u32 leaf, u32 subleaf, u32 *a, u32 *b, u32 *c, u32 *d)
{
    u32 ra, rb, rc, rd;
    asm volatile("cpuid" : "=a"(ra), "=b"(rb), "=c"(rc), "=d"(rd) : "a"(leaf), "c"(subleaf) : "memory");
    if (a) *a = ra;
    if (b) *b = rb;
    if (c) *c = rc;
    if (d) *d = rd;
}

/**
 * read_tsc_begin - Get starting TSC timestamp with serialization
 *
 * If RDTSCP is supported, use MFENCE+RDTSCP. Otherwise, serialize with CPUID
 * then read TSC via RDTSC.
 */
static inline u64 read_tsc_begin(void)
{
    if (g_has_rdtscp) {
        u32 lo, hi;
        asm volatile("mfence\n\trdtscp\n\t" : "=a"(lo), "=d"(hi) : : "rcx", "memory");
        return ((u64)hi << 32) | lo;
    } else if (g_has_rdtsc) {
        u32 lo, hi, ta, tb, tc, td;
        /* CPUID flushes pipeline and serializes */
        cpuid_query(1, 0, &ta, &tb, &tc, &td);
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
        return ((u64)hi << 32) | lo;
    } else {
        return 0;
    }
}

/**
 * read_tsc_end - Get ending TSC timestamp
 *
 * If RDTSCP is supported, use RDTSCP. Otherwise use RDTSC. We do not add an
 * extra CPUID here per request (serialize only first read to flush pipeline).
 */
static inline u64 read_tsc_end(void)
{
    if (g_has_rdtscp) {
        u32 lo, hi;
        asm volatile("rdtscp" : "=a"(lo), "=d"(hi) : : "rcx", "memory");
        return ((u64)hi << 32) | lo;
    } else if (g_has_rdtsc) {
        u32 lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
        return ((u64)hi << 32) | lo;
    } else {
        return 0;
    }
}

/**
 * do_cpuid - Execute CPUID leaf 1 for timing purposes
 */
static inline void do_cpuid(void)
{
    u32 a, b, c, d;
    a = 1;
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a) : "memory");
}

/**
 * do_fyl2xp1 - Execute x87 FYL2XP1 on benign stack values
 *
 * Sets up the x87 stack with 1.0,1.0 to compute 1.0 * log2(1+1.0) and then
 * clears the top of stack to avoid leaking state across iterations.
 */
static inline void do_fyl2xp1(void)
{
    asm volatile(
        "fld1\n\t"
        "fld1\n\t"
        "fyl2xp1\n\t"
        "ffree %%st(0)\n\t"
        "fincstp\n\t"
        :: : "memory");
}

/**
 * do_rdmsr_tsc - Execute RDMSR for IA32_TIMESTAMP_COUNTER (0x10)
 */
static inline void do_rdmsr_tsc(void)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0x10) : "memory");
}

/**
 * hv_init - Main entrypoint for timing profile
 * @iterations: number of interleaved iterations (0 => default 200)
 *
 * Interleaves CPUID, FYL2XP1, and RDMSR(IA32_TSC) timing using RDTSCP to
 * measure cycles. Aggregates per-instruction count, average, and max, then
 * emits a hex dump of 3 packed records (36 bytes total) and a verdict line
 * indicating whether CPUID took longer on average than FYL2XP1.
 */
void hv_init(unsigned long iterations)
{
    const unsigned long iters = iterations ? iterations : 200UL;
    u64 sum_cpuid = 0, sum_fyl = 0, sum_rdmsr = 0;
    u32 max_cpuid = 0, max_fyl = 0, max_rdmsr = 0;
    u16 cnt_cpuid = 0, cnt_fyl = 0, cnt_rdmsr = 0;
    unsigned long i;

    /* Detect RDTSC and RDTSCP capabilities once */
    {
        u32 a, b, c, d;
        cpuid_query(0, 0, &a, &b, &c, &d);
        /* Standard feature flags leaf 1 */
        cpuid_query(1, 0, &a, &b, &c, &d);
        g_has_rdtsc = !!(d & (1u << 4)); /* EDX bit 4: RDTSC */
        /* Extended features leaf 0x80000001 for RDTSCP */
        cpuid_query(0x80000000u, 0, &a, &b, &c, &d);
        if (a >= 0x80000001u) {
            cpuid_query(0x80000001u, 0, &a, &b, &c, &d);
            g_has_rdtscp = !!(d & (1u << 27)); /* EDX bit 27: RDTSCP */
        } else {
            g_has_rdtscp = false;
        }
    }

    for (i = 0; i < iters; i++) {
        /* CPUID */
        {
            u64 t0, t1, dt;
            (void)read_tsc_begin(); /* warm */
            t0 = read_tsc_begin();
            do_cpuid();
            t1 = read_tsc_end();
            dt = t1 - t0;
            sum_cpuid += dt;
            if ((u32)dt > max_cpuid)
                max_cpuid = (u32)dt;
            if (cnt_cpuid != 0xFFFF)
                cnt_cpuid++;
        }
        /* FYL2XP1 */
        {
            u64 t0, t1, dt;
            (void)read_tsc_begin();
            t0 = read_tsc_begin();
            do_fyl2xp1();
            t1 = read_tsc_end();
            dt = t1 - t0;
            sum_fyl += dt;
            if ((u32)dt > max_fyl)
                max_fyl = (u32)dt;
            if (cnt_fyl != 0xFFFF)
                cnt_fyl++;
        }
        /* RDMSR IA32_TSC */
        {
            u64 t0, t1, dt;
            (void)read_tsc_begin();
            t0 = read_tsc_begin();
            do_rdmsr_tsc();
            t1 = read_tsc_end();
            dt = t1 - t0;
            sum_rdmsr += dt;
            if ((u32)dt > max_rdmsr)
                max_rdmsr = (u32)dt;
            if (cnt_rdmsr != 0xFFFF)
                cnt_rdmsr++;
        }
    }

    /* Prepare and emit report */
    {
        struct hv_prof_rec recs[3];
        u32 avg_cpuid = cnt_cpuid ? (u32)(sum_cpuid / cnt_cpuid) : 0;
        u32 avg_fyl   = cnt_fyl   ? (u32)(sum_fyl   / cnt_fyl)   : 0;
        u32 avg_rdmsr = cnt_rdmsr ? (u32)(sum_rdmsr / cnt_rdmsr) : 0;

        memset(recs, 0, sizeof(recs));

        recs[0].instr_enum = HV_INSTR_CPUID;
        recs[0].alignment = 0;
        recs[0].run_count = cpu_to_le16(cnt_cpuid);
        recs[0].avg_cycles = cpu_to_le32(avg_cpuid);
        recs[0].max_cycles = cpu_to_le32(max_cpuid);

        recs[1].instr_enum = HV_INSTR_FYL2XP1;
        recs[1].alignment = 0;
        recs[1].run_count = cpu_to_le16(cnt_fyl);
        recs[1].avg_cycles = cpu_to_le32(avg_fyl);
        recs[1].max_cycles = cpu_to_le32(max_fyl);

        recs[2].instr_enum = HV_INSTR_RDMSR_TSC;
        recs[2].alignment = 0;
        recs[2].run_count = cpu_to_le16(cnt_rdmsr);
        recs[2].avg_cycles = cpu_to_le32(avg_rdmsr);
        recs[2].max_cycles = cpu_to_le32(max_rdmsr);

        if (avg_cpuid > avg_fyl)
            DBG("HV_TIMED_PROF verdict: virtualized! (cpuid_avg=%u, fyl2xp1_avg=%u, rdmsr_avg=%u)\n", avg_cpuid, avg_fyl, avg_rdmsr);
        else
            DBG("HV_TIMED_PROF verdict: not virtualized (cpuid_avg=%u, fyl2xp1_avg=%u, rdmsr_avg=%u)\n", avg_cpuid, avg_fyl, avg_rdmsr);

        {
            const u8 *p = (const u8 *)recs;
            char line[36 * 3 + 1];
            size_t pos = 0;
            size_t j;
            for (j = 0; j < sizeof(recs); j++)
                pos += scnprintf(line + pos, sizeof(line) - pos, "%02x ", p[j]);
            if (pos > 0 && pos < sizeof(line))
                line[pos - 1] = '\0';
            DBG("HV_TIMED_PROF (iters=%lu): %s\n", iters, line);
			{
				int ret = gonzo_dump_to_file("dekermit.hv", (const u8 *)recs, sizeof(recs));
				if (ret)
					DBG("failed to dump hv blob: %d\n", ret);
			}
        }
    }
}

MODULE_DESCRIPTION("Gonzo hypervisor timing profile");
MODULE_LICENSE("GPL");


