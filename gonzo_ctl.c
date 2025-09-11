// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* Keep in sync with kernel header values */
#ifndef _IOC
#include <linux/ioctl.h>
#endif

#define DRV_NAME "gonzo"
#define DEV_PATH "/dev/gonzo"

/* Must match gonzo.h: #define IOCTL_HV_TIMED_PROF _IO('G', 0x02) */
#ifndef IOCTL_HV_TIMED_PROF
#define IOCTL_HV_TIMED_PROF _IO('G', 0x02)
#endif

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [iterations]\n", prog);
    fprintf(stderr, "If iterations omitted, passes 0 (kernel defaults to 200).\n");
}

int main(int argc, char **argv)
{
    unsigned long iterations = 0; /* 0 => let kernel pick default */
    int fd;
    int ret;

    if (argc > 2) {
        usage(argv[0]);
        return 1;
    }
    if (argc == 2) {
        char *end = NULL;
        unsigned long val = strtoul(argv[1], &end, 0);
        if (end == argv[1] || *end != '\0') {
            fprintf(stderr, "Invalid iterations: %s\n", argv[1]);
            return 1;
        }
        iterations = val;
    }

    fd = open(DEV_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open /dev/gonzo");
        return 1;
    }

    ret = ioctl(fd, IOCTL_HV_TIMED_PROF, iterations);
    if (ret != 0) {
        perror("ioctl IOCTL_HV_TIMED_PROF");
        close(fd);
        return 1;
    }

    printf("Triggered IOCTL_HV_TIMED_PROF with iterations=%lu. Check dmesg.\n", iterations);
    close(fd);
    return 0;
}


