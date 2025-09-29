#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define GONZO_DEV "/dev/gonzo"
#define IOCTL_ACPI_DUMP _IO('G', 0x01)
#define IOCTL_PCI_DUMP _IO('G', 0x06)
/* Keep in sync with kernel header */
#ifndef IOCTL_HV_TIMED_PROF
#define IOCTL_HV_TIMED_PROF _IO('G', 0x02)
#endif
#ifndef IOCTL_TIMERS_DUMP
#define IOCTL_TIMERS_DUMP _IO('G', 0x03)
#endif
#ifndef IOCTL_USB_DUMP
#define IOCTL_USB_DUMP _IO('G', 0x04)
#endif
#ifndef IOCTL_MSR_DUMP
#define IOCTL_MSR_DUMP _IO('G', 0x05)
#endif

static void usage(const char *prog)
{
	printf("Usage: %s [--hv-prof [iterations] | --timers | --usb | --msr | --acpi | --pci | --all]\n", prog);
	fprintf(stderr, "  --hv-prof: Triggers timing profile (default 200 iters).\n");
	fprintf(stderr, "  --timers: Dumps timer configurations.\n");
	fprintf(stderr, "  --usb: Dumps USB topology.\n");
	fprintf(stderr, "  --msr: Dumps MSRs.\n");
	fprintf(stderr, "  --acpi: Dumps ACPI tables.\n");
	fprintf(stderr, "  --pci: Dumps PCI config spaces.\n");
	fprintf(stderr, "  --all: Triggers all dumps.\n");
}

int main(int argc, char **argv)
{
	int fd = open(GONZO_DEV, O_RDONLY);
	if (fd < 0) {
		perror("open /dev/gonzo");
		return 1;
	}
	if (argc >= 2 && (strcmp(argv[1], "--hv-prof") == 0 || strcmp(argv[1], "-p") == 0)) {
		unsigned long iterations = 0; /* 0 => kernel default 200 */
		if (argc >= 3) {
			char *end = NULL;
			unsigned long val = strtoul(argv[2], &end, 0);
			if (end == argv[2] || *end != '\0') {
				usage(argv[0]);
				close(fd);
				return 1;
			}
			iterations = val;
		}
		if (ioctl(fd, IOCTL_HV_TIMED_PROF, iterations) != 0) {
			perror("ioctl IOCTL_HV_TIMED_PROF");
			close(fd);
			return 1;
		}
		printf("gonzo: HV_TIMED_PROF triggered (iterations=%lu). Check dmesg.\n", iterations);
	} else if (argc >= 2 && (strcmp(argv[1], "--timers") == 0 || strcmp(argv[1], "-t") == 0)) {
		if (ioctl(fd, IOCTL_TIMERS_DUMP, 0) != 0) {
			perror("ioctl IOCTL_TIMERS_DUMP");
			close(fd);
			return 1;
		}
		printf("gonzo: timers dump triggered. Check dmesg.\n");
	} else if (argc >= 2 && (strcmp(argv[1], "--usb") == 0 || strcmp(argv[1], "-u") == 0)) {
		if (ioctl(fd, IOCTL_USB_DUMP, 0) != 0) {
			perror("ioctl IOCTL_USB_DUMP");
			close(fd);
			return 1;
		}
		printf("gonzo: USB dump triggered. Check dmesg.\n");
	} else if (argc >= 2 && (strcmp(argv[1], "--msr") == 0 || strcmp(argv[1], "-m") == 0)) {
		if (ioctl(fd, IOCTL_MSR_DUMP, 0) != 0) {
			perror("ioctl IOCTL_MSR_DUMP");
			close(fd);
			return 1;
		}
		printf("gonzo: MSR dump triggered. Check dmesg.\n");
	} else if (argc >= 2 && (strcmp(argv[1], "--acpi") == 0)) {
		if (ioctl(fd, IOCTL_ACPI_DUMP, 0) != 0) {
			perror("ioctl IOCTL_ACPI_DUMP");
			close(fd);
			return 1;
		}
		printf("gonzo: ACPI dump triggered. Check dmesg.\n");
	} else if (argc >= 2 && (strcmp(argv[1], "--pci") == 0)) {
		if (ioctl(fd, IOCTL_PCI_DUMP, 0) != 0) {
			perror("ioctl IOCTL_PCI_DUMP");
			close(fd);
			return 1;
		}
		printf("gonzo: PCI dump triggered. Check dmesg.\n");
	} else if (argc >= 2 && (strcmp(argv[1], "--all") == 0 || strcmp(argv[1], "-a") == 0)) {
		if (ioctl(fd, IOCTL_ACPI_DUMP, 0) != 0) perror("ioctl ACPI_DUMP");
		if (ioctl(fd, IOCTL_PCI_DUMP, 0) != 0) perror("ioctl PCI_DUMP");
		if (ioctl(fd, IOCTL_HV_TIMED_PROF, 0) != 0) perror("ioctl HV_TIMED_PROF");
		if (ioctl(fd, IOCTL_TIMERS_DUMP, 0) != 0) perror("ioctl TIMERS_DUMP");
		if (ioctl(fd, IOCTL_USB_DUMP, 0) != 0) perror("ioctl USB_DUMP");
		if (ioctl(fd, IOCTL_MSR_DUMP, 0) != 0) perror("ioctl MSR_DUMP");
		printf("gonzo: All dumps triggered. Check dmesg.\n");
	} else {
		usage(argv[0]);
	}
	close(fd);
	return 0;
}


