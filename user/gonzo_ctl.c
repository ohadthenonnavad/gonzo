#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define GONZO_DEV "/dev/gonzo"
#define GONZO_IOCTL_BUILD _IO('G', 0x01)
/* Keep in sync with kernel header */
#ifndef IOCTL_HV_TIMED_PROF
#define IOCTL_HV_TIMED_PROF _IO('G', 0x02)
#endif

static void usage(const char *prog)
{
	printf("Usage: %s [--hv-prof [iterations]]\n", prog);
	fprintf(stderr, "Without flags, triggers build ioctl. --hv-prof triggers timing (default 200 iters).\n");
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
	} else {
		if (ioctl(fd, GONZO_IOCTL_BUILD, 0) != 0) {
			perror("ioctl BUILD");
			close(fd);
			return 1;
		}
		printf("gonzo: build complete\n");
	}
	close(fd);
	return 0;
}


