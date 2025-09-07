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

int main()
{
	int fd = open(GONZO_DEV, O_RDONLY);
	if (fd < 0) {
		perror("open /dev/gonzo");
		return 1;
	}
	if (ioctl(fd, GONZO_IOCTL_BUILD, 0) != 0) {
		perror("ioctl BUILD");
		close(fd);
		return 1;
	}
	printf("gonzo: build complete\n");
	close(fd);
	return 0;
}


