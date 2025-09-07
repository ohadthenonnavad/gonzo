CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror
LDFLAGS ?= -static

all: gonzo_ctl

gonzo_ctl: gonzo_ctl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f gonzo_ctl


