obj-m += gonzo.o
gonzo-objs := gonzo_core.o acpi_dump.o hypervisor.o usb.o msr.o net_logger.o

#KDIR ?= /lib/modules/$(shell uname -r)/build
KDIR ?= /kernel/linux-3.10
PWD  := $(shell pwd)

EXTRA_CFLAGS += -O2 -g -DDEBUG

all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

user:
	$(MAKE) -C user


