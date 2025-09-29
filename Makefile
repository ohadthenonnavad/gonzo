obj-m += gonzo.o
gonzo-objs := gonzo_core.o acpi_dump.o pci_dump.o hypervisor.o timers.o usb.o msr.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

EXTRA_CFLAGS += -O2 -g -DDEBUG

all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

user:
	$(MAKE) -C user


