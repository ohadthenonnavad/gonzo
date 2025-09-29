// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "gonzo.h"

/* USB blob header per entry */
struct usb_entry_hdr {
	__le16 entry_len;      /* total length including header */
	__u8  is_hub;          /* 1 if hub, 0 if device */
	__u8  depth;           /* topology depth from root */
	__le16 vendor_id;      /* idVendor */
	__le16 product_id;     /* idProduct */
	__u8  busnum;          /* usb bus number */
	__u8  devnum;          /* usb device number */
	__u8  portnum;         /* port number on parent (if known) */
	__u8  speed;           /* enum usb_device_speed */
} __packed;

/* Globals */
uint8_t *usb_blob;
size_t usb_blob_len;


static void append_string(uint8_t **blob, size_t *len, const char *s)
{
	size_t sl = s ? strlen(s) : 0;
	__le16 l = cpu_to_le16((__u16)sl);
	append_blob(blob, len, &l, sizeof(l));
	if (sl)
		append_blob(blob, len, s, sl);
}

static const char *usb_speed_str(enum usb_device_speed s)
{
	switch (s) {
	case USB_SPEED_LOW: return "low";
	case USB_SPEED_FULL: return "full";
	case USB_SPEED_HIGH: return "high";
	case USB_SPEED_WIRELESS: return "wireless";
	case USB_SPEED_SUPER: return "super";
	case USB_SPEED_SUPER_PLUS: return "super+";
	default: return "unknown";
	}
}

static int add_usb_device(struct usb_device *udev, int depth)
{
	struct usb_entry_hdr hdr;
	char mfg[128] = "", prod[128] = "", serial[128] = "";
	const char *speed_s;
	speed_s = usb_speed_str(udev->speed);

	hdr.entry_len = 0; /* fill after */
    hdr.is_hub = (udev->descriptor.bDeviceClass == USB_CLASS_HUB) || (udev->parent == NULL);
	hdr.depth = (u8)depth;
	hdr.vendor_id = cpu_to_le16(le16_to_cpu(udev->descriptor.idVendor));
	hdr.product_id = cpu_to_le16(le16_to_cpu(udev->descriptor.idProduct));
	hdr.busnum = udev->bus->busnum;
	hdr.devnum = udev->devnum;
	hdr.portnum = udev->portnum;
	hdr.speed = (u8)udev->speed;

	/* Strings (best effort) */
	usb_string(udev, udev->descriptor.iManufacturer, mfg, sizeof(mfg));
	usb_string(udev, udev->descriptor.iProduct, prod, sizeof(prod));
	usb_string(udev, udev->descriptor.iSerialNumber, serial, sizeof(serial));

	{
		size_t start = usb_blob_len;
		if (!append_blob(&usb_blob, &usb_blob_len, &hdr, sizeof(hdr)))
			return -ENOMEM;
		/* textual speed */
		append_string(&usb_blob, &usb_blob_len, speed_s);
		/* manufacturer/product/serial */
		append_string(&usb_blob, &usb_blob_len, mfg[0] ? mfg : NULL);
		append_string(&usb_blob, &usb_blob_len, prod[0] ? prod : NULL);
		append_string(&usb_blob, &usb_blob_len, serial[0] ? serial : NULL);
		/* configuration info */
		{
			__u8 ncfg = udev->descriptor.bNumConfigurations;
			append_blob(&usb_blob, &usb_blob_len, &ncfg, sizeof(ncfg));
			if (udev->actconfig) {
				__u8 nintf = udev->actconfig->desc.bNumInterfaces;
				append_blob(&usb_blob, &usb_blob_len, &nintf, sizeof(nintf));
			} else {
				__u8 zero = 0;
				append_blob(&usb_blob, &usb_blob_len, &zero, sizeof(zero));
			}
		}
		/* backfill entry length */
		((struct usb_entry_hdr *)(usb_blob + start))->entry_len = cpu_to_le16((__u16)(usb_blob_len - start));
	}
	return 0;
}

struct usb_enum_ctx { int dummy; };

static int usb_enum_cb(struct usb_device *udev, void *arg)
{
    int depth = 0;
    struct usb_device *p = udev->parent;
    while (p) { depth++; p = p->parent; }
    return add_usb_device(udev, depth);
}

int usb_build_blob(void)
{
    kfree(usb_blob);
	usb_blob = NULL;
	usb_blob_len = 0;

    /* Enumerate all USB devices via usb_for_each_dev */
    usb_for_each_dev(NULL, usb_enum_cb);

	DBG("USB dump complete, len=%zu\n", usb_blob_len);
	if (usb_blob_len > 0) {
		int ret = gonzo_dump_to_file("dekermit.usb", usb_blob, usb_blob_len);
		if (ret)
			DBG("failed to dump usb blob: %d\n", ret);
	}
	return 0;
}

MODULE_DESCRIPTION("Gonzo USB enumerator");
MODULE_LICENSE("GPL");
