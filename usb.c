// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#include <linux/pci.h>
#include <linux/usb/hcd.h>
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	case USB_SPEED_SUPER_PLUS: return "super+";
#endif
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
		((struct usb_entry_hdr *)(usb_blob + start))->entry_len = 
			cpu_to_le16((__u16)(usb_blob_len - start));
	}
	
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
/* Modern kernel path (4.0+): use usb_for_each_dev */

static int usb_enum_cb(struct usb_device *udev, void *arg)
{
	int depth = 0;
	struct usb_device *p = udev->parent;
	while (p) { 
		depth++; 
		p = p->parent; 
	}
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

#else
/* Old kernel path (3.10): Manual enumeration via PCI scan for USB controllers */

/* Recursive function to walk USB device tree */
static int walk_usb_tree(struct usb_device *udev, int depth)
{
	int i, ret;
	struct usb_device *child;
	
	/* Add this device */
	ret = add_usb_device(udev, depth);
	if (ret)
		return ret;
	
	/* If this is a hub, enumerate its children */
	usb_lock_device(udev);
	for (i = 0; i < udev->maxchild; i++) {
		child = usb_hub_find_child(udev, i + 1);
		if (child) {
			usb_get_dev(child);
			usb_unlock_device(udev);
			ret = walk_usb_tree(child, depth + 1);
			usb_put_dev(child);
			usb_lock_device(udev);
			if (ret)
				break;
		}
	}
	usb_unlock_device(udev);
	
	return ret;
}

int usb_build_blob(void)
{
	struct pci_dev *pdev = NULL;
	
	kfree(usb_blob);
	usb_blob = NULL;
	usb_blob_len = 0;
	
	/* 
	 * Find all USB host controllers via PCI scan.
	 * USB controllers have PCI class code 0x0c03xx:
	 * - 0x0c0300: UHCI
	 * - 0x0c0310: OHCI  
	 * - 0x0c0320: EHCI
	 * - 0x0c0330: XHCI
	 */
	while ((pdev = pci_get_class(PCI_CLASS_SERIAL_USB << 8, pdev)) != NULL) {
		struct usb_hcd *hcd;
		void *drvdata;
		
		/* Get driver private data - might be HCD */
		drvdata = pci_get_drvdata(pdev);
		if (!drvdata)
			continue;
			
		/* Try to interpret as USB HCD */
		hcd = (struct usb_hcd *)drvdata;
		
		/* Basic sanity check - does it have a root hub? */
		if (hcd && hcd->self.root_hub) {
			/* Walk from this root hub */
			walk_usb_tree(hcd->self.root_hub, 0);
		}
	}
	
	DBG("USB dump complete, len=%zu\n", usb_blob_len);
	if (usb_blob_len > 0) {
		int ret = gonzo_dump_to_file("dekermit.usb", usb_blob, usb_blob_len);
		if (ret)
			DBG("failed to dump usb blob: %d\n", ret);
	}
	
	return 0;
}

#endif

MODULE_DESCRIPTION("Gonzo USB enumerator");
MODULE_LICENSE("GPL");