// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include "gonzo.h"

static dev_t gonzo_devno;
static struct cdev gonzo_cdev;
static struct class *gonzo_class;

uint8_t *acpi_blob;
size_t acpi_blob_len;
uint8_t *pci_blob;
size_t pci_blob_len;

/**
 * append_blob - Grow a heap buffer and append bytes
 * @blob: pointer to buffer pointer
 * @len: pointer to current length
 * @data: source bytes to append
 * @add: number of bytes to add
 *
 * Return: pointer to the start of appended region on success, NULL on OOM.
 */
 void *append_blob(uint8_t **blob, size_t *len, const void *data, size_t add)
 {
     void *dst;
     uint8_t *newbuf = krealloc(*blob, *len + add, GFP_KERNEL);
     if (!newbuf)
         return NULL;
     dst = newbuf + *len;
     memcpy(dst, data, add);
     *blob = newbuf;
     *len += add;
     return dst;
 }

int gonzo_dump_to_file(const char *path, const uint8_t *buf, size_t len)
{
    struct file *filp;
    loff_t pos = 0;
    ssize_t written;
    int ret = 0;
    if (!path || !buf || !len)
        return -EINVAL;
    filp = filp_open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (IS_ERR(filp))
        return PTR_ERR(filp);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
    /* kernel_write is available; set_fs removal after 5.10 */
    written = kernel_write(filp, buf, len, &pos);
#else
    {
        struct kvec iov = { .iov_base = (void *)buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = 0;
        iov_iter_kvec(&iter, WRITE, &iov, 1, len);
        written = vfs_write(filp, buf, len, &pos);
    }
#endif
    if (written < 0 || (size_t)written != len)
        ret = written < 0 ? (int)written : -EIO;
    filp_close(filp, NULL);
    return ret;
}

/* moved to hypervisor.c */

/**
 * gonzo_unlocked_ioctl - Handle control requests from userspace
 * @filp: opened file pointer for /dev/gonzo
 * @cmd: ioctl command (GONZO_IOCTL_BUILD, IOCTL_HV_TIMED_PROF, IOCTL_TIMERS_DUMP)
 * @arg: for IOCTL_HV_TIMED_PROF, iteration count (0 => default)
 *
 * Triggers ACPI/PCI buffer builds, runs timing profile, or dumps timer configurations.
 *
 * Return: 0 on success, -ENOTTY for unknown cmd, or sub-build error if both fail.
 */
static long gonzo_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case IOCTL_ACPI_DUMP: {
        int ret = acpi_build_blob();
        if (ret == 0)
            DBG("ACPI build ok, len=%zu\n", acpi_blob_len);
        else
            DBG("ACPI build failed: %d\n", ret);
        return ret;
    }
    case IOCTL_PCI_DUMP: {
        int ret = pci_build_blob();
        if (ret == 0)
            DBG("PCI build ok, len=%zu\n", pci_blob_len);
        else
            DBG("PCI build failed: %d\n", ret);
        return ret;
    }
    case IOCTL_HV_TIMED_PROF: {
        hv_init(arg);
        return 0;
    }
    case IOCTL_TIMERS_DUMP: {
        int ret = timers_dump_all();
        return ret;
    }
    case _IO('G', 0x04): { /* IOCTL_USB_DUMP (implicit) */
        int ret = usb_build_blob();
        return ret;
    }
    case IOCTL_MSR_DUMP: {
        int ret = msr_dump_blob();
        return ret;
    }
    default:
        return -ENOTTY;
    }
}

/**
 * gonzo_open - Open callback for /dev/gonzo
 * @inode: inode of the device
 * @file: file pointer to initialize
 *
 * No per-open state is needed.
 *
 * Return: 0
 */
static int gonzo_open(struct inode *inode, struct file *file)
{
    return 0;
}

/**
 * gonzo_release - Release callback for /dev/gonzo
 * @inode: inode of the device
 * @file: file pointer being closed
 *
 * No resources to release.
 *
 * Return: 0
 */
static int gonzo_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations gonzo_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = gonzo_unlocked_ioctl,
    .open = gonzo_open,
    .release = gonzo_release,
};

/**
 * gonzo_init - Module initialization
 *
 * Registers a single char device /dev/gonzo and its class. Does not allocate
 * any buffers; buffers are built on demand via ioctl.
 *
 * Return: 0 on success or a negative errno on failure.
 */
static int __init gonzo_init(void)
{
    int err;
    err = alloc_chrdev_region(&gonzo_devno, 0, 1, DRV_NAME);
    if (err)
        return err;
    cdev_init(&gonzo_cdev, &gonzo_fops);
    gonzo_cdev.owner = THIS_MODULE;
    err = cdev_add(&gonzo_cdev, gonzo_devno, 1);
    if (err)
        goto err_unregister;
    gonzo_class = class_create(THIS_MODULE, DRV_NAME);
    if (IS_ERR(gonzo_class)) {
        err = PTR_ERR(gonzo_class);
        goto err_cdev;
    }
    if (!device_create(gonzo_class, NULL, gonzo_devno, NULL, DRV_NAME)) {
        err = -ENODEV;
        goto err_class;
    }
    DBG("loaded\n");
    return 0;
err_class:
    class_destroy(gonzo_class);
err_cdev:
    cdev_del(&gonzo_cdev);
err_unregister:
    unregister_chrdev_region(gonzo_devno, 1);
    return err;
}

/**
 * gonzo_exit - Module teardown
 *
 * Frees any allocated buffers and unregisters the device and class.
 */
static void __exit gonzo_exit(void)
{
    kfree(acpi_blob);
    kfree(pci_blob);
    device_destroy(gonzo_class, gonzo_devno);
    class_destroy(gonzo_class);
    cdev_del(&gonzo_cdev);
    unregister_chrdev_region(gonzo_devno, 1);
    DBG("unloaded\n");
}

module_init(gonzo_init);
module_exit(gonzo_exit);

MODULE_AUTHOR("gonzo");
MODULE_DESCRIPTION("Gonzo ACPI/PCI snapshot builder (core)");
MODULE_LICENSE("GPL");


