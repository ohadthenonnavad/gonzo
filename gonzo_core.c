// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/device.h>
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
 * gonzo_unlocked_ioctl - Handle control requests from userspace
 * @filp: opened file pointer for /dev/gonzo
 * @cmd: ioctl command (only GONZO_IOCTL_BUILD is supported)
 * @arg: unused for now
 *
 * Triggers both ACPI and PCI buffer builds. Each sub-build is attempted
 * independently; success is returned if at least one of them succeeds.
 *
 * Return: 0 on success, -ENOTTY for unknown cmd, or sub-build error if both fail.
 */
static long gonzo_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case GONZO_IOCTL_BUILD: {
        int acpi_ret = gonzo_build_acpi_blob();
        if (acpi_ret)
            pr_warn(DRV_NAME ": ACPI build failed: %d\n", acpi_ret);
        else
            pr_info(DRV_NAME ": ACPI build ok, len=%zu\n", acpi_blob_len);

        int pci_ret = gonzo_build_pci_blob();
        if (pci_ret)
            pr_warn(DRV_NAME ": PCI build failed: %d\n", pci_ret);
        else
            pr_info(DRV_NAME ": PCI build ok, len=%zu\n", pci_blob_len);

        if (acpi_ret && pci_ret)
            return acpi_ret;
        return 0;
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
    pr_info(DRV_NAME ": loaded\n");
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
    pr_info(DRV_NAME ": unloaded\n");
}

module_init(gonzo_init);
module_exit(gonzo_exit);

MODULE_AUTHOR("gonzo");
MODULE_DESCRIPTION("Gonzo ACPI/PCI snapshot builder (core)");
MODULE_LICENSE("GPL");


