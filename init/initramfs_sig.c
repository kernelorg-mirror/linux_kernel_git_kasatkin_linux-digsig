/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Author:
 * Dmitry Kasatkin <dmitry.kasatkin@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 */

#define pr_fmt(fmt) "initramfs_sig: " fmt

/*
 * Many of the syscalls used in this file expect some of the arguments
 * to be __user pointers not __kernel pointers.  To limit the sparse
 * noise, turn off sparse checking for this file.
 */

#ifdef __CHECKER__
#undef __CHECKER__
#warning "Sparse checking disabled for this file"
#endif

#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/kmod.h>
#include <linux/module.h>

#include "../kernel/module-internal.h"
#include "do_mounts.h"

#define BUF_SIZE	BLOCK_SIZE

static const char *secmnt = "/root";
static const char *initramfs_img = "/initramfs-sig.img";

static int __init load_image(const char *from)
{
	int err = -EINVAL, fd;
	char *buf = NULL, *msg;
	off_t len, offset;
	int size = BLOCK_SIZE;
	const unsigned long markerlen = sizeof(MODULE_SIG_STRING) - 1;

	fd = sys_open(from, O_RDONLY, 0);
	if (fd < 0) {
		pr_err("cannot open %s: %d\n", from, fd);
		return fd;
	}

	len = sys_lseek(fd, 0, SEEK_END);
	pr_info("%s image size: %lu\n", from, len);
	if (len < 0)
		goto out;

	buf = vmalloc(len);
	if (!buf) {
		pr_err("unable to allocate large block of memory\n");
		err = -ENOMEM;
		goto out_close;
	}

	sys_lseek(fd, 0, SEEK_SET);

	for (offset = 0; len; offset += size, len -= size) {
		if (len < size)
			size = len;
		if (sys_read(fd, buf + offset, size) != size)
			goto out;
	}

	pr_info("image offset: %lu\n", offset);

	offset -= markerlen;

	if (offset < 0 || memcmp(buf + offset, MODULE_SIG_STRING, markerlen)) {
		pr_err("image has no marker\n");
		goto out;
	}

	err = mod_verify_sig(buf, &offset);
	pr_info("mod_verify_sig() = %d, len: %lu\n", err, offset);
	if (err)
		goto out;

	err = sys_mount("tpmfs", (char *)secmnt, "tmpfs", MS_SILENT, NULL);
	if (err) {
		pr_err("sys_mount() = %d\n", err);
		goto out;
	}

	sys_unshare(CLONE_FS | CLONE_FILES);
	sys_chdir(secmnt);
	sys_chroot(".");
	sys_setsid();

	pr_info("unpack start\n");
	msg = unpack_to_rootfs(buf, offset);
	if (msg) {
		pr_err("unable to unpack rootfs\n");
		err = -EINVAL;
		goto out;
	}
	pr_info("unpack end\n");

	err = 0;

out:
	vfree(buf);
out_close:
	sys_close(fd);

	return err;
}

static int __init init_init(struct subprocess_info *info, struct cred *new)
{
	return load_image(initramfs_img);
}

static void init_cleanup(struct subprocess_info *info)
{
	int err;

	pr_info("cleanup\n");

	err = sys_umount((char *)secmnt, MNT_DETACH);
	if (err)
		pr_err("unable to umount secmnt: %d\n", err);
}

static int __init load_initramfs(void)
{
	static char *argv[] = { "pre-init", NULL, };
	extern char *envp_init[];
	int err;

	/*
	 * In case that a resume from disk is carried out by linuxrc or one of
	 * its children, we need to tell the freezer not to wait for us.
	 */
	current->flags |= PF_FREEZER_SKIP;

	err = call_usermodehelper_fns("/pre-init", argv, envp_init,
				      UMH_WAIT_PROC, init_init, init_cleanup,
				      NULL);

	current->flags &= ~PF_FREEZER_SKIP;

	pr_info("initramfs_sig /pre-init completed: %d\n", err);

	return err;
}

int __init initramfs_sig_load(void)
{
	if (sys_access(initramfs_img, 0))
		panic("signed initramfs image not found (INITRAMFS_SIG is anabled)\n");

	if (load_initramfs())
		panic("initramfs_sig failed! (INITRAMFS_SIG is anabled)\n");

	pr_info("initramfs_sig finished\n");

	return 0;
}
