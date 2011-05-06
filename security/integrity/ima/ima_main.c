/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Serge Hallyn <serue@us.ibm.com>
 * Kylene Hall <kylene@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_main.c
 *	implements the IMA hooks: ima_bprm_check, ima_file_mmap,
 *	and ima_file_check.
 */
#include <linux/module.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/ima.h>

#include "ima.h"

int ima_initialized;

#ifdef CONFIG_IMA_APPRAISE
int ima_appraise = IMA_APPRAISE_ENABLED | IMA_APPRAISE_ENFORCE;
#else
int ima_appraise;
#endif

char *ima_hash = "sha1";
static int __init hash_setup(char *str)
{
	if (strncmp(str, "md5", 3) == 0)
		ima_hash = "md5";
	return 1;
}
__setup("ima_hash=", hash_setup);

/*
 * ima_rdwr_violation_check
 *
 * Only invalidate the PCR for measured files:
 * 	- Opening a file for write when already open for read,
 *	  results in a time of measure, time of use (ToMToU) error.
 *	- Opening a file for read when already open for write,
 * 	  could result in a file measurement error.
 *
 */
static void ima_rdwr_violation_check(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	fmode_t mode = file->f_mode;
	int rc;
	bool send_tomtou = false, send_writers = false;

	if (!S_ISREG(inode->i_mode) || !ima_initialized)
		return;

	mutex_lock(&inode->i_mutex);	/* file metadata: permissions, xattr */

	if (mode & FMODE_WRITE) {
		if (atomic_read(&inode->i_readcount) && IS_IMA(inode))
			send_tomtou = true;
		goto out;
	}

	rc = ima_must_appraise_or_measure(inode, MAY_READ, FILE_CHECK,
					  NULL, NULL);
	if (rc < 0)
		goto out;

	if (atomic_read(&inode->i_writecount) > 0)
		send_writers = true;
out:
	mutex_unlock(&inode->i_mutex);

	if (send_tomtou)
		ima_add_violation(inode, dentry->d_name.name, "invalid_pcr",
				  "ToMToU");
	if (send_writers)
		ima_add_violation(inode, dentry->d_name.name, "invalid_pcr",
				  "open_writers");
}

static void ima_check_last_writer(struct integrity_iint_cache *iint,
				  struct inode *inode,
				  struct file *file)
{
	fmode_t mode = file->f_mode;

	mutex_lock(&inode->i_mutex);
	if (mode & FMODE_WRITE &&
	    atomic_read(&inode->i_writecount) == 1 &&
	    iint->version != inode->i_version) {
		iint->flags &= ~(IMA_COLLECTED | IMA_APPRAISED | IMA_MEASURED);
		if (iint->flags & IMA_APPRAISE)
			ima_update_xattr(iint, file);
	}
	mutex_unlock(&inode->i_mutex);
}

/**
 * ima_file_free - called on __fput()
 * @file: pointer to file structure being freed
 *
 * Flag files that changed, based on i_version
 */
void ima_file_free(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct integrity_iint_cache *iint;

	if (!iint_initialized || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	ima_check_last_writer(iint, inode, file);
}

static int process_measurement(struct file *file, const unsigned char *filename,
			       int mask, int function)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct integrity_iint_cache *iint;
	int rc = 0, err = 0, must_measure, must_appraise;

	if (!ima_initialized || !S_ISREG(inode->i_mode))
		return 0;

	/* Determine if in appraise/measurement policy */
	rc = ima_must_appraise_or_measure(inode, mask, function,
					  &must_measure, &must_appraise);
	if (!must_measure && !must_appraise)
		return 0;

retry:
	iint = integrity_iint_find(inode);
	if (!iint) {
		rc = integrity_inode_alloc(inode);
		if (!rc || rc == -EEXIST)
			goto retry;
		return rc;
	}

	mutex_lock(&inode->i_mutex);

	/* Determine if already appraised/measured */
	if (must_measure) {
		iint->flags |= IMA_MEASURE;
		must_measure = iint->flags & IMA_MEASURED ? 0 : 1;
	}
	if (must_appraise) {
		iint->flags |= IMA_APPRAISE;
		must_appraise = iint->flags & IMA_APPRAISED ? 0 : 1;
	}
	if (!must_measure && !must_appraise) {
		if (iint->flags & IMA_APPRAISED)
			err = iint->ima_status;
		goto out;
	}

	rc = ima_collect_measurement(iint, file);
	if (rc != 0)
		goto out;
	if (must_measure)
		ima_store_measurement(iint, file, filename);
	if (must_appraise)
		err = ima_appraise_measurement(iint, file, filename);
out:
	mutex_unlock(&inode->i_mutex);
	return (!err) ? 0 : -EACCES;
}

/**
 * ima_file_mmap - based on policy, collect/store measurement.
 * @file: pointer to the file to be measured (May be NULL)
 * @prot: contains the protection that will be applied by the kernel.
 *
 * Measure files being mmapped executable based on the ima_must_measure()
 * policy decision.
 *
 * Return 0 on success, an error code on failure.
 * (Based on the results of appraise_measurement().)
 */
int ima_file_mmap(struct file *file, unsigned long prot)
{
	int rc = 0;

	if (!file)
		return 0;
	if (prot & PROT_EXEC)
		rc = process_measurement(file, file->f_dentry->d_name.name,
					 MAY_EXEC, FILE_MMAP);
	return (ima_appraise & IMA_APPRAISE_ENFORCE) ? rc : 0;
}

/**
 * ima_bprm_check - based on policy, collect/store measurement.
 * @bprm: contains the linux_binprm structure
 *
 * The OS protects against an executable file, already open for write,
 * from being executed in deny_write_access() and an executable file,
 * already open for execute, from being modified in get_write_access().
 * So we can be certain that what we verify and measure here is actually
 * what is being executed.
 *
 * Return 0 on success, an error code on failure.
 * (Based on the results of appraise_measurement().)
 */
int ima_bprm_check(struct linux_binprm *bprm)
{
	int rc;

	rc = process_measurement(bprm->file, bprm->filename,
				 MAY_EXEC, BPRM_CHECK);
	return (ima_appraise & IMA_APPRAISE_ENFORCE) ? rc : 0;
}

/**
 * ima_path_check - based on policy, collect/store measurement.
 * @file: pointer to the file to be measured
 * @mask: contains MAY_READ, MAY_WRITE or MAY_EXECUTE
 *
 * Measure files based on the ima_must_measure() policy decision.
 *
 * Always return 0 and audit dentry_open failures.
 * (Return code will be based upon measurement appraisal.)
 */
int ima_file_check(struct file *file, int mask)
{
	int rc;

	ima_rdwr_violation_check(file);
	rc = process_measurement(file, file->f_dentry->d_name.name,
				 mask & (MAY_READ | MAY_WRITE | MAY_EXEC),
				 FILE_CHECK);
	return (ima_appraise & IMA_APPRAISE_ENFORCE) ? rc : 0;
}
EXPORT_SYMBOL_GPL(ima_file_check);

/**
 * ima_inode_post_setattr - reflect file metadata changes
 * @dentry: pointer to the affected dentry
 *
 * Changes to a dentry's metadata might result in needing to appraise.
 *
 * This function is called from notify_change(), which expects the caller
 * to lock the inode's i_mutex.
 */
void ima_inode_post_setattr(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct integrity_iint_cache *iint;
	int must_appraise, rc;

	if (!ima_initialized || !ima_appraise || !S_ISREG(inode->i_mode)
	    || !inode->i_op->removexattr)
		return;

	must_appraise = ima_must_appraise(inode, MAY_ACCESS, POST_SETATTR);
	iint = integrity_iint_find(inode);
	if (iint) {
		iint->flags &= ~(IMA_APPRAISE | IMA_APPRAISED);
		if (must_appraise)
			iint->flags |= IMA_APPRAISE;
	}
	if (!must_appraise)
		rc = inode->i_op->removexattr(dentry, XATTR_NAME_IMA);
	return;
}

/*
 * ima_protect_xattr - protect 'security.ima'
 *
 * Ensure that not just anyone can modify or remove 'security.ima'.
 */
static int ima_protect_xattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	if (strcmp(xattr_name, XATTR_NAME_IMA) == 0) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return 1;
	}
	return 0;
}

static void ima_reset_appraise_flags(struct inode *inode)
{
	struct integrity_iint_cache *iint;

	if (!ima_initialized || !ima_appraise || !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	iint->flags &= ~(IMA_COLLECTED | IMA_APPRAISED | IMA_MEASURED);
	return;
}

int ima_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len)
{
	int result;

	result = ima_protect_xattr(dentry, xattr_name, xattr_value,
				 xattr_value_len);
	if (result == 1) {
		ima_reset_appraise_flags(dentry->d_inode);
		result = 0;
	}
	return result;
}

int ima_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	int result;

	result = ima_protect_xattr(dentry, xattr_name, NULL, 0);
	if (result == 1) {
		ima_reset_appraise_flags(dentry->d_inode);
		result = 0;
	}
	return result;
}


static int __init init_ima(void)
{
	int error;

	error = ima_init();
	ima_initialized = 1;
	return error;
}

static void __exit cleanup_ima(void)
{
	ima_cleanup();
}

late_initcall(init_ima);	/* Start IMA after the TPM is available */

MODULE_DESCRIPTION("Integrity Measurement Architecture");
MODULE_LICENSE("GPL");
