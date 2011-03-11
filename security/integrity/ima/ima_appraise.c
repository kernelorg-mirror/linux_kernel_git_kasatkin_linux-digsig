/*
 * Copyright (C) 2011 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/magic.h>
#include <linux/evm.h>

#include "ima.h"

static int __init default_appraise_setup(char *str)
{
	if (strncmp(str, "off", 3) == 0)
		ima_appraise = 0;
	else if (strncmp(str, "log", 3) == 0)
		ima_appraise = IMA_APPRAISE_ENABLED | IMA_APPRAISE_LOG;
	else if (strncmp(str, "fix", 3) == 0)
		ima_appraise = IMA_APPRAISE_ENABLED | IMA_APPRAISE_FIX;
	return 1;
}

__setup("ima_appraise=", default_appraise_setup);

/*
 * ima_must_appraise - set appraise flag
 *
 * Return 1 to appraise
 */
int ima_must_appraise(struct inode *inode, enum ima_hooks func, int mask)
{
	return 0;
}

static void ima_fix_xattr(struct dentry *dentry,
			  struct integrity_iint_cache *iint)
{
	iint->digest[0] = IMA_XATTR_DIGEST;
	__vfs_setxattr_noperm(dentry, XATTR_NAME_IMA,
			      iint->digest, IMA_DIGEST_SIZE + 1, 0);
}

/*
 * ima_appraise_measurement - appraise file measurement
 *
 * Call evm_verifyxattr() to verify the integrity of 'security.ima'.
 * Assuming success, compare the xattr hash with the collected measurement.
 *
 * Return 0 on success, error code otherwise
 */
int ima_appraise_measurement(struct integrity_iint_cache *iint,
			     struct file *file, const unsigned char *filename)
{
	struct dentry *dentry = file->f_dentry;
	struct inode *inode = dentry->d_inode;
	u8 xattr_value[IMA_DIGEST_SIZE];
	enum integrity_status status = INTEGRITY_UNKNOWN;
	const char *op = "appraise_data";
	char *cause = "unknown";
	int rc;

	if (!ima_appraise || !inode->i_op->getxattr)
		return 0;
	if (iint->flags & IMA_APPRAISED)
		return iint->hash_status;

	rc = inode->i_op->getxattr(dentry, XATTR_NAME_IMA, xattr_value,
				   IMA_DIGEST_SIZE);
	if (rc <= 0) {
		if (rc && rc != -ENODATA)
			goto out;

		cause = "missing-hash";
		status =
		    (inode->i_size == 0) ? INTEGRITY_PASS : INTEGRITY_NOLABEL;
		goto out;
	}

	status = evm_verifyxattr(dentry, XATTR_NAME_IMA, xattr_value, rc, iint);
	if ((status != INTEGRITY_PASS) && (status != INTEGRITY_UNKNOWN)) {
		if (status == INTEGRITY_NOLABEL)
			cause = "missing-HMAC";
		else if (status == INTEGRITY_FAIL)
			cause = "invalid-HMAC";
		goto out;
	}

	rc = memcmp(xattr_value, iint->digest, IMA_DIGEST_SIZE);
	if (rc) {
		status = INTEGRITY_FAIL;
		cause = "invalid-hash";
		print_hex_dump_bytes("security.ima: ", DUMP_PREFIX_NONE,
				     xattr_value, IMA_DIGEST_SIZE);
		print_hex_dump_bytes("collected: ", DUMP_PREFIX_NONE,
				     iint->digest, IMA_DIGEST_SIZE);
		goto out;
	}
	status = INTEGRITY_PASS;
	iint->flags |= IMA_APPRAISED;
out:
	if (status != INTEGRITY_PASS) {
		if (ima_appraise & IMA_APPRAISE_FIX) {
			ima_fix_xattr(dentry, iint);
			status = INTEGRITY_PASS;
		}
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode, filename,
				    op, cause, 1, 0);
	}
	iint->hash_status = status;
	return status;
}

/*
 * ima_update_xattr - update 'security.ima' hash value
 */
void ima_update_xattr(struct integrity_iint_cache *iint, struct file *file)
{
	struct dentry *dentry = file->f_dentry;
	int read = 0;
	int rc = 0;

	if (!(file->f_mode & FMODE_READ)) {
		file->f_mode |= FMODE_READ;
		read = 1;
	}
	rc = ima_collect_measurement(iint, file);
	if (read)
		file->f_mode &= ~FMODE_READ;
	if (rc < 0)
		return;
	ima_fix_xattr(dentry, iint);
}
