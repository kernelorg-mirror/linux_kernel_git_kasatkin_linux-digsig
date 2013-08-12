/*
 * Copyright (C) 2011,2012 Intel Corporation
 *		 2013 Samsung Electronics
 *
 * Authors:
 * Dmitry Kasatkin <d.kasatkin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_dir.c
 *	implements the IMA directories hooks: ima_dir_check, ima_dir_update.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": %s: " fmt, __func__

#include <linux/module.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/ima.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>

#include "ima.h"

static int ima_dir_enabled = 1;

static int __init ima_dir_setup(char *str)
{
	if (strncmp(str, "off", 3) == 0)
		ima_dir_enabled = 0;
	return 1;
}

__setup("ima_dir=", ima_dir_setup);

struct readdir_callback {
	struct dir_context ctx;
	struct shash_desc *shash;
};

static int ima_filldir(struct dir_context *__ctx, const char *name, int namelen,
		       loff_t offset, u64 ino, unsigned int d_type)
{
	struct readdir_callback *ctx = container_of(__ctx, typeof(*ctx), ctx);
	struct shash_desc *shash = ctx->shash;
	int rc;

	rc = crypto_shash_update(shash, name, namelen);
	rc |= crypto_shash_update(shash, (const u8 *)&ino, sizeof(ino));
	rc |= crypto_shash_update(shash, (const u8 *)&d_type, sizeof(d_type));

	return rc;
}

static int ima_calc_dir_hash_tfm(struct path *path, struct file *file,
				 struct ima_digest_data *hash,
				 struct crypto_shash *tfm)
{
	struct inode *inode = path->dentry->d_inode;
	int rc = -ENOTDIR, opened = 0;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(tfm)];
	} desc;
	struct readdir_callback buf = {
		.ctx.actor = ima_filldir,
		.shash = &desc.shash
	};

	if (IS_DEADDIR(inode))
		return -ENOENT;

	if (!file) {
		file = dentry_open(path, O_RDONLY, current->cred);
		if (IS_ERR(file))
			return PTR_ERR(file);
		opened = 1;
	}

	if (!file->f_op || !file->f_op->iterate)
		goto out;

	/* Directory can only be opened for reading? */
	WARN_ON(!(file->f_mode & FMODE_READ));

	desc.shash.tfm = tfm;
	desc.shash.flags = 0;

	rc = crypto_shash_init(&desc.shash);
	if (rc != 0)
		goto out;

	/* we do not use iterate_dir() because it locks dir i_mutex,
	   which is already locked by our call path */
	WARN(buf.ctx.pos, "ctx.pos is not NULL");
	rc = file->f_op->iterate(file, &buf.ctx);
	if (rc)
		goto out;

	hash->length = crypto_shash_digestsize(tfm);
	rc = crypto_shash_final(&desc.shash, hash->digest);

out:
	if (opened)
		fput(file);
	return rc;
}

int static ima_calc_dir_hash(struct path *path, struct file *file,
			     struct ima_digest_data *hash)
{
	struct crypto_shash *tfm;
	int rc;

	tfm = ima_alloc_tfm(hash->algo);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	rc = ima_calc_dir_hash_tfm(path, file, hash, tfm);

	ima_free_tfm(tfm);

	return rc;
}

static int ima_dir_collect(struct integrity_iint_cache *iint,
			  struct path *path, struct file *file,
			  enum hash_algo algo, const char *link)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	int rc = -EINVAL;
	u32 dev;
	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;

	if (iint->flags & IMA_COLLECTED)
		return 0;

	/* use default hash algorithm */
	hash.hdr.algo = algo;

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		rc = ima_calc_dir_hash(path, file, &hash.hdr);
		break;
	case S_IFIFO: case S_IFSOCK:
	case S_IFCHR: case S_IFBLK:
		dev = new_encode_dev(inode->i_rdev);
		rc = ima_calc_buffer_hash(&dev, sizeof(dev), &hash.hdr);
		break;
	case S_IFLNK:
		rc = ima_calc_buffer_hash(link, strlen(link), &hash.hdr);
		break;
	default:
		pr_debug("UKNOWN: dentry: %s, 0%o\n",
			 dentry->d_name.name, inode->i_mode & S_IFMT);
		break;
	}

	if (!rc) {
		int length = sizeof(hash.hdr) + hash.hdr.length;
		void *tmpbuf = krealloc(iint->ima_hash, length, GFP_NOFS);
		if (tmpbuf) {
			iint->ima_hash = tmpbuf;
			memcpy(iint->ima_hash, &hash, length);
		} else
			rc = -ENOMEM;
	}

	if (!rc)
		iint->flags |= IMA_COLLECTED;
	else
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode,
				    dentry->d_name.name,
				    "collect_data", "failed", rc, 0);
	return rc;
}

static int dir_measurement(struct path *path, struct file *file, int mask,
			   const char *link)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	struct integrity_iint_cache *iint;
	char *pathbuf = NULL;
	const char *pathname;
	int rc = 0, action, xattr_len = 0;
	int func = S_ISDIR(inode->i_mode) ? DIR_CHECK : SPECIAL_CHECK;
	struct evm_ima_xattr_data *xattr_value = NULL;
	enum hash_algo algo;
	int permit;

	if (!ima_dir_enabled || !ima_initialized)
		return 0;

	if (IS_IMA(inode)) {
		/* inode was already appraised or it is pending... */
		iint = integrity_iint_find(inode);
		BUG_ON(!iint);

		permit = iint->flags & IMA_APPRAISE_PERMIT;
		action = iint->flags & IMA_DO_MASK;
		action &= ~((iint->flags & IMA_DONE_MASK) >> 1);

		if (!action)
			goto out_unlocked;

		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;

		mutex_lock(&inode->i_mutex);
	} else {
		int func = S_ISDIR(inode->i_mode) ? DIR_CHECK : SPECIAL_CHECK;
		/* Determine if in appraise/measurement policy,
		* returns IMA_MEASURE, IMA_APPRAISE bitmask.  */
		action = ima_must_appraise(dentry, mask, func);
		if (!action)
			return 0;

		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;
		if (action < 0)
			return action;

		permit = action & IMA_APPRAISE_PERMIT;

		mutex_lock(&inode->i_mutex);

		iint = integrity_inode_get(inode);
		if (!iint) {
			rc = -ENOMEM;
			goto out_locked;
		}

		iint->flags |= action;
		action &= IMA_DO_MASK;
	}

	action &= ~((iint->flags & IMA_DONE_MASK) >> 1);

	/* we only appraise, no other action bits */
	if (!action)
		goto out_locked;

	xattr_len = ima_read_xattr(dentry, &xattr_value);
	algo = ima_get_hash_algo(xattr_value, xattr_len);

	rc = ima_dir_collect(iint, path, file, algo, link);
	if (rc)
		goto out_locked;

	pathname = ima_d_path(path, &pathbuf);

	rc = ima_appraise_measurement(func, iint, dentry, pathname,
				      xattr_value, xattr_len, 0);
	kfree(pathbuf);
out_locked:
	mutex_unlock(&inode->i_mutex);
out_unlocked:
	if (rc && (ima_appraise & IMA_APPRAISE_ENFORCE) && !permit)
		return -EACCES;
	return 0;
}

/**
 * ima_dir_check: verifies directory integrity
 * @dir:	path to verify
 * @return:	error code if appraisal enforced, 0 otherwise
 *
 */
int ima_dir_check(struct path *dir, int mask)
{
	BUG_ON(!S_ISDIR(dir->dentry->d_inode->i_mode));

	return dir_measurement(dir, NULL, mask, NULL);
}
EXPORT_SYMBOL_GPL(ima_dir_check);

int ima_special_check(struct file *file, int mask)
{
	return dir_measurement(&file->f_path, file, mask, NULL);
}

static void ima_dir_update_xattr(struct integrity_iint_cache *iint,
				 struct path *path, const char *link)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = NULL;
	int rc;

	if (!iint) {
		/* if iint is NULL, then we allocated iint for new directory */
		int action, func;

		inode = dentry->d_inode;
		func = S_ISDIR(inode->i_mode) ? DIR_CHECK : SPECIAL_CHECK;

		/* Determine if in appraise/measurement policy */
		action = ima_must_appraise(dentry, MAY_READ, func);
		if (action <= 0)
			return;

		mutex_lock(&inode->i_mutex);
		iint = integrity_inode_get(inode);
		if (!iint)
			goto out;

		/* set new inode as measured or/and appraised */
		action &= IMA_DO_MASK;
		iint->flags |= action | (action << 1);
		iint->ima_file_status = INTEGRITY_PASS;
	}

	rc = ima_dir_collect(iint, path, NULL, ima_hash_algo, link);
	if (!rc)
		ima_fix_xattr(dentry, iint);
out:
	if (inode)
		mutex_unlock(&inode->i_mutex);
}

/**
 * ima_dir_update - update directory integrity information
 * @dir:	path to update
 * newdir:	dir entry, which added
 *
 * It is called when directory content has changed,
 * and is used to re-calculate and update integrity data.
 * It is called with dir i_mutex locked.
 */
void ima_dir_update(struct path *dir, struct dentry *dentry, const char *link)
{
	struct inode *inode = dir->dentry->d_inode;
	struct integrity_iint_cache *iint;

	if (!ima_dir_enabled || !ima_initialized)
		return;

	WARN(IS_PRIVATE(inode), "PRIVATE\n");

	if (unlikely(IS_PRIVATE(inode)))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	if (dentry) {
		/* new entry -> set initial security.ima value */
		struct path path = { .mnt = dir->mnt, .dentry = dentry };
		BUG_ON(!dentry->d_inode);
		ima_dir_update_xattr(NULL, &path, link);
	}

	/* do not reset flags for directories, correct ?
	iint->flags &= ~(IMA_COLLECTED | IMA_APPRAISED | IMA_MEASURED);
	*/
	iint->flags &= ~IMA_COLLECTED;
	if (iint->flags & IMA_APPRAISE)
		ima_dir_update_xattr(iint, dir, NULL);
}
EXPORT_SYMBOL_GPL(ima_dir_update);

int ima_link_check(struct dentry *dentry, const char *link)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	return dir_measurement(&path, NULL, MAY_READ, link);
}
