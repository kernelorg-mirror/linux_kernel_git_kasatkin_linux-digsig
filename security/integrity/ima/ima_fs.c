/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Kylene Hall <kjhall@us.ibm.com>
 * Reiner Sailer <sailer@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_fs.c
 *	implemenents security file system for reporting
 *	current measurement list and IMA statistics
 */
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>

#include "ima.h"

static int valid_policy = 1;
#define TMPBUFLEN 12
static const struct seq_operations ima_policy_seqops;
static ssize_t ima_show_htable_value(char __user *buf, size_t count,
				     loff_t *ppos, atomic_long_t *val)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t len;

	len = scnprintf(tmpbuf, TMPBUFLEN, "%li\n", atomic_long_read(val));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static ssize_t ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.violations);
}

static const struct file_operations ima_htable_violations_ops = {
	.read = ima_show_htable_violations,
	.llseek = generic_file_llseek,
};

static ssize_t ima_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.len);

}

static const struct file_operations ima_measurements_count_ops = {
	.read = ima_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *ima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_queue_entry *qe;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, &ima_measurements, later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_queue_entry *qe = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == &ima_measurements) ? NULL : qe;
}

static void ima_measurements_stop(struct seq_file *m, void *v)
{
}

void ima_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

/* print format:
 *       32bit-le=pcr#
 *       char[20]=template digest
 *       32bit-le=template name size
 *       char[n]=template name
 *       [eventdata length]
 *       eventdata[n]=template specific data
 */
static int ima_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int namelen;
	u32 pcr = CONFIG_IMA_MEASURE_PCR_IDX;
	bool is_ima_template = false;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/*
	 * 1st: PCRIndex
	 * PCR used is always the same (config option) in
	 * little-endian format
	 */
	ima_putc(m, &pcr, sizeof(pcr));

	/* 2nd: template digest */
	ima_putc(m, e->digest, TPM_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = strlen(template_name);
	ima_putc(m, &namelen, sizeof(namelen));

	/* 4th:  template name */
	ima_putc(m, template_name, namelen);

	/* 5th:  template length (except for 'ima' template) */
	if (strcmp(template_name, IMA_TEMPLATE_IMA_NAME) == 0)
		is_ima_template = true;

	if (!is_ima_template)
		ima_putc(m, &e->template_data_len,
			 sizeof(e->template_data_len));

	/* 6th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		enum ima_show_type show = IMA_SHOW_BINARY;
		struct ima_template_field *field = e->template_desc->fields[i];

		if (is_ima_template && strcmp(field->field_id, "d") == 0)
			show = IMA_SHOW_BINARY_NO_FIELD_LEN;
		if (is_ima_template && strcmp(field->field_id, "n") == 0)
			show = IMA_SHOW_BINARY_OLD_STRING_FMT;
		field->field_show(m, show, &e->template_data[i]);
	}
	return 0;
}

static const struct seq_operations ima_measurments_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_measurements_show
};

static int ima_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_measurments_seqops);
}

static const struct file_operations ima_measurements_ops = {
	.open = ima_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

void ima_print_hex(struct seq_file *m, u8 *digest, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		seq_printf(m, "%02x", *(digest + i));
}

/* print in ascii */
static int ima_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 1st: PCR used (config option) */
	seq_printf(m, "%2d ", CONFIG_IMA_MEASURE_PCR_IDX);

	/* 2nd: SHA1 template hash */
	ima_print_hex(m, e->digest, TPM_DIGEST_SIZE);

	/* 3th:  template name */
	seq_printf(m, " %s", template_name);

	/* 4th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		seq_puts(m, " ");
		if (e->template_data[i].len == 0)
			continue;

		e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
							&e->template_data[i]);
	}
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations ima_ascii_measurements_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ascii_measurements_show
};

static int ima_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_ascii_measurements_seqops);
}

static const struct file_operations ima_ascii_measurements_ops = {
	.open = ima_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static ssize_t ima_read_policy(char *path)
{
	char *data, *datap;
	int rc, size, pathlen = strlen(path);
	char *p;

	/* remove \n */
	datap = path;
	strsep(&datap, "\n");

	rc = integrity_read_file(path, &data);
	if (rc < 0)
		return rc;

	size = rc;
	datap = data;

	while (size > 0 && (p = strsep(&datap, "\n"))) {
		pr_debug("rule: %s\n", p);
		rc = ima_parse_add_rule(p);
		if (rc < 0)
			break;
		size -= rc;
	}

	kfree(data);
	if (rc < 0)
		return rc;
	else if (size)
		return -EINVAL;
	else
		return pathlen;
}

static ssize_t ima_write_policy(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data = NULL;
	ssize_t result;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	result = -ENOMEM;
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		goto out;

	*(data + datalen) = '\0';

	result = -EFAULT;
	if (copy_from_user(data, buf, datalen))
		goto out;

	if (data[0] == '/')
		result = ima_read_policy(data);
	else
		result = ima_parse_add_rule(data);
out:
	if (result < 0)
		valid_policy = 0;
	kfree(data);
	return result;
}

static struct dentry *ima_dir;
static struct dentry *binary_runtime_measurements;
static struct dentry *ascii_runtime_measurements;
static struct dentry *runtime_measurements_count;
static struct dentry *violations;
static struct dentry *ima_policy;

enum ima_fs_flags {
	IMA_FS_BUSY,
};

static unsigned long ima_fs_flags;

/*
 * ima_open_policy: sequentialize access to the policy file
 */
static int ima_open_policy(struct inode *inode, struct file *filp)
{
#ifndef CONFIG_IMA_READABLE_POLICY_INTERFACE
	/* No point in being allowed to open it if you aren't going to write */
	if (!(filp->f_flags & O_WRONLY))
		return -EACCES;
#endif /* CONFIG_IMA_READABLE_POLICY_INTERFACE */
#ifdef CONFIG_IMA_READABLE_POLICY_INTERFACE
	if (!(filp->f_flags & O_WRONLY)) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return seq_open(filp, &ima_policy_seqops);
	}
#endif /* CONFIG_IMA_READABLE_POLICY_INTERFACE */
	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;
	if (!ima_default_policy()) {
		clear_bit(IMA_FS_BUSY, &ima_fs_flags);
		return -EACCES;
	}
	return 0;
}

/*
 * ima_release_policy - start using the new measure policy rules.
 *
 * Initially, ima_measure points to the default policy rules, now
 * point to the new policy rules, and remove the securityfs policy file,
 * assuming a valid policy.
 */
static void ima_check_policy(void)
{
	const char *cause = valid_policy ? "completed" : "failed";

	pr_info("IMA: policy update %s\n", cause);
	integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
			    "policy_update", cause, !valid_policy, 0);

	if (!valid_policy) {
		ima_delete_rules();
		valid_policy = 1;
	} else {
		ima_update_policy();
	}
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);
}

static int ima_release_policy(struct inode *inode, struct file *file)
{
#ifdef CONFIG_IMA_READABLE_POLICY_INTERFACE
	if (file->f_flags & O_WRONLY)
		ima_check_policy();
#else
	ima_check_policy();
#endif /* CONFIG_IMA_READABLE_POLICY_INTERFACE */
	return 0;
}

static const struct file_operations ima_measure_policy_ops = {
	.open = ima_open_policy,
	.write = ima_write_policy,
#ifdef CONFIG_IMA_READABLE_POLICY_INTERFACE
	.read = seq_read,
#endif
	.release = ima_release_policy,
	.llseek = generic_file_llseek,
};

#ifdef CONFIG_IMA_LOAD_POLICY
void __init ima_load_policy(char *path)
{
	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return;
	if (ima_read_policy(path) < 0)
		valid_policy = 0;
	ima_check_policy();
}
#endif

int __init ima_fs_init(void)
{
	ima_dir = securityfs_create_dir("ima", NULL);
	if (IS_ERR(ima_dir))
		return -1;

	binary_runtime_measurements =
	    securityfs_create_file("binary_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_ops);
	if (IS_ERR(binary_runtime_measurements))
		goto out;

	ascii_runtime_measurements =
	    securityfs_create_file("ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_ascii_measurements_ops);
	if (IS_ERR(ascii_runtime_measurements))
		goto out;

	runtime_measurements_count =
	    securityfs_create_file("runtime_measurements_count",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_count_ops);
	if (IS_ERR(runtime_measurements_count))
		goto out;

	violations =
	    securityfs_create_file("violations", S_IRUSR | S_IRGRP,
				   ima_dir, NULL, &ima_htable_violations_ops);
	if (IS_ERR(violations))
		goto out;

	ima_policy = securityfs_create_file("policy",
#ifndef CONFIG_IMA_READABLE_POLICY_INTERFACE
					    S_IWUSR,
#else
					    S_IWUSR | S_IRUSR,
#endif /* CONFIG_IMA_READABLE_POLICY_INTERFACE */
					    ima_dir, NULL,
					    &ima_measure_policy_ops);
	if (IS_ERR(ima_policy))
		goto out;

	return 0;
out:
	securityfs_remove(violations);
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(ima_dir);
	securityfs_remove(ima_policy);
	return -1;
}

#ifdef CONFIG_IMA_READABLE_POLICY_INTERFACE
static void *ima_policy_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_rule_entry *entry;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, ima_rules, list) {
		if (!l--) {
			rcu_read_unlock();
			return entry;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_policy_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_rule_entry *entry = v;

	rcu_read_lock();
	entry = list_entry_rcu(entry->list.next, struct ima_rule_entry, list);
	rcu_read_unlock();
	(*pos)++;

	return (&entry->list == ima_rules) ? NULL : entry;
}

static void ima_policy_stop(struct seq_file *m, void *v)
{
}

static int ima_policy_show(struct seq_file *m, void *v)
{
	struct ima_rule_entry *entry = v;
	int i = 0;

	rcu_read_lock();

	if (entry->action & MEASURE)
		seq_puts(m, "measure");
	if (entry->action & DONT_MEASURE)
		seq_puts(m, "dont_measure");
	if (entry->action & APPRAISE)
		seq_puts(m, "appraise");
	if (entry->action & DONT_APPRAISE)
		seq_puts(m, "dont_appraise");
	if (entry->action & AUDIT)
		seq_puts(m, "audit");

	seq_puts(m, " ");

	if (entry->flags & IMA_FUNC) {
		seq_puts(m, "func=");
		switch (entry->func) {
		case MMAP_CHECK:
			seq_puts(m, "MMAP_CHECK");
			break;
		case BPRM_CHECK:
			seq_puts(m, "BPRM_CHECK");
			break;
		case MODULE_CHECK:
			seq_puts(m, "MODULE_CHECK");
			break;
		case FILE_CHECK:
			seq_puts(m, "FILE_CHECK");
			break;
		default:
			seq_printf(m, "%d", entry->func);
			break;
		}
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_MASK) {
		seq_puts(m, "mask=");
		if (entry->mask & MAY_EXEC)
			seq_puts(m, "MAY_EXEC");
		if (entry->mask & MAY_WRITE)
			seq_puts(m, "MAY_WRITE");
		if (entry->mask & MAY_READ)
			seq_puts(m, "MAY_READ");
		if (entry->mask & MAY_APPEND)
			seq_puts(m, "MAY_APPEND");
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_FSMAGIC) {
		seq_printf(m, "fsmagic=0x%lx", entry->fsmagic);
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_FSUUID) {
		seq_puts(m, "fsuuid=");
		for (i = 0; i < ARRAY_SIZE(entry->fsuuid); ++i) {
			switch (i) {
			case 4:
			case 6:
			case 8:
			case 10:
				seq_puts(m, "-");
			}
			seq_printf(m, "%x", entry->fsuuid[i]);
		}
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_UID) {
		seq_printf(m, "uid=%d", __kuid_val(entry->uid));
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_FOWNER) {
		seq_printf(m, "fowner=%d", __kuid_val(entry->fowner));
		seq_puts(m, " ");
	}

	if (entry->flags & IMA_PATH) {
		seq_printf(m, "path=%s", entry->path);
		seq_puts(m, " ");
	}

	for (i = 0; i < MAX_LSM_RULES; i++) {
		if (entry->lsm[i].rule) {
			switch (i) {
			case LSM_OBJ_USER:
				seq_printf(m, "obj_user=%s ",
					(char *)entry->lsm[i].args_p);
				break;
			case LSM_OBJ_ROLE:
				seq_printf(m, "obj_role=%s ",
					(char *)entry->lsm[i].args_p);
				break;
			case LSM_OBJ_TYPE:
				seq_printf(m, "obj_type=%s",
					(char *)entry->lsm[i].args_p);
				break;
			case LSM_SUBJ_USER:
				seq_printf(m, "subj_user=%s ",
					(char *)entry->lsm[i].args_p);
				break;
			case LSM_SUBJ_ROLE:
				seq_printf(m, "subj_role=%s ",
					(char *)entry->lsm[i].args_p);
				break;
			case LSM_SUBJ_TYPE:
				seq_printf(m, "subj_type=%s",
					(char *)entry->lsm[i].args_p);
				break;
			}
		}
	}
	rcu_read_unlock();
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations ima_policy_seqops = {
	.start = ima_policy_start,
	.next = ima_policy_next,
	.stop = ima_policy_stop,
	.show = ima_policy_show,
};
#endif /* CONFIG_IMA_READABLE_POLICY_INTERFACE */
