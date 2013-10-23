/*
 * dm-integrity - device mapper integrity target
 *
 * Copyright (C) 2012,2013 Intel Corporation,
 *               2013 Samsung Electronics.
 *
 * Author: Dmitry Kasatkin <dmitry.kasatkin@intel.com>
 *         Dmitry Kasatkin <d.kasatkin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define DM_MSG_PREFIX KBUILD_MODNAME

#define pr_fmt(fmt) KBUILD_MODNAME ": %s: " fmt, __func__

#include "dm.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <keys/encrypted-type.h>
#include <linux/wait.h>
#include <linux/reboot.h>

#include "dm-bufio.h"

#define DM_INT_STATS

#define DM_INT_MIN_IOS		16
#define DM_INT_BLOCK_SIZE	PAGE_SIZE
#define DM_INT_MAX_KEY_SIZE	128

/* best parameters for fastest Ubuntu boot */
#define DM_INT_PREFETCH_COUNT	16

struct ahash_result {
	struct completion completion;
	int err;
};

struct dm_int_io {
	struct dm_int *dmi;	/* mapping it belongs to */
	struct work_struct work;

#define DM_INT_BIO_DONE		1
#define DM_INT_VERIFIED		2
	unsigned long flags;

	atomic_t count;
	int error;

	sector_t sector;

	bio_end_io_t *bi_end_io;	/* original bio callback */
	void *bi_private;	/* original bio private data */
	unsigned int bi_size;
	unsigned short bi_idx;

	struct ahash_request req;
};

/*
 * integrity mapping configuration
 */
struct dm_int {
	struct dm_target *ti;
	struct dm_dev *dev;
	char *table_string;
	sector_t start;
	struct dm_dev *hdev;
	sector_t hmac_start;
	sector_t hmac_count;

	struct workqueue_struct *io_queue;

	struct crypto_ahash *ahash;
	struct crypto_shash *hmac;

	struct notifier_block reboot_nb;

	struct dm_bufio_client *bufio;

	unsigned int hmac_size;
	unsigned int data_block_size;
	unsigned int data_block_bits;
	unsigned int hmac_block_size;
	unsigned int hmac_block_bits;
	unsigned int hmac_per_block;
	unsigned int hmac_block_shift;

#define DM_INT_FLAGS_FIX		0x01	/* fix wrong hmacs */
#define DM_INT_FLAGS_VERBOSE		0x02	/* show failed blocks */
#define DM_INT_FLAGS_ZERO		0x04	/* zero on error */
#define DM_INT_FLAGS_SYNC_MODE		0x08	/* sync mode */

	unsigned int flags;

	atomic_t violations;

#ifdef DM_INT_STATS
#define DM_INT_FLAGS_STATS		0x80	/* calc statistics */
	atomic_t io_count;
	int io_count_max;
	atomic_t data_write_count;
	atomic_t data_read_count;
#else
/* setting to 0 will eliminate the code due to optimization */
#define DM_INT_FLAGS_STATS		0x00
#endif
};


#define io_block(io) (io->sector >> (io->dmi->data_block_bits - SECTOR_SHIFT))

static void dm_int_queue_hmac(struct dm_int_io *io);

/*
 * Get the key from the TPM for the HMAC
 */
static int dm_int_init_crypto(struct dm_int *dmi, const char *hash_algo,
			      const char *hmac_algo, const char *keyname)
{
	struct key *key;
	struct encrypted_key_payload *ekp;
	int err = -EINVAL;

	dmi->ahash = crypto_alloc_ahash(hash_algo, 0, 0);
	if (IS_ERR(dmi->ahash)) {
		err = PTR_ERR(xchg(&dmi->ahash, NULL));
		DMERR("failed to load %s algorithm: %d", hash_algo, err);
		dmi->ti->error = "Cannot allocate hash algorithm";
		return err;
	}

	dmi->hmac = crypto_alloc_shash(hmac_algo, 0, 0);
	if (IS_ERR(dmi->hmac)) {
		err = PTR_ERR(xchg(&dmi->hmac, NULL));
		DMERR("failed to load %s algorithm: %d", hmac_algo, err);
		dmi->ti->error = "Cannot allocate hash algorithm";
		return err;
	}

	key = request_key(&key_type_encrypted, keyname, NULL);
	if (IS_ERR(key)) {
		dmi->ti->error = "Invalid key name";
		return -ENOENT;
	}

	down_read(&key->sem);
	ekp = key->payload.data;
	if (ekp->decrypted_datalen <= DM_INT_MAX_KEY_SIZE)
		err = crypto_shash_setkey(dmi->hmac, ekp->decrypted_data,
					  ekp->decrypted_datalen);

	/* burn the original key contents */
	/*memset(ekp->decrypted_data, 0, ekp->decrypted_datalen); */
	up_read(&key->sem);
	key_put(key);

	return err;
}

static void dm_int_io_get(struct dm_int_io *io)
{
	atomic_inc(&io->count);

	pr_debug("block: %llu, pending %d\n",
		 (loff_t)io_block(io), atomic_read(&io->count));
}

static void dm_int_io_put(struct dm_int_io *io)
{
	struct dm_int *dmi = io->dmi;
	struct bio *bio;
	int err = io->error;

	pr_debug("block: %llu, pending %d\n",
		 (loff_t)io_block(io), atomic_read(&io->count));

	if (!atomic_dec_and_test(&io->count))
		return;

	/* request has completed */
	if (!err && test_bit(DM_INT_BIO_DONE, &io->flags) &&
	    !test_bit(DM_INT_VERIFIED, &io->flags)) {
		/* io->count will be 1 */
		pr_debug("queue to verify block: %llu\n", (loff_t)io_block(io));
		dm_int_queue_hmac(io);
		return;
	}

	pr_debug("io done: err: %d, pending: %d\n",
		 err, atomic_read(&io->count));

	bio = dm_bio_from_per_bio_data(io, dmi->ti->per_bio_data_size);

	if (dmi->flags & DM_INT_FLAGS_STATS)
		atomic_dec(&dmi->io_count);

	if (err)
		DMERR_LIMIT("%s block %llu failed (%d) - %s",
			    bio_data_dir(bio) ? "write" : "read",
			    (loff_t)io_block(io), err,
			    err == -EKEYREJECTED ?
					    "hmac mismatch" : " system error");

	bio_endio(bio, err);	/* finally completed, end main bio */
}

static void dm_int_prefetch(struct dm_int_io *io)
{
	struct dm_int *dmi = io->dmi;
	sector_t first, last, data;
	loff_t offset;

	/* block number to read */
	offset = io->sector << SECTOR_SHIFT;
	data = offset >> dmi->data_block_bits;
	if (dmi->hmac_block_shift)
		first = data >> dmi->hmac_block_shift;
	else {
		first = data;
		sector_div(first, dmi->hmac_per_block);
	}

	/* offset to the last byte of data */
	offset += (io->bi_size - 1);
	data = offset >> dmi->data_block_bits;
	if (dmi->hmac_block_shift)
		last = data >> dmi->hmac_block_shift;
	else  {
		last = data;
		sector_div(last, dmi->hmac_per_block);
	}

	/* prefetch multiple of DM_INT_PREFETCH_COUNT */
	first = round_down(first, DM_INT_PREFETCH_COUNT);
	last = round_up(last + 1, DM_INT_PREFETCH_COUNT);
	/* check the end of the device */
	if (last > dmi->hmac_count)
		last = dmi->hmac_count;

	dm_bufio_prefetch(dmi->bufio, dmi->hmac_start + first, last - first);
}

static int dm_int_verify_hmac(struct dm_int_io *io, loff_t offset,
			      u8 *collected, int update)
{
	struct dm_int *dmi = io->dmi;
	sector_t block, data = offset >> dmi->data_block_bits;
	unsigned int index;
	u8 *digest;
	int err = 0;
	struct dm_buffer *buf;

	if (dmi->hmac_block_shift) {
		block = data >> dmi->hmac_block_shift;
		index = data & ((1 << dmi->hmac_block_shift) - 1);
	} else {
		block = data;
		index = sector_div(block, dmi->hmac_per_block);
	}

	pr_debug("hmac: block: %llu, index: %u\n", (loff_t)block, index);

	digest = dm_bufio_read(dmi->bufio, dmi->hmac_start + block, &buf);
	if (unlikely(IS_ERR(digest)))
		return PTR_ERR(digest);

	digest += dmi->hmac_size * index;

	if (!update) {
		err = memcmp(digest, collected, dmi->hmac_size);
		if (err) {
			err = -EKEYREJECTED;
			/* update buffer and store it back */
			atomic_inc(&dmi->violations);
			if (dmi->flags & DM_INT_FLAGS_FIX) {
				err = 0;
				update = 1;
			}
			if (dmi->flags & DM_INT_FLAGS_VERBOSE) {
				DMERR("hmac mismatch: block: %llu, index: %u",
				      (loff_t)block, index);
				print_hex_dump(KERN_CRIT, "collected: ",
					       0, 32, 1, collected, 20, 0);
				print_hex_dump(KERN_CRIT, "hmac: ",
					       0, 32, 1, digest, 20, 0);
			}
		}
	}

	if (update) {
		memcpy(digest, collected, dmi->hmac_size);
		dm_bufio_mark_buffer_dirty(buf);
	}

	dm_bufio_release(buf);

	return err;
}

static void dm_int_ahash_complete(struct crypto_async_request *req, int err)
{
	struct ahash_result *res = req->data;

	if (err == -EINPROGRESS)
		return;
	res->err = err;
	complete(&res->completion);
}

static int dm_int_ahash_wait(int err, struct ahash_result *res)
{
	switch (err) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&res->completion);
		reinit_completion(&res->completion);
		err = res->err;
		/* fall through */
	default:
		DMERR("HMAC calculation failed: err: %d", err);
	}

	return err;
}

static int dm_int_calc_hmac(struct dm_int_io *io, loff_t offset,
			    u8 *digest, unsigned int size, u8 *hmac)
{
	struct dm_int *dmi = io->dmi;
	int err;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(dmi->hmac)];
	} desc;

	desc.shash.tfm = dmi->hmac;
	desc.shash.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	err = crypto_shash_init(&desc.shash);
	if (!err)
		err = crypto_shash_update(&desc.shash, digest, size);
	if (!err)
		err = crypto_shash_finup(&desc.shash, (u8 *)&offset,
					  sizeof(offset), hmac);
	if (err)
		DMERR_LIMIT("calc hmac failed: %d", err);
	return err;
}

static void dm_int_verify_io(struct dm_int_io *io)
{
	struct dm_int *dmi = io->dmi;
	struct bio *bio;
	struct bio_vec *bv;
	int i, err = -EIO;
	struct scatterlist sg[1];
	u8 hmac[dmi->hmac_size];
	u8 digest[crypto_ahash_digestsize(dmi->ahash)];
	loff_t offset = io->sector << SECTOR_SHIFT;
	struct ahash_request *req = &io->req;
	struct ahash_result res;
	ssize_t size = io->bi_size;

	init_completion(&res.completion);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				   CRYPTO_TFM_REQ_MAY_SLEEP,
				   dm_int_ahash_complete, &res);

	sg_init_table(sg, 1);

	bio = dm_bio_from_per_bio_data(io, dmi->ti->per_bio_data_size);

	pr_debug("block: %llu, size: %d, vcnt: %d, idx: %d\n",
		 (loff_t)io_block(io), bio->bi_size, bio->bi_vcnt, bio->bi_idx);

	bio_for_each_segment(bv, bio, i) {
		pr_debug("bv: %d: offset: %llu, bv_offset: %d, bv_len: %d\n",
			 i, offset, bv->bv_offset, bv->bv_len);

		BUG_ON(bv->bv_offset & (dmi->data_block_size - 1));
		BUG_ON(bv->bv_len & (dmi->data_block_size - 1));

		sg_set_page(sg, bv->bv_page, bv->bv_len, bv->bv_offset);

		ahash_request_set_crypt(req, sg, digest, bv->bv_len);

		err = crypto_ahash_digest(req);
		err = dm_int_ahash_wait(err, req->base.data);
		if (err)
			break;

		err = dm_int_calc_hmac(io, offset, digest, sizeof(digest),
				       hmac);
		if (err)
			break;

		err = dm_int_verify_hmac(io, offset, hmac, bio_data_dir(bio));
		if (err) {
			if (dmi->flags & DM_INT_FLAGS_ZERO) {
				void *ptr = kmap(bv->bv_page);
				if (!ptr)
					break;
				DMERR_LIMIT("Ignoring bad HMAC");
				memset(ptr + bv->bv_offset, 0, bv->bv_len);
				kunmap(ptr);
				err = 0;
			} else
				break;
		}

		offset += bv->bv_len;
		size -= bv->bv_len;
	}

	WARN(!err && size, "bio has date left: %zd\n", size);

	io->error = err;
	set_bit(DM_INT_VERIFIED, &io->flags);

	if (dmi->flags & DM_INT_FLAGS_SYNC_MODE)
		dm_bufio_write_dirty_buffers(dmi->bufio);
}

static void dm_int_hmac_task(struct work_struct *work)
{
	struct dm_int_io *io = container_of(work, struct dm_int_io, work);

	dm_int_verify_io(io);
	dm_int_io_put(io);
}

static void dm_int_queue_hmac(struct dm_int_io *io)
{
	struct dm_int *dmi = io->dmi;
	int err;

	/* what if it is queued already? */
	dm_int_io_get(io);
	err = queue_work(dmi->io_queue, &io->work);
	if (!err)
		dm_int_io_put(io);
	BUG_ON(!err);
}

static void dm_int_end_io(struct bio *bio, int err)
{
	struct dm_int_io *io = bio->bi_private;

	pr_debug("pending: %d, block: %llu, size: %u, vcnt: %d, idx: %d\n",
		 atomic_read(&io->count), (loff_t)io_block(io),
		 bio->bi_size, bio->bi_vcnt, bio->bi_idx);

	if (unlikely(!bio_flagged(bio, BIO_UPTODATE) && !err))
		err = -EIO;

	if (err)
		DMERR("bio failed: %d", err);

	if (unlikely(err))
		io->error = err;

	set_bit(DM_INT_BIO_DONE, &io->flags);

	bio->bi_private = io->bi_private;
	bio->bi_end_io = io->bi_end_io;
	bio->bi_idx = io->bi_idx;

	dm_int_io_put(io);
}

static void dm_int_start_io(struct dm_int_io *io)
{
	struct dm_int *dmi = io->dmi;
	struct bio *bio;

	if (io->error)
		return;

	bio = dm_bio_from_per_bio_data(io, dmi->ti->per_bio_data_size);

	io->bi_private = bio->bi_private;
	io->bi_end_io = bio->bi_end_io;

	/* io->sector starts from 0 */
	bio->bi_sector = dmi->start + io->sector;
	bio->bi_bdev = dmi->dev->bdev;

	bio->bi_private = io;
	bio->bi_end_io = dm_int_end_io;

	dm_int_io_get(io);

	if (dmi->flags & DM_INT_FLAGS_STATS) {
		if (bio_data_dir(bio) == READ)
			atomic_inc(&dmi->data_read_count);
		else
			atomic_inc(&dmi->data_write_count);
	}

	generic_make_request(bio);
}

static struct dm_int_io *dm_int_io_alloc(struct dm_int *dmi,
					 struct bio *bio, sector_t sector)
{
	struct dm_int_io *io;

	/* no allocation */
	io = dm_per_bio_data(bio, dmi->ti->per_bio_data_size);

	io->dmi = dmi;
	io->bi_size = bio->bi_size;
	io->bi_idx = bio->bi_idx;
	io->sector = sector;
	io->error = 0;
	io->flags = 0;

	INIT_WORK(&io->work, dm_int_hmac_task);

	ahash_request_set_tfm(&io->req, dmi->ahash);

	atomic_set(&io->count, 1);

	/* stats */
	if (dmi->flags & DM_INT_FLAGS_STATS) {
		atomic_inc(&dmi->io_count);
		if (atomic_read(&dmi->io_count) > dmi->io_count_max)
			dmi->io_count_max = atomic_read(&dmi->io_count);
	}

	return io;
}

static int dm_int_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_int *dmi = ti->private;
	struct dm_int_io *io;

	/*
	 * If bio is REQ_FLUSH or REQ_DISCARD, just bypass crypt queues.
	 * - for REQ_FLUSH device-mapper core ensures that no IO is in-flight
	 * - for REQ_DISCARD caller must use flush if IO ordering matters
	 */
	if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_DISCARD))) {
		bio->bi_bdev = dmi->dev->bdev;
		bio->bi_sector =
			dmi->start + dm_target_offset(ti, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/* a check to see if something unhandled might come */
	if (!bio->bi_size || !bio->bi_vcnt)
		DMERR("bio without data: size: %d, vcnt: %d",
		      bio->bi_size, bio->bi_vcnt);

	BUG_ON(bio->bi_sector & (to_sector(dmi->data_block_size) - 1));
	BUG_ON(bio->bi_size & (dmi->data_block_size - 1));

	io = dm_int_io_alloc(dmi, bio, dm_target_offset(ti, bio->bi_sector));

	pr_debug("%s block: %llu, size: %u, vcnt: %d, idx: %d, %s (%d)\n",
		 bio_data_dir(bio) ? "write" : "read", (loff_t)io_block(io),
		 bio->bi_size, bio->bi_vcnt, bio->bi_idx,
		 current->comm, current->pid);

	dm_int_start_io(io);
	dm_int_prefetch(io);

	dm_int_io_put(io);

	return DM_MAPIO_SUBMITTED;
}

static void dm_int_cleanup(struct dm_target *ti)
{
	struct dm_int *dmi = (struct dm_int *)ti->private;

	if (dmi->bufio)
		dm_bufio_client_destroy(dmi->bufio);
	if (dmi->io_queue)
		destroy_workqueue(dmi->io_queue);
	if (dmi->ahash)
		crypto_free_ahash(dmi->ahash);
	if (dmi->hmac)
		crypto_free_shash(dmi->hmac);
	if (dmi->hdev)
		dm_put_device(ti, dmi->hdev);
	if (dmi->dev)
		dm_put_device(ti, dmi->dev);
	kfree(dmi->table_string);
	kfree(dmi);
}

static void dm_int_sync(struct dm_int *dmi)
{
	/* first flush hmac queue, which might schedule idata delayed work */
	flush_workqueue(dmi->io_queue);
	/* write all updated hmac blocks */
	dm_bufio_write_dirty_buffers(dmi->bufio);
}

static int dm_int_notify_reboot(struct notifier_block *this,
				unsigned long code, void *x)
{
	struct dm_int *dmi = container_of(this, struct dm_int, reboot_nb);

	if ((code == SYS_DOWN) || (code == SYS_HALT) ||
						(code == SYS_POWER_OFF)) {
		dmi->flags |= DM_INT_FLAGS_SYNC_MODE;
		pr_info("syncing target...");
		dm_int_sync(dmi);
		pr_cont(" done.\n");
	}
	return NOTIFY_DONE;
}

/*
 * Construct an integrity mapping:
 * <dev> <bs> <start> <hdev> <hbs> <hstart> <hash_algo> <hmac_algo> <keyname> \
 * [opt_params]
 */
static int dm_int_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_int *dmi;
	int err, i, count;
	unsigned long long tmpll;
	char table[256], dummy;
	unsigned tmp;
	fmode_t mode;
	sector_t datadevsize, hmacdevsize, maxdatasize, maxhmacsize;

	if (argc < 9) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	dmi = kzalloc(sizeof(*dmi), GFP_KERNEL);
	if (dmi == NULL) {
		ti->error = "dm-integrity: Cannot allocate linear context";
		return -ENOMEM;
	}

	dmi->ti = ti;
	ti->private = dmi;

	err = -EINVAL;

	mode = dm_table_get_mode(ti->table);

	if (dm_get_device(ti, argv[0], mode, &dmi->dev)) {
		ti->error = "Device lookup failed";
		goto err;
	}

	if (sscanf(argv[1], "%u%c", &tmp, &dummy) != 1 ||
	   !is_power_of_2(tmp) ||
	   tmp < bdev_logical_block_size(dmi->dev->bdev) ||
	   tmp > PAGE_SIZE) {
		ti->error = "Invalid device block size";
		goto err;
	}
	dmi->data_block_size = tmp;
	dmi->data_block_bits = ffs(dmi->data_block_size) - 1;

	if (sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) {
		ti->error = "Invalid device start";
		goto err;
	}
	dmi->start = tmpll;

	if (dm_get_device(ti, argv[3], mode, &dmi->hdev)) {
		ti->error = "HMAC device lookup failed";
		goto err;
	}

	if (sscanf(argv[4], "%u%c", &tmp, &dummy) != 1 ||
	   !is_power_of_2(tmp) ||
	   tmp < bdev_logical_block_size(dmi->dev->bdev) ||
	   tmp > PAGE_SIZE) {
		ti->error = "Invalid device block size";
		goto err;
	}
	dmi->hmac_block_size = tmp;
	dmi->hmac_block_bits = ffs(dmi->hmac_block_size) - 1;

	if (sscanf(argv[5], "%llu%c", &tmpll, &dummy) != 1) {
		ti->error = "Invalid hmac device start";
		goto err;
	}
	dmi->hmac_start = tmpll;

	err = dm_int_init_crypto(dmi, argv[6], argv[7], argv[8]);
	if (err)
		goto err;

	count = snprintf(table, sizeof(table), "%s %u %llu %s %u %llu %s %s %s",
			 dmi->dev->name, dmi->data_block_size,
			 (loff_t)dmi->start,
			 dmi->hdev->name, dmi->hmac_block_size,
			 (loff_t)dmi->hmac_start,
			 argv[6], argv[7], argv[8]);

	for (i = 9; i < argc; i++) {
		count += snprintf(table + count, sizeof(table) - count,
				  " %s", argv[i]);
	}

	dmi->table_string = kstrdup(table, GFP_KERNEL);

	dmi->hmac_size = crypto_shash_digestsize(dmi->hmac);

	/* how many hmacs do we need for data device */
	dmi->hmac_count = ti->len >> (dmi->data_block_bits - SECTOR_SHIFT);

	datadevsize = i_size_read(dmi->dev->bdev->bd_inode) >> SECTOR_SHIFT;
	hmacdevsize = i_size_read(dmi->hdev->bdev->bd_inode) >> SECTOR_SHIFT;

	err = -EINVAL;

	if (dmi->start > datadevsize) {
		DMERR("start sector is beyond device size: %llu (%llu)",
		      (loff_t)dmi->start, (loff_t)datadevsize);
		ti->error = "start sector is beyond data device size";
		goto err;
	}

	if (dmi->hmac_start > hmacdevsize) {
		DMERR("start sector is beyond device size: %llu (%llu)",
		      (loff_t)dmi->hmac_start, (loff_t)hmacdevsize);
		ti->error = "start sector is beyond integrity device size";
		goto err;
	}

	if (dmi->dev->bdev == dmi->hdev->bdev) {
		if (dmi->hmac_start > dmi->start) {
			maxdatasize = dmi->hmac_start - dmi->start;
			maxhmacsize = datadevsize - dmi->hmac_start;
		} else {
			maxhmacsize = dmi->start - dmi->hmac_start;
			maxdatasize = datadevsize - dmi->start;
		}
	} else {
		maxdatasize = datadevsize - dmi->start;
		maxhmacsize = hmacdevsize - dmi->hmac_start;
	}

	if (ti->len > maxdatasize) {
		DMERR("target size is too big: %llu (%llu)",
		      (loff_t)ti->len, (loff_t)maxdatasize);
		ti->error = "target size is too big";
		goto err;
	}

	/* hmac start in blocks */
	dmi->hmac_start >>= (dmi->hmac_block_bits - SECTOR_SHIFT);

	/* optimize for SHA256  which is 32 bytes */
	if (is_power_of_2(dmi->hmac_size)) {
		dmi->hmac_block_shift =
			dmi->hmac_block_bits - (ffs(dmi->hmac_size) - 1);
		/* how many hmac blocks do we need */
		dmi->hmac_count >>= dmi->hmac_block_shift;
	} else {
		dmi->hmac_per_block = dmi->hmac_block_size / dmi->hmac_size;
		/* how many hmac blocks do we need */
		tmpll = sector_div(dmi->hmac_count, dmi->hmac_per_block);
		if (tmpll)
			dmi->hmac_count++;
	}

	/* device may hold as many hmac blocks */
	maxhmacsize >>= (dmi->hmac_block_bits - SECTOR_SHIFT);

	if (dmi->hmac_count > maxhmacsize) {
		DMERR("HMAC device is too small: %llu (%llu)",
		      (unsigned long long)dmi->hmac_count,
		      (unsigned long long)maxhmacsize);
		ti->error = "HMAC device is too small";
		goto err;
	}

	ti->num_discard_bios = 1;

	for (i = 9; i < argc; i++) {
		if (!strcmp(argv[i], "fix"))
			dmi->flags |= DM_INT_FLAGS_FIX;
		else if (!strcmp(argv[i], "zero_on_error"))
			dmi->flags |= DM_INT_FLAGS_ZERO;
		else if (!strcmp(argv[i], "stats"))
			dmi->flags |= DM_INT_FLAGS_STATS;
		else if (!strcmp(argv[i], "verbose"))
			dmi->flags |= DM_INT_FLAGS_VERBOSE;
		else if (!strcmp(argv[i], "disallow_discards"))
			ti->num_discard_bios = 0;
	}

	ti->per_bio_data_size = sizeof(struct dm_int_io);
	ti->per_bio_data_size += crypto_ahash_reqsize(dmi->ahash);

	err = -ENOMEM;

	dmi->io_queue = alloc_workqueue("dm_int_hmac",
					  WQ_CPU_INTENSIVE |
					  WQ_HIGHPRI |
					  WQ_UNBOUND |
					  WQ_MEM_RECLAIM,
					  1);
	if (!dmi->io_queue) {
		ti->error = "Couldn't create dm_int hmac queue";
		goto err;
	}

	dmi->bufio = dm_bufio_client_create(dmi->hdev->bdev,
					    dmi->hmac_block_size, 1, 0,
					    NULL, NULL);
	if (IS_ERR(dmi->bufio)) {
		ti->error = "Cannot initialize dm-bufio";
		err = PTR_ERR(xchg(&dmi->bufio, NULL));
		goto err;
	}

	ti->num_flush_bios = 1;
	/* it should depend on read block device... */
	/*ti->discard_zeroes_data_unsupported = true;*/

	dmi->reboot_nb.notifier_call = dm_int_notify_reboot,
	dmi->reboot_nb.priority	= INT_MAX, /* before any real devices */
	/* always returns 0 */
	register_reboot_notifier(&dmi->reboot_nb);

	return 0;

err:
	dm_int_cleanup(ti);
	return err;
}

static void dm_int_dtr(struct dm_target *ti)
{
	struct dm_int *dmi = (struct dm_int *)ti->private;

	unregister_reboot_notifier(&dmi->reboot_nb);

	dm_int_cleanup(ti);
}

static int dm_int_ioctl(struct dm_target *ti, unsigned int cmd,
			unsigned long arg)
{
	struct dm_int *dmi = (struct dm_int *)ti->private;
	struct dm_dev *dev = dmi->dev;
	int err = 0;

	if (cmd == BLKFLSBUF)
		dm_int_sync(dmi);

	/*
	 * Only pass ioctls through if the device sizes match exactly.
	 */
	if (dmi->start ||
	    ti->len != i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT)
		err = scsi_verify_blk_ioctl(NULL, cmd);

	return err ? : __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);
}

static int dm_int_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct dm_int *dmi = ti->private;
	struct request_queue *q = bdev_get_queue(dmi->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = dmi->dev->bdev;
	bvm->bi_sector = dmi->start + dm_target_offset(ti, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int dm_int_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct dm_int *dmi = ti->private;

	return fn(ti, dmi->dev, dmi->start, ti->len, data);
}

static void dm_int_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct dm_int *dmi = ti->private;

	limits->logical_block_size = dmi->data_block_size;
	limits->physical_block_size = dmi->data_block_size;
	blk_limits_io_min(limits, dmi->data_block_size);
}

static void dm_int_postsuspend(struct dm_target *ti)
{
	struct dm_int *dmi = ti->private;

	dm_int_sync(dmi);

	DMINFO("%s suspended\n", dm_device_name(dm_table_get_md(ti->table)));
}

static void dm_int_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct dm_int *dmi = (struct dm_int *)ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
#ifdef DM_INT_STATS
		DMEMIT("io: %d (%d), read: %d, write: %d, violations: %d",
		       atomic_read(&dmi->io_count), dmi->io_count_max,
		       atomic_read(&dmi->data_read_count),
		       atomic_read(&dmi->data_write_count),
		       atomic_read(&dmi->violations));
#else
		DMEMIT("violations: %d",
		       atomic_read(&dmi->violations));
#endif
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s", dmi->table_string);
		break;
	}
}

static struct target_type dm_int_target = {
	.name = "integrity",
	.version = {0, 1, 0},
	.module = THIS_MODULE,
	.ctr = dm_int_ctr,
	.dtr = dm_int_dtr,
	.map = dm_int_map,
	.status = dm_int_status,
	.ioctl = dm_int_ioctl,
	.postsuspend = dm_int_postsuspend,
	.merge = dm_int_merge,
	.iterate_devices = dm_int_iterate_devices,
	.io_hints = dm_int_io_hints,
};

int __init dm_int_init(void)
{
	int err;

	err = dm_register_target(&dm_int_target);
	if (err < 0)
		DMERR("register failed %d", err);

	return err;
}

void dm_int_exit(void)
{
	dm_unregister_target(&dm_int_target);
}

/* Module hooks */
module_init(dm_int_init);
module_exit(dm_int_exit);

MODULE_DESCRIPTION(DM_NAME " integrity target");
MODULE_AUTHOR("Dmitry Kasatkin");
MODULE_LICENSE("GPL");
