/*
 * Copyright (C) 2011 Nokia Corporation
 *
 * Author:
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: sign.c
 *	implements signature (RSA) verification
 *	pkcs decoding is originated from LibTomCrypt code
 */

#include <linux/slab.h>
#include <linux/key.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <keys/user-type.h>
#include <linux/crypto/mpi.h>
#include <linux/crypto/ksign.h>

static struct crypto_shash *shash;

static int pkcs_1_v1_5_decode_emsa(const unsigned char *msg,
			unsigned long  msglen,
			unsigned long  modulus_bitlen,
			unsigned char *out,
			unsigned long *outlen,
			int *is_valid)
{
	unsigned long modulus_len, ps_len, i;
	int result;

	/* default to invalid packet */
	*is_valid = 0;

	modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

	/* test message size */
	if ((msglen > modulus_len) || (modulus_len < 11))
		return -EINVAL;

	/* separate encoded message */
	if ((msg[0] != 0x00) || (msg[1] != (unsigned char)1)) {
		result = -EINVAL;
		goto bail;
	}

	for (i = 2; i < modulus_len - 1; i++)
		if (msg[i] != 0xFF)
			break;

	/* separator check */
	if (msg[i] != 0) {
		/* There was no octet with hexadecimal value 0x00
		to separate ps from m. */
		result = -EINVAL;
		goto bail;
	}

	ps_len = i - 2;

	if (*outlen < (msglen - (2 + ps_len + 1))) {
		*outlen = msglen - (2 + ps_len + 1);
		result = -EOVERFLOW;
		goto bail;
	}

	*outlen = (msglen - (2 + ps_len + 1));
	memcpy(out, &msg[2 + ps_len + 1], *outlen);

	/* valid packet */
	*is_valid = 1;
	result    = 0;
bail:
	return result;
}

/*
 * RSA Signature verification with public key
 */
static int ksign_verify_rsa(struct key *key,
		    const char *sig, int siglen,
		       const char *h, int hlen)
{
	int err = -ENOMEM;
	unsigned long len;
	unsigned long mlen, mblen;
	unsigned nret, l;
	int valid, head, i;
	unsigned char *out1 = NULL, *out2 = NULL;
	MPI in = NULL, res = NULL, pkey[2];
	uint8_t *p, *datap, *endp;
	struct user_key_payload *ukp;
	struct pubkey_hdr *pkh;

	down_read(&key->sem);
	ukp = key->payload.data;
	pkh = (struct pubkey_hdr *)ukp->data;

	if (pkh->version != 1)
		return -EINVAL;

	if (pkh->algo != PUBKEY_ALGO_RSA)
		return -EINVAL;

	if (pkh->nmpi != 2) {
		err = -EINVAL;
		goto err1;
	}

	datap = pkh->mpi;
	endp = datap + ukp->datalen;

	for (i = 0; i < pkh->nmpi; i++) {
		unsigned int remaining = endp - datap;
		pkey[i] = mpi_read_from_buffer(datap, &remaining);
		datap += remaining;
	}

	mblen = mpi_get_nbits(pkey[0]);
	mlen = (mblen + 7)/8;

	out1 = kzalloc(mlen, GFP_KERNEL);
	if (!out1)
		goto err;

	out2 = kzalloc(mlen, GFP_KERNEL);
	if (!out1)
		goto err;

	nret = siglen;
	in = mpi_read_from_buffer(sig, &nret);
	if (!in)
		goto err;

	res = mpi_alloc(mpi_get_nlimbs(in) * 2);
	if (!res)
		goto err;

	err = mpi_powm(res, in, pkey[1], pkey[0]);
	if (err)
		goto err;

	if (mpi_get_nlimbs(res) * BYTES_PER_MPI_LIMB > mlen) {
		err = -EINVAL;
		goto err;
	}

	p = mpi_get_buffer(res, &l, NULL);
	if (!p) {
		err = -EINVAL;
		goto err;
	}

	len = mlen;
	head = len - l;
	memset(out1, 0, head);
	memcpy(out1 + head, p, l);

	err = -EINVAL;
	pkcs_1_v1_5_decode_emsa(out1, len, mblen, out2, &len, &valid);

	if (valid && len == hlen)
		err = memcmp(out2, h, hlen);

err:
	mpi_free(in);
	mpi_free(res);
	kfree(out1);
	kfree(out2);
	mpi_free(pkey[0]);
	mpi_free(pkey[1]);
err1:
	up_read(&key->sem);

	return err;
}

/*
 * Signature verification with public key
 */
int ksign_verify(const char *sig, int siglen,
		       const char *digest, int digestlen)
{
	int err = -ENOMEM;
	struct signature_hdr *sh = (struct signature_hdr *)sig;
	struct shash_desc *desc = NULL;
	unsigned char h[SHA1_DIGEST_SIZE];
	struct key *key;
	char name[20];

	if (siglen < sizeof(*sh) + 2)
		return -EINVAL;

	if (sh->algo != PUBKEY_ALGO_RSA)
		return -ENOTSUPP;

	sprintf(name, "%llX", __be64_to_cpup((uint64_t *)sh->keyid));

	key = request_key(&key_type_user, name, NULL);
	if (IS_ERR(key)) {
		pr_err("key not found, id: %s\n", name);
		return -ENOENT;
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(shash),
		       GFP_KERNEL);
	if (!desc)
		goto err;

	desc->tfm = shash;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	crypto_shash_init(desc);
	crypto_shash_update(desc, digest, digestlen);
	crypto_shash_update(desc, sig, sizeof(*sh));
	crypto_shash_final(desc, h);

	kfree(desc);

	/* pass signature mpis address */
	err = ksign_verify_rsa(key, sig + sizeof(*sh), siglen - sizeof(*sh),
			     h, sizeof(h));

err:
	key_put(key);

	if (err)
		pr_info("ksign_verify: %d\n", err);

	return err ? -EINVAL : 0;
}
EXPORT_SYMBOL_GPL(ksign_verify);

static int __init ksign_init(void)
{
	shash = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(shash)) {
		pr_err("shash allocation failed\n");
		return  PTR_ERR(shash);
	}

	return 0;

}

static void __exit ksign_cleanup(void)
{
	crypto_free_shash(shash);
}

module_init(ksign_init);
module_exit(ksign_cleanup);

MODULE_LICENSE("GPL");
