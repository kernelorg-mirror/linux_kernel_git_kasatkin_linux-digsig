/*
 * Copyright (C) 2011 Nokia Corporation
 * Copyright (C) 2011 Intel Corporation
 *
 * Author:
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *                 <dmitry.kasatkin@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: sign.c
 *	implements signature (RSA) verification
 *	pkcs decoding is originated from LibTomCrypt code
 */

#ifndef CRYPTO_KSIGN_H
#define CRYPTO_KSIGN_H

#include <linux/key.h>

enum pubkey_type {
	PUBKEY_ALGO_RSA,
	PUBKEY_ALGO_DSA,
	PUBKEY_ALGO_MAX,
};

enum digest_algo {
	DIGEST_ALGO_SHA1,
	DIGEST_ALGO_SHA256,
	DIGEST_ALGO_MAX
};

struct pubkey_hdr {
	uint8_t		version;
	uint8_t		algo;
	uint8_t		nmpi;
	char		mpi[0];
} __attribute__ ((packed));

struct signature_hdr {
	uint8_t		version;
	time_t		timestamp;	/* signature made */
	uint8_t		algo;
	uint8_t		hash;
	uint8_t		keyid[8];
	uint8_t		nmpi;
	char		mpi[0];
} __attribute__ ((packed));

#ifdef CONFIG_CRYPTO_KSIGN

int ksign_verify(struct key *keyring, const char *sig, int siglen,
		 const char *digest, int digestlen);

#else

static inline int ksign_verify(struct key *keyring, const char *sig, int siglen,
		 const char *digest, int digestlen)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_CRYPTO_KSIGN */

#endif /* CRYPTO_KSIGN_H */
