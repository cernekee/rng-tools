/*
 * Copyright (c) 2012, Intel Corporation
 * Authors: Richard B. Hill <richard.b.hill@intel.com>,
 *          H. Peter Anvin <hpa@linux.intel.com>,
 *          John P. Mechalas <john.p.mechalas@intel.com>
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

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stddef.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

#if defined(__i386__) || defined(__x86_64__)

/* Struct for CPUID return values */
struct cpuid {
        uint32_t eax, ecx, edx, ebx;
};

/* Get data from RDRAND */
extern int x86_rdrand_nlong(void *ptr, size_t count);
/* Conditioning RDRAND for seed-grade entropy */
extern void x86_aes_mangle(void *data, void *state);

/* Checking eflags to confirm cpuid instruction available */
/* Only necessary for 32 bit processors */
#if defined (__i386__)
static int x86_has_eflag(uint32_t flag)
{
        uint32_t f0, f1;
		asm("pushfl ; "
            "pushfl ; "
            "popl %0 ; "
            "movl %0,%1 ; "
            "xorl %2,%1 ; "
            "pushl %1 ; "
            "popfl ; "
            "pushfl ; "
            "popl %1 ; "
            "popfl"
            : "=&r" (f0), "=&r" (f1)
            : "ri" (flag));
        return !!((f0^f1) & flag);
}
#endif

/* Calling cpuid instruction to verify rdrand and aes-ni capability */
static void cpuid(unsigned int leaf, unsigned int subleaf, struct cpuid *out)
{
#ifdef __i386__
    /* %ebx is a forbidden register if we compile with -fPIC or -fPIE */
    asm volatile("movl %%ebx,%0 ; cpuid ; xchgl %%ebx,%0"
                 : "=r" (out->ebx),
                   "=a" (out->eax),
                   "=c" (out->ecx),
                   "=d" (out->edx)
                 : "a" (leaf), "c" (subleaf));
#else
    asm volatile("cpuid"
                 : "=b" (out->ebx),
                   "=a" (out->eax),
                   "=c" (out->ecx),
                   "=d" (out->edx)
                 : "a" (leaf), "c" (subleaf));
#endif
}

/* Read data from the drng in chunks of 128 bytes for AES scrambling */
#define CHUNK_SIZE		(16*8)

static unsigned char iv_buf[CHUNK_SIZE] __attribute__((aligned(128)));
static int have_aesni= 0;

/* Necessary if we have RDRAND but not AES-NI */

#ifdef HAVE_LIBGCRYPT

#define MIN_GCRYPT_VERSION "1.0.0"

static gcry_cipher_hd_t gcry_cipher_hd;

/* Arbitrary 128-bit AES key 0x00102030405060708090A0B0C0D0E0F0 */

static const unsigned char key[16]= {
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0
};

#endif


int xread_drng(void *buf, size_t size, struct rng *ent_src)
{
	char *p = buf;
	size_t chunk;
	const int rdrand_round_count = 512;
	unsigned char tmp[CHUNK_SIZE] __attribute__((aligned(128)));
	int i;

	while (size) {
		for (i = 0; i < rdrand_round_count; i++) {
			if (!x86_rdrand_nlong(tmp, CHUNK_SIZE/sizeof(long))) {
				message(LOG_DAEMON|LOG_ERR, "read error\n");
				return -1;
			}

			// Use 128-bit AES in CBC mode to mangle our random data

			if ( have_aesni ) x86_aes_mangle(tmp, iv_buf);
			else {
#ifdef HAVE_LIBGCRYPT
				gcry_error_t gcry_error;

				/* Encrypt tmp in-place. */

				gcry_error= gcry_cipher_encrypt(gcry_cipher_hd,
					tmp, CHUNK_SIZE, NULL, 0);

				if ( gcry_error ) {
					message(LOG_DAEMON|LOG_ERR,
						"gcry_cipher_encrypt error: %s\n",
						gcry_strerror(gcry_error));
					return -1;
				}
#else
				return -1;
#endif
			}
		}
		chunk = (sizeof(tmp) > size) ? size : sizeof(tmp);
		memcpy(p, tmp, chunk);
		p += chunk;
		size -= chunk;
	}

	return 0;
}

/*
 * Confirm RDRAND capabilities for drng entropy source
 */
int init_drng_entropy_source(struct rng *ent_src)
{
	struct cpuid info;
	/* We need RDRAND, but AESni is optional */
	const uint32_t features_ecx1_rdrand = 1 << 30;
	const uint32_t features_ecx1_aesni = 1 << 25;

#if defined(__i386__)
	if (!x86_has_eflag(1 << 21))
		return 1;	/* No CPUID instruction */
#endif

	cpuid(0, 0, &info);
	if (info.eax < 1)
		return 1;
	cpuid(1, 0, &info);
	if (! (info.ecx & features_ecx1_rdrand) )
		return 1;

	have_aesni= (info.ecx & features_ecx1_aesni) ? 1 : 0;
#ifndef HAVE_LIBGCRYPT
	if ( ! have_aesni ) return 1;
#endif

	/* Initialize the IV buffer */
	if (!x86_rdrand_nlong(iv_buf, CHUNK_SIZE/sizeof(long)))
		return 1;

#ifdef HAVE_LIBGCRYPT
	if ( ! have_aesni ) {
		gcry_error_t gcry_error;

		if (! gcry_check_version(MIN_GCRYPT_VERSION) ) {
			message(LOG_DAEMON|LOG_ERR,
				"libgcrypt version mismatch: have %s, require >= %s\n",
				gcry_check_version(NULL), MIN_GCRYPT_VERSION);
			return 1;
		}

		gcry_error= gcry_cipher_open(&gcry_cipher_hd,
			GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);

		if ( ! gcry_error ) {
			gcry_error= gcry_cipher_setkey(gcry_cipher_hd, key, 16);
		}

		if ( ! gcry_error ) {
			/*
			 * Only need the first 16 bytes of iv_buf. AES-NI can
			 * encrypt multiple blocks in parallel but we can't.
			 */

			gcry_error= gcry_cipher_setiv(gcry_cipher_hd, iv_buf, 16);
		}

		if ( gcry_error ) {
			message(LOG_DAEMON|LOG_ERR,
				"could not set key or IV: %s\n",
				gcry_strerror(gcry_error));
			gcry_cipher_close(gcry_cipher_hd);
			return 1;
		}
	}
#endif

	src_list_add(ent_src);
	/* Bootstrap FIPS tests */
	ent_src->fipsctx = malloc(sizeof(fips_ctx_t));
	fips_init(ent_src->fipsctx, 0);
	return 0;
}

#else /* Not i386 or x86-64 */

int init_drng_entropy_source(struct rng *ent_src)
{
	(void)ent_src;
	return 1;
}

int xread_drng(void *buf, size_t size, struct rng *ent_src)
{
	(void)buf;
	(void)size;
	(void)ent_src;

	return -1;
}

#endif /* Not i386 or x86-64 */
