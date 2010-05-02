/*
 * rngd_entsource.c -- Entropy source and conditioning
 *
 * Copyright (C) 2001 Philipp Rumpf
 * Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include <sys/poll.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <assert.h>

#include "rngd.h"
#include "fips.h"
#include "stats.h"
#include "exits.h"
#include "rngd_threads.h"
#include "rngd_signals.h"
#include "rngd_entsource.h"

#define MAX_THROTTLE_LEVEL 6
#define NONBLOCK_READ_RETRIES 10	/* must be > 4 */

/* Logic and contexts */
static volatile int throttling = 0;	/* Throttling level, 0 = normal */
static volatile int pausesource = 0;	/* Pause reading from entropy source */
static fips_ctx_t fipsctx;		/* Context for the FIPS tests */

/* Data source */
static int rng_fd = -1;			/* rng data source */
static int rng_source_timeout = 10;	/* rng data source timeout (s) */

/* RNG data source thread waits on this condition */
pthread_cond_t	rng_buffer_empty = PTHREAD_COND_INITIALIZER;
pthread_mutex_t	rng_buffer_empty_mutex = PTHREAD_MUTEX_INITIALIZER;

/* FIPS processing thread waits on this condition */
pthread_cond_t  rng_buffer_raw = PTHREAD_COND_INITIALIZER;
pthread_mutex_t rng_buffer_raw_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Read data from the entropy source 
 *
 * Works for both blocking and non-blocking mode,
 * but it will spin using CPU in non-blocking mode...
 *
 * We cannot trust poll/select fully when talking to
 * /dev/hwrng, which is a real pity.
 */
static int xread(void *buf, size_t size, unsigned int abortonsigalrm)
{
	size_t off = 0;
	ssize_t r;

	assert(buf != NULL);

	while (size > 0) {
		do {
			r = read(rng_fd, (unsigned char *)buf + off, size);
			if (gotsigterm || (abortonsigalrm && gotsigalrm))
				return -1;
		} while ((r == -1) && ((errno == EINTR) || (errno == EAGAIN)));
		if (r < 0) break;
		if (r == 0) {
			message(LOG_ERR, "entropy source exhausted!");
			return -1;
		}
		off += r;
		size -= r;
		pthread_mutex_lock(&rng_stats.group1_mutex);
		rng_stats.bytes_received += r;
		pthread_mutex_unlock(&rng_stats.group1_mutex);
	}

	if (size != 0) {
		message_strerr(LOG_ERR, errno,
				"error reading from entropy source:");
		exitstatus = EXIT_IOERR;
		return -1;
	}
	return 0;
}

/*
 * Open entropy source, and initialize it
 *
 * We have to trash 32 bits of what is probably stale 
 * (non-random) initial state from the RNG.  For Intel's, 8 
 * bits would be enough, but since AMD's generates 32 bits 
 * at a time...
 * 
 * The kernel drivers should be doing this at device powerup,
 * but at least up to 2.4.28/2.6.9, it doesn't.  This is a 
 * bug, but not really serious unless something is using the
 * TRNG to seed the PRNGs, in which case it could be deadly.
 *
 * We use the opportunity to detect a stuck entropy source.
 */
void init_entropy_source( void )
{
	unsigned char tempbuf[4];

	assert(rng_fd == -1);

	rng_source_timeout = arguments->rng_timeout;

	rng_fd = open(arguments->rng_name, O_RDONLY);
	if (rng_fd == -1) {
		message_strerr(LOG_ERR, errno, "can't open %s",
				arguments->rng_name);
		die(EXIT_FAIL);
	}

	if (enable_sigalrm(rng_source_timeout)) die(EXIT_FAIL);
	/* Discard the first 32 bits */
	if (xread(tempbuf, sizeof tempbuf, 1)) die(EXIT_FAIL);
	/* Get the next 32 bits to bootstrap FIPS tests */
	if (xread(tempbuf, sizeof tempbuf, 1)) die(EXIT_FAIL);
	disable_sigalrm();

	fips_init(&fipsctx, tempbuf[0] | (tempbuf[1] << 8) |
		(tempbuf[2] << 16) | (tempbuf[3] << 24));
}



/*
 * RNG data source thread
 *
 * This thread receives data from the RNG source into the buffers.
 *
 * It is awakened every time a buffer is freed (by the other threads).
 * It awakens the FIPS thread when a buffer of raw data is ready.
 * 
 * Only one data source thread is supported
 */

static void rng_data_source_work(int i, struct timeval *start, 
		struct timeval *stop)
{
	gettimeofday (start, 0);
	if (xread(rng_buf[i], FIPS_RNG_BUFFER_SIZE, 0) == -1) {
		/* any errors are likely to be permanent. kill rngd */
		kill(masterprocess, SIGTERM);
		pthread_exit(NULL);
	}
	gettimeofday (stop, 0);

	BUFFIFO_WRITE(full, i);

	pthread_mutex_lock(&rng_buffer_raw_mutex);
	pthread_cond_signal(&rng_buffer_raw);
	pthread_mutex_unlock(&rng_buffer_raw_mutex);

	pthread_mutex_lock(&rng_stats.group1_mutex);
	update_usectimer_stat(&rng_stats.source_blockfill, start, stop);
	pthread_mutex_unlock(&rng_stats.group1_mutex);
}

void *do_rng_data_source_loop( void *trash )
{
	int i;
	struct timeval start, stop;

	for (;;) {
		if (gotsigterm) pthread_exit(NULL);

		if (!pausesource && ISBUFFIFO_NONEMPTY(empty)) {
			if (throttling) sleep(1 << throttling);
			if (gotsigterm) pthread_exit(NULL);

			BUFFIFO_READ(empty, i);
			rng_data_source_work(i, &start, &stop);
		} else if (!pausesource && ISBUFFIFO_NONEMPTY(rejected)) {
			if (throttling) sleep(1 << throttling);
			if (gotsigterm) pthread_exit(NULL);

			BUFFIFO_READ(rejected, i);
			rng_data_source_work(i, &start, &stop);
		} else {
			pthread_mutex_lock(&rng_buffer_empty_mutex);
			pthread_cond_wait(&rng_buffer_empty, &rng_buffer_empty_mutex);
			pthread_mutex_unlock(&rng_buffer_empty_mutex);
		}
	}
}


/*
 * RNG FIPS test thread
 *
 * This thread searches for buffers full of raw data, and runs a FIPS test on
 * them.  If the buffer passes, it marks it as OK, otherwise, it marks the
 * buffer as empty (discards the old data).
 *
 * It is awakened when there are buffers full of raw data (by the RNG source
 * thread). It awakens the RNG source thread when it discards a buffer, and the
 * RNG sink thread when it approves a buffer.
 *
 * Only one FIPS test thread is supported.
 */
void *do_rng_fips_test_loop( void *trash )
{
	int i,j;
	int fips_result;
	struct timeval start, stop;
	int  bad_run;
	int  warnuser;

	/* Startup: wait until we get some data to work on */
	while (ISBUFFIFO_EMPTY(full)) {
		if (gotsigterm) pthread_exit(NULL);

		pthread_mutex_lock(&rng_buffer_raw_mutex);
		pthread_cond_wait(&rng_buffer_raw, &rng_buffer_raw_mutex);
		pthread_mutex_unlock(&rng_buffer_raw_mutex);
	}

	bad_run = 0;
	warnuser = 1;

	for (;;) {
		if (gotsigterm) pthread_exit(NULL);

		if (ISBUFFIFO_NONEMPTY(full)) {
			BUFFIFO_READ(full, i);
			
			gettimeofday(&start, 0);
			fips_result = fips_run_rng_test(&fipsctx, rng_buf[i]);

			if (!fips_result) {
				/* block is good */
				BUFFIFO_WRITE(accepted, i);
				bad_run = 0;
			} else {
				/* block is not random */
				if (++bad_run > 3) {
					if (!pausesource) throttling++;
					pausesource = (ISBUFFIFO_NONEMPTY(full));
				}

				BUFFIFO_WRITE(rejected, i);
			}

			gettimeofday (&stop, 0);
			pthread_mutex_lock(&rng_stats.group2_mutex);
			update_usectimer_stat(&rng_stats.fips_blockfill,
					&start, &stop);
			pthread_mutex_unlock(&rng_stats.group2_mutex);

			if (fips_result) {
				if (!pausesource) {
					pthread_mutex_lock(&rng_buffer_empty_mutex);
					pthread_cond_signal(&rng_buffer_empty);
					pthread_mutex_unlock(&rng_buffer_empty_mutex);
				}

				pthread_mutex_lock(&rng_stats.group2_mutex);
				rng_stats.bad_fips_blocks++;
				for (j = 0; j < N_FIPS_TESTS; j++)
					if (fips_result & fips_test_mask[j])
						rng_stats.fips_failures[j]++;
				pthread_mutex_unlock(&rng_stats.group2_mutex);
				message(LOG_NOTICE,
					"block failed FIPS test: 0x%02x", 
					fips_result);

				if (warnuser && throttling) {
					warnuser = 0;
					message(LOG_WARNING,
					  "Too many consecutive bad blocks of data, check RNG!");
					message(LOG_NOTICE,
					  "Throttling down RNG read speed...");
				} 
				if (throttling > MAX_THROTTLE_LEVEL) {
					message(LOG_CRIT,
					  "Too many bad blocks, RNG malfunction assumed");
					exitstatus = EXIT_FAIL;
					kill(masterprocess, SIGTERM);
					pthread_exit(NULL);
				}
			} else {
				pausesource = 0;
				if (throttling) {
					throttling = 0;
					warnuser = 1;
					message(LOG_NOTICE, "RNG recovered");
				}

				pthread_mutex_lock(&rng_buffer_ready_mutex);
				pthread_cond_signal(&rng_buffer_ready);
				pthread_mutex_unlock(&rng_buffer_ready_mutex);

				pthread_mutex_lock(&rng_stats.group2_mutex);
				rng_stats.good_fips_blocks++;
				pthread_mutex_unlock(&rng_stats.group2_mutex);
			}
		} else {
			pausesource = 0;	/* avoid deadlock */
			pthread_mutex_lock(&rng_buffer_raw_mutex);
			pthread_cond_wait(&rng_buffer_raw, &rng_buffer_raw_mutex);
			pthread_mutex_unlock(&rng_buffer_raw_mutex);
		}
	}
}

