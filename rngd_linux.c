/*
 * rngd_linux.c -- Entropy sink for the Linux Kernel (/dev/random)
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
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/random.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include "rngd.h"
#include "fips.h"
#include "stats.h"
#include "exits.h"
#include "rngd_threads.h"
#include "rngd_linux.h"

/* Kernel output device */
static int random_fd;

/* RNG data sink thread waits on this condition */
pthread_cond_t	rng_buffer_ready = PTHREAD_COND_INITIALIZER;
pthread_mutex_t	rng_buffer_ready_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 *
 * randomdev is the path to the random device
 */
void init_kernel_rng(const char* randomdev)
{
	random_fd = open(randomdev, O_RDWR);
	if (random_fd == -1) {
		message(LOG_ERR, "can't open %s: %s",
			randomdev, strerror(errno));
		die(EXIT_USAGE);
	}
}


/*
 * RNG data sink thread
 *
 * This thread feeds the output device with data that has been approved by the
 * FIPS tests.
 *
 * It is awakened by the FIPS test thread when there are buffers ready. It
 * awakens the RNG source thread when it empties a buffer
 *
 * Only one data sink thread is supported.
 */

/*
 * Send entropy to the kernel entropy pool
 */
static void random_add_entropy(void *buf, size_t size)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;
	char errbuf[STR_BUF_LEN];

	entropy.ent_count = (int)(arguments->rng_entropy * size * 8);
	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(random_fd, RNDADDENTROPY, &entropy) != 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		errbuf[sizeof(errbuf)-1]=0;
		message(LOG_ERR, "RNDADDENTROPY failed: %s",
			errbuf);
		exitstatus = EXIT_OSERR;
		kill(masterprocess, SIGTERM);
		pthread_exit(NULL);
	}

	memset(entropy.data, 0, size);

	pthread_mutex_lock(&rng_stats.group3_mutex);
	rng_stats.bytes_sent += size;
	rng_stats.entropy_sent += entropy.ent_count;
	pthread_mutex_unlock(&rng_stats.group3_mutex);
}

/*
 * Wait until the kernel needs more entropy
 */
static void random_sleep( void )
{
	int ent_count;
	struct pollfd pfd = {
		fd:	random_fd,
		events:	POLLOUT,
	};

	if (ioctl(random_fd, RNDGETENTCNT, &ent_count) == 0 &&
	    ent_count < arguments->fill_watermark)
		return;
	
	poll(&pfd, 1, 1000.0 * (arguments->poll_timeout ? : -1.0));
}

void *do_rng_data_sink_loop( void *trash )
{
	int i,s,r;
	int starving = 0;
	int nready;
	unsigned char *p;
	struct timeval start, stop;

	thread_init_sighandlers();

	/*  Startup: Wait until we get some data to work on */
	if (ISBUFFIFO_EMPTY(accepted)) {
		pthread_mutex_lock(&rng_buffer_ready_mutex);
		pthread_cond_wait(&rng_buffer_ready, &rng_buffer_ready_mutex);
		pthread_mutex_unlock(&rng_buffer_ready_mutex);
	}

	message(LOG_INFO, "entropy feed to the kernel ready");

	for (;;) {
		if (gotsigterm) pthread_exit(NULL);

		if (ISBUFFIFO_NONEMPTY(accepted)) {
			BUFFIFO_READ(accepted, i);
			
			if (starving) {
				gettimeofday(&stop, 0);
				pthread_mutex_lock(&rng_stats.group3_mutex);
				update_usectimer_stat(&rng_stats.sink_wait,
						      &start, &stop);
				pthread_mutex_unlock(&rng_stats.group3_mutex);
				starving = 0;
			}

			p = (unsigned char *)rng_buf[i];
			r = FIPS_RNG_BUFFER_SIZE;

			while (r > 0) {
				if (gotsigterm) pthread_exit(NULL);

				if ((s = arguments->random_step) > r) s = r;
				random_add_entropy(p, s);
				r -= s;
				p += s;
				random_sleep();
			}

			nready = getbuffifo_count(&buffer_queues.accepted);
			pthread_mutex_lock(&rng_stats.group3_mutex);
			if (nready < rng_stats.buffer_lowmark)
				rng_stats.buffer_lowmark = nready;
			pthread_mutex_unlock(&rng_stats.group3_mutex);

			BUFFIFO_WRITE(empty, i);

			pthread_mutex_lock(&rng_buffer_empty_mutex);
			pthread_cond_signal(&rng_buffer_empty);
			pthread_mutex_unlock(&rng_buffer_empty_mutex);
		} else {
			gettimeofday(&start, 0);
			starving = 1;
			pthread_mutex_lock(&rng_stats.group3_mutex);
			rng_stats.sink_starved++;
			pthread_mutex_unlock(&rng_stats.group3_mutex);

			pthread_mutex_lock(&rng_buffer_ready_mutex);
			pthread_cond_wait(&rng_buffer_ready, &rng_buffer_ready_mutex);
			pthread_mutex_unlock(&rng_buffer_ready_mutex);
		}
	}
}

