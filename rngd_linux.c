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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/random.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <assert.h>

#include "rngd.h"
#include "fips.h"
#include "stats.h"
#include "exits.h"
#include "util.h"
#include "rngd_threads.h"
#include "rngd_signals.h"
#include "rngd_linux.h"

/* Kernel output device */
static int random_fd = -1;

/* Kernel RNG parameters */
static long int random_pool_size = 4096;
static long int random_pool_fill_watermark = 2048;
static int random_device_timeout; /* seconds */

/* RNG data sink thread waits on this condition */
pthread_cond_t	rng_buffer_ready = PTHREAD_COND_INITIALIZER;
pthread_mutex_t	rng_buffer_ready_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * RNG parameter helpers
 */
static int get_rng_proc_parameter(const char* param, long int *value)
{
	FILE *fp = NULL;
	int error = 0;

	long int curvalue;
	char procname[512];

	assert(param != NULL && value != NULL);

	snprintf(procname, sizeof(procname), "/proc/sys/kernel/random/%s",
		 param);
	procname[sizeof(procname)-1] = 0;
	if ( ((fp = fopen(procname, "r")) != NULL) &&
		(fscanf(fp, "%ld", &curvalue) == 1) ) {
		*value = curvalue;
	} else error = 1;
	if (fp != NULL) error |= fclose(fp);
	
	if (error) {
		message_strerr(LOG_WARNING, error,
			"Cannot read %s", procname);
		return -1;
	}
	return 0;
}

#if 0
static int set_rng_proc_parameter(const char* param, long int *value)
{
	FILE *fp = NULL;
	int error = 0;
	
	long int curvalue;
	char procname[512];

	assert(param != NULL, value != NULL);

	snprintf(procname, sizeof(procname), "/proc/sys/kernel/random/%s", 
		 param);
	procname[sizeof(procname)-1] = 0;
	if ( ((fp = fopen(procname, "r+")) != NULL) &&
		 (fscanf(fp, "%ld", &curvalue) == 1) ) {
		if ( *value > curvalue ) {
			rewind(fp);
			fprintf(fp, "%ld\n", *value);
			message(LOG_NOTICE, "Setting %s to %ld",
				procname, *value);
		} else {
			*value = curvalue;
		}
	} else error = 1;
	if (fp != NULL) error |= fclose(fp);
	
	if (error) {
		message_strerr(LOG_WARNING, errno,
			"Cannot set %s to a minimum of %ld",
			procname, *value);
		return -1;
	}
	return 0;
}
#endif

/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 */
void init_kernel_rng( void )
{
	assert(random_fd == -1);

	random_fd = open(arguments->random_name, O_RDWR);
	if (random_fd == -1) {
		message_strerr(LOG_ERR, errno, "can't open %s",
			arguments->random_name);
		die(EXIT_USAGE);
	}

	random_device_timeout = arguments->feed_interval;

	get_rng_proc_parameter("poolsize", &random_pool_size);
	if (arguments->fill_watermark >= 0)
		random_pool_fill_watermark = arguments->fill_watermark;
	else
		random_pool_fill_watermark = (long int) random_pool_size * 
			(-arguments->fill_watermark) / 100.0;

	/* Avoid looping on something that will never happen,
	 * with a off-by-one tolerance margin just in case */
	if (random_pool_fill_watermark > random_pool_size - 1)
		random_pool_fill_watermark = random_pool_size - 1;
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

	assert(buf != NULL);

	entropy.ent_count = (int)(arguments->rng_entropy * size * 8);
	/* Linux kernel 2.4 mode, account for 4x entropy accounting bug */
	if (kernel == KERNEL_LINUX_24) entropy.ent_count /= 4;

	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(random_fd, RNDADDENTROPY, &entropy) != 0) {
		message_strerr(LOG_ERR, errno, "RNDADDENTROPY failed");
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
		events: POLLOUT,
	};
	struct timeval start, now;
	int64_t timeout_usec;

	if (ioctl(random_fd, RNDGETENTCNT, &ent_count) == 0 &&
	    ent_count < random_pool_fill_watermark)
		return;

	if (random_device_timeout > 0) {
		timeout_usec = random_device_timeout * 1000;
		gettimeofday(&start, NULL);
		while (!gotsigterm && timeout_usec > 0 &&
				poll(&pfd, 1, timeout_usec) < 0 &&
				errno != EINTR) {
			gettimeofday(&now, NULL);
			timeout_usec -= elapsed_time(&start, &now);
			start = now;
		}
	} else {
		while (!gotsigterm && poll(&pfd, 1, -1) < 0) {
			if (errno != EINTR) break;
		}
	}
				
}

void *do_rng_data_sink_loop( void *trash )
{
	int i,s,r;
	int starving = 0;
	int nready;
	unsigned char *p;
	struct timeval start, stop;

	/* Warn of KERNEL_LINUX_24 entropy correction */
	if (kernel == KERNEL_LINUX_24)
		message(LOG_INFO, "Activating Linux kernel 2.4 entropy accounting bug workaround");

	/*  Startup: Wait until we get some data to work on */
	while (ISBUFFIFO_EMPTY(accepted)) {
		if (gotsigterm) pthread_exit(NULL);

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

