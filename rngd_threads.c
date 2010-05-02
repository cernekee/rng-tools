/*
 * rngd_threads.c -- Common thread code
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
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>

#include "rngd.h"
#include "fips.h"
#include "stats.h"
#include "exits.h"
#include "rngd_threads.h"

/* Buffers for RNG data */
int rng_buffers;                 /* number of active buffers */
rng_buffer_t *rng_buf[MAX_RNG_BUFFERS];

/*
 * FIFOs to pass blocks among the threads
 */
struct buffer_queues buffer_queues;

int getbuffifo_count(struct buf_fifo *fifo)
{
	int count;

	pthread_mutex_lock(&(fifo->mutex));
	count = (fifo->head >= fifo->tail) ?
		 fifo->head - fifo->tail :
		 GETBUFFIFO_SIZE + fifo->head - fifo->tail;
	pthread_mutex_unlock(&(fifo->mutex));
	return count;
}

/*
 * Thread signal handling
 */
void thread_init_sighandlers(void)
{
	sigset_t	sigs;
	
	sigfillset(&sigs);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);
}

/*
 *  Init the RNG buffer structures
 */
void init_rng_buffers(int n)
{
	int i;

	rng_buffers = n;

	BUFFIFO_INIT(empty);
	BUFFIFO_INIT(full);
	BUFFIFO_INIT(accepted);
	BUFFIFO_INIT(rejected);

	for (i = 0; i < rng_buffers; i++) {
		BUFFIFO_WRITE(empty, i);

		rng_buf[i] = malloc(FIPS_RNG_BUFFER_SIZE);
		if (!rng_buf[i]) {
			message(LOG_ERR, "cannot allocate buffers");
			die(EXIT_OSERR);
		}
		if (mlock(rng_buf[i], FIPS_RNG_BUFFER_SIZE)) {
			message(LOG_ERR, "cannot lock buffers: %s",
					strerror(errno));
                        die(EXIT_OSERR);
		}
	}
}

