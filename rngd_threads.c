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
#include <sys/mman.h>

#include <assert.h>

#include "rngd.h"
#include "fips.h"
#include "stats.h"
#include "exits.h"
#include "rngd_threads.h"


/* Buffers for RNG data */
int rng_buffers = 0;		/* number of active buffers */
rng_buffer_t **rng_buf = NULL;	/* vector of pointers to the buffers */	

/*
 * FIFOs to pass blocks among the threads
 */
struct buffer_queues buffer_queues;


/*
 * Get the amount of data in a FIFO
 */
int getbuffifo_count(struct buf_fifo *fifo)
{
	int count;

	assert(fifo != NULL);

	pthread_mutex_lock(&(fifo->mutex));
	count = (fifo->head >= fifo->tail) ?
		 fifo->head - fifo->tail :
		 GETBUFFIFO_SIZE + fifo->head - fifo->tail;
	pthread_mutex_unlock(&(fifo->mutex));
	return count;
}


/* handy malloc()/calloc() error handler */
void *test_malloc(void *p) {
	if (!p) {
		message(LOG_ERR, "cannot allocate buffers");
		die(EXIT_OSERR);
	}
	return p;
}

/*
 *  Init the RNG buffer structures
 */

#define BUFFIFO_INIT(fifo) do { \
	pthread_mutex_init(&buffer_queues.fifo.mutex, NULL); \
	buffer_queues.fifo.head = buffer_queues.fifo.tail = 0; \
	buffer_queues.fifo.data = test_malloc(calloc(GETBUFFIFO_SIZE, \
		sizeof(*buffer_queues.fifo.data))); \
} while (0)

void init_rng_buffers(int n)
{
	int i;

	assert(n <= MAX_RNG_BUFFERS);

	rng_buffers = n;

	BUFFIFO_INIT(empty);
	BUFFIFO_INIT(full);
	BUFFIFO_INIT(accepted);
	BUFFIFO_INIT(rejected);

	rng_buf = test_malloc(calloc(rng_buffers, sizeof(*rng_buf)));

	for (i = 0; i < rng_buffers; i++) {
		BUFFIFO_WRITE(empty, i);

		rng_buf[i] = test_malloc(malloc(FIPS_RNG_BUFFER_SIZE));
		if (mlock(rng_buf[i], FIPS_RNG_BUFFER_SIZE)) {
			message_strerr(LOG_ERR, errno, "cannot lock buffers");
                        die(EXIT_OSERR);
		}
	}
}

