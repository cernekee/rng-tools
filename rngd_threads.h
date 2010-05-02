/*
 * rngd_threads.h -- Thread communication
 *
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

#ifndef RNGD_THREADS__H
#define RNGD_THREADS__H

#include "rng-tools-config.h"

#include "rngd.h"
#include "fips.h"

#include <unistd.h>
#include <stdint.h>
#include <pthread.h>


/* Buffers for RNG data */
extern int rng_buffers;                 /* number of active buffers */

typedef unsigned char rng_buffer_t[FIPS_RNG_BUFFER_SIZE];
extern rng_buffer_t **rng_buf;

/* Initialize "n" RNG data buffers, and the FIFOs */
extern void init_rng_buffers(int n);

/*
 * FIFOs to pass blocks among the threads
 */
struct buf_fifo {
	pthread_mutex_t mutex;
	volatile int *data;
	volatile int head;
	volatile int tail;
};
struct buffer_queues {
	struct buf_fifo empty;		/* Empty buffers */
	struct buf_fifo full;		/* Buffers full of data of unknown quality */
	struct buf_fifo accepted;	/* Buffers that passed FIPS tests */
	struct buf_fifo rejected;	/* Buffers that failed FIPS tests */
};
extern struct buffer_queues buffer_queues;


/*
 * FIFO Control
 */
#define GETBUFFIFO_SIZE (rng_buffers+1)
#define BUFFIFO_READ(fifo, var) do { \
	pthread_mutex_lock(&buffer_queues.fifo.mutex); \
	var = buffer_queues.fifo.data[buffer_queues.fifo.tail]; \
	buffer_queues.fifo.tail = (buffer_queues.fifo.tail + 1) % GETBUFFIFO_SIZE; \
	pthread_mutex_unlock(&buffer_queues.fifo.mutex); \
} while (0)

#define BUFFIFO_WRITE(fifo, value) do { \
	pthread_mutex_lock(&buffer_queues.fifo.mutex); \
	buffer_queues.fifo.data[buffer_queues.fifo.head] = value; \
	buffer_queues.fifo.head = (buffer_queues.fifo.head + 1) % GETBUFFIFO_SIZE; \
	pthread_mutex_unlock(&buffer_queues.fifo.mutex); \
} while (0)

#define ISBUFFIFO_EMPTY(fifo) (buffer_queues.fifo.head == buffer_queues.fifo.tail)
#define ISBUFFIFO_NONEMPTY(fifo) (buffer_queues.fifo.head != buffer_queues.fifo.tail)
extern int getbuffifo_count(struct buf_fifo *fifo);


/*
 * Thread control
 */
/* RNG data source thread waits on this condition */
extern pthread_cond_t	rng_buffer_empty;
extern pthread_mutex_t	rng_buffer_empty_mutex;

/* FIPS processing thread waits on this condition */
extern pthread_cond_t	rng_buffer_raw;
extern pthread_mutex_t	rng_buffer_raw_mutex;

/* RNG data sink thread waits on this condition */
extern pthread_cond_t	rng_buffer_ready;
extern pthread_mutex_t	rng_buffer_ready_mutex;

#endif /* RNGD_THREADS__H */
