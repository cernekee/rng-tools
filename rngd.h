/*
 * rngd.h -- rngd globals
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

#ifndef RNGD__H
#define RNGD__H

#define _GNU_SOURCE

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <syslog.h>

#include "fips.h"
#include "stats.h"

#define MAX_RNG_BUFFERS 10
#define STR_BUF_LEN 1024

/* Command line arguments and processing */
struct arguments {
	char *random_name;
	char *rng_name;
	char *pidfile_name;
	
	int random_step;
	int fill_watermark;
	double poll_timeout;

	int daemon;

	double rng_entropy;
	int rng_buffers;
};
extern struct arguments *arguments;

/* Statistics */
struct rng_stats {
	/* Group 1 */
	pthread_mutex_t group1_mutex;	/* Mutex to access group 1 */
	uint64_t bytes_received;	/* Bytes read from RNG source */
	struct rng_stat source_blockfill;	/* Block-receive time */

	/* Group 2 */
	pthread_mutex_t group2_mutex;	/* Mutex to access group 2 */
	struct rng_stat fips_blockfill;	/* FIPS-processing time */
	uint64_t bad_fips_blocks;	/* Blocks reproved by FIPS tests */
	uint64_t good_fips_blocks;	/* Blocks approved by FIPS tests */
	uint64_t 
	   fips_failures[N_FIPS_TESTS];	/* Breakdown of failed FIPS tests */
	
	/* Group 3 */
	pthread_mutex_t group3_mutex;	/* Mutex to access group 3 */
	uint64_t bytes_sent;		/* Bytes sent to RNG sink */
	uint64_t entropy_sent;		/* Bits of entropy sent to RNG sink */
	uint64_t sink_starved;		/* How many times we waited for 
					   FIPS-approved buffers to be ready */
	uint64_t buffer_lowmark;	/* Minimum number of ready buffers we
					   had after startup */
	struct rng_stat sink_wait;	/* Sink starvation wait */
};
extern struct rng_stats rng_stats;

/* Background/daemon mode */
extern pid_t masterprocess;		/* PID of the master process */
extern int am_daemon;			/* Nonzero if we went daemon */
extern int exitstatus;			/* Exit status on SIGTERM */

/* Signals */
extern volatile int gotsigterm;		/* Received a TERM signal */


/*
 * Routines and macros
 */
#define message(priority,fmt,args...) do { \
	if (am_daemon) { \
		syslog((priority), fmt, ##args); \
	} else { \
		fprintf(stderr, fmt, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

/* Exit rngd from outside a thread context */
extern void die(int status);

#endif /* RNGD__H */

