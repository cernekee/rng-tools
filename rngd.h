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
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>

#include "fips.h"
#include "stats.h"
#include "util.h"
#include "rngd_entsource.h"

#define MAX_RNG_BUFFERS 1000
#define STR_BUF_LEN 1024

/* Command line arguments and processing */
struct arguments {
	/* Paths to devices */
	char *random_name;
	char *rng_name;
	char *pidfile_name;

	int random_step;
	int fill_watermark;	/* n<0: percentage of poolsize, 
				   n>=0: number of bits */
	int feed_interval;

	int rng_timeout;
	int rng_quality;	/* 0: default, 1=low, 2=med, 3=high */
	
	int daemon;

	double rng_entropy;
	int rng_buffers;

	entropy_source_driver_t rng_driver;
};
extern struct arguments *arguments;

/* Statistics */
struct rng_stats {
	/* Group 1 */
	pthread_mutex_t group1_mutex;	/* Mutex to access group 1 */
	uint64_t bytes_received;	/* Bytes read from entropy source */
	struct rng_stat source_blockfill;  /* Block-receive time */

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
	uint64_t entropy_sent;		/* Bits of entropy sent to ent. sink */
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

/* Other global information */
extern kernel_mode_t kernel;		/* Kernel compatibility mode */

/*
 * Log messages to syslog or stdio (thread-safe)
 */
extern void message(int priority, const char* fmt, ...)
     __attribute__ ((__format__(__printf__, 2, 3)));

/* appends ": <strerr_r(errornumber)>" */
extern void message_strerr(int priority, int errornumber,
		const char* fmt, ...)
     __attribute__ ((__format__(__printf__, 3, 4)));


/* 
 * Exit rngd the hard way 
 * */
extern void die(int status)
	__attribute__ ((noreturn));

#endif /* RNGD__H */
