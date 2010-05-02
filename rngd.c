/*
 * rngd.c -- Random Number Generator daemon
 *
 * rngd reads data from a hardware random number generator, verifies it
 * looks like random data, and adds it to /dev/random's entropy store.
 * 
 * In theory, this should allow you to read very quickly from
 * /dev/random; rngd also adds bytes to the entropy store periodically
 * when it's full, which makes predicting the entropy store's contents
 * harder.
 *
 * Copyright (C) 2001 Philipp Rumpf
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

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/types.h>
#include <linux/random.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include <syslog.h>
#include <sysexits.h>

#include "fips.h"

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

/*
 * argp stuff
 */


const char *argp_program_version = "rngd " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = "rngd";

static struct argp_option options[] = {
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for random number output (default: /dev/random)" },

	{ "rng-device", 'r', "file", 0,
	  "Kernel device used for random number input (default: /dev/hwrandom)" },

	{ "random-step", 's', "nnn", 0,
	  "Number of bytes written to random-device at a time (default: 64)" },

	{ "timeout", 't', "nnn", 0,
	  "Interval written to random-device when the entropy pool is full, in seconds (default: 60)" },

	{ "pidfile", 'p', "file", 0,
	  "Path to file to write PID to in daemon mode (default: /var/run/rngd.pid)" },

	{ "rng-entropy", 'H', "nnn", 0,
	  "Entropy per bit of the hardware RNG (default: 1), 0 < nnn <= 1" },

	{ 0 },
};

struct arguments {
	char *random_name;
	char *rng_name;
	char *pidfile_name;
	
	int random_step;
	double poll_timeout;

	int daemon;

	double rng_entropy;
};

static struct arguments default_arguments = {
	.rng_name	= "/dev/hwrandom",
	.random_name	= "/dev/random",
	.pidfile_name	= "/var/run/rngd.pid",
	.poll_timeout	= 60,
	.random_step	= 64,
	.daemon		= 1,
	.rng_entropy	= 1.0,
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	
	switch(key) {
	case 'o':
		arguments->random_name = arg;
		break;
	case 'r':
		arguments->rng_name = arg;
		break;
	case 'p':
		arguments->pidfile_name = arg;
		break;
	case 't': {
		float f;
		if (sscanf(arg, "%f", &f) == 0)
			argp_usage(state);
		else
			arguments->poll_timeout = f;
		break;
	}

	case 'f':
		arguments->daemon = 0;
		break;
	case 'b':
		arguments->daemon = 1;
		break;
	case 's':
		if (sscanf(arg, "%i", &arguments->random_step) == 0)
			argp_usage(state);
		break;

	case 'H': {
		float H;
		if ((sscanf(arg, "%f", &H) == 0) || (H <= 0) || (H > 1))
			argp_usage(state);
		else
			arguments->rng_entropy = H;
		break;
	}

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

/* Logic and contexts */
static fips_ctx_t fipsctx;		/* Context for the FIPS tests */


/*
 * daemon abstraction
 */


static int am_daemon;

#define message(priority,fmt,args...) do { \
	if (am_daemon) { \
		syslog((priority), fmt, ##args); \
	} else { \
		fprintf(stderr, fmt, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

/* 
 * Write our pid to our pidfile, and lock it
 */
static FILE *daemon_lockfp = NULL;
static int daemon_lockfd;

void get_lock(const char* pidfile_name)
{
    int otherpid = 0;

    if (!daemon_lockfp) {
	    if (((daemon_lockfd = open(pidfile_name, O_RDWR|O_CREAT, 0644)) == -1 )
		|| ((daemon_lockfp = fdopen(daemon_lockfd, "r+"))) == NULL) {
		    message(LOG_DAEMON|LOG_ERR, "can't open or create %s", pidfile_name);
		    exit (EX_USAGE);
    	    }
    }

#ifdef HAVE_FLOCK
    if ( flock(daemon_lockfd, LOCK_EX|LOCK_NB) != 0 ) {
#else
    if ( lockf(fileno(daemon_lockfp), F_TLOCK, 0) != 0 ) {
#endif
    		rewind(daemon_lockfp);
		fscanf(daemon_lockfp, "%d", &otherpid);
		message(LOG_DAEMON|LOG_ERR, "can't lock %s, running daemon's pid may be %d",
		      pidfile_name, otherpid);
		exit (EX_USAGE);
	    }

    fcntl(daemon_lockfd, F_SETFD, 1);

    rewind(daemon_lockfp);
    fprintf(daemon_lockfp, "%d\n", (int) getpid());
    fflush(daemon_lockfp);
    ftruncate(fileno(daemon_lockfp), ftell(daemon_lockfp));
}



static void xread(int fd, void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size > 0) {
		do {
			r = read(fd, buf + off, size);
		} while ((r == -1) && ((errno == EINTR) || (errno == EAGAIN)));
		if (r < 0)
			break;
		off += r;
		size -= r;
	}

	if (size) {
		message(LOG_DAEMON|LOG_ERR, "error reading rng device: %s", strerror(errno));
		message(LOG_DAEMON|LOG_ERR, "terminating rngd...");
		exit(EX_OSERR);
	}
}

static void random_add_entropy(int fd, void *buf, size_t size,
			       double rng_entropy)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;

	entropy.ent_count = (int)(rng_entropy * size * 8);
	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(fd, RNDADDENTROPY, &entropy) != 0) {
		message(LOG_DAEMON|LOG_ERR, "RNDADDENTROPY failed: %s",
			strerror(errno));
		message(LOG_DAEMON|LOG_ERR, "terminating rngd...");
		exit(EX_OSERR);
	}
}

static void random_sleep(int fd, double poll_timeout)
{
	int ent_count;
	struct pollfd pfd = {
		fd:	fd,
		events:	POLLOUT,
	};

	if (ioctl(fd, RNDGETENTCNT, &ent_count) == 0 &&
	    ent_count < 2048)
		return;
	
	poll(&pfd, 1, 1000.0 * poll_timeout);
}

static void do_loop(int rng_fd, int random_fd, int random_step,
		    double poll_timeout,
		    double rng_entropy)
{
	unsigned char buf[FIPS_RNG_BUFFER_SIZE];
	unsigned char *p;
	int fips;

	for (;;) {
		xread(rng_fd, buf, sizeof buf);

		fips = fips_run_rng_test(&fipsctx, buf);

		if (fips) {
			message(LOG_DAEMON|LOG_ERR, "failed fips test\n");
			sleep(1);
			continue;
		}

		for (p = buf; p + random_step <= &buf[sizeof buf];
		     p += random_step) {
			random_add_entropy(random_fd, p, random_step, rng_entropy);
			random_sleep(random_fd, poll_timeout);
		}
	}
}

/* Initialize entropy source */
static int discard_initial_data(int fd)
{
	/* Trash 32 bits of what is probably stale (non-random)
	 * initial state from the RNG.  For Intel's, 8 bits would
	 * be enough, but since AMD's generates 32 bits at a time...
	 * 
	 * The kernel drivers should be doing this at device powerup,
	 * but at least up to 2.4.24, it doesn't. */
	unsigned char tempbuf[4];
	xread(fd, tempbuf, sizeof tempbuf);

	/* Return 32 bits of bootstrap data */
	xread(fd, tempbuf, sizeof tempbuf);

	return tempbuf[0] | (tempbuf[1] << 8) | 
		(tempbuf[2] << 16) | (tempbuf[3] << 24);
}


int main(int argc, char **argv)
{
	int rng_fd;
	int random_fd;
	int fd;
	struct arguments *arguments = &default_arguments;

	argp_parse(&argp, argc, argv, 0, 0, arguments);

	/* close useless FDs we might have gotten somehow */
	for(fd = 3; fd < 250; fd++) (void) close(fd);

	rng_fd = open(arguments->rng_name, O_RDONLY);

	if (rng_fd < 0) {
		message(LOG_DAEMON|LOG_ERR, "can't open RNG file %s: %s",
			arguments->rng_name, strerror(errno));
		return EX_USAGE;
	}
	
	random_fd = open(arguments->random_name, O_RDWR);

	if (random_fd < 0) {
		message(LOG_DAEMON|LOG_ERR, "can't open random file %s: %s",
			arguments->random_name, strerror(errno));
		return EX_USAGE;
	}

	if (arguments->daemon) {
		/* check if another rngd is running, create pidfile and lock it */
		get_lock(arguments->pidfile_name);

		if (daemon(0, 0) < 0) {
			message(LOG_DAEMON|LOG_ERR, "can't daemonize: %s",
					strerror(errno));
			return EX_OSERR;
		}

		openlog("rngd", 0, LOG_DAEMON);
		am_daemon = 1;

		/* update pidfile */
		get_lock(arguments->pidfile_name);
	}

	/* Bootstrap FIPS tests */
	fips_init(&fipsctx, discard_initial_data(rng_fd));

	do_loop(rng_fd, random_fd, arguments->random_step,
		arguments->poll_timeout ? : -1.0,
		arguments->rng_entropy);

	return EX_OK;
}
