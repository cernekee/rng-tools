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
 * Copyright (C) 2001 Philipp Rumpf <prumpf@mandrakesoft.com>
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

#ifdef HAVE_CONFIG_H
#  include "rng-tools-config.h"
#endif

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

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

/*
 * argp stuff
 */


const char *argp_program_version = "rngd " VERSION;
const char *argp_program_bug_address = "Philipp Rumpf <prumpf@mandrakesoft.com>";

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
	rng_name:	"/dev/hwrandom",
	random_name:	"/dev/random",
	pidfile_name:	"/var/run/rngd.pid",
	poll_timeout:	60,
	random_step:	64,
	daemon:		1,
	rng_entropy:	1.0,
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


/*
 * FIPS test
 */


/*
 * number of bytes required for a FIPS test.
 * do not alter unless you really, I mean
 * REALLY know what you are doing.
 * (and make sure it is an even number)
 */
#define FIPS_THRESHOLD 2500

/* These are the startup tests suggested by the FIPS 140-1 spec section
*  4.11.1 (http://csrc.nist.gov/fips/fips1401.htm)
*  The Monobit, Poker, Runs, and Long Runs tests are implemented below.
*  This test is run at periodic intervals to verify
*  data is sufficiently random. If the tests are failed the RNG module
*  will no longer submit data to the entropy pool, but the tests will
*  continue to run at the given interval. If at a later time the RNG
*  passes all tests it will be re-enabled for the next period.
*   The reason for this is that it is not unlikely that at some time
*  during normal operation one of the tests will fail. This does not
*  necessarily mean the RNG is not operating properly, it is just a
*  statistically rare event. In that case we don't want to forever
*  disable the RNG, we will just leave it disabled for the period of
*  time until the tests are rerun and passed.
*
*  For argument sake I tested /dev/urandom with these tests and it
*  took 142,095 tries before I got a failure, and urandom isn't as
*  random as random :)
*
*  hmh@debian.org: I've added the continuous run test, as per FIPS
*  140-1 4.11.2.
*/

static int poker[16], runs[12], last32;
static int ones, rlength = -1, current_bit, longrun;

/*
 * rng_fips_test_store - store 8 bits of entropy in FIPS
 * 			 internal test data pool
 */
static void rng_fips_test_store (int rng_data)
{
	int j;
	static int last_bit = 0;

	poker[rng_data >> 4]++;
	poker[rng_data & 15]++;

	/* Note in the loop below rlength is always one less than the actual
	   run length. This makes things easier. */
	for (j = 7; j >= 0; j--) {
		ones += current_bit = (rng_data & 1 << j) >> j;
		if (current_bit != last_bit) {
			/* If runlength is 1-6 count it in correct bucket. 0's go in
			   runs[0-5] 1's go in runs[6-11] hence the 6*current_bit below */
			if (rlength < 5) {
				runs[rlength +
				     (6 * current_bit)]++;
			} else {
				runs[5 + (6 * current_bit)]++;
			}

			/* Check if we just failed longrun test */
			if (rlength >= 33)
				longrun = 1;
			rlength = 0;
			/* flip the current run type */
			last_bit = current_bit;
		} else {
			rlength++;
		}
	}
}

/*
 * now that we have some data, run a FIPS test
 */
static int rng_run_fips_test (unsigned char *buf)
{
	int i, j;
	int rng_test = 0;

	for (i=0; i<FIPS_THRESHOLD; i += 4) {
		int new32 = buf[i] | ( buf[i+1] << 8 ) | 
			    ( buf[i+2] << 16 )  | ( buf[i+3] << 24 );
		if (new32 == last32) rng_test |= 16;
		last32 = new32;
		rng_fips_test_store(buf[i]);
		rng_fips_test_store(buf[i+1]);
		rng_fips_test_store(buf[i+2]);
		rng_fips_test_store(buf[i+3]);
	}

	/* add in the last (possibly incomplete) run */
	if (rlength < 5)
		runs[rlength + (6 * current_bit)]++;
	else {
		runs[5 + (6 * current_bit)]++;
		if (rlength >= 33)
			rng_test |= 8;
	}
	
	if (longrun) {
		rng_test |= 8;
		longrun = 0;
	}

	/* Ones test */
	if ((ones >= 10346) || (ones <= 9654))
		rng_test |= 1;
	/* Poker calcs */
	for (i = 0, j = 0; i < 16; i++)
		j += poker[i] * poker[i];
	if ((j >= 1580457) || (j <= 1562821))
		rng_test |= 2;
	if ((runs[0] < 2267) || (runs[0] > 2733) ||
	    (runs[1] < 1079) || (runs[1] > 1421) ||
	    (runs[2] < 502) || (runs[2] > 748) ||
	    (runs[3] < 223) || (runs[3] > 402) ||
	    (runs[4] < 90) || (runs[4] > 223) ||
	    (runs[5] < 90) || (runs[5] > 223) ||
	    (runs[6] < 2267) || (runs[6] > 2733) ||
	    (runs[7] < 1079) || (runs[7] > 1421) ||
	    (runs[8] < 502) || (runs[8] > 748) ||
	    (runs[9] < 223) || (runs[9] > 402) ||
	    (runs[10] < 90) || (runs[10] > 223) ||
	    (runs[11] < 90) || (runs[11] > 223)) {
		rng_test |= 4;
	}
	
	/* finally, clear out FIPS variables for start of next run */
	memset (poker, 0, sizeof (poker));
	memset (runs, 0, sizeof (runs));
	ones = 0;
	rlength = -1;
	current_bit = 0;

	return rng_test;
}

static void xread(int fd, void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size) {
		r = read(fd, buf + off, size);
		if (r < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) continue;
			break;
		}
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
	struct {
		int ent_count;
		int pool_size;
	} pool = { 0, };
	struct pollfd pfd = {
		fd:	fd,
		events:	POLLOUT,
	};

	if (ioctl(fd, RNDGETPOOL, &pool) == 0 &&
	    pool.ent_count/8 < pool.pool_size*4)
		return;
	
	poll(&pfd, 1, 1000.0 * poll_timeout);
}

static void do_loop(int rng_fd, int random_fd, int random_step,
		    double poll_timeout,
		    double rng_entropy)
{
	unsigned char buf[FIPS_THRESHOLD];
	unsigned char *p;
	int fips;

	for (;;) {
		xread(rng_fd, buf, sizeof buf);

		fips = rng_run_fips_test(buf);
		if (fips) {
			message(LOG_DAEMON|LOG_ERR, "failed fips test: 0x%02x", fips);
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

static void discard_initial_data(int rng_fd)
{
	/* Trash 32 bits of what is probably stale (non-random)
	 * initial state from the RNG.  For Intel's, 8 bits would
	 * be enough, but since AMD's generates 32 bits at a time...
	 * 
	 * The kernel drivers should be doing this at device powerup,
	 * but at least up to 2.4.24, it doesn't. */
	unsigned char tempbuf[4];
	xread (rng_fd, tempbuf, sizeof tempbuf);

	/* Bootstrap FIPS test, sacrificing 32 bits of possibly
	 * good random data.  Better this than risk 2500 bytes 
	 * of wastage if the first FIPS test fails. */
	xread (rng_fd, tempbuf, sizeof tempbuf);
	last32 = tempbuf[0] | (tempbuf[1] << 8) | 
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

	/* At startup, discard the first 4 bytes of random data, to
	 * make sure we are not getting stale data from the hardware RNG.
	 * The kernel driver should do it, but it is buggy */
	discard_initial_data(rng_fd);

	do_loop(rng_fd, random_fd, arguments->random_step,
		arguments->poll_timeout ? : -1.0,
		arguments->rng_entropy);

	return EX_OK;
}
